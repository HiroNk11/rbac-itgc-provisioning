using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Api.Security;

public sealed class ApiKeyMiddleware
{
    private readonly RequestDelegate next;
    private readonly byte[] expectedDigest;
    private readonly string actorId;

    public ApiKeyMiddleware(RequestDelegate next, IOptions<ApiKeyOptions> options)
    {
        this.next = next;
        expectedDigest = SHA256.HashData(Encoding.UTF8.GetBytes(options.Value.Key));
        actorId = options.Value.ActorId;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Corre antes del binding del JSON: sin credencial válida siempre devuelve 401.
        if (!context.Request.Headers.TryGetValue("X-Api-Key", out var values) ||
            values.Count != 1 || string.IsNullOrEmpty(values[0]) || values[0]!.Length > 512 ||
            !CryptographicOperations.FixedTimeEquals(expectedDigest,
                SHA256.HashData(Encoding.UTF8.GetBytes(values[0]!))))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        context.User = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, actorId)], "ApiKey"));
        await next(context);
    }
}
