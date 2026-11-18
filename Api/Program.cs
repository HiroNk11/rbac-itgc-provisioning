using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Api.Security;
using Api.Storage;
using Application;
using Domain;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<ApiKeyOptions>()
    .BindConfiguration(ApiKeyOptions.SectionName)
    .Validate(o => !string.IsNullOrWhiteSpace(o.Key) && o.Key.Length is >= 32 and <= 512,
        "ApiKey:Key debe tener entre 32 y 512 caracteres.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.ActorId) && o.ActorId.Length <= 200,
        "ApiKey:ActorId es obligatorio y admite hasta 200 caracteres.")
    .ValidateOnStart();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SodPolicyValidator>();
builder.Services.AddSingleton<IProvisioningStore, InMemoryProvisioningStore>();
builder.Services.AddScoped<SubmitRequestHandler>();
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false));
    o.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
});
builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 16 * 1024);

var app = builder.Build();
app.UseMiddleware<ApiKeyMiddleware>();

app.MapPost("/api/v1/requests", (SubmitCommand command, SubmitRequestHandler handler, HttpContext context) =>
{
    try
    {
        var actorId = context.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var result = handler.Handle(command, actorId);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Accepted($"/api/v1/requests/{result.Request.Id}", result.Request);
    }
    catch (InvalidRequestException ex)
    {
        return Results.BadRequest(new { code = ex.Message });
    }
    catch (IdempotencyConflictException ex)
    {
        return Results.Conflict(new { code = ex.Message });
    }
});

app.MapGet("/api/v1/requests/{id:guid}", (Guid id, IProvisioningStore store, HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";
    return store.Find(id) is { } request ? Results.Ok(request) : Results.NotFound();
});
app.MapGet("/api/v1/audit", (IProvisioningStore store, HttpContext context) =>
{
    context.Response.Headers.CacheControl = "no-store";
    return Results.Ok(store.ReadAudit());
});
app.Run();
