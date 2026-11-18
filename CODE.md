# Código completo — Hito 1, .NET 10

Ver README.md para configuración, decisiones de contrato y pruebas.

## Directory.Build.props

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>
</Project>
```

## Domain/Domain.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk" />
```

## Domain/ProvisioningRequest.cs

```csharp
using System.Collections.Immutable;

namespace Domain;

// Implementaciones de referencia: adaptar estas firmas a tus clases existentes.
public enum SystemRole { Reader, Operator, Approver, Administrator, Auditor }
public enum ProvisioningOperation { Create, ReplaceRoles, Disable }
public enum ProvisioningStatus { Pending, Rejected }

public sealed class ProvisioningRequest
{
    public Guid Id { get; }
    public string ExternalId { get; }
    public string UserId { get; }
    public ProvisioningOperation Operation { get; }
    public ImmutableArray<SystemRole> Roles { get; }
    public int ExpectedVersion { get; }
    public string Reason { get; }
    public string ActorId { get; }
    public DateTimeOffset ReceivedAtUtc { get; }
    public ProvisioningStatus Status { get; }
    public string PolicyVersion { get; }
    public string? RejectionCode { get; }

    public ProvisioningRequest(Guid id, string externalId, string userId,
        ProvisioningOperation operation, IEnumerable<SystemRole> roles, int expectedVersion,
        string reason, string actorId, DateTimeOffset receivedAtUtc,
        ProvisioningStatus status, string policyVersion, string? rejectionCode)
    {
        Id = id; ExternalId = externalId; UserId = userId; Operation = operation;
        Roles = roles.ToImmutableArray(); ExpectedVersion = expectedVersion;
        Reason = reason; ActorId = actorId; ReceivedAtUtc = receivedAtUtc.ToUniversalTime();
        Status = status; PolicyVersion = policyVersion; RejectionCode = rejectionCode;
    }
}
```

## Domain/SodPolicyValidator.cs

```csharp
namespace Domain;

public sealed record SodDecision(bool Allowed, string? Code);

public sealed class SodPolicyValidator
{
    public const string PolicyVersion = "sod-v1";

    public SodDecision Validate(IEnumerable<SystemRole> proposedRoles)
    {
        var roles = proposedRoles.ToHashSet();
        if (roles.Any(role => !Enum.IsDefined(role))) return new(false, "UNKNOWN_ROLE");
        if (roles.Contains(SystemRole.Operator) && roles.Contains(SystemRole.Approver))
            return new(false, "SOD_OPERATOR_APPROVER");
        if (roles.Contains(SystemRole.Administrator) && roles.Contains(SystemRole.Auditor))
            return new(false, "SOD_ADMINISTRATOR_AUDITOR");
        return new(true, null);
    }
}
```

## Domain/AuditEvent.cs

```csharp
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Domain;

// sealed, sin setters ni init; todas las colecciones son inmutables.
public sealed class AuditEvent
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private static readonly JsonSerializerOptions HashJson = CreateHashOptions();
    public long Sequence { get; }
    public Guid RequestId { get; }
    public DateTimeOffset TimestampUtc { get; }
    public string ActorId { get; }
    public string UserId { get; }
    public ProvisioningOperation Operation { get; }
    public ImmutableArray<SystemRole> RequestedRoles { get; }
    // null: el evento de recepción no observó ni modificó una cuenta.
    public ImmutableArray<SystemRole>? Before { get; }
    public ImmutableArray<SystemRole>? After { get; }
    public string Outcome { get; }
    public string Reason { get; }
    public string PolicyVersion { get; }
    public string PreviousHash { get; }
    public string Hash { get; }

    public AuditEvent(long sequence, ProvisioningRequest request, string previousHash)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (sequence < 1) throw new ArgumentOutOfRangeException(nameof(sequence));
        if (previousHash is null || previousHash.Length != 64 ||
            previousHash.Any(c => !(c is >= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new ArgumentException("Se requiere SHA-256 hexadecimal en mayúsculas.", nameof(previousHash));
        Sequence = sequence; RequestId = request.Id; TimestampUtc = request.ReceivedAtUtc;
        ActorId = request.ActorId; UserId = request.UserId; Operation = request.Operation;
        RequestedRoles = request.Roles.ToImmutableArray();
        Before = null; After = null;
        Outcome = request.Status == ProvisioningStatus.Pending ? "REQUEST_RECEIVED" : request.RejectionCode!;
        Reason = request.Reason; PolicyVersion = request.PolicyVersion; PreviousHash = previousHash;
        Hash = CalculateHash();
    }

    // Contrato: SHA256(JSON UTF-8 del evento, PreviousHash incluido y Hash vacío).
    // No se puede incluir el Hash final en su propio cálculo.
    // Orden explícito y opciones privadas: no depende de las opciones HTTP de ASP.NET.
    public byte[] GetHashPayloadUtf8() => JsonSerializer.SerializeToUtf8Bytes(new
    {
        Sequence, RequestId, TimestampUtc, ActorId, UserId, Operation,
        RequestedRoles, Before, After, Outcome, Reason, PolicyVersion, PreviousHash,
        Hash = string.Empty
    }, HashJson);

    public string CalculateHash() => Convert.ToHexString(SHA256.HashData(GetHashPayloadUtf8()));

    public bool HasValidHash() => CryptographicOperations.FixedTimeEquals(
        Convert.FromHexString(Hash), SHA256.HashData(GetHashPayloadUtf8()));

    private static JsonSerializerOptions CreateHashOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter<SystemRole>(allowIntegerValues: false));
        options.Converters.Add(new JsonStringEnumConverter<ProvisioningOperation>(allowIntegerValues: false));
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }
}
```

## Application/Application.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup><ProjectReference Include="../Domain/Domain.csproj" /></ItemGroup>
</Project>
```

## Application/SubmitRequest.cs

```csharp
using System.Collections.Immutable;
using Domain;

namespace Application;

public sealed record SubmitCommand(string? ExternalId, string? UserId,
    ProvisioningOperation? Operation, SystemRole[]? Roles, int? ExpectedVersion, string? Reason);

public sealed record Submission(string ExternalId, string UserId,
    ProvisioningOperation Operation, ImmutableArray<SystemRole> Roles, int ExpectedVersion,
    string Reason, string ActorId, DateTimeOffset ReceivedAtUtc,
    ProvisioningStatus Status, string? RejectionCode);

public sealed record SubmissionResult(ProvisioningRequest Request, bool Replayed);
public sealed class InvalidRequestException(string code) : Exception(code);
public sealed class IdempotencyConflictException() : Exception("IDEMPOTENCY_KEY_REUSED");

public interface IProvisioningStore
{
    SubmissionResult Register(Submission submission);
    ProvisioningRequest? Find(Guid id);
    ImmutableArray<AuditEvent> ReadAudit();
}

public sealed class SubmitRequestHandler(IProvisioningStore store,
    SodPolicyValidator policy, TimeProvider clock)
{
    public SubmissionResult Handle(SubmitCommand c, string actorId)
    {
        if (string.IsNullOrWhiteSpace(c.ExternalId) || c.ExternalId.Length > 100 ||
            string.IsNullOrWhiteSpace(c.UserId) || c.UserId.Length > 100 ||
            string.IsNullOrWhiteSpace(c.Reason) || c.Reason.Length > 1000 ||
            c.Operation is null || !Enum.IsDefined(c.Operation.Value) ||
            c.ExpectedVersion is null or < 0 || c.Roles is null || c.Roles.Length > 5 ||
            c.Roles.Any(r => !Enum.IsDefined(r)))
            throw new InvalidRequestException("INVALID_REQUEST");
        if (string.IsNullOrWhiteSpace(actorId)) throw new ArgumentException("Actor requerido.", nameof(actorId));
        if (c.Operation == ProvisioningOperation.Disable && c.Roles.Length != 0)
            throw new InvalidRequestException("DISABLE_REQUIRES_EMPTY_ROLES");
        if (c.Operation != ProvisioningOperation.Disable && c.Roles.Length == 0)
            throw new InvalidRequestException("ROLES_REQUIRED");

        var roles = c.Roles.Distinct().Order().ToImmutableArray();
        var decision = policy.Validate(roles);
        var submission = new Submission(c.ExternalId, c.UserId, c.Operation.Value, roles,
            c.ExpectedVersion.Value, c.Reason, actorId, clock.GetUtcNow(),
            decision.Allowed ? ProvisioningStatus.Pending : ProvisioningStatus.Rejected, decision.Code);
        return store.Register(submission);
    }
}
```

## Api/Api.csproj

```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup><ProjectReference Include="../Application/Application.csproj" /></ItemGroup>
</Project>
```

## Api/Security/ApiKeyOptions.cs

```csharp
namespace Api.Security;

public sealed class ApiKeyOptions
{
    public const string SectionName = "ApiKey";
    public string Key { get; init; } = "";
    public string ActorId { get; init; } = "";
}
```

## Api/Security/ApiKeyMiddleware.cs

```csharp
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
```

## Api/Storage/InMemoryProvisioningStore.cs

```csharp
using System.Collections.Immutable;
using Application;
using Domain;

namespace Api.Storage;

// Adaptador local en el host API, detrás de un puerto de Application.
// Un snapshot contiene solicitudes, índice de idempotencia y auditoría juntos.
// Se publica con un único intercambio de referencia después de construirlo completo.
public sealed class InMemoryProvisioningStore : IProvisioningStore
{
    private sealed record StoreState(
        ImmutableDictionary<Guid, ProvisioningRequest> Requests,
        ImmutableDictionary<string, Guid> ExternalIds,
        ImmutableArray<AuditEvent> Audit);

    private readonly Lock gate = new();
    private StoreState state = new(ImmutableDictionary<Guid, ProvisioningRequest>.Empty,
        ImmutableDictionary.Create<string, Guid>(StringComparer.Ordinal), []);

    public SubmissionResult Register(Submission s)
    {
        lock (gate)
        {
            var current = state;
            if (current.ExternalIds.TryGetValue(s.ExternalId, out var id))
            {
                var existing = current.Requests[id];
                if (!SameContent(existing, s)) throw new IdempotencyConflictException();
                return new(existing, true);
            }

            var request = new ProvisioningRequest(Guid.NewGuid(), s.ExternalId, s.UserId,
                s.Operation, s.Roles, s.ExpectedVersion, s.Reason, s.ActorId,
                s.ReceivedAtUtc, s.Status, SodPolicyValidator.PolicyVersion, s.RejectionCode);
            var previousHash = current.Audit.IsEmpty ? AuditEvent.GenesisHash : current.Audit[^1].Hash;
            var audit = new AuditEvent((long)current.Audit.Length + 1, request, previousHash);
            var next = new StoreState(current.Requests.Add(request.Id, request),
                current.ExternalIds.Add(request.ExternalId, request.Id), current.Audit.Add(audit));
            Volatile.Write(ref state, next);
            return new(request, false);
        }
    }

    public ProvisioningRequest? Find(Guid id) =>
        Volatile.Read(ref state).Requests.GetValueOrDefault(id);
    public ImmutableArray<AuditEvent> ReadAudit() => Volatile.Read(ref state).Audit;

    private static bool SameContent(ProvisioningRequest r, Submission s) =>
        r.UserId == s.UserId && r.ActorId == s.ActorId && r.Operation == s.Operation &&
        r.ExpectedVersion == s.ExpectedVersion && r.Reason == s.Reason &&
        r.Roles.SequenceEqual(s.Roles);
}
```

## Api/Program.cs

```csharp
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
```

## Api/appsettings.Example.json

```json
{
  "ApiKey": {
    "Key": "",
    "ActorId": "local-hr-service"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "localhost;127.0.0.1"
}
```

## .gitignore

```text
**/bin/
**/obj/
.vs/
.env
**/appsettings.json
**/appsettings.*.json
!**/appsettings.Example.json
```
