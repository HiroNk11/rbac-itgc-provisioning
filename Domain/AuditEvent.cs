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
