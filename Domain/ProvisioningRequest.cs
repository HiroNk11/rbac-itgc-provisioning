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
