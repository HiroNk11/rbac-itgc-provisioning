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
