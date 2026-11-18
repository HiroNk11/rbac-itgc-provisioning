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
