using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Api.Storage;
using Application;
using Domain;

var checks = 0;
void Check(bool condition, string message)
{
    if (!condition) throw new Exception(message);
    checks++;
    Console.WriteLine($"PASS {message}");
}
SubmitCommand Command(string key, SystemRole[]? roles = null) =>
    new(key, "employee-001", ProvisioningOperation.Create, roles ?? [SystemRole.Operator], 0, "Ticket IAM-001");
var store = new InMemoryProvisioningStore();
var handler = new SubmitRequestHandler(store, new SodPolicyValidator(), TimeProvider.System);
var roles = new[] { SystemRole.Reader, SystemRole.Operator };
var accepted = handler.Handle(Command("accepted", roles), "hr-service");
roles[0] = SystemRole.Administrator;
Check(accepted.Request.Status == ProvisioningStatus.Pending, "Solicitud válida queda Pending");
Check(accepted.Request.Roles[0] == SystemRole.Reader, "Copia inmutable de roles de entrada");
Check(store.ReadAudit()[0].RequestedRoles[0] == SystemRole.Reader, "Auditoría no comparte arreglo mutable");
Check(store.ReadAudit()[0].Before is null && store.ReadAudit()[0].After is null,
    "Recepción no afirma haber observado o aplicado permisos");
var replay = handler.Handle(Command("accepted", [SystemRole.Operator, SystemRole.Reader]), "hr-service");
Check(replay.Replayed && replay.Request.Id == accepted.Request.Id, "Roles normalizados preservan idempotencia");
Check(store.ReadAudit().Length == 1, "Reintento no crea otro evento");
try { handler.Handle(Command("accepted"), "hr-service"); throw new Exception("Debía rechazar conflicto"); }
catch (IdempotencyConflictException) { Check(store.ReadAudit().Length == 1, "Conflicto no modifica el snapshot"); }
try { handler.Handle(Command("accepted", [SystemRole.Reader, SystemRole.Operator]), "other-service"); throw new Exception("Debía rechazar otro actor"); }
catch (IdempotencyConflictException) { Check(true, "Idempotencia vincula al principal técnico"); }
var denied = handler.Handle(Command("denied", [SystemRole.Operator, SystemRole.Approver]), "hr-service");
Check(denied.Request.Status == ProvisioningStatus.Rejected && denied.Request.RejectionCode == "SOD_OPERATOR_APPROVER",
    "Segregación Operator/Approver");
Check(handler.Handle(Command("denied2", [SystemRole.Administrator, SystemRole.Auditor]), "hr-service")
    .Request.Status == ProvisioningStatus.Rejected, "Segregación Administrator/Auditor");
Check(handler.Handle(new("disable", "employee-001", ProvisioningOperation.Disable, [], 10, "Baja"), "hr-service")
    .Request.Status == ProvisioningStatus.Pending, "Baja no queda bloqueada por SoD");
try { handler.Handle(Command("missing") with { ExpectedVersion = null }, "hr-service"); throw new Exception("Debía rechazar campo faltante"); }
catch (InvalidRequestException) { Check(true, "ExpectedVersion requerido"); }
try { handler.Handle(Command("unknown", [(SystemRole)999]), "hr-service"); throw new Exception("Debía rechazar rol desconocido"); }
catch (InvalidRequestException) { Check(true, "Rol desconocido rechazado"); }

Parallel.For(0, 200, i => handler.Handle(Command($"parallel-{i}"), "hr-service"));
var ids = new System.Collections.Concurrent.ConcurrentBag<Guid>();
Parallel.For(0, 100, _ => ids.Add(handler.Handle(Command("parallel-same"), "hr-service").Request.Id));
Check(ids.Distinct().Count() == 1, "100 altas concurrentes con misma clave producen un ID");
var audit = store.ReadAudit();
Check(audit.Length == 205, "Una evidencia por solicitud única incluso bajo concurrencia");
var previous = AuditEvent.GenesisHash;
foreach (var item in audit)
{
    if (item.Sequence < 1 || item.PreviousHash != previous || !item.HasValidHash())
        throw new Exception("Cadena inválida");
    previous = item.Hash;
}
Check(audit.Select(x => x.Sequence).SequenceEqual(Enumerable.Range(1, audit.Length).Select(x => (long)x)),
    "Cadena continua, sin bifurcaciones ni secuencias repetidas");
var first = audit[0];
Check(first.Hash == Convert.ToHexString(SHA256.HashData(first.GetHashPayloadUtf8())), "SHA-256 reproducible");
var payload = JsonNode.Parse(first.GetHashPayloadUtf8())!;
payload["actorId"] = "intruder";
var alteredHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(payload.ToJsonString())));
Check(first.Hash != alteredHash,
    "Alteración del contenido cambia la huella");
Check(typeof(AuditEvent).IsSealed && typeof(AuditEvent).GetProperties().All(p => p.SetMethod is null),
    "AuditEvent sellado sin setters ni init");
Console.WriteLine($"{checks} comprobaciones aprobadas.");
