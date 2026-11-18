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
