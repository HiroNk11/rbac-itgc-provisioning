namespace Api.Security;

public sealed class ApiKeyOptions
{
    public const string SectionName = "ApiKey";
    public string Key { get; init; } = "";
    public string ActorId { get; init; } = "";
}
