namespace SecureApiDemo.Services;

public interface ISecretService
{
    Task<string> GetSecretAsync(string secretName);
}

/// <summary>
/// In production, replace with Azure.Security.KeyVault.Secrets.SecretClient:
///   var client = new SecretClient(new Uri(vaultUri), new DefaultAzureCredential());
///   var secret = await client.GetSecretAsync(secretName);
///   return secret.Value.Value;
/// </summary>
public class SecretService : ISecretService
{
    private readonly ILogger<SecretService> _logger;

    private static readonly Dictionary<string, string> _vault = new()
    {
        ["demo-api-secret"]   = "super-secret-value-from-keyvault",
        ["database-password"] = "db-password-from-keyvault",
    };

    public SecretService(ILogger<SecretService> logger) => _logger = logger;

    public Task<string> GetSecretAsync(string secretName)
    {
        _logger.LogInformation("Retrieving secret '{SecretName}' from Key Vault", secretName);

        if (_vault.TryGetValue(secretName, out var value))
            return Task.FromResult(value);

        _logger.LogWarning("Secret '{SecretName}' not found in vault", secretName);
        throw new KeyNotFoundException($"Secret '{secretName}' not found.");
    }
}
