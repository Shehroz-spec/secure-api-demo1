namespace SecureApiDemo.Models;

/// <summary>
/// Persisted refresh token record. Stored in SQL Server.
/// One user can have multiple active refresh tokens (multi-device support).
/// </summary>
public class RefreshToken
{
    public int Id { get; set; }

    // The opaque token string sent to the client
    public string Token { get; set; } = string.Empty;

    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Set when token is revoked (logout / rotation)
    public DateTime? RevokedAt { get; set; }

    // FK to ApplicationUser
    public string UserId { get; set; } = string.Empty;
    public ApplicationUser? User { get; set; }

    public bool IsExpired  => DateTime.UtcNow >= ExpiresAt;
    public bool IsRevoked  => RevokedAt.HasValue;
    public bool IsActive   => !IsRevoked && !IsExpired;
}
