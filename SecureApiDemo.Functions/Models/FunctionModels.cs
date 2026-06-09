namespace SecureApiDemo.Functions.Models;

/// <summary>Mirrors the RefreshTokens table in SecureApiDb.</summary>
public class RefreshToken
{
    public int      Id        { get; set; }
    public string   Token     { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string   UserId    { get; set; } = string.Empty;

    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsRevoked => RevokedAt.HasValue;
    public bool IsActive  => !IsRevoked && !IsExpired;
}

/// <summary>Mirrors AspNetUsers table — only columns Functions need.</summary>
public class AppUser
{
    public string  Id       { get; set; } = string.Empty;
    public string? UserName { get; set; }
    public string? Email    { get; set; }
}

/// <summary>Security audit log for suspicious activity tracking.</summary>
public class SecurityAuditLog
{
    public int      Id         { get; set; }
    public string   EventType  { get; set; } = string.Empty;
    public string   Username   { get; set; } = string.Empty;
    public string   IpAddress  { get; set; } = string.Empty;
    public string   Details    { get; set; } = string.Empty;
    public DateTime CreatedAt  { get; set; } = DateTime.UtcNow;
    public bool     IsArchived { get; set; } = false;
}

/// <summary>Welcome email message payload from Service Bus.</summary>
public class WelcomeEmailMessage
{
    public string UserId   { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email    { get; set; } = string.Empty;
    public string Role     { get; set; } = string.Empty;
}

/// <summary>Suspicious login alert payload.</summary>
public class SuspiciousLoginAlert
{
    public string   Username      { get; set; } = string.Empty;
    public string   IpAddress     { get; set; } = string.Empty;
    public int      FailedAttempts { get; set; }
    public DateTime DetectedAt    { get; set; } = DateTime.UtcNow;
}
