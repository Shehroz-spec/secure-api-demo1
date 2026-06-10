namespace SecureApiDemo.Models;

/// <summary>
/// Security audit log for suspicious activity tracking.
/// Used by Azure Functions SuspiciousLoginAlert.
/// </summary>
public class SecurityAuditLog
{
    public int      Id        { get; set; }
    public string   EventType { get; set; } = string.Empty;
    public string   Username  { get; set; } = string.Empty;
    public string   IpAddress { get; set; } = string.Empty;
    public string   Details   { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool     IsArchived { get; set; } = false;
}
