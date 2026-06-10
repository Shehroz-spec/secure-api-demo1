using System.ComponentModel.DataAnnotations;
using SecureApiDemo.Validators;

namespace SecureApiDemo.Models;

/// <summary>
/// OWASP A03: Input validation on all request models
/// Using custom validators to prevent injection and enforce strong passwords.
/// </summary>
public class LoginRequest
{
    [Required]
    [StringLength(50, MinimumLength = 3)]
    [NoSqlInjection]  // A03: Prevent SQL injection
    [NoXss]           // A03: Prevent XSS
    [SafeUsername]    // A03: Allow only safe characters
    public string Username { get; set; } = string.Empty;

    [Required]
    [StringLength(100, MinimumLength = 8)]
    public string Password { get; set; } = string.Empty;

    // Optional — only required when 2FA is enabled
    [StringLength(6, MinimumLength = 6)]
    public string? TotpCode { get; set; }
}

public class RegisterRequest
{
    [Required]
    [StringLength(50, MinimumLength = 3)]
    [NoSqlInjection]  // A03: Prevent SQL injection
    [NoXss]           // A03: Prevent XSS
    [SafeUsername]    // A03: Allow only safe characters
    public string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [StringLength(256)]
    [NoXss]           // A03: Prevent XSS in email
    public string Email { get; set; } = string.Empty;

    [Required]
    [StrongPassword]  // A07: Enforce strong password policy
    public string Password { get; set; } = string.Empty;

    public string Role { get; set; } = "User";
}

public class RefreshRequest
{
    [Required]
    [StringLength(500, MinimumLength = 10)]
    public string RefreshToken { get; set; } = string.Empty;
}

public class Verify2FARequest
{
    [Required]
    [StringLength(6, MinimumLength = 6)]
    [RegularExpression(@"^\d{6}$", ErrorMessage = "TOTP code must be exactly 6 digits.")]
    public string TotpCode { get; set; } = string.Empty;
}
