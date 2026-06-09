using Microsoft.AspNetCore.Identity;

namespace SecureApiDemo.Models;

/// <summary>
/// Extends IdentityUser with 2FA TOTP secret storage.
/// TwoFactorEnabled (built-in) tracks whether 2FA is active.
/// </summary>
public class ApplicationUser : IdentityUser
{
    // TOTP secret key (Base32) stored per-user for Google Authenticator
    public string? TotpSecret { get; set; }

    // Navigation property for refresh tokens
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
