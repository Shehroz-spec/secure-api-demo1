using OtpNet;
using QRCoder;
using SecureApiDemo.Models;
using Microsoft.AspNetCore.Identity;

namespace SecureApiDemo.Services;

public interface ITwoFactorService
{
    (string Secret, string QrCodeBase64) GenerateSetup(ApplicationUser user);
    bool ValidateTotp(string secret, string code);
}

public class TwoFactorService : ITwoFactorService
{
    private readonly IConfiguration _config;
    private readonly ILogger<TwoFactorService> _logger;

    public TwoFactorService(IConfiguration config, ILogger<TwoFactorService> logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Generates a new TOTP secret and QR code for the user to scan
    /// with Google Authenticator / Authy.
    /// Returns: (Base32Secret, Base64PngQrCode)
    /// </summary>
    public (string Secret, string QrCodeBase64) GenerateSetup(ApplicationUser user)
    {
        // Generate a cryptographically secure 20-byte secret
        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var base32Secret = Base32Encoding.ToString(secretBytes);

        // Build the otpauth URI (Google Authenticator standard)
        var appName  = _config["TwoFactor:AppName"] ?? "SecureApiDemo";
        var label    = Uri.EscapeDataString($"{appName}:{user.UserName}");
        var issuer   = Uri.EscapeDataString(appName);
        var otpUri   = $"otpauth://totp/{label}?secret={base32Secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";

        // Generate QR code as Base64 PNG
        using var qrGenerator  = new QRCodeGenerator();
        using var qrCodeData   = qrGenerator.CreateQrCode(otpUri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode       = new PngByteQRCode(qrCodeData);
        var qrCodeBytes        = qrCode.GetGraphic(20);
        var qrCodeBase64       = Convert.ToBase64String(qrCodeBytes);

        _logger.LogInformation("2FA setup generated for user {Username}", user.UserName);

        return (base32Secret, qrCodeBase64);
    }

    /// <summary>
    /// Validates a 6-digit TOTP code against the user's stored secret.
    /// Allows ±1 time step (30s) to handle clock drift.
    /// </summary>
    public bool ValidateTotp(string base32Secret, string code)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Length != 6)
            return false;

        try
        {
            var secretBytes = Base32Encoding.ToBytes(base32Secret);
            var totp        = new Totp(secretBytes);

            // VerifyTotp checks current window + ±1 step for clock drift
            return totp.VerifyTotp(code.Trim(), out _, new VerificationWindow(1, 1));
        }
        catch (Exception ex)
        {
            _logger.LogWarning("TOTP validation error: {Message}", ex.Message);
            return false;
        }
    }
}
