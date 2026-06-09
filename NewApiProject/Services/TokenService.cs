using Microsoft.IdentityModel.Tokens;
using SecureApiDemo.Data;
using SecureApiDemo.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SecureApiDemo.Services;

public interface ITokenService
{
    string GenerateAccessToken(ApplicationUser user, string role);
    Task<RefreshToken> GenerateRefreshTokenAsync(string userId);
    Task<(string AccessToken, RefreshToken RefreshToken)> RotateRefreshTokenAsync(string oldToken, string ipAddress);
    Task RevokeRefreshTokenAsync(string token);
}

public class TokenService : ITokenService
{
    private readonly IConfiguration _config;
    private readonly AppDbContext _db;
    private readonly ILogger<TokenService> _logger;

    public TokenService(IConfiguration config, AppDbContext db, ILogger<TokenService> logger)
    {
        _config = config;
        _db     = db;
        _logger = logger;
    }

    // ── Access Token (JWT, short-lived) ──────────────────────────────────────
    public string GenerateAccessToken(ApplicationUser user, string role)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub,   user.UserName!),
        new Claim(JwtRegisteredClaimNames.Jti,   Guid.NewGuid().ToString()),
        new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
        new Claim(ClaimTypes.Name,               user.UserName!),
        new Claim(ClaimTypes.NameIdentifier,     user.Id),
        new Claim(ClaimTypes.Role,               role),
        new Claim("role",                        role),
        new Claim("2fa_verified",                user.TwoFactorEnabled.ToString().ToLower()),
    };

        var expiryMinutes = int.Parse(_config["Jwt:AccessTokenExpiryMinutes"] ?? "60");

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    // ── Refresh Token (opaque, long-lived, stored in DB) ─────────────────────
    public async Task<RefreshToken> GenerateRefreshTokenAsync(string userId)
    {
        // Cryptographically secure random token
        var tokenBytes = RandomNumberGenerator.GetBytes(64);
        var token = Convert.ToBase64String(tokenBytes);

        var expiryDays = int.Parse(_config["Jwt:RefreshTokenExpiryDays"] ?? "7");

        var refreshToken = new RefreshToken
        {
            Token     = token,
            UserId    = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(expiryDays),
            CreatedAt = DateTime.UtcNow,
        };

        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();

        _logger.LogInformation("Refresh token created for user {UserId}", userId);
        return refreshToken;
    }

    // ── Token Rotation: revoke old, issue new pair ────────────────────────────
    public async Task<(string AccessToken, RefreshToken RefreshToken)> RotateRefreshTokenAsync(
        string oldToken, string ipAddress)
    {
        var existing = _db.RefreshTokens
            .SingleOrDefault(r => r.Token == oldToken)
            ?? throw new SecurityTokenException("Refresh token not found.");

        if (!existing.IsActive)
            throw new SecurityTokenException("Refresh token is expired or revoked.");

        var user = await _db.Users.FindAsync(existing.UserId)
            as ApplicationUser
            ?? throw new SecurityTokenException("User not found.");

        // Revoke old token
        existing.RevokedAt = DateTime.UtcNow;

        // Get user role
        var userRoles = _db.UserRoles.Where(ur => ur.UserId == user.Id).ToList();
        var roleId    = userRoles.FirstOrDefault()?.RoleId ?? "";
        var role      = _db.Roles.Find(roleId)?.Name ?? "User";

        // Issue new pair
        var newAccessToken  = GenerateAccessToken(user, role);
        var newRefreshToken = await GenerateRefreshTokenAsync(user.Id);

        await _db.SaveChangesAsync();

        _logger.LogInformation("Refresh token rotated for user {UserId} from IP {IP}",
            user.Id, ipAddress);

        return (newAccessToken, newRefreshToken);
    }

    // ── Revoke on logout ──────────────────────────────────────────────────────
    public async Task RevokeRefreshTokenAsync(string token)
    {
        var existing = _db.RefreshTokens.SingleOrDefault(r => r.Token == token);
        if (existing is null || !existing.IsActive) return;

        existing.RevokedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();

        _logger.LogInformation("Refresh token revoked for user {UserId}", existing.UserId);
    }
}
