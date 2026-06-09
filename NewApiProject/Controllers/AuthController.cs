using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SecureApiDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("auth")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly ITwoFactorService _twoFactorService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        ITwoFactorService twoFactorService,
        ILogger<AuthController> logger)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _twoFactorService = twoFactorService;
        _logger = logger;
    }

    // ── POST /api/auth/register ───────────────────────────────────────────────
    /// <summary>Registers a new user in SQL Server via ASP.NET Identity.</summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = new ApplicationUser
        {
            UserName = request.Username.ToLower(),
            Email = request.Email,
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        // Assign role (Admin only assignable by existing Admin in production)
        var role = request.Role == "Admin" ? "Admin" : "User";
        await _userManager.AddToRoleAsync(user, role);

        _logger.LogInformation("User registered: {Username} with role {Role}", user.UserName, role);
        return Ok(new { message = "Registration successful. You can now log in." });
    }

    // ── POST /api/auth/login ──────────────────────────────────────────────────
    /// <summary>
    /// Authenticates user. If 2FA is enabled, TotpCode must be provided.
    /// Returns: access token (JWT) + refresh token.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _userManager.FindByNameAsync(request.Username.ToLower());
        if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
        {
            _logger.LogWarning("Failed login for {Username} from {IP}",
                request.Username, HttpContext.Connection.RemoteIpAddress);
            return Unauthorized(new { message = "Invalid credentials." });
        }

        // ── 2FA Check ─────────────────────────────────────────────────────────
        if (user.TwoFactorEnabled)
        {
            if (string.IsNullOrWhiteSpace(request.TotpCode))
                return Ok(new { requires2FA = true, message = "Please provide your 6-digit authenticator code." });

            if (string.IsNullOrWhiteSpace(user.TotpSecret) ||
                !_twoFactorService.ValidateTotp(user.TotpSecret, request.TotpCode))
            {
                _logger.LogWarning("Invalid 2FA code for {Username} from {IP}",
                    user.UserName, HttpContext.Connection.RemoteIpAddress);
                return Unauthorized(new { message = "Invalid 2FA code." });
            }
        }

        // ── Issue tokens ──────────────────────────────────────────────────────
        var roles = await _userManager.GetRolesAsync(user);
        var role = roles.FirstOrDefault() ?? "User";
        var accessToken = _tokenService.GenerateAccessToken(user, role);
        var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user.Id);

        _logger.LogInformation("Successful login: {Username} ({Role})", user.UserName, role);

        return Ok(new
        {
            accessToken,
            refreshToken = refreshToken.Token,
            expiresIn = 3600,
            tokenType = "Bearer"
        });
    }

    // ── POST /api/auth/refresh ────────────────────────────────────────────────
    /// <summary>
    /// Exchanges a valid refresh token for a new access token + new refresh token.
    /// Old refresh token is revoked (rotation pattern).
    /// </summary>
    [HttpPost("refresh")]
    [EnableRateLimiting("fixed")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        try
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var (accessToken, newRefreshToken) =
                await _tokenService.RotateRefreshTokenAsync(request.RefreshToken, ip);

            return Ok(new
            {
                accessToken,
                refreshToken = newRefreshToken.Token,
                expiresIn = 3600,
                tokenType = "Bearer"
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Token refresh failed: {Message}", ex.Message);
            return Unauthorized(new { message = "Invalid or expired refresh token." });
        }
    }

    // ── POST /api/auth/logout ─────────────────────────────────────────────────
    /// <summary>Revokes the provided refresh token, effectively logging out.</summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout([FromBody] RefreshRequest request)
    {
        await _tokenService.RevokeRefreshTokenAsync(request.RefreshToken);
        _logger.LogInformation("User {Username} logged out", User.Identity?.Name);
        return Ok(new { message = "Logged out successfully." });
    }

    // ── POST /api/auth/2fa/setup ──────────────────────────────────────────────
    /// <summary>
    /// Generates a TOTP secret + QR code for the authenticated user.
    /// User must call /2fa/verify to confirm and enable 2FA.
    /// </summary>
    [HttpPost("2fa/setup")]
    [Authorize]
    public async Task<IActionResult> Setup2FA()
    {
        var username = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                    ?? User.Identity?.Name;
        var user = await _userManager.FindByNameAsync(username!);
        if (user is null) return Unauthorized();

        if (user.TwoFactorEnabled)
            return BadRequest(new { message = "2FA is already enabled." });

        var (secret, qrCodeBase64) = _twoFactorService.GenerateSetup(user);

        // Store secret (not yet enabled — requires verification)
        user.TotpSecret = secret;
        await _userManager.UpdateAsync(user);

        return Ok(new
        {
            secret,
            qrCode = $"data:image/png;base64,{qrCodeBase64}",
            message = "Scan the QR code with Google Authenticator or Authy, then call /2fa/verify."
        });
    }

    // ── POST /api/auth/2fa/verify ─────────────────────────────────────────────
    /// <summary>
    /// Verifies the first TOTP code to confirm 2FA setup and enable it.
    /// </summary>
    [HttpPost("2fa/verify")]
    [Authorize]
    public async Task<IActionResult> Verify2FA([FromBody] Verify2FARequest request)
    {
        var username = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                    ?? User.Identity?.Name;
        var user = await _userManager.FindByNameAsync(username!); if (user is null) return Unauthorized();

        if (string.IsNullOrWhiteSpace(user.TotpSecret))
            return BadRequest(new { message = "2FA setup not initiated. Call /2fa/setup first." });

        if (!_twoFactorService.ValidateTotp(user.TotpSecret, request.TotpCode))
        {
            _logger.LogWarning("2FA verification failed for {Username}", user.UserName);
            return BadRequest(new { message = "Invalid TOTP code. Try again." });
        }

        // Enable 2FA — Identity's built-in flag
        await _userManager.SetTwoFactorEnabledAsync(user, true);

        _logger.LogInformation("2FA enabled for {Username}", user.UserName);
        return Ok(new { message = "2FA enabled successfully. All future logins require your authenticator code." });
    }

    // ── POST /api/auth/2fa/disable ────────────────────────────────────────────
    /// <summary>Disables 2FA for the authenticated user (requires valid TOTP code).</summary>
    [HttpPost("2fa/disable")]
    [Authorize]
    public async Task<IActionResult> Disable2FA([FromBody] Verify2FARequest request)
    {
        var username = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                    ?? User.Identity?.Name;
        var user = await _userManager.FindByNameAsync(username!); if (user is null) return Unauthorized();

        if (!user.TwoFactorEnabled)
            return BadRequest(new { message = "2FA is not currently enabled." });

        if (!_twoFactorService.ValidateTotp(user.TotpSecret!, request.TotpCode))
            return Unauthorized(new { message = "Invalid TOTP code." });

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        user.TotpSecret = null;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("2FA disabled for {Username}", user.UserName);
        return Ok(new { message = "2FA disabled." });
    }
}
