using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using System.Security.Cryptography;

namespace SecureApiDemo.Controllers;

/// <summary>
/// SSO Controller — handles Microsoft Entra ID OAuth2 flow.
///
/// Endpoints:
/// GET  /api/sso/login/microsoft  → redirects user to Microsoft login
/// GET  /api/sso/callback         → handles Microsoft callback with auth code
/// GET  /api/sso/providers        → returns available login methods
///
/// After SSO login succeeds, user gets our own JWT token —
/// the rest of the API works exactly the same as local login.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class SsoController : ControllerBase
{
    private readonly ISsoService                   _ssoService;
    private readonly ITokenService                 _tokenService;
    private readonly UserManager<ApplicationUser>  _userManager;
    private readonly ILogger<SsoController>        _logger;

    public SsoController(
        ISsoService                  ssoService,
        ITokenService                tokenService,
        UserManager<ApplicationUser> userManager,
        ILogger<SsoController>       logger)
    {
        _ssoService   = ssoService;
        _tokenService = tokenService;
        _userManager  = userManager;
        _logger       = logger;
    }

    // ── GET /api/sso/providers ────────────────────────────────────────────────
    /// <summary>
    /// Returns available login methods so the frontend can show
    /// the appropriate login buttons.
    /// </summary>
    [HttpGet("providers")]
    [Authorize(Policy = "AdminOnly")]
    public IActionResult GetProviders()
    {
        return Ok(new
        {
            providers = new[]
            {
                new
                {
                    name        = "Local",
                    displayName = "Username & Password",
                    endpoint    = "/api/auth/login",
                    method      = "POST"
                },
                new
                {
                    name        = "Microsoft",
                    displayName = "Login with Microsoft",
                    endpoint    = "/api/sso/login/microsoft",
                    method      = "GET"
                }
            }
        });
    }

    // ── GET /api/sso/login/microsoft ──────────────────────────────────────────
    /// <summary>
    /// Step 1 of SSO flow — redirects user to Microsoft login page.
    /// State parameter is a random value to prevent CSRF attacks.
    /// </summary>
    
    [HttpGet("login/microsoft")]
    //[AllowAnonymous]
    public IActionResult LoginWithMicrosoft()
    {
        // Generate random state to prevent CSRF
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        // Store state in session/cookie for validation in callback
        Response.Cookies.Append("sso_state", state, new CookieOptions
        {
            HttpOnly = true,
            Secure   = true,
            SameSite = SameSiteMode.Lax,
            Expires  = DateTimeOffset.UtcNow.AddMinutes(10)
        });

        var loginUrl = _ssoService.GetMicrosoftLoginUrl(state);

        _logger.LogInformation("SSO: Redirecting to Microsoft login");

        // Redirect user to Microsoft login
        return Redirect(loginUrl);
    }

    // ── GET /api/sso/callback ─────────────────────────────────────────────────
    /// <summary>
    /// Step 2 of SSO flow — Microsoft redirects here after user logs in.
    /// We exchange the auth code for user info, then issue our JWT.
    /// </summary>
    [HttpGet("callback")]
    [AllowAnonymous]

    public async Task<IActionResult> MicrosoftCallback(
        [FromQuery] string code,
        [FromQuery] string state,
        [FromQuery] string? error = null)
    {
        // Handle Microsoft login errors
        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogWarning("SSO: Microsoft login error: {Error}", error);
            return BadRequest(new { message = $"Microsoft login failed: {error}" });
        }

        // Validate state to prevent CSRF
        var savedState = Request.Cookies["sso_state"];
        if (savedState != state)
        {
            _logger.LogWarning("SSO: State mismatch — possible CSRF attack from {IP}",
                HttpContext.Connection.RemoteIpAddress);
            return BadRequest(new { message = "Invalid state parameter." });
        }

        // Clear state cookie
        Response.Cookies.Delete("sso_state");

        try
        {
            // ── Step 1: Get Microsoft user info ───────────────────────────────
            var microsoftUser = await _ssoService.GetMicrosoftUserInfoAsync(code);
            if (microsoftUser is null)
                return Unauthorized(new { message = "Failed to get user info from Microsoft." });

            // ── Step 2: Get or create local user ──────────────────────────────
            var user = await _ssoService.GetOrCreateSsoUserAsync(microsoftUser);

            // ── Step 3: Issue our JWT tokens ──────────────────────────────────
            var roles        = await _userManager.GetRolesAsync(user);
            var role         = roles.FirstOrDefault() ?? "User";
            var accessToken  = _tokenService.GenerateAccessToken(user, role);
            var refreshToken = await _tokenService.GenerateRefreshTokenAsync(user.Id);

            _logger.LogInformation(
                "SSO: Microsoft login successful for {Email} ({Role})",
                user.Email, role);

            return Ok(new SsoLoginResponse
            {
                AccessToken  = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresIn    = 3600,
                TokenType    = "Bearer",
                LoginMethod  = "Microsoft",
                Username     = user.UserName ?? "",
                Email        = user.Email    ?? "",
                Role         = role
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SSO: Callback failed: {Message}", ex.Message);
            return StatusCode(500, new { message = "SSO login failed." });
        }
    }

    // ── GET /api/sso/me ───────────────────────────────────────────────────────
    /// <summary>
    /// Returns current SSO user info — works for both local and SSO users.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var username = User.Identity?.Name;
        var user     = await _userManager.FindByNameAsync(username!);
        if (user is null) return Unauthorized();

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new
        {
            username        = user.UserName,
            email           = user.Email,
            role            = roles.FirstOrDefault() ?? "User",
            twoFactorEnabled = user.TwoFactorEnabled,
            loginMethod     = user.PasswordHash == null ? "Microsoft SSO" : "Local"
        });
    }
}
