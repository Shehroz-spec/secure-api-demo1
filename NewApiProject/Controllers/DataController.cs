using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using SecureApiDemo.Data;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using System.Security.Claims;

namespace SecureApiDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
[EnableRateLimiting("fixed")]
public class DataController : ControllerBase
{
    private readonly ISecretService _secretService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AppDbContext _db;
    private readonly ILogger<DataController> _logger;

    public DataController(
        ISecretService secretService,
        UserManager<ApplicationUser> userManager,
        AppDbContext db,
        ILogger<DataController> logger)
    {
        _secretService = secretService;
        _userManager = userManager;
        _db = db;
        _logger = logger;
    }

    /// <summary>Profile — any authenticated user.</summary>
    [HttpGet("profile")]
    [Authorize] // ← remove Policy = "UserOrAdmin"
    public async Task<IActionResult> GetProfile()
    {
        // var user = await _userManager.GetUserAsync(User);
        var username = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
            ?? User.Identity?.Name;
        var user = await _userManager.FindByNameAsync(username!);
        if (user is null) return Unauthorized();

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new
        {
            username = user.UserName,
            email = user.Email,
            role = roles.FirstOrDefault() ?? "User",
            twoFactorEnabled = user.TwoFactorEnabled,
            message = "Profile data — visible to all authenticated users."
        });
    }

    /// <summary>Admin secret from Key Vault — Admin only.</summary>
    [HttpGet("admin/secret")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> GetAdminSecret()
    {
        _logger.LogInformation("Admin secret accessed by {Username}", User.Identity?.Name);
        var secret = await _secretService.GetSecretAsync("demo-api-secret");
        return Ok(new { secret, retrievedAt = DateTime.UtcNow });
    }

    /// <summary>User list from SQL Server — Admin only.</summary>
    [HttpGet("admin/users")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<IActionResult> GetAllUsers()
    {
        var users = await _userManager.Users
            .Select(u => new
            {
                u.Id,
                u.UserName,
                u.Email,
                u.TwoFactorEnabled,
                u.EmailConfirmed,
            })
            .ToListAsync();

        return Ok(users);
    }

    /// <summary>Returns active refresh tokens for the current user — useful for security audit.</summary>
    [HttpGet("my-sessions")]
    [Authorize(Policy = "UserOrAdmin")]
    public async Task<IActionResult> GetMySessions()
    {
        var username = User.FindFirstValue(JwtRegisteredClaimNames.Sub)
                    ?? User.Identity?.Name;
        var user = await _userManager.FindByNameAsync(username!);
        if (user is null) return Unauthorized();

        var tokens = await _db.RefreshTokens
            .Where(r => r.UserId == user.Id && r.RevokedAt == null && r.ExpiresAt > DateTime.UtcNow)
            .Select(r => new { r.CreatedAt, r.ExpiresAt })
            .ToListAsync();

        return Ok(new { activeSessions = tokens.Count, sessions = tokens });
    }
}
