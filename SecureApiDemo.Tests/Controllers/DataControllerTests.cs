using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SecureApiDemo.Controllers;
using SecureApiDemo.Data;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using SecureApiDemo.Tests.Helpers;
using System.Security.Claims;
using Xunit;

namespace SecureApiDemo.Tests.Controllers;

public class DataControllerTests
{
    private readonly Mock<ISecretService>        _mockSecretService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole>    _roleManager;
    private readonly DataController               _controller;
    private readonly AppDbContext                 _db;

    public DataControllerTests()
    {
        _db          = TestHelpers.BuildInMemoryDbContext();
        _userManager = TestHelpers.BuildUserManager(_db);
        _roleManager = TestHelpers.BuildRoleManager(_db);

        _mockSecretService = new Mock<ISecretService>();

        _controller = new DataController(
            _mockSecretService.Object,
            _userManager,
            _db,
            new NullLogger<DataController>()
        );
    }

    // ── Helper: Set Authenticated User on Controller ──────────────────────────
    private void SetAuthenticatedUser(ApplicationUser user, string role)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name,           user.UserName!),
            new(ClaimTypes.Role,           role),
            new("sub",                     user.UserName!)
        };

        var identity  = new ClaimsIdentity(claims, "Bearer");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = principal }
        };
    }

    // ── Profile Tests ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetProfile_AuthenticatedUser_Returns200()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        SetAuthenticatedUser(user, "User");

        // Act
        var result = await _controller.GetProfile() as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task GetProfile_ReturnsCorrectUsername()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        SetAuthenticatedUser(user, "User");

        // Act
        var result  = await _controller.GetProfile() as OkObjectResult;
        var value   = result!.Value as dynamic;

        // Assert
        ((string)value!.username).Should().Be("alice");
    }

    [Fact]
    public async Task GetProfile_ReturnsCorrectRole()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager,
            role: "Admin");
        SetAuthenticatedUser(user, "Admin");

        // Act
        var result = await _controller.GetProfile() as OkObjectResult;
        var value  = result!.Value as dynamic;

        // Assert
        ((string)value!.role).Should().Be("Admin");
    }

    [Fact]
    public async Task GetProfile_Returns2FAStatus()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        SetAuthenticatedUser(user, "User");

        // Act
        var result = await _controller.GetProfile() as OkObjectResult;
        var value  = result!.Value as dynamic;

        // Assert
        ((bool)value!.twoFactorEnabled).Should().BeFalse();
    }

    // ── Admin Secret Tests ────────────────────────────────────────────────────

    [Fact]
    public async Task GetAdminSecret_AdminUser_Returns200()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager,
            role: "Admin");
        SetAuthenticatedUser(user, "Admin");

        _mockSecretService
            .Setup(x => x.GetSecretAsync("demo-api-secret"))
            .ReturnsAsync("super-secret-value");

        // Act
        var result = await _controller.GetAdminSecret() as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task GetAdminSecret_CallsSecretServiceWithCorrectKey()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager,
            role: "Admin");
        SetAuthenticatedUser(user, "Admin");

        _mockSecretService
            .Setup(x => x.GetSecretAsync(It.IsAny<string>()))
            .ReturnsAsync("secret-value");

        // Act
        await _controller.GetAdminSecret();

        // Assert — verifies correct secret name was requested
        _mockSecretService.Verify(
            x => x.GetSecretAsync("demo-api-secret"), Times.Once);
    }

    // ── My Sessions Tests ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetMySessions_AuthenticatedUser_Returns200()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        SetAuthenticatedUser(user, "User");

        // Act
        var result = await _controller.GetMySessions() as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task GetMySessions_NoActiveSessions_ReturnsZeroCount()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        SetAuthenticatedUser(user, "User");

        // Act
        var result = await _controller.GetMySessions() as OkObjectResult;
        var value  = result!.Value as dynamic;

        // Assert
        ((int)value!.activeSessions).Should().Be(0);
    }
}
