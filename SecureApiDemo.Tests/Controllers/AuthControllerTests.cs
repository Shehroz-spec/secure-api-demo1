using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using SecureApiDemo.Controllers;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using SecureApiDemo.Tests.Helpers;
using Xunit;

namespace SecureApiDemo.Tests.Controllers;

public class AuthControllerTests
{
    private readonly Mock<ITokenService>       _mockTokenService;
    private readonly Mock<ITwoFactorService>   _mockTwoFactorService;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole>   _roleManager;
    private readonly AuthController              _controller;

    public AuthControllerTests()
    {
        var db = TestHelpers.BuildInMemoryDbContext();

        _userManager          = TestHelpers.BuildUserManager(db);
        _roleManager          = TestHelpers.BuildRoleManager(db);
        _mockTokenService     = new Mock<ITokenService>();
        _mockTwoFactorService = new Mock<ITwoFactorService>();

        _controller = new AuthController(
            _userManager,
            _mockTokenService.Object,
            _mockTwoFactorService.Object,
            new NullLogger<AuthController>()
        );

        // Set up default HTTP context
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
    }

    // ── Register Tests ────────────────────────────────────────────────────────

    [Fact]
    public async Task Register_ValidRequest_Returns200()
    {
        // Arrange
        await _roleManager.CreateAsync(new IdentityRole("User"));
        var request = new RegisterRequest
        {
            Username = "bob",
            Email    = "bob@test.com",
            Password = "Password123!",
            Role     = "User"
        };

        // Act
        var result = await _controller.Register(request) as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Register_DuplicateUsername_ReturnsBadRequest()
    {
        // Arrange
        await _roleManager.CreateAsync(new IdentityRole("User"));
        var request = new RegisterRequest
        {
            Username = "alice",
            Email    = "alice@test.com",
            Password = "Password123!",
            Role     = "User"
        };

        // Register once
        await _controller.Register(request);

        // Act — register again with same username
        var request2 = new RegisterRequest
        {
            Username = "alice",
            Email    = "alice2@test.com",
            Password = "Password123!",
            Role     = "User"
        };
        var result = await _controller.Register(request2) as BadRequestObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(400);
    }

    [Fact]
    public async Task Register_InvalidModelState_ReturnsBadRequest()
    {
        // Arrange
        _controller.ModelState.AddModelError("Username", "Required");
        var request = new RegisterRequest();

        // Act
        var result = await _controller.Register(request) as BadRequestObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(400);
    }

    // ── Login Tests ───────────────────────────────────────────────────────────

    [Fact]
    public async Task Login_ValidCredentials_Returns200WithTokens()
    {
        // Arrange
        await TestHelpers.SeedUserAsync(_userManager, _roleManager);

        _mockTokenService
            .Setup(x => x.GenerateAccessToken(It.IsAny<ApplicationUser>(), It.IsAny<string>()))
            .Returns("fake-access-token");

        _mockTokenService
            .Setup(x => x.GenerateRefreshTokenAsync(It.IsAny<string>()))
            .ReturnsAsync(new RefreshToken
            {
                Token     = "fake-refresh-token",
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            });

        var request = new LoginRequest
        {
            Username = "alice",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.Login(request) as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(200);

        var value = result.Value as dynamic;
        ((string)value!.accessToken).Should().Be("fake-access-token");
        ((string)value!.refreshToken).Should().Be("fake-refresh-token");
    }

    [Fact]
    public async Task Login_InvalidPassword_Returns401()
    {
        // Arrange
        await TestHelpers.SeedUserAsync(_userManager, _roleManager);

        var request = new LoginRequest
        {
            Username = "alice",
            Password = "WrongPassword!"
        };

        // Act
        var result = await _controller.Login(request) as UnauthorizedObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task Login_NonExistentUser_Returns401()
    {
        // Arrange
        var request = new LoginRequest
        {
            Username = "nonexistent",
            Password = "Password123!"
        };

        // Act
        var result = await _controller.Login(request) as UnauthorizedObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task Login_2FAEnabled_WithoutTotpCode_Returns200WithRequires2FA()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        user.TwoFactorEnabled = true;
        user.TotpSecret       = "JBSWY3DPEHPK3PXP";
        await _userManager.UpdateAsync(user);

        var request = new LoginRequest
        {
            Username  = "alice",
            Password  = "Password123!",
            TotpCode  = null
        };

        // Act
        var result = await _controller.Login(request) as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        var value = result!.Value as dynamic;
        ((bool)value!.requires2FA).Should().BeTrue();
    }

    [Fact]
    public async Task Login_2FAEnabled_InvalidTotpCode_Returns401()
    {
        // Arrange
        var user = await TestHelpers.SeedUserAsync(_userManager, _roleManager);
        user.TwoFactorEnabled = true;
        user.TotpSecret       = "JBSWY3DPEHPK3PXP";
        await _userManager.UpdateAsync(user);

        _mockTwoFactorService
            .Setup(x => x.ValidateTotp(It.IsAny<string>(), It.IsAny<string>()))
            .Returns(false);

        var request = new LoginRequest
        {
            Username = "alice",
            Password = "Password123!",
            TotpCode = "000000"
        };

        // Act
        var result = await _controller.Login(request) as UnauthorizedObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(401);
    }

    // ── Refresh Tests ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Refresh_InvalidToken_Returns401()
    {
        // Arrange
        _mockTokenService
            .Setup(x => x.RotateRefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new Exception("Invalid token"));

        var request = new RefreshRequest { RefreshToken = "invalid-token" };

        // Act
        var result = await _controller.Refresh(request) as UnauthorizedObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task Refresh_ValidToken_Returns200WithNewTokens()
    {
        // Arrange
        _mockTokenService
            .Setup(x => x.RotateRefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync(("new-access-token", new RefreshToken
            {
                Token     = "new-refresh-token",
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            }));

        var request = new RefreshRequest { RefreshToken = "valid-token" };

        // Act
        var result = await _controller.Refresh(request) as OkObjectResult;

        // Assert
        result.Should().NotBeNull();
        result!.StatusCode.Should().Be(200);
    }
}
