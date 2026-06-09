using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using OtpNet;
using SecureApiDemo.Models;
using SecureApiDemo.Services;
using SecureApiDemo.Tests.Helpers;
using Xunit;

namespace SecureApiDemo.Tests.Services;

public class TwoFactorServiceTests
{
    private readonly TwoFactorService _twoFactorService;
    private readonly ApplicationUser _testUser;

    public TwoFactorServiceTests()
    {
        var config = TestHelpers.BuildTestConfiguration();
        var logger = new NullLogger<TwoFactorService>();

        _twoFactorService = new TwoFactorService(config, logger);

        _testUser = new ApplicationUser
        {
            Id       = Guid.NewGuid().ToString(),
            UserName = "alice",
            Email    = "alice@test.com"
        };
    }

    // ── GenerateSetup Tests ───────────────────────────────────────────────────

    [Fact]
    public void GenerateSetup_ReturnsNonEmptySecret()
    {
        // Act
        var (secret, _) = _twoFactorService.GenerateSetup(_testUser);

        // Assert
        secret.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GenerateSetup_ReturnsNonEmptyQrCode()
    {
        // Act
        var (_, qrCode) = _twoFactorService.GenerateSetup(_testUser);

        // Assert
        qrCode.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void GenerateSetup_QrCodeIsValidBase64()
    {
        // Act
        var (_, qrCode) = _twoFactorService.GenerateSetup(_testUser);

        // Assert
        var act = () => Convert.FromBase64String(qrCode);
        act.Should().NotThrow();
    }

    [Fact]
    public void GenerateSetup_TwoCalls_ReturnDifferentSecrets()
    {
        // Act
        var (secret1, _) = _twoFactorService.GenerateSetup(_testUser);
        var (secret2, _) = _twoFactorService.GenerateSetup(_testUser);

        // Assert
        secret1.Should().NotBe(secret2);
    }

    [Fact]
    public void GenerateSetup_SecretIsValidBase32()
    {
        // Act
        var (secret, _) = _twoFactorService.GenerateSetup(_testUser);

        // Assert — Base32 only contains A-Z and 2-7
        secret.Should().MatchRegex("^[A-Z2-7]+=*$");
    }

    // ── ValidateTotp Tests ────────────────────────────────────────────────────

    [Fact]
    public void ValidateTotp_ValidCode_ReturnsTrue()
    {
        // Arrange — generate a real TOTP code from the secret
        var (secret, _)  = _twoFactorService.GenerateSetup(_testUser);
        var secretBytes  = Base32Encoding.ToBytes(secret);
        var totp         = new Totp(secretBytes);
        var validCode    = totp.ComputeTotp();

        // Act
        var result = _twoFactorService.ValidateTotp(secret, validCode);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void ValidateTotp_InvalidCode_ReturnsFalse()
    {
        // Arrange
        var (secret, _) = _twoFactorService.GenerateSetup(_testUser);

        // Act
        var result = _twoFactorService.ValidateTotp(secret, "000000");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateTotp_EmptyCode_ReturnsFalse()
    {
        // Arrange
        var (secret, _) = _twoFactorService.GenerateSetup(_testUser);

        // Act
        var result = _twoFactorService.ValidateTotp(secret, "");

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateTotp_NullCode_ReturnsFalse()
    {
        // Arrange
        var (secret, _) = _twoFactorService.GenerateSetup(_testUser);

        // Act
        var result = _twoFactorService.ValidateTotp(secret, null!);

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData("12345")]    // too short
    [InlineData("1234567")]  // too long
    [InlineData("abcdef")]   // not numeric
    public void ValidateTotp_WrongFormatCode_ReturnsFalse(string code)
    {
        // Arrange
        var (secret, _) = _twoFactorService.GenerateSetup(_testUser);

        // Act
        var result = _twoFactorService.ValidateTotp(secret, code);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void ValidateTotp_WrongSecret_ReturnsFalse()
    {
        // Arrange
        var (secret1, _) = _twoFactorService.GenerateSetup(_testUser);
        var (secret2, _) = _twoFactorService.GenerateSetup(_testUser);

        // Generate code for secret1 but validate against secret2
        var secretBytes = Base32Encoding.ToBytes(secret1);
        var totp        = new Totp(secretBytes);
        var code        = totp.ComputeTotp();

        // Act
        var result = _twoFactorService.ValidateTotp(secret2, code);

        // Assert
        result.Should().BeFalse();
    }
}
