using Microsoft.AspNetCore.Identity;
using SecureApiDemo.Models;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SecureApiDemo.Services;

public interface ISsoService
{
    string GetMicrosoftLoginUrl(string state);
    Task<MicrosoftUserInfo?> GetMicrosoftUserInfoAsync(string accessToken);
    Task<ApplicationUser> GetOrCreateSsoUserAsync(MicrosoftUserInfo microsoftUser);
}

/// <summary>
/// SSO Service — handles Microsoft Entra ID OAuth2 flow.
///
/// Flow:
/// 1. User clicks "Login with Microsoft"
/// 2. API redirects to Microsoft login page
/// 3. User logs in with Microsoft account
/// 4. Microsoft redirects back to /api/sso/callback with auth code
/// 5. API exchanges code for Microsoft access token
/// 6. API gets user info from Microsoft Graph
/// 7. API creates/finds local user in SQL Server
/// 8. API issues our own JWT token
/// 9. User is now logged in with both SSO and local JWT
///

/// </summary>
public class SsoService : ISsoService
{
    private readonly IConfiguration _config;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SsoService> _logger;

    public SsoService(
        IConfiguration config,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        IHttpClientFactory httpClientFactory,
        ILogger<SsoService> logger)
    {
        _config = config;
        _userManager = userManager;
        _roleManager = roleManager;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    /// Generates the Microsoft login URL the user is redirected to.
    /// State parameter prevents CSRF attacks.
    /// </summary>
    public string GetMicrosoftLoginUrl0(string state)
    {
        var tenantId = _config["AzureAd:TenantId"];
        var clientId = _config["AzureAd:ClientId"];
        // var callbackUrl = _config["AzureAd:CallbackPath"];
        var callbackUrl = "https://localhost:7028/api/sso/callback";

        var scopes = Uri.EscapeDataString("openid profile email User.Read");

        return $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize" +
               $"?client_id={clientId}" +
               $"&response_type=code" +
               $"&redirect_uri={callbackUrl}" +
               $"&scope={scopes}" +
               $"&state={state}" +
               $"&response_mode=query";
    }
    public string GetMicrosoftLoginUrl(string state)
    {
        var tenantId = _config["AzureAd:TenantId"];
        var clientId = _config["AzureAd:ClientId"];
        var redirectUri = _config["AzureAd:CallbackPath"];

        return $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize" +
               $"?client_id={clientId}" +
               $"&response_type=code" +
               $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
               $"&scope={Uri.EscapeDataString("openid profile email User.Read")}" +
               $"&state={Uri.EscapeDataString(state)}" +
               $"&response_mode=query";
    }
    /// <summary>
    /// Exchanges the authorization code for an access token,
    /// then calls Microsoft Graph to get user information.
    /// </summary>
    public async Task<MicrosoftUserInfo?> GetMicrosoftUserInfoAsync(string authCode)
    {
        var tenantId = _config["AzureAd:TenantId"];
        var clientId = _config["AzureAd:ClientId"];
        var clientSecret = _config["AzureAd:ClientSecret"];
        var callbackUrl = "https://localhost:7028/api/sso/callback";

        var httpClient = _httpClientFactory.CreateClient();

        // ── Step 1: Exchange auth code for access token ───────────────────────
        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode,
            ["redirect_uri"] = callbackUrl,
            ["client_id"] = clientId!,
            ["client_secret"] = clientSecret!,
            ["scope"] = "openid profile email User.Read"
        };

        var tokenResponse = await httpClient.PostAsync(
            $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token",
            new FormUrlEncodedContent(tokenRequest));

        var tokenResponseBody = await tokenResponse.Content.ReadAsStringAsync();

        _logger.LogInformation("Token Response Status: {Status}", tokenResponse.StatusCode);

        if (!tokenResponse.IsSuccessStatusCode)
        {
            _logger.LogError("Token exchange failed: {Body}", tokenResponseBody);
            return null;
        }

        // ✅ Fix — properly parse access token
        var tokenData = JsonSerializer.Deserialize<JsonElement>(tokenResponseBody);
        var accessToken = tokenData.GetProperty("access_token").GetString();

        _logger.LogInformation("Access token obtained successfully");

        if (string.IsNullOrEmpty(accessToken))
        {
            _logger.LogError("Access token was empty");
            return null;
        }

        // ── Step 2: Call Microsoft Graph ──────────────────────────────────────
        // ✅ Fix — create new client without reusing old one
        var graphClient = _httpClientFactory.CreateClient();
        graphClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        //var graphResponse = await graphClient.GetAsync(
        //    "https://graph.microsoft.com/v1.0/me");
        var graphResponse = await graphClient.GetAsync(
    "https://graph.microsoft.com/v1.0/me?$select=id,displayName,mail,userPrincipalName,givenName,surname,identities");


        var graphBody = await graphResponse.Content.ReadAsStringAsync();

        _logger.LogInformation("Graph Response Status: {Status}", graphResponse.StatusCode);
        _logger.LogInformation("Graph Response Body: {Body}", graphBody);

        if (!graphResponse.IsSuccessStatusCode)
        {
            _logger.LogError("Graph call failed: {Body}", graphBody);
            return null;
        }

        // ✅ Fix — parse graph response manually
        var graphData = JsonSerializer.Deserialize<JsonElement>(graphBody);

        var userInfo = new MicrosoftUserInfo
        {
            Id = graphData.TryGetProperty("id", out var id) ? id.GetString() ?? "" : "",
            DisplayName = graphData.TryGetProperty("displayName", out var dn) ? dn.GetString() ?? "" : "",
            Mail = graphData.TryGetProperty("mail", out var mail) ? mail.GetString() ?? "" : "",
            UserPrincipalName = graphData.TryGetProperty("userPrincipalName", out var upn) ? upn.GetString() ?? "" : "",
            GivenName = graphData.TryGetProperty("givenName", out var gn) ? gn.GetString() ?? "" : "",
            Surname = graphData.TryGetProperty("surname", out var sn) ? sn.GetString() ?? "" : "",
        };
        // ✅ Fix email — use mail if available, otherwise extract from identities
        var email = "";

        // Try mail first (work accounts)
        if (graphData.TryGetProperty("mail", out var mailProp) &&
            !string.IsNullOrEmpty(mailProp.GetString()))
        {
            email = mailProp.GetString()!;
        }
        // For personal accounts — extract real email from userPrincipalName
        else if (graphData.TryGetProperty("userPrincipalName", out var upnProp))
        {
            var _upn = upnProp.GetString() ?? "";
            // Remove #EXT# suffix and get real email
            // "shehroz.reaz_hotmail.com#EXT#@tenant.com" → "shehroz.reaz@hotmail.com"
            if (_upn.Contains("#EXT#"))
            {
                var localPart = _upn.Split('#')[0]; // "shehroz.reaz_hotmail.com"
                                                   // Find last underscore — that separates name from domain
                var lastUnderscore = localPart.LastIndexOf('_');
                if (lastUnderscore > 0)
                {
                    var name = localPart[..lastUnderscore];    // "shehroz.reaz"
                    var domain = localPart[(lastUnderscore + 1)..]; // "hotmail.com"
                    email = $"{name}@{domain}";
                }
            }
            else
            {
                email = _upn;
            }
        }

        userInfo.Mail = email;

        _logger.LogInformation(
            "Microsoft Graph: Got user {DisplayName} {Email}",
            userInfo.DisplayName, userInfo.Mail);

        return userInfo;
    }

    /// <summary>
    /// Gets existing user or creates a new one from Microsoft SSO info.
    /// SSO users are identified by their Microsoft email address.
    /// </summary>
    public async Task<ApplicationUser> GetOrCreateSsoUserAsync(MicrosoftUserInfo msUser)
    {
        var email = msUser.Mail ?? msUser.UserPrincipalName;

        // Try to find existing user by email
        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser != null)
        {
            _logger.LogInformation(
                "SSO: Found existing user {Email}", email);
            return existingUser;
        }

        // Create new user from Microsoft info
        _logger.LogInformation(
            "SSO: Creating new user from Microsoft account {Email}", email);

        // Ensure User role exists
        if (!await _roleManager.RoleExistsAsync("User"))
            await _roleManager.CreateAsync(new IdentityRole("User"));

        // Use email local part for username (before @)
        var emailLocal = email.Split('@')[0]; // remove #ext# suffix

        var username = new string(emailLocal
            .ToLower()
            .Select(c => char.IsLetterOrDigit(c) ? c : '_')
            .ToArray())
            .Trim('_');

        // Remove consecutive underscores
        while (username.Contains("__"))
            username = username.Replace("__", "_");

        // Remove leading/trailing underscores
        username = username.Trim('_');


        // Ensure uniqueness — add random suffix if username exists
        var existingByName = await _userManager.FindByNameAsync(username);
        if (existingByName != null)
            username = $"{username}_{new Random().Next(1000, 9999)}";

        var newUser = new ApplicationUser
        {
            UserName = username,
            Email = email,
            EmailConfirmed = true, // Microsoft already verified the email
        };
        // SSO users don't have a local password — they authenticate via Microsoft
        var result = await _userManager.CreateAsync(newUser);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new Exception($"Failed to create SSO user: {errors}");
        }

        // Assign default User role
        await _userManager.AddToRoleAsync(newUser, "User");

        _logger.LogInformation(
            "SSO: Created new user {Username} from Microsoft account", username);

        return newUser;
    }
}
