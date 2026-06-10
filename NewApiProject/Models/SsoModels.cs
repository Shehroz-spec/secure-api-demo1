namespace SecureApiDemo.Models;

/// <summary>
/// Response returned after successful SSO login.
/// Contains JWT tokens for subsequent API calls.
/// </summary>
public class SsoLoginResponse
{
    public string AccessToken  { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public int    ExpiresIn    { get; set; } = 3600;
    public string TokenType    { get; set; } = "Bearer";
    public string LoginMethod  { get; set; } = string.Empty; // "Local" or "Microsoft"
    public string Username     { get; set; } = string.Empty;
    public string Email        { get; set; } = string.Empty;
    public string Role         { get; set; } = string.Empty;
}

/// <summary>
/// Microsoft SSO user info returned from Microsoft Graph API.
/// </summary>
public class MicrosoftUserInfo
{
    public string Id                { get; set; } = string.Empty;
    public string DisplayName       { get; set; } = string.Empty;
    public string Mail              { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string GivenName         { get; set; } = string.Empty;
    public string Surname           { get; set; } = string.Empty;
}

/// <summary>
/// SSO initiation request — tells the API which provider to use.
/// </summary>
public class SsoInitRequest
{
    public string Provider    { get; set; } = "Microsoft"; // Microsoft, Google (future)
    public string RedirectUri { get; set; } = string.Empty;
}
