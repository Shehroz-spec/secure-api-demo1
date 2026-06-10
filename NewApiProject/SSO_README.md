# SSO Implementation — Microsoft Entra ID

Both local login and Microsoft SSO available — user chooses.

---

## How It Works

```
Option A — Local Login:
User → POST /api/auth/login → Username + Password → JWT issued

Option B — Microsoft SSO:
User → GET /api/sso/login/microsoft
     → Redirect to Microsoft login page
     → User logs in with Microsoft account
     → Microsoft redirects to /api/sso/callback
     → API exchanges code for user info
     → API creates/finds local user
     → JWT issued (same as local login)
     → User is logged in ✅
```

---

## SSO OAuth2 Flow Diagram

```
Browser          Our API          Microsoft
   │                │                 │
   │──GET /sso/login/microsoft──►     │
   │                │                 │
   │◄──Redirect to Microsoft login────│
   │                │                 │
   │──────────────────────────────────►
   │          (User logs in)           │
   │◄─────────────────────────────────│
   │    Redirect to /sso/callback      │
   │         ?code=AUTH_CODE           │
   │                │                 │
   │──GET /sso/callback?code=...──►   │
   │                │                 │
   │                │──Exchange code──►
   │                │◄──Access token──│
   │                │                 │
   │                │──GET /me────────►
   │                │◄──User info─────│
   │                │                 │
   │                │ Create/find user in SQL
   │                │ Issue JWT token
   │                │                 │
   │◄──JWT token────│                 │
   │                │                 │
```

---

## Setup — Azure Portal

### Step 1 — Register App in Azure

1. Go to `https://portal.azure.com`
2. Search **"App registrations"**
3. Click **"New registration"**
4. Fill in:
   - Name: `SecureApiDemo`
   - Supported account types: **"Accounts in any organizational directory and personal Microsoft accounts"**
   - Redirect URI: `https://localhost:7028/api/sso/callback`
5. Click **Register**

### Step 2 — Get Credentials

From the app registration Overview page:
- Copy **Application (client) ID** → `ClientId`
- Copy **Directory (tenant) ID** → `TenantId`

### Step 3 — Create Client Secret

1. Click **"Certificates & secrets"**
2. Click **"New client secret"**
3. Description: `SecureApiDemo-Secret`
4. Expiry: 24 months
5. Click **Add**
6. Copy the **Value** → `ClientSecret`

### Step 4 — Add API Permissions

1. Click **"API permissions"**
2. Click **"Add a permission"**
3. Select **"Microsoft Graph"**
4. Select **"Delegated permissions"**
5. Add: `openid`, `profile`, `email`, `User.Read`
6. Click **"Grant admin consent"**

---

## Setup — Project

### Step 1 — Install Package

```bash
dotnet add package Microsoft.Identity.Web --version 3.3.0
```

### Step 2 — Update `appsettings.json`

```json
"AzureAd": {
  "TenantId": "YOUR_TENANT_ID",
  "ClientId": "YOUR_CLIENT_ID",
  "ClientSecret": "YOUR_CLIENT_SECRET",
  "Instance": "https://login.microsoftonline.com/",
  "CallbackPath": "/api/sso/callback",
  "Scopes": "openid profile email User.Read"
}
```

### Step 3 — Copy Files to Project

```
NewApiProject/
├── Controllers/
│   └── SsoController.cs      ← copy here
├── Models/
│   └── SsoModels.cs          ← copy here
└── Services/
    └── SsoService.cs         ← copy here
```

### Step 4 — Update `Program.cs`

See `ProgramChanges.cs` for exact changes needed.

---

## API Endpoints

```
GET  /api/sso/providers           → list available login methods
GET  /api/sso/login/microsoft     → redirect to Microsoft login
GET  /api/sso/callback            → handle Microsoft callback
GET  /api/sso/me                  → current user info (requires JWT)
```

---

## Test SSO Flow

1. Open browser: `https://localhost:7028/api/sso/login/microsoft`
2. You'll be redirected to Microsoft login
3. Sign in with your Microsoft account
4. You'll be redirected back with a JWT token
5. Use the JWT token for subsequent API calls

---

## How Users Are Identified

| Login Method | User Identified By | Password in DB |
|---|---|---|
| Local | Username + Password | ✅ BCrypt hash |
| Microsoft SSO | Email address | ❌ No password |

SSO users have `PasswordHash = null` in `AspNetUsers` table.
The `GET /api/sso/me` endpoint returns `"loginMethod": "Microsoft SSO"` for these users.

---

## Security Notes

- State parameter prevents CSRF attacks
- Auth code is single-use (exchanged for token immediately)
- Microsoft verifies email — no need for local email confirmation
- Our JWT is issued after SSO — downstream API unchanged
- SSO users can still enable 2FA on their account

---

## Interview Talking Points

**Q: What is SSO?**
> "SSO allows users to authenticate once with a trusted provider (Microsoft) and access multiple applications without logging in again. It eliminates password management for users and centralizes authentication."

**Q: What OAuth2 grant type did you use?**
> "Authorization Code flow — the most secure OAuth2 grant type. The auth code is exchanged server-side for tokens, so access tokens never appear in the browser URL."

**Q: How does SSO work with your existing JWT setup?**
> "After Microsoft authentication succeeds, we issue our own JWT token. This means the downstream API works identically whether the user logged in locally or via SSO — the JWT claim structure is the same."

**Q: How do you prevent CSRF in the SSO flow?**
> "We generate a cryptographically random state parameter before redirecting to Microsoft. When Microsoft redirects back, we validate the state matches what we stored — if it doesn't match we block the request."

---

## Author

Shehroz Reaz — Software Engineer specializing in secure cloud-native systems.
