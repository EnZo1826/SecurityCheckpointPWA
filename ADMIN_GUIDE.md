# Security Checkpoint — Admin Setup Guide

## Quick Start

### 1. Deployment

Place all three files in the same directory on a web server:

```
security-checkpoint/
  index.html
  sw.js
  manifest.json
```

**Serve via HTTPS** — PWA features (service worker, install prompt) require HTTPS.

**Simple local server** (for testing):
```bash
# Python
python3 -m http.server 8080

# Node.js
npx serve .

# Or use any static file server (Nginx, Apache, Caddy)
```

Then open `https://your-domain/security-checkpoint/` on the device browser.

### 2. Install as PWA

On the device (phone/tablet):
- **Chrome (Android)**: Tap the "Install" banner or Menu > "Add to Home Screen"
- **Safari (iOS)**: Tap Share > "Add to Home Screen"
- **Chrome (Desktop)**: Click the install icon in the address bar

### 3. Default Credentials

| Username | PIN  | Role  |
|----------|------|-------|
| admin    | 1234 | Admin |

**Change the admin PIN immediately after first login.**

---

## Admin Configuration

### Branding

Navigate to **Settings > Branding** to set:
- **Site / Gate Name**: Appears on login screen and top bar (e.g., "Main Gate", "North Entrance")

### User Management

Navigate to **Settings > User Management**:
- **Add Guard**: Create guard accounts with username + PIN (minimum 4 characters)
- **Reset PIN**: Click the key icon next to any user to reset their PIN
- **Remove Guard**: Click the trash icon (cannot remove the admin account)

Guard accounts can only access: Dashboard, Check-In, Search/Check-Out, Logs, and Export.

### Online Database Sync

Navigate to **Settings > Online Database Sync** to connect to a REST API backend using OAuth2 token authentication.

#### Configuration Fields

1. **REST API Base URL**: Your data endpoint (e.g., `https://api.example.com/visitors`)
2. **Auth Token URL**: OAuth2 token endpoint (e.g., `https://auth.example.com/oauth/token`)
3. **Client ID**: Your OAuth2 client identifier
4. **Client Secret**: Your OAuth2 client secret
5. **Grant Type**:
   - **Client Credentials** (default): Machine-to-machine authentication, no user context
   - **Resource Owner Password**: Requires username/password fields (for legacy systems)
6. **Scope** (optional): Space-separated list of scopes (e.g., `read write sync`)
7. **Test Connection**: Acquires a token and verifies the API endpoint is reachable
8. **Save Config**: Persists all settings locally (clears any existing token)

#### Token Lifecycle

- Tokens are acquired automatically before sync operations
- Tokens are cached locally and refreshed proactively at 75% of their lifetime
- If a sync request returns HTTP 401, the engine acquires a fresh token and retries once
- If a `refresh_token` is provided by the auth server, it is used for renewal before falling back to a full credential exchange
- Token status (active/expired/remaining time) is displayed in the settings panel
- The "Refresh Token" button forces immediate re-acquisition

#### Token Request Format

The app sends a standard OAuth2 token request:

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=your-client-id
&client_secret=your-client-secret
&scope=read+write
```

Expected response:

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBh..."
}
```

#### API Request Format

Once authenticated, sync requests include the token as a Bearer header:

```
POST /visitors
Authorization: Bearer eyJhbGciOi...
Content-Type: application/json

{
  "id": "xxxx-xxxx-4xxx-yxxx-xxxx-xxxxx",
  "visitor_name": "John Smith",
  "cell_no": "072 123 4567",
  "company": "Acme Corp",
  "vehicle_reg": "CA 123-456",
  "time_in": "2025-01-15T08:30:00.000Z",
  "time_out": "2025-01-15T16:45:00.000Z",
  "status": "EXITED",
  "total_minutes_on_site": 495,
  "notes": "",
  "created_at": "2025-01-15T08:30:00.000Z",
  "updated_at": "2025-01-15T16:45:00.000Z",
  "device_id": "DEV-xxxx-xxxx",
  "synced": false,
  "sync_error": null,
  "version": 2
}
```

Your API should:
- Accept POST with JSON body
- Return HTTP 200/201 on success
- Handle upsert by `id` field
- Use `version` for conflict resolution (highest version wins)

#### Sync Behavior
- **Token-first**: A valid access token is acquired before any sync attempt
- **Auto-sync**: When online, unsynced records sync automatically with exponential backoff
- **401 retry**: If the API returns 401, the engine re-acquires a token and retries once
- **Manual sync**: "Sync Now" button in Admin Settings
- **Retry failed**: Clears sync errors and re-queues failed records
- **Diagnostics**: Exports a JSON file with sync status, token state, and failed records
- **Never blocks**: Gate operations always work regardless of sync or token status

#### CORS Configuration (Required)

Since the PWA runs in a browser on a different origin than your API server, the server must return CORS headers. Without this, the browser will block all sync and token requests.

**For Frappe/ERPNext**, add the PWA origin to `site_config.json`:

```json
{
  "allow_cors": ["https://your-pwa-domain.vercel.app"]
}
```

Then restart the server:

```bash
bench restart
```

**For other backends**, ensure the server returns these headers on all responses (including preflight OPTIONS):

```
Access-Control-Allow-Origin: https://your-pwa-domain.vercel.app
Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
```

The "Test Connection" button will detect CORS issues and display specific guidance if blocked.

### Data Management

- **Retention Period**: Set how long exited records are kept (30-365 days)
- **Archive Now**: Immediately removes exited records older than the retention period
- On-site records are never archived

---

## Operations Guide

### Guard Workflow

1. **Check-In** (< 10 seconds):
   - Tap the + button (center of bottom nav)
   - Fill in Name, Cell, Company (Vehicle optional)
   - Confirm check-in

2. **Check-Out**:
   - From Dashboard: Tap a visitor > "Mark Exit"
   - From Search: Search by name/cell/company/vehicle > "Exit"
   - Confirm check-out — total time displayed immediately

3. **Export**:
   - Dashboard: Tap export icon for today's log (.xlsx)
   - Logs: Select date range > Export (.xlsx or .csv)

### Offline Operation

The app works fully offline:
- All data stored locally in IndexedDB
- Service worker caches the app shell
- Sync status shown in top bar
- Records sync automatically when connection returns

---

## Technical Notes

- **Storage**: IndexedDB (persists across browser restarts)
- **Export**: SheetJS library for .xlsx generation (client-side)
- **PWA**: Service worker + manifest for installable offline app
- **Timezone**: All times captured in device timezone (ISO format)
- **Duplicate Prevention**: Same name + cell number cannot have two active on-site records
