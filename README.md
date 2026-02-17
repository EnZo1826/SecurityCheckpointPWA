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

Navigate to **Settings > Online Database Sync** to connect to a REST API backend.

#### Configuration Fields

1. **REST API Endpoint**: Your Frappe API endpoint (e.g., `https://example.com/api/method/app.api.visitors.post_visitor`)
2. **API Token**: Static authentication token in Frappe format: `token api_key:api_secret`
3. **Test Connection**: Verifies the endpoint is reachable and the token is accepted
4. **Save**: Persists settings locally

#### Generating a Frappe API Token

1. In your Frappe/ERPNext site, go to **Settings > API Access** (or generate keys for a user)
2. The format is: `token <api_key>:<api_secret>`
3. Example: `token ad389f7e50d0a46:bc87cd51c070794`

#### API Request Format

Sync requests POST visitor records with the token in the Authorization header:

```
POST /api/method/safenetops.api.visitors.post_visitor
Authorization: token ad389f7e50d0a46:bc87cd51c070794
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
- **Auto-sync**: When online, unsynced records sync automatically with exponential backoff
- **Manual sync**: "Sync Now" button in Admin Settings
- **Retry failed**: Clears sync errors and re-queues failed records
- **CORS detection**: If the server blocks requests due to CORS, the app stops retrying and displays actionable guidance
- **Diagnostics**: Exports a JSON file with sync status and failed records
- **Never blocks**: Gate operations always work regardless of sync status

#### CORS Configuration (Required)

Since the PWA runs in a browser on a different origin than your Frappe server, the server **must** return CORS headers. Without this, the browser will block all sync requests.

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
