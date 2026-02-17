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

Navigate to **Settings > Online Database Sync** to connect to a REST API backend:

1. **Base URL**: Your API endpoint (e.g., `https://api.example.com/visitors`)
2. **API Key**: Bearer token for authentication
3. **Test Connection**: Validates the endpoint is reachable
4. **Save**: Stores the configuration locally

#### API Contract

The app will POST visitor records to your endpoint as JSON:

```json
POST /visitors
Authorization: Bearer <your-api-key>
Content-Type: application/json

{
  "id": "xxxx-xxxx-4xxx-yxxx-xxxx-xxxxx",
  "name": "John Smith",
  "cellNo": "072 123 4567",
  "company": "Acme Corp",
  "vehicleReg": "CA 123-456",
  "timeIn": "2025-01-15T08:30:00.000Z",
  "timeOut": "2025-01-15T16:45:00.000Z",
  "status": "EXITED",
  "totalMinutesOnSite": 495,
  "notes": "",
  "createdAt": "2025-01-15T08:30:00.000Z",
  "updatedAt": "2025-01-15T16:45:00.000Z",
  "deviceId": "DEV-xxxx-xxxx",
  "synced": false,
  "syncError": null,
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
- **Diagnostics**: Exports a JSON file with sync status of all records
- **Never blocks**: Gate operations always work regardless of sync status

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
