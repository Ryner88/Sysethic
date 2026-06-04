# Operational Startup

Use this checklist to run SAAOE on a local computer.

## First Run

1. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

2. Create local configuration:

   ```bash
   cp .env.example .env
   ```

3. Edit `.env` and set `SAAOE_SECRET_KEY` to a long random value.

4. Start SAAOE:

   ```bash
   scripts/start-saaoe.sh
   ```

5. Open `http://127.0.0.1:5000`.

6. Create the first workspace owner account.

## Health Check

Run:

```bash
scripts/saaoe-healthcheck.sh
```

The health check confirms that the Flask app is reachable and that protected telemetry is not exposed to anonymous requests. After login, use the sidebar to verify Workspace Members, Incidents, Approvals, Validation, and Workspace Audit access.

## Operational Defaults

- The app binds to `127.0.0.1` by default.
- Flask debug mode is disabled by default.
- Operational data is stored in `data/saaoe.sqlite3`.
- SQLite initialization runs automatically during app startup via `init_db()`, creates missing tables, and applies additive column migrations for older local databases.
- Approval requests expire after `SAAOE_APPROVAL_TTL_SECONDS` seconds, defaulting to 24 hours.
- Audit logs can be filtered by actor, event type, result, and time range.
- Local SQLite databases are ignored by git.
- The legacy diagnostic WebSocket fails closed even if started; browser diagnostics use the authenticated API.
- The browser terminal uses the authenticated `/api/terminal/run` endpoint.

## Durable Storage Checklist

The following operational records are initialized in SQLite and must survive process restarts:

- Workspace accounts, roles, workspace membership, join requests, and explicit user permissions.
- Workspace audit events.
- Incidents, incident timeline events, response approvals, and validation events.
- Anomalies, anomaly rules, automation rules, automation history, playbooks, and playbook runs.
- File classifications, report generation history, and workspace app configuration.

Operational API writes insert or update SQLite before returning success. In-memory lists are only runtime caches and are reloaded from SQLite on startup. API storage failures return JSON errors with `error: "storage write failed"` and an explanatory `detail` field.

Database setup is automatic when the Flask app imports. For a manual initialization check, run:

```bash
venv/bin/python -c "import web.saaoe_api; print(web.saaoe_api.DB_PATH)"
```

## Phase 1 Access Checklist

- Logged-out browser users are redirected from protected pages, and logged-out API requests return `401`.
- Signup creates a new workspace with the creator as Workspace Admin; joining with a workspace code creates or requests a Regular User account based on the workspace policy.
- Workspace Admins can invite members, disable members, and assign workspace permissions.
- Regular Users can use normal workspace features, and extra permissions are independent: `manage_members`, `mutate_playbooks`, and `access_terminal`.
- `manage_members` allows `/users` and `/api/users` member management, but not playbook mutation or terminal diagnostics.
- `mutate_playbooks` allows creating and deleting workspace playbooks, but not member management or terminal diagnostics.
- `access_terminal` allows `/terminal`, `/api/terminal/status`, and `/api/terminal/run`, but not member or playbook mutation.
- Permission grants, permission revokes, access denials, login, logout, user creation, and user disablement create audit records scoped to the current workspace.
