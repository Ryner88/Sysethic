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

6. Create the first local admin account.

## Health Check

Run:

```bash
scripts/saaoe-healthcheck.sh
```

The health check confirms that the Flask app is reachable. After login, use the sidebar to verify Users, Incidents, Approvals, Validation, Audit Logs, and Terminal access.

## Operational Defaults

- The app binds to `127.0.0.1` by default.
- Flask debug mode is disabled by default.
- Operational data is stored in `data/saaoe.sqlite3`.
- Local SQLite databases are ignored by git.
- The legacy diagnostic WebSocket is disabled unless `SAAOE_ENABLE_TERMINAL_WS=1`.
- The browser terminal uses the authenticated `/api/terminal/run` endpoint.
