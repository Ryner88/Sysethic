# SysEthic / SAAOE

Secure Autonomous Operating Environment monitoring and response workspace.

## Features

| Feature | Description |
|---------|-------------|
| **User and process isolation** | Monitors process state and isolation controls for workspace operators. |
| **Real-time analytics** | Shows live CPU, memory, disk, network, process, and asset telemetry. |
| **Visualization lab** | Provides anomaly timelines, heatmaps, and multidimensional metric views. |
| **Anomaly detection** | Detects unusual system behavior with configurable threshold rules. |
| **Security operations** | Tracks alerts, incidents, approvals, automation, and validation workflows. |
| **Workspace audit logging** | Records workspace activity, security events, and operational changes. |
| **Privacy-conscious files** | Tracks file access with privacy classification and review context. |

## Project Status

Phase 3, Controlled Operations, is complete. The current `main` history preserves the final Phase 3 work as:

- `70e5c01` - approval contract foundation for risky response actions.
- `831f1dc` - first bounded approved host-impacting execution path.

Verification: `venv/bin/python -m unittest discover tests` passed with 37 tests.

Phase 4 handoff: continue with controlled operational validation, starting at Phase 4 #10, from the clean Phase 3 closeout on `main`.

## Architecture

See [SAAOE UML Diagrams](docs/uml-diagrams.md) for component, domain, sequence, state, and deployment diagrams. See [Priority Fixes](docs/priority-fixes.md), [Future Feature Implementation](docs/future-feature-implementation.md), and [Method, Function, List Meaning, and Design](docs/method-function-list-meaning-and-design.md) for roadmap and implementation reference docs.

### Entities
- **AuditLog**: System and workspace activity logs
- **SystemMetric**: Performance and resource metrics
- **SecurityAlert**: Security events and alerts
- **Process**: Running processes with isolation status
- **FileAccess**: File operations with privacy classification

### Pages
- **Dashboard**: Overview with key metrics and alerts
- **Processes**: Process isolation monitor and controls
- **Analytics**: Detailed real-time system analytics
- **Visualization Lab**: Advanced scientific-style visualization with timeline replay, heatmaps, and multidimensional metric plots
- **Security**: Alerts, incident response, approvals, and validation
- **Audit Logs**: Transparent logging and compliance
- **Ethics**: Privacy dashboard and ethical AI monitoring
- **Files**: Privacy-conscious file handling and access logs

## Design
- **Theme**: Dark operations console with restrained cyan, green, amber, and red status colors
- **Layout**: Sidebar navigation with dense workspace dashboards
- **UI**: Responsive grid-based layout with real-time updates and overflow-safe tables

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Optional: start the process monitor to collect local logs:
   ```bash
   python src/process_monitor.py &
   ```

3. Configure an operational secret key:

   ```bash
   cp .env.example .env
   ```

   For local development, the app can start without `SAAOE_SECRET_KEY` and will generate an ephemeral development key. For operational or production use, edit `.env`, set `SAAOE_MODE=production`, and set `SAAOE_SECRET_KEY` to a long random value of at least 32 characters.

4. Run the web dashboard:
   ```bash
   python web/saaoe_api.py
   ```

5. Open http://127.0.0.1:5001 in your browser.

6. Complete first-run setup by creating the first workspace owner.

## Usage

Log in with a SysEthic workspace account, then navigate through the sidebar to access monitoring sections. Workspace Admins manage members, workspace settings, playbooks, audits, and reports for their own workspace. Regular Users can view assigned dashboards, run allowed playbooks, and submit incident findings. Platform-owner diagnostics are separate from workspace administration.

By default, the app binds to `127.0.0.1`, listens on port `5001`, stores operational data in `data/saaoe.db`, reads local telemetry logs from `logs/system_log.csv`, and disables Flask debug mode. Configuration can be changed with environment variables or `.env`.

Common configuration variables:

- `SAAOE_MODE`: operational mode, default `development`.
- `SAAOE_SECRET_KEY`: required outside development mode.
- `SAAOE_HOST`: bind host, default `127.0.0.1`.
- `SAAOE_PORT`: bind port, default `5001`.
- `SAAOE_DEBUG`: Flask debug mode, default `false`.
- `SAAOE_DATABASE_PATH`: SQLite database path, default `data/saaoe.db`.
- `SAAOE_LOG_PATH`: telemetry CSV path, default `logs/system_log.csv`.
- `SAAOE_SESSION_SECONDS`: authenticated idle timeout in seconds, default `28800`.
- `SAAOE_SESSION_COOKIE_SECURE`: marks session cookies HTTPS-only. Defaults to `true` outside local development.
- `SAAOE_CPU_THRESHOLD`, `SAAOE_MEMORY_THRESHOLD`, `SAAOE_DISK_THRESHOLD`, `SAAOE_NETWORK_THRESHOLD`: telemetry thresholds used by seeded rules and live scoring.

See [Operational Startup](docs/operational-startup.md) for the local startup checklist, health check, and operational defaults.

## Tests

Run the full regression suite:

```bash
venv/bin/python -m unittest discover -s tests
```
