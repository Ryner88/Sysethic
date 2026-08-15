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

Phase 4 #10, Controlled Validation Event Center, is complete. It adds safe CPU pressure, memory pressure, suspicious network, and sensitive-file validation events that create normal anomalies, incidents, matching playbook runs, audit records, and incident timeline entries without executing host-impacting actions or bypassing approvals.

Phase 4 #11 and #12 add persisted seeded operational playbook definitions, safe declarative step validation, versioned definition digests, immutable playbook run snapshots, and shared persisted matching for live and controlled anomalies.

Verification: `venv/bin/python -m unittest discover` passed with 42 tests.

Phase 5 #13 adds local installation/startup packaging: `scripts/setup_saaoe.py`, the shared `web.saaoe_cli` operations interface, `/healthz`, Waitress foreground serving, PID-validated lifecycle commands, wrappers, CI, and the expanded [Operational Startup](docs/operational-startup.md) guide. It does not enable `quarantine_file` or `block_ip`.

Phase 5 #14 adds security-critical test coverage and enforcement around response-action registry metadata, role and platform gates, approval floors, route authentication inventory, strict rule validation, exception sanitization, and CodeQL remediation. `quarantine_file` and `block_ip` remain registered but disabled and fail closed.

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
- **Validation**: Controlled CPU, memory, network, and sensitive-file workflow checks
- **Audit Logs**: Transparent logging and compliance
- **Ethics**: Privacy dashboard and ethical AI monitoring
- **Files**: Privacy-conscious file handling and access logs

## Design
- **Theme**: Dark operations console with restrained cyan, green, amber, and red status colors
- **Layout**: Sidebar navigation with dense workspace dashboards
- **UI**: Responsive grid-based layout with real-time updates and overflow-safe tables

## Installation

1. Run setup:
   ```bash
   python3 scripts/setup_saaoe.py
   ```

   Python 3.11 or newer is required.

2. Optional: start the process monitor to collect local logs:
   ```bash
   python src/process_monitor.py &
   ```

3. Create the first administrator if setup could not prompt interactively and no user exists yet:

   ```bash
   venv/bin/python -m web.saaoe_cli bootstrap-admin
   ```

   This command is refused after the initial administrator has been created.

4. Start the local service:
   ```bash
   venv/bin/python -m web.saaoe_cli start
   ```

5. Open http://127.0.0.1:5001 in your browser.

6. Check status and health:
   ```bash
   venv/bin/python -m web.saaoe_cli status
   venv/bin/python -m web.saaoe_cli health
   ```

## Usage

Log in with a SysEthic workspace account, then navigate through the sidebar to access monitoring sections. Workspace Admins manage members, workspace settings, playbooks, audits, and reports for their own workspace. Regular Users can view assigned dashboards, run allowed playbooks, and submit incident findings. Platform-owner diagnostics are separate from workspace administration.

Use **Validation** to create controlled validation inputs for CPU pressure, memory pressure, suspicious network activity, and sensitive file access. These events are labeled as validation inputs, create normal anomalies and incidents, and record matching playbook runs. Approval-required response actions remain gated by the response approval workflow.

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

See [Operational Startup](docs/operational-startup.md) for setup idempotency, first-run admin bootstrap, local-only security defaults, service-manager guidance, backup, troubleshooting, and upgrade instructions.

## Tests

Run the full regression suite:

```bash
python -m unittest discover
```

Use the Python interpreter from the setup-created virtual environment; without activation, run `venv/bin/python -m unittest discover`.
