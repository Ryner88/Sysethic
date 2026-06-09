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

   Then edit `.env` and set `SAAOE_SECRET_KEY` to a long random value.

4. Run the web dashboard:
   ```bash
   python web/saaoe_api.py
   ```

5. Open http://localhost:5000 in your browser.

6. Complete first-run setup by creating the first workspace owner.

## Usage

Log in with a SysEthic workspace account, then navigate through the sidebar to access monitoring sections. Workspace Admins manage members, workspace settings, playbooks, audits, and reports for their own workspace. Regular Users can view assigned dashboards, run allowed playbooks, and submit incident findings. Platform-owner diagnostics are separate from workspace administration.

By default, the app binds to `127.0.0.1`, stores operational data in `data/saaoe.sqlite3`, and disables Flask debug mode. Configuration can be changed with environment variables or `.env`.

See [Operational Startup](docs/operational-startup.md) for the local startup checklist, health check, and operational defaults.

## Tests

Run the workflow tests:

```bash
venv/bin/python -m unittest discover -s tests
```
