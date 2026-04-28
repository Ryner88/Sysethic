# SAAOE Project

Secure Autonomous Autonomous Operating Environment Monitor

## Features

| Feature | Description |
|---------|-------------|
| 🔐 **User & Process Isolation** | Uses OS-level sandboxing to isolate and monitor apps and users (namespaces, cgroups, etc.). |
| 📊 **Real-time Analytics** | Live system monitoring with CPU, memory, disk, and network usage charts. |
| 🧪 **Visualization Lab** | Scientific-style visualization of system metrics, anomaly scores, heatmaps, and timeline replay. |
| 🚨 **Anomaly Detection** | Automatic detection of unusual system behavior based on statistical thresholds. |
| 🛡️ **Ethics Dashboard** | Monitoring for ethical AI operations, including alerts and system health. |
| 📋 **Audit Logging** | Comprehensive logging of system metrics and events for auditing purposes. |
| 🔒 **Security Operations** | Security alerts, access control, and intrusion detection. |
| 📁 **Privacy-Conscious Files** | Secure file handling with classification and encryption. |

## Architecture

See [SAAOE UML Diagrams](docs/uml-diagrams.md) for component, domain, sequence, state, and deployment diagrams. See [Priority Fixes](docs/priority-fixes.md), [Future Feature Implmentation](docs/future-feature-implmentation.md), and [Method, Function, List Meaning, and Design](docs/method-function-list-meaning-and-design.md) for roadmap and implementation reference docs.

### Entities
- **AuditLog**: System and user activity logs
- **SystemMetric**: Performance and resource metrics
- **SecurityAlert**: Security events and alerts
- **Process**: Running processes with isolation status
- **FileAccess**: File operations with privacy classification

### Pages
- **Dashboard**: Overview with key metrics and alerts
- **Processes**: Process isolation monitor and controls
- **Analytics**: Detailed real-time system analytics
- **Visualization Lab**: Advanced scientific-style visualization with timeline replay, heatmaps, and multidimensional metric plots
- **Security**: Alerts, access control, and firewall status
- **Audit Logs**: Transparent logging and compliance
- **Ethics**: Privacy dashboard and ethical AI monitoring
- **Files**: Privacy-conscious file handling and access logs

## Design
- **Theme**: Dark, terminal-inspired with green/cyan accents
- **Layout**: Sidebar navigation with professional security-ops feel
- **UI**: Responsive grid-based layout with real-time updates

## Installation

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. (Optional) Start the process monitor to collect logs:
   ```bash
   python src/process_monitor.py &
   ```

3. Run the web dashboard:
   ```bash
   python web/saaoe_api.py
   ```

4. Open http://localhost:5000 in your browser.

## Usage

Navigate through the sidebar to access different monitoring sections. The dashboard provides real-time updates and comprehensive security monitoring for autonomous operations.
