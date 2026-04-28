# SAAOE UML Diagrams

These diagrams describe the current SAAOE Flask dashboard, telemetry pipeline, anomaly workflow, and response surfaces. They use Mermaid so GitHub can render them directly from Markdown.

## System Component Diagram

```mermaid
flowchart LR
    Operator[Security Operator]
    Browser[Web Browser]
    Flask[Flask App<br/>web/saaoe_api.py]
    Sampler[Background Sampler Thread]
    Psutil[psutil / Host OS]
    Logs[(logs/system_log.csv)]
    Rules[(In-memory Rules<br/>anomaly, automation, playbooks)]
    ThreatIntel[(Local Threat Intel JSON)]
    TerminalWS[Diagnostic WebSocket<br/>127.0.0.1:8765]

    Operator --> Browser
    Browser -->|HTML pages| Flask
    Browser -->|REST fetch / SSE| Flask
    Browser -->|WebSocket commands| TerminalWS
    Flask --> Sampler
    Sampler --> Psutil
    Flask --> Psutil
    Flask --> Logs
    Flask --> Rules
    Flask --> ThreatIntel
    TerminalWS -->|allowlisted commands| Psutil

    subgraph Pages
      Dashboard[Dashboard]
      Analytics[Analytics]
      VisualizationLab[Visualization Lab]
      Anomalies[Anomalies]
      Security[Security]
      Reports[Reports]
      Automation[Automation]
      Playbooks[Playbooks]
      Terminal[Terminal]
    end

    Browser --> Pages
```

## Domain Class Diagram

```mermaid
classDiagram
    class SystemMetric {
        +datetime timestamp
        +float cpu_percent
        +float memory_percent
        +float disk_read_mbs
        +float disk_write_mbs
        +float net_rx_mbs
        +float net_tx_mbs
    }

    class Anomaly {
        +string id
        +datetime timestamp
        +string metric
        +float value
        +float threshold
        +string severity
        +float confidence
        +int risk_score
        +string indicator
        +list frameworks
    }

    class ThreatIntelMatch {
        +bool matched
        +int confidence
        +string source
        +list tags
    }

    class AutomationRule {
        +int id
        +string name
        +string field
        +string operator
        +string value
        +string action
        +bool enabled
    }

    class Playbook {
        +int id
        +string name
        +string category
        +string metric
        +string operator
        +float threshold
        +string action
        +string target
        +bool auto
        +string yaml
    }

    class PlaybookRun {
        +int id
        +datetime timestamp
        +string name
        +string action
        +string target
        +string status
    }

    class ReportSummary {
        +int anomaly_count
        +int critical_count
        +int high_risk_count
        +int audit_count
        +map frameworks
    }

    SystemMetric --> Anomaly : evaluated into
    Anomaly --> ThreatIntelMatch : decorated with
    AutomationRule --> Anomaly : matches
    Playbook --> Anomaly : responds to
    Playbook --> PlaybookRun : creates
    ReportSummary --> Anomaly : summarizes
```

## Anomaly Detection and Response Sequence

```mermaid
sequenceDiagram
    participant Sampler as Background Sampler
    participant Host as Host Metrics
    participant API as Flask API
    participant Rules as Rule Stores
    participant UI as Browser UI
    participant PB as Playbook Engine

    Sampler->>Host: Read CPU, memory, disk, network
    Sampler->>API: Append ring-buffer samples
    UI->>API: GET /api/anomalies
    API->>API: Load logs and calculate statistical anomalies
    API->>API: Decorate anomaly with risk score and framework mappings
    API->>Rules: Apply automation rules
    API-->>UI: Return anomaly list
    UI->>API: POST /api/playbook_trigger
    API->>PB: Match enabled playbook
    PB->>Rules: Record playbook run
    API-->>UI: Return response run status
```

## Visualization Lab Sequence

```mermaid
sequenceDiagram
    participant UI as Visualization Lab Page
    participant API as /api/visualization_lab
    participant Buffers as Ring Buffers
    participant Charts as Chart.js Views

    UI->>API: Fetch visualization payload
    API->>Buffers: Read usage, disk, and network series
    API->>API: Build points with anomaly_score and risk_level
    API->>API: Build recent heatmap cells
    API-->>UI: Return summary, series, points, heatmap
    UI->>Charts: Update timeline chart
    UI->>Charts: Update bubble scatterplot
    UI->>UI: Render risk heatmap and recent points table
```

## Automation Rule State Diagram

```mermaid
stateDiagram-v2
    [*] --> Draft
    Draft --> Enabled: create rule
    Enabled --> Matched: anomaly satisfies condition
    Matched --> ActionQueued: build automation history record
    ActionQueued --> Completed: action recorded
    Completed --> Enabled: continue monitoring
    Enabled --> Disabled: operator disables or deletes rule
    Disabled --> [*]
```

## Runtime Deployment Diagram

```mermaid
flowchart TB
    subgraph HostMachine["Local SAAOE Host"]
        FlaskProcess["Python Flask Process"]
        SamplerThread["Sampler Thread"]
        TerminalServer["Terminal WebSocket Server"]
        StaticAssets["Templates + CSS + Chart.js"]
        LogFile["logs/system_log.csv"]
        HostOS["Operating System APIs"]
    end

    subgraph Client["Operator Workstation"]
        Browser["Browser"]
    end

    Browser -->|HTTP 5000| FlaskProcess
    Browser -->|SSE notifications| FlaskProcess
    Browser -->|WS 8765 localhost| TerminalServer
    FlaskProcess --> StaticAssets
    FlaskProcess --> LogFile
    FlaskProcess --> HostOS
    SamplerThread --> HostOS
    FlaskProcess --> SamplerThread
    TerminalServer --> HostOS
```
