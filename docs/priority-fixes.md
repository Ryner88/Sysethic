# Priority Fixes

These are the near-term fixes required to make SAAOE an operational tool that users can safely run on their own computers. The order matters: identity, storage, auditability, and safety controls must come before real host-impacting response actions.

## Phase 1: Operational Foundation

### 1. Add Authentication and Local User Access Control

Goal: prevent unauthenticated users from viewing local telemetry or triggering diagnostic actions.

Build:

- Login and logout
- Password hashing
- Session timeout
- First-run admin setup
- Roles: admin, analyst, viewer
- Permission checks for every page and API route

Minimum permissions:

- Admin: full access, including terminal, response actions, user management, configuration, and report exports.
- Analyst: view telemetry, manage incidents, recommend playbooks, and request approved actions.
- Viewer: read-only access to dashboards, reports, and incident history.

Acceptance criteria:

- A logged-out user is redirected away from protected pages and APIs.
- A viewer cannot access terminal, automation mutation, playbook mutation, or response-action routes.
- An admin can create and disable users.
- All login, logout, denied-access, and user-management events create audit records.

Why priority: SAAOE exposes sensitive system data and diagnostic controls. It needs identity and authorization before it can be operational.

### 2. Add Durable Storage

Goal: replace in-memory operational state with persistent records that survive restarts.

Store:

- Users and roles
- Audit logs
- Anomalies
- Incidents
- Playbooks
- Playbook runs
- Automation rules
- Response approvals
- File classifications
- Report history
- App configuration

Acceptance criteria:

- Restarting the app does not erase users, incidents, rules, playbooks, or audit logs.
- Database initialization is automatic or documented as a single setup command.
- Existing API responses are backed by storage where persistence is required.
- Storage errors return clear operational errors instead of silently dropping records.

Why priority: operational tools must preserve evidence, configuration, and workflow state.

### 3. Add Safe Configuration Defaults

Goal: make SAAOE configurable without editing source code and safe to start on a user machine.

Build:

- `.env` support
- App config loader
- Secret key configuration
- Configurable host, port, database path, log path, and telemetry thresholds
- Debug mode disabled by default
- Local-only binding by default
- Startup validation with clear error messages

Acceptance criteria:

- The app refuses to start with an unsafe missing secret key outside development mode.
- The default bind address is `127.0.0.1`.
- Thresholds and paths can be changed without editing Python files.
- Startup prints or logs the active operational mode and protected bind address.

Why priority: users need predictable, safe startup behavior on their own computers.

## Phase 2: Evidence and Workflow

### 4. Normalize Audit Logging

Goal: every meaningful user, system, and response event should create a consistent audit record.

Log:

- Login and logout
- Denied access
- Alert generated
- Incident created or updated
- Rule created, changed, or deleted
- Playbook created, changed, or deleted
- Terminal command attempted
- Response action requested, approved, rejected, started, succeeded, or failed
- Report downloaded
- Configuration changed

Audit fields:

- Timestamp
- Actor
- Role
- Event type
- Target object
- Result
- Source IP or local session identifier
- Reason or detail message

Acceptance criteria:

- Every protected mutation route writes an audit record.
- Failed and denied actions are logged, not only successful actions.
- Audit logs can be filtered by actor, event type, result, and time range.
- Audit records survive app restarts.

Why priority: audit history is required for trust, debugging, accountability, and incident review.

### 5. Create a Real Incident Workflow

Goal: turn alerts into tracked incidents that a user can investigate, assign, update, and close.

Build:

- Incident IDs
- Severity and status
- Owner or assignee
- Linked anomalies
- Recommended playbook
- Timeline of actions
- Notes and resolution summary
- Close and reopen actions

Statuses:

- Open
- Investigating
- Waiting for Approval
- Resolved
- Dismissed

Acceptance criteria:

- A high or critical anomaly can create an incident.
- Users can assign, update status, add notes, and close an incident.
- The incident timeline shows linked anomaly, playbook, approval, terminal, and response events.
- Incident changes create audit records.

Why priority: users need an investigation workflow, not just charts and alerts.

### 6. Standardize Severity, Status, and Risk Labels

Goal: make alerts, anomalies, incidents, and responses use the same language throughout the app.

Use these severities:

- Info
- Low
- Medium
- High
- Critical

Use these common statuses:

- Open
- Investigating
- Waiting for Approval
- Resolved
- Dismissed
- Failed

Acceptance criteria:

- Dashboard, Security, Anomalies, Reports, and Incident views use the same labels.
- API payloads use stable lowercase values.
- UI labels are human-readable and consistently colored.
- Reports use the same severity and status vocabulary as the app.

Why priority: consistent language reduces operator mistakes and makes reporting clearer.

## Phase 3: Controlled Operations

### 7. Harden the Diagnostic Terminal

Goal: keep diagnostic access useful without turning the local dashboard into an unsafe command surface.

Build:

- Admin-only access
- Explicit allowlist of commands and arguments
- Command timeout
- Output size limits
- Full audit logging
- No shell expansion
- Clear warning labels for privileged diagnostics

Acceptance criteria:

- Non-admin users cannot open or use the terminal API/WebSocket.
- Commands outside the allowlist are rejected and audited.
- Long-running commands are terminated.
- Large command output is truncated safely.
- Every command attempt records actor, command, result, and timestamp.

Why priority: terminal access is one of the highest-risk surfaces in SAAOE.

### 8. Add Manual Approval for Risky Actions

Goal: prevent destructive or disruptive automation from running without explicit human approval.

Risky actions:

- Kill process
- Suspend process
- Block IP
- Quarantine file
- Delete file
- Restart service
- Change firewall rules

Build:

- Approval request records
- Approve and reject actions
- Required approver role
- Reason field
- Dry-run preview
- Expiration for stale approval requests

Acceptance criteria:

- Risky actions cannot run without an approved request.
- The user who requests an action and the user who approves it are recorded.
- Rejected and expired approvals prevent execution.
- Approval decisions appear in the incident timeline and audit log.

Why priority: operational response must be controlled, attributable, and reversible where possible.

### 9. Implement Real, Gated Response Actions

Goal: make playbook and automation actions affect the host only after permission, validation, and approval checks pass.

Start with:

- Kill process by PID
- Suspend or resume process where supported
- Quarantine file by moving it to a controlled local folder
- Block IP using an OS-specific adapter
- Create incident report

Required safeguards:

- Admin permission required for execution
- Human approval required for destructive actions
- Dry-run mode
- Target validation before execution
- Audit entry before and after action
- Clear failure handling
- Rollback instructions where possible

Acceptance criteria:

- Each response action has a dry-run result.
- Each response action refuses invalid or stale targets.
- Each response action writes success or failure to the incident timeline and audit log.
- OS-specific unsupported actions fail closed with a clear message.

Why priority: this is the main difference between a monitoring dashboard and an operational response system.

## Phase 4: Operational Validation

### 10. Add Controlled Validation Event Center

Goal: generate safe, local validation events that prove detection, incident creation, playbook recommendation, approval, and audit logging work end to end.

Build:

- CPU pressure validation event
- Memory pressure validation event
- Suspicious network validation event
- Sensitive file validation event
- Validation event history
- Clear labeling that events are controlled validation inputs

Acceptance criteria:

- Validation events create normal anomalies and incidents through the same code paths as live telemetry.
- Validation events never require dangerous system changes.
- Validation events are clearly marked in the audit log and incident timeline.
- Users can run a complete validation path from event to incident closure.

Why priority: operational systems need repeatable validation without requiring users to create real security problems on their machines.

### 11. Add Seeded Operational Playbooks

Goal: ship useful starter playbooks that map to real incident types.

Start with:

- Runaway CPU Process Review
- Memory Pressure Response
- Suspicious Network Connection Review
- Sensitive File Access Review
- Human Approval Required
- Create Incident Report
- Quarantine File with Approval
- Block IP with Approval

Acceptance criteria:

- Each seeded playbook has a name, category, trigger condition, recommended action, required approval level, and YAML steps.
- Playbooks can be enabled or disabled.
- Playbook changes are persistent and audited.
- A matching anomaly recommends the correct playbook.

Why priority: playbooks are central to SAAOE's operational identity.

### 12. Connect Validation Events to Playbooks

Goal: controlled validation events should trigger the same detection and recommendation path used by real telemetry.

Example:

- CPU pressure validation event
- CPU anomaly created
- Incident opened
- Runaway CPU Process Review playbook recommended
- Analyst requests action
- Admin approves or rejects
- Audit and incident timeline updated

Acceptance criteria:

- Each validation event maps to at least one seeded playbook.
- The recommended playbook is visible from the incident and anomaly views.
- Approval-required actions cannot bypass the approval workflow.
- The full path is visible in reports and audit logs.

Why priority: this proves the operational workflow before real response actions are used on a user machine.

## Phase 5: Packaging and Test Coverage

### 13. Add Installation and Startup Packaging

Goal: make it easy for users to install, start, stop, and verify SAAOE.

Build:

- Setup script
- Health check command
- Start and stop scripts
- Windows, macOS, and Linux notes
- Optional system service instructions
- Dependency checks
- First-run setup instructions

Acceptance criteria:

- A new user can install dependencies and start the app by following one document.
- Health check verifies database, config, telemetry sampler, and protected routes.
- Setup instructions explain local-only access and first-run admin creation.
- Start/stop commands are documented for each supported operating system.

Why priority: a real user should not need to understand the codebase to operate the tool.

### 14. Add Tests for Security-Critical Behavior

Goal: prevent regressions in authentication, permissions, audit logging, approvals, and response safety.

Cover:

- Unauthenticated users cannot access protected pages or APIs.
- Viewers cannot run terminal commands or response actions.
- Analysts can request but not execute destructive response actions.
- Admins can approve and execute allowed actions.
- Destructive actions require approval.
- Audit entries are written for important events.
- Invalid playbook, rule, and response inputs are rejected.
- Unsupported OS actions fail closed.

Acceptance criteria:

- Security-critical routes have automated tests.
- Tests run from a documented command.
- CI or precommit workflow runs the test suite.
- New response actions require tests before being enabled.

Why priority: once SAAOE controls local machine actions, tests become a safety requirement.
