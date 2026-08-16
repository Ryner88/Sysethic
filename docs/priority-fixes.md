# Priority Fixes

These are the near-term fixes required to make SAAOE an operational tool that users can safely run on their own computers. The order matters: identity, storage, auditability, and safety controls must come before real host-impacting response actions.

## Follow-Up Maintainability

- Simplify the response-action registry by storing validator and executor callables directly and validating registry shape once during startup. This is a maintainability cleanup; it must preserve the current disabled-action, platform, digest, expiry, self-approval, and single-use safety contracts.

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

Playbooks:

#### First-Run Admin Setup

Trigger: no local admin user exists.

Action: create the initial admin account, hash the password, start an authenticated session, and audit the setup event.

Required approval level: local console access.

```yaml
name: First-Run Admin Setup
category: authentication
trigger:
  event: application_start
  condition: no_admin_user_exists
approval: local_console
steps:
  - action: verify_setup_mode
    require:
      admin_count: 0
      bind_address: 127.0.0.1
  - action: collect_admin_credentials
    fields:
      - username
      - password
  - action: hash_password
    algorithm: werkzeug_password_hash
  - action: create_user
    role: admin
    enabled: true
  - action: create_session
  - action: audit_event
    event_type: first_run_admin_created
    result: success
```

#### Failed Login Review

Trigger: repeated failed login attempts for the same user or source address.

Action: create an audit finding, show recent failed attempts, and recommend disabling the account or waiting for timeout.

Required approval level: admin.

```yaml
name: Failed Login Review
category: authentication
trigger:
  event: login_failed
  window_minutes: 10
  threshold: 5
  group_by:
    - username
    - source_ip
approval: admin
steps:
  - action: collect_audit_events
    event_type: login_failed
    window_minutes: 10
  - action: correlate_attempts
    fields:
      - username
      - source_ip
  - action: create_incident
    severity: medium
    title: Repeated failed login attempts
  - action: recommend_response
    options:
      - disable_user
      - keep_account_enabled
      - require_password_reset
  - action: notify_admin
```

#### Session Timeout Enforcement

Trigger: authenticated session exceeds idle or absolute timeout.

Action: revoke the session, redirect to login, and audit the timeout.

Required approval level: automatic policy enforcement.

```yaml
name: Session Timeout Enforcement
category: authentication
trigger:
  event: request_received
  condition: session_expired
approval: automatic
steps:
  - action: evaluate_session_timeout
    idle_minutes: 30
    absolute_hours: 8
  - action: revoke_session
  - action: audit_event
    event_type: session_timeout
    result: success
  - action: require_login
```

#### Unauthorized Route Access Review

Trigger: logged-out user or low-permission user attempts a protected page or API route.

Action: deny access, record the target route, and surface the event in audit history.

Required approval level: automatic policy enforcement.

```yaml
name: Unauthorized Route Access Review
category: access_control
trigger:
  event: access_denied
  targets:
    - protected_page
    - protected_api
approval: automatic
steps:
  - action: check_authentication
  - action: check_permission
    source: route_policy
  - action: deny_request
    status:
      page: 302
      api: 401_or_403
  - action: audit_event
    event_type: access_denied
    include:
      - actor
      - role
      - route
      - required_permission
```

#### User Disablement

Trigger: admin disables a local user.

Action: mark user disabled, revoke active sessions, and audit the user-management event.

Required approval level: admin.

```yaml
name: User Disablement
category: access_control
trigger:
  event: user_disable_requested
approval: admin
steps:
  - action: verify_actor_role
    role: admin
  - action: prevent_last_admin_disable
  - action: disable_user
    enabled: false
  - action: revoke_user_sessions
  - action: audit_event
    event_type: user_disabled
    result: success
    include:
      - actor
      - target_user
```

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

### 4. Normalize Audit Logging — Complete

Implemented durable normalized audit records for user, system, workflow, security, and response events. Added centralized `audit_event` helper, protected mutation fallback auditing, `/api/audit` filtering, failure/denial coverage, structured details JSON, and persistence tests.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 21 tests in 105.451s - OK

Manual test:

`manual-testing/audit-logging-manual-test.md`

Why priority: audit history is required for trust, debugging, accountability, and incident review.

### 5. Create a Real Incident Workflow — Complete

Implemented durable incident workflow with incident IDs, severity, status, assignee, linked anomalies, recommended playbooks, notes, resolution summaries, close/reopen actions, timeline events, and audit logging for all incident mutations.

Acceptance verified:

- High/critical anomalies can create incidents.
- Users can assign, update status, add notes, close, and reopen incidents.
- Incident detail includes linked anomalies, playbook, notes, and timeline.
- Incident changes create audit records.
- Incident records survive app restarts.
- Full test suite passes.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 21 tests in 105.451s - OK

Manual test:

`manual-testing/incident-workflow-manual-test.md`

Why priority: users need an investigation workflow, not just charts and alerts.

### 6. Standardize Severity, Status, and Risk Labels — Complete

Implemented shared severity and status vocabularies for API payloads, UI badges, filtering, report output, and legacy data backfill. Added stable lowercase API values, human-readable labels, shared CSS classes, risk labels derived from risk scores, and a `/api/vocabulary` endpoint for frontend consistency.

Acceptance verified:

- Dashboard, Security, Anomalies, Reports, and Incident views use shared labels and badge classes.
- API payloads use stable lowercase values for severity and status.
- UI labels are human-readable and consistently colored.
- Reports use the same severity and status vocabulary as the app.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 21 tests in 132.224s - OK

Manual test:

`manual-testing/severity-status-risk-manual-test.md`

Why priority: consistent language reduces operator mistakes and makes reporting clearer.

Historical plan:

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

## Phase 3: Controlled Operations

### 7. Harden the Diagnostic Terminal — Complete

Implemented admin-only diagnostic terminal access, per-command argument allowlists, legacy WebSocket disablement, command timeout enforcement, output truncation, and full audit coverage for allowed, denied, failed, and timed-out command attempts.

Acceptance verified:

- Non-admin users cannot open or use the terminal page, API, or legacy WebSocket path.
- Commands and argument forms outside the allowlist are rejected and audited.
- Long-running commands are terminated.
- Large command output is truncated safely.
- Every command attempt records actor, command, result, and timestamp.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 24 tests in 104.262s - OK

Manual test:

`manual-testing/terminal-hardening-manual-test.md`

Why priority: terminal access is one of the highest-risk surfaces in SAAOE.

Historical plan:

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

Status: Complete in `70e5c01` (`Add approval contract foundation`).

Verification: `venv/bin/python -m unittest tests.test_response_approval_contract` passed with 8 approval-contract tests before the #9 execution layer was restored.

Why priority: operational response must be controlled, attributable, and reversible where possible.

### 9. Implement Real, Gated Response Actions

Goal: make playbook and automation actions affect the host only after permission, validation, and approval checks pass.

Start with:

- Restart approved service target
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

Phase 3 #9 status:

- Implemented `restart_service` as the first real bounded host-impacting execution path.
- The only enabled target is `saaoe-dashboard`, mapped to fixed `systemctl restart saaoe-dashboard.service` arguments with `shell=False` and a 15 second timeout.
- Recovery is fixed to `systemctl start saaoe-dashboard.service` and is recorded with the execution result.
- `kill_process`, `quarantine_file`, and `block_ip` remain authorization-only no-ops until their own bounded adapters are implemented.
- Commit: `831f1dc` (`Add bounded approved service restart execution`).
- Verification: `venv/bin/python -m unittest discover tests` passed with 37 tests.

Phase 3 closeout: Complete. The branch was split into the #8 foundation commit and #9 bounded-execution commit, merged to `main`, and pushed.

Why priority: this is the main difference between a monitoring dashboard and an operational response system.

## Phase 4: Operational Validation

Handoff: begin with #10, Controlled Validation Event Center. Validation work should reuse the completed approval contract and bounded execution safeguards instead of adding broader host-impacting adapters.

### 10. Add Controlled Validation Event Center

Status: Complete.

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

Implementation:

- `/api/validation_events` supports CPU pressure, memory pressure, suspicious network, and sensitive-file validation events from a bounded catalog.
- Each validation event creates a normal anomaly, opens an incident, records matching playbook runs, writes structured audit details, and adds incident timeline entries identifying the controlled validation input.
- Approval-contract actions remain waiting for approval and cannot be executed by the validation event center.
- The validation page renders event types from the API and shows validation history.

Verification: `venv/bin/python -m unittest discover` passed with 38 tests.

Why priority: operational systems need repeatable validation without requiring users to create real security problems on their machines.

### 11. Add Seeded Operational Playbooks

Status: Complete.

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

Implementation:

- Eight `source = seeded` operational playbook definitions are inserted idempotently with stable keys, descriptions, kinds, structured triggers, recommended action keys, required approval roles, canonical YAML steps, versions, and definition digests.
- Startup preserves administrator edits and only inserts missing seed definitions.
- Create, update, enable, and disable writes validate trigger JSON and allowlisted declarative YAML before persistence.
- Invalid writes return `400` and write sanitized `playbook.write_rejected` audit events with request digests, not raw YAML.
- Persisted matching returns enabled definitions from `trigger_json`; #11 does not execute actions.

Verification: `venv/bin/python -m unittest tests.test_seeded_operational_playbooks` passed.

Why priority: playbooks are central to SAAOE's operational identity.

### 12. Connect Validation Events to Playbooks

Status: Complete.

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

Implementation:

- Live and controlled anomalies use the shared persisted matcher.
- Playbook run creation is idempotent by anomaly and playbook definition and snapshots stable key, name, kind, version, digest, action, approval role, and YAML steps.
- Validation events stop at ingestion, incident creation, recommendation, and run creation; they never request, approve, consume, or execute response actions.
- Anomaly and incident detail payloads expose persisted recommendations and immutable run snapshots.
- Report summaries include scoped incident reconstruction with controlled-validation provenance, playbook runs, approvals, and closure state.
- `quarantine_file` and `block_ip` execution remains unavailable in Phase 4.

Verification: `venv/bin/python -m unittest tests.test_validation_event_center` passed.

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

Implementation:

- Added `scripts/setup_saaoe.py` as a standard-library bootstrapper that creates `venv/`, installs pinned requirements, and delegates to the shared operations CLI.
- Added `web.saaoe_cli` with `setup`, `bootstrap-admin`, `start`, `stop`, `status`, `health`, and `run --foreground`.
- Added PID, process creation time, and command identity validation before lifecycle stop can terminate a process.
- Added a minimal `/healthz` endpoint and CLI health checks for configuration, schema, telemetry sampler, protected page/API behavior, application identity, and live reachability.
- Added Waitress foreground serving, systemd example packaging, wrapper delegation, CI, and startup tests.
- Preserved Phase 3-4 response safety: `quarantine_file` and `block_ip` remain unavailable and fail closed.

Status: Complete. Merged to `main` in PR #2 as `75805a6`.

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

Implementation:

- Consolidated response-action registry metadata and added executable contract cases.
- Enforced request roles, approval floors, execution roles, disabled-action state, and supported platforms before adapter calls or approval consumption.
- Added transactional, idempotent playbook migration backfill for registry approval floors while preserving historical run snapshots.
- Added exact public-endpoint inventory tests, anonymous protected-route coverage, invalid rule-body/input coverage, rejected-write auditing, exception sanitization, redirect hardening, and CodeQL regression tests.
- Updated CI action versions and preserved the documented `python -m unittest discover` command.

Status: Complete. Merged to `main` in PR #3 as `87c4270`.

Manual sign-off status:

- Completed: anonymous route protection.
- Completed: viewer restrictions and audit logging.
- Completed: analyst access and request restrictions.
- Completed: separate-admin approval.
- Completed: safe dry-run execution.
- Completed: single-use and replay protection.
- Completed: sanitized approval audit trail.
- Blocked: P1 broken Anomalies page requires fix and retest before full manual sign-off.
- Remaining: manually test invalid automation and anomaly-rule writes, verifying rejection, no mutation, and audit entries.
- Remaining: verify cross-workspace isolation with Acme and Northstar accounts.
- Remaining: safely verify disabled and unsupported response actions fail closed.
- Remaining: run final health check and audit review.

Why priority: once SAAOE controls local machine actions, tests become a safety requirement.
