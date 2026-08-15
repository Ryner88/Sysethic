# Fixed Work

## Phase 1: Operational Foundation

Status: Complete

Completed items:

- 1. Add Authentication and Local User Access Control
- 2. Add Durable Storage
- 3. Add Safe Configuration Defaults

Evidence:

- Authentication, session, role, and permission enforcement are implemented and covered by security workflow tests.
- Durable SQLite storage is implemented for users, audit logs, anomalies, incidents, playbooks, playbook runs, automation rules, response approvals, file classifications, report history, and app configuration.
- Safe configuration defaults are implemented with `.env` support, a config loader, safe local bind defaults, debug disabled by default, secret-key validation, configurable paths, configurable thresholds, and startup summary output.

Relevant commits:

- `7e0abd4` Complete phase 1 workspace permission enforcement
- `0a411ab` 1.2. Add Durable Storage
- `d5f7636` Add safe configuration defaults
- `163afdf` Document and test auth access-control playbooks

Verification:

```bash
venv/bin/python -m unittest tests.test_security_workflows
venv/bin/python -m unittest tests.test_durable_storage tests.test_config
```

Result: all tests passed.

## Phase 2: Evidence and Workflow

### 4. Normalize Audit Logging — Complete

Implemented durable normalized audit records for user, system, workflow, security, and response events. Added centralized `audit_event` helper, protected mutation fallback auditing, `/api/audit` filtering, failure/denial coverage, structured details JSON, and persistence tests.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 12 tests in 48.643s - OK

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

Result: Ran 14 tests in 60.559s - OK

### 6. Standardize Severity, Status, and Risk Labels — Complete

Implemented shared severity, status, and risk vocabulary across API payloads, UI badges, reports, legacy data backfill, and frontend helpers. Added `/api/vocabulary`, stable lowercase API values, human-readable labels, consistent CSS classes, and manual Phase 2 verification evidence.

Acceptance verified:

- Dashboard, Security, Anomalies, Reports, and Incident views use shared labels and badge classes.
- API payloads use stable lowercase values for severity and status.
- Reports use the same severity and status vocabulary as the app.
- Manual tests cover audit logging, incident workflow, and vocabulary standardization.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 21 tests in 105.451s - OK

## Phase 3: Controlled Operations

### 7. Harden the Diagnostic Terminal — Complete

Implemented admin-only diagnostic terminal access, explicit command and argument allowlists, disabled legacy WebSocket startup, timeout enforcement, output truncation, and audit logging for allowed, denied, failed, and timed-out command attempts.

Acceptance verified:

- Non-admin users cannot open or use terminal routes.
- Commands and argument forms outside the allowlist are rejected and audited.
- Long-running commands are terminated.
- Large command output is truncated safely.
- Every command attempt records actor, command, result, and timestamp.

Verification:

```bash
venv/bin/python -m unittest discover -s tests
```

Result: Ran 24 tests in 104.262s - OK

### 8. Add Manual Approval for Risky Actions — Complete

Implemented the durable response approval contract for risky actions. Requests now store requester and approver roles, decision reasons, expiration, canonical payload digests, deterministic preview digests, action type, required role, and single-use consumption metadata. Approval decisions and execution authorization are written to audit history and incident timelines with `correlation_id = approval:<approval_id>`.

Acceptance verified:

- Requests require supported actions and validated targets.
- Approve, reject, cancel, expire, and consume transitions are bounded.
- Requesters cannot approve or consume their own approvals.
- Rejected, expired, replayed, and digest-mismatched requests cannot execute.
- Host-impacting `kill_process`, `quarantine_file`, and `block_ip` remain authorization-only no-ops until bounded adapters exist.

Relevant commit:

- `70e5c01` Add approval contract foundation

Verification:

```bash
venv/bin/python -m unittest tests.test_response_approval_contract
```

Result: Ran 8 tests - OK

### 9. Add First Bounded Approved Execution Path — Complete

Implemented `restart_service` as the first real host-impacting execution path connected to the approval contract. The only enabled target is `saaoe-dashboard`; execution uses fixed argv `systemctl restart saaoe-dashboard.service` with `shell=False`, a 15 second timeout, single-use approval consumption, audit/timeline result recording, and fixed recovery via `systemctl start saaoe-dashboard.service`.

Acceptance verified:

- Only approved, unexpired, digest-matching requests execute.
- No arbitrary shell-command support exists in the approval execution path.
- Target allowlist, timeout, idempotency, and single-use approval consumption are enforced.
- Success, failure, and recovery metadata are recorded in audit logs and incident timelines.
- Tests cover rejection, expiry, replay, digest mismatch, concurrency, and execution failure.

Relevant commit:

- `831f1dc` Add bounded approved service restart execution

Verification:

```bash
venv/bin/python -m unittest discover tests
```

Result: Ran 37 tests in 111.192s - OK

Phase 3 status: Complete.

Phase 4 handoff: start with Phase 4 #10, Controlled Validation Event Center, using the completed approval and bounded-execution path as the safety boundary for validation workflows.

### Phase 4 #10: Controlled Validation Event Center

Started the Controlled Validation Event Center with safe CPU pressure, memory pressure, suspicious network, and sensitive-file validation events. Each event is a clearly labeled controlled validation input that creates a normal anomaly, opens an incident through the same incident creation path, records matching playbook runs, and writes validation-specific audit and incident timeline events.

Safety boundary:

- Validation events do not execute dangerous host changes.
- Approval-contract actions remain approval-gated and are recorded as waiting for approval.
- Existing bounded execution safeguards are reused; no broader host-impacting adapters were added.

Relevant commit:

- `10c3b7c` Add controlled validation event center

Verification:

```bash
venv/bin/python -m unittest tests.test_validation_event_center
venv/bin/python -m unittest tests.test_response_approval_contract
venv/bin/python -m unittest tests.test_security_workflows
venv/bin/python -m unittest discover
```

Result: Ran 38 tests in 126.587s - OK

### Phase 4 #11: Seeded Operational Playbooks

Implemented persisted operational playbook definitions with stable keys, structured triggers, recommended action keys, required approval roles, canonical declarative YAML steps, versions, definition digests, source labels, and actor/timestamp metadata. Added eight idempotent `source = seeded` operational definitions and retained authentication/access-control definitions as `source = system` compatibility playbooks.

Safety boundary:

- Playbook YAML is declarative and allowlisted.
- Playbooks recommend and coordinate action requests; they do not execute host commands.
- Invalid writes are rejected with sanitized audit records.

Relevant commit:

- `89eb5e1` Add persisted operational playbook workflow

### Phase 4 #12: Shared Validation-to-Playbook Integration

Replaced the #10 transitional validation mapping with shared persisted matching and idempotent playbook run creation. Live and controlled anomalies use the same matcher, playbook runs snapshot definition metadata, and anomaly/incident/report payloads expose recommendation provenance without rewriting history after definition edits.

Safety boundary:

- Validation events stop at ingestion, incident creation, recommendation, and run creation.
- Validation events do not request, approve, consume, or execute response actions.
- `quarantine_file` and `block_ip` execution remains unavailable in Phase 4.

Verification:

```bash
venv/bin/python -m unittest tests.test_seeded_operational_playbooks
venv/bin/python -m unittest tests.test_validation_event_center
venv/bin/python -m unittest discover
```

Result: Ran 42 tests in 118.072s - OK

### Phase 5 #13: Installation and Startup Packaging

Implemented local packaging and lifecycle operations around one shared Python CLI.

Added:

- `scripts/setup_saaoe.py` standard-library bootstrapper.
- `web/saaoe_cli.py` with `setup`, `bootstrap-admin`, `start`, `stop`, `status`, `health`, and `run --foreground`.
- Minimal `/healthz` and `create_app(config_overrides=None)` entry point.
- Waitress production serving for foreground and background starts.
- PID-reuse-safe runtime metadata under `instance/runtime/`.
- Shell and PowerShell wrapper delegation.
- `packaging/systemd/saaoe.service.example`.
- `.github/workflows/tests.yml`.
- `tests/test_installation_startup.py`.
- Expanded `docs/operational-startup.md`.

Safety boundary:

- Packaging does not enable public exposure.
- Packaging does not add MSI/DMG installers or container orchestration.
- `quarantine_file` and `block_ip` execution remain unavailable and fail closed.
- Health output is intentionally minimal and does not expose secrets, paths, usernames, environment values, or telemetry details.

### Phase 5 #14: Security-Critical Test Coverage

Implemented the security coverage milestone around the response-action registry, route authentication inventory, rule validation, exception sanitization, and CodeQL remediation.

Added:

- Registry metadata and executable contract cases for enabled response actions.
- Request-role, approval-role, execution-role, platform, disabled-action, and adapter-call enforcement.
- Playbook migration backfill that reapplies registry approval floors transactionally and idempotently while preserving historical run snapshots.
- Authentication inventory tests with an exact public-endpoint allowlist.
- Rule validation tests for malformed request bodies, unsupported fields/operators/actions, invalid severities, non-finite thresholds, malformed delete IDs, rejected-write auditing, and positive valid anomaly-rule creation.
- Regression coverage for debug-mode startup, local redirect validation, JSON-shaped exception sanitization, and raw exception suppression.
- CI updates using current checkout, setup-python, and CodeQL actions across Linux, macOS, and Windows.

Closeout:

- PR #2 merged Phase 5 #13 as `75805a6`.
- PR #3 merged Phase 5 #14 as `87c4270` from head `0398b03`.
- `quarantine_file` and `block_ip` remain registered but disabled and fail closed.
- Public exposure, MSI/DMG installers, and container orchestration remain out of scope for Phase 5.
