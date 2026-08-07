# Response Approval Contract

## States

Approval requests use these persisted states:

- `pending`: request has been created and is awaiting a decision.
- `approved`: an authorized approver has approved the exact request payload.
- `rejected`: an authorized approver rejected the request.
- `cancelled`: the requester or a workspace admin cancelled the request.
- `expired`: the request passed `expires_at` before approval or consumption.
- `consumed`: an approved request was used once by the execution authorization boundary.

Only `pending` may transition to a decision state: `approved`, `rejected`, `cancelled`, or `expired`.
Only `approved` may transition to `consumed` or `expired`.

## Required Fields

Every request stores `id`, `organization_id`, `action`, `target`, `requested_by`, `requester_role`, `status`, `dry_run`, `created_at`, `updated_at`, `expires_at`, `payload_digest`, `action_type`, and `required_role`.

Every approve, reject, or cancel decision requires `decision_reason`, `approved_by`, `approver_role`, and `decided_at`.

Consumption records `consumed_by`, `consumed_at`, and `executed_at` when the no-op execution boundary completes.

## Roles

- `create_incident_report`: `analyst` or stronger.
- `kill_process`: `admin`.
- `quarantine_file`: `admin`.
- `block_ip`: `admin`.
- `restart_service`: `admin`.

Requesters cannot approve or consume their own approvals.

## Payload Digest

The digest is `sha256` over canonical JSON containing `action`, `target`, `incident_id`, `anomaly_id`, and `dry_run`.
Execution must present the same normalized payload. Any action, target, requester, or digest mismatch is denied before consumption.

## Dry-Run Preview Digest

Dry-run previews are deterministic. They are generated from normalized payload fields and the action contract only; they do not include live process names, file existence, timestamps, adapter state, or other changing host data.

Each request stores `preview_digest = sha256(payload_digest + canonical_preview)`. Execution authorization recomputes the preview and denies consumption if the stored preview digest differs.

## Execution Boundary

`authorizeApprovedAction` validates approval status, expiry, approver role, action type, target, requester, payload digest, and single-use consumption in one SQLite `BEGIN IMMEDIATE` transaction.

Host-impacting actions remain disabled by default for `kill_process`, `quarantine_file`, and `block_ip`. Consuming an approval for those actions records authorization and returns a no-op result without changing the host.

`restart_service` is the first bounded host-impacting action. It does not accept shell commands. It accepts only exact service allowlist keys and currently enables:

- `saaoe-dashboard`: runs fixed argv `systemctl restart saaoe-dashboard.service` with `shell=False` and a 15 second timeout.

The recovery adapter for `saaoe-dashboard` is fixed argv `systemctl start saaoe-dashboard.service`. If restart fails or times out, SAAOE attempts that recovery action, records whether recovery succeeded, and writes the failed execution result to the approval row, incident timeline, and audit log. The consumed approval cannot be replayed after either success or failure.

Every approval audit and incident timeline entry carries `correlation_id = approval:<approval_id>` along with the request, incident, actor, action, target, status, and payload digest fields.

## Operator Diagnostics

`GET /api/response_approvals/<approval_id>` returns an operator reconstruction payload with:

- the stored approval row
- the normalized request payload
- the expected deterministic preview
- payload and preview digest match checks
- correlated audit events
- correlated incident timeline events
- a timestamp-ordered reconstruction across audit and incident sources

## Audit Vocabulary

Normalized approval events use these event types:

- `response_action_requested`
- `response_approval_requested`
- `response_action_approved`
- `response_approval_approved`
- `response_action_rejected`
- `response_approval_rejected`
- `response_action_cancelled`
- `response_approval_cancelled`
- `response_approval_expired`
- `approval_decision_blocked`
- `response_execution_blocked`
- `response_action_started`
- `response_action_succeeded`
- `response_action_failed`
- `response_action_executed`
- `response_approval_failed`
