# Manual Test: Normalize Audit Logging

## Goal

Verify that Phase 2 item 4 writes normalized, filterable, durable audit records for user, system, workflow, security, and response events.

## Test Method

1. Started the app through Flask's test client with an isolated SQLite database:
   `/tmp/saaoe-audit-manual.sqlite3`
2. Created a first-run workspace admin session.
3. Generated failure and denial audit events through unsupported validation, unsupported approval, bad playbook creation, and premature response execution.
4. Generated a successful validation event to create an anomaly, incident, and alert audit event.
5. Queried `/api/audit_events` and `/api/audit` with actor, event type, result, and future time filters.
6. Reloaded app state and logged in with a fresh test client to verify audit records persisted after restart.

## Evidence

Captured evidence:

`manual-testing/audit-logging-manual-evidence.json`

Key observations:

- Unsupported validation and approval requests returned `400` and wrote failed audit records.
- Premature response execution returned `409` and wrote a denied `response_action_started` audit record.
- The filtered denied response-action row included normalized fields: actor, role, event type, target type, target ID, result, source, detail, details JSON, structured details, action, outcome, resource, and details.
- Alert-generated audit records used target type `anomaly` and validation anomaly target IDs.
- Future time filtering returned no rows.
- Alert audit records persisted after reloading app state and logging in with a fresh test client.

## Verification

Automated regression coverage also passed:

```bash
venv/bin/python -m unittest tests.test_audit_logging
venv/bin/python -m unittest discover -s tests
```

Results:

- `tests.test_audit_logging`: Ran 1 test - OK
- Full suite: Ran 21 tests - OK

## Conclusion

Passed.

Normalized audit logging is filterable, durable, and covers the tested success, failure, and denial paths.
