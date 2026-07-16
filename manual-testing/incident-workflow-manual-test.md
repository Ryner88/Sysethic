# Manual Test: Create a Real Incident Workflow

## Goal

Verify that Phase 2 item 5 supports a durable incident workflow with assignment, status updates, notes, approvals, response execution, terminal timeline context, close/reopen actions, audit records, and restart persistence.

## Test Method

1. Started the app through Flask's test client with an isolated SQLite database:
   `/tmp/saaoe-incident-manual.sqlite3`
2. Created a first-run workspace admin session.
3. Created a controlled CPU-pressure validation event, producing a critical anomaly and incident.
4. Assigned the incident, changed status to investigating, and added a triage note.
5. Requested, approved, and executed a dry-run incident report response approval.
6. Ran an allowed terminal diagnostic command linked to the incident.
7. Closed and reopened the incident.
8. Queried incident detail, timeline, and audit records.
9. Reloaded app state and logged in with a fresh test client to verify the reopened incident and note persisted.

## Evidence

Captured evidence:

`manual-testing/incident-workflow-manual-evidence.json`

Key observations:

- Validation event creation returned `200` and produced an incident ID and linked anomaly ID.
- Assignment, status update, note creation, approval request, approval, execution, terminal command, close, and reopen routes all returned successful responses.
- Closing set status to `resolved` and populated `closed_at`.
- Reopening set status back to `open` and cleared `closed_at`.
- Incident detail included the linked anomaly, recommended playbook, and manual triage note.
- Timeline included linked anomaly, playbook recommendation, approval request, successful response action, terminal command, note, status update, assignment update, close, and reopen events.
- Incident update, close, and reopen audit records were present.
- After reloading app state, the incident remained open and the manual note was still present.

## Verification

Automated regression coverage also passed:

```bash
venv/bin/python -m unittest tests.test_incident_workflow
venv/bin/python -m unittest discover -s tests
```

Results:

- `tests.test_incident_workflow`: Ran 2 tests - OK
- Full suite: Ran 21 tests - OK

## Conclusion

Passed.

The incident workflow is durable, auditable, and supports the tested investigation lifecycle end to end.
