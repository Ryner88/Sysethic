# Manual Test: Standardize Severity, Status, and Risk Labels

## Goal

Verify that Phase 2 item 6 uses shared severity, status, and risk vocabulary across API payloads, UI pages, and report output.

## Test Method

1. Started the app through Flask's test client with an isolated SQLite database:
   `/tmp/saaoe-vocabulary-manual.sqlite3`
2. Created a first-run workspace admin session.
3. Queried `/api/vocabulary` to confirm the canonical severity and status values.
4. Created a controlled validation event through `/api/validation_events`.
5. Queried anomalies, incident detail, security alerts, audit logs, and CSV reports.
6. Loaded Dashboard, Security, Anomalies, Reports, and Incidents pages and checked that each page includes the shared vocabulary bootstrap and helper.

## Evidence

Captured evidence:

`manual-testing/severity-status-risk-manual-evidence.json`

Key observations:

- Canonical severities were `critical`, `high`, `info`, `low`, and `medium`.
- Canonical statuses were `dismissed`, `failed`, `investigating`, `open`, `resolved`, and `waiting_for_approval`.
- Validation event creation returned lowercase API values plus human labels and CSS classes.
- The validation anomaly returned `critical`, `Critical`, and `severity-critical`.
- The validation anomaly risk returned `critical`, `Critical`, and `severity-critical`.
- The incident detail returned `open`, `Open`, and `status-open`.
- Security alerts and audit rows included shared label/class fields.
- CSV report output used human-readable labels such as `Critical` and `Open`.
- Dashboard, Security, Anomalies, Reports, and Incidents pages all loaded `window.SYSETHIC_VOCABULARY` and `SysEthicVocabulary`.

## Verification

Automated regression coverage also passed:

```bash
venv/bin/python -m unittest tests.test_vocabulary
venv/bin/python -m unittest discover -s tests
```

Results:

- `tests.test_vocabulary`: Ran 3 tests - OK
- Full suite: Ran 21 tests in 132.224s - OK

## Conclusion

Passed.

Severity, status, and risk labels are standardized across the tested API payloads, UI pages, and report output.
