# Manual Test: Harden the Diagnostic Terminal

## Goal

Verify that Phase 3 item 7 keeps diagnostic terminal access admin-only, constrained by explicit command and argument allowlists, timeouts, output limits, and audit logging.

## Test Method

1. Started the app through Flask's test client with an isolated SQLite database:
   `/tmp/saaoe-terminal-manual.sqlite3`
2. Created a first-run workspace admin session.
3. Created a regular viewer account and attempted to grant `access_terminal`.
4. Logged in as the viewer and attempted to open `/terminal`, query `/api/terminal/status`, and run `/api/terminal/run`.
5. Logged in as the admin and queried terminal status metadata.
6. Attempted a disallowed command and a disallowed argument form.
7. Added temporary allowlisted test commands to verify timeout and output truncation behavior.
8. Queried audit logs for terminal attempts, access denials, and permission-change failures.

## Evidence

Captured evidence:

`manual-testing/terminal-hardening-manual-evidence.json`

Key observations:

- Granting terminal access to a non-admin returned `400` with `terminal access is admin-only`.
- The non-admin viewer received `403` from the terminal page, terminal status API, and terminal run API.
- Admin terminal status reported the legacy WebSocket as disabled and exposed only approved command forms.
- `cat /etc/passwd` was rejected because `cat` is not enabled.
- `ps -ax` was rejected because that argument form is not enabled.
- A long-running test command timed out with status `408`.
- A large-output test command returned `truncated: true` and appended `[output truncated]`.
- Terminal audit rows included command details and covered denied, failed, and successful attempts.

## Verification

Automated regression coverage also passed:

```bash
venv/bin/python -m unittest tests.test_terminal_hardening
venv/bin/python -m unittest tests.test_security_workflows
venv/bin/python -m unittest discover -s tests
```

Results:

- `tests.test_terminal_hardening`: Ran 3 tests - OK
- `tests.test_security_workflows`: Ran 6 tests - OK
- Full suite: Ran 24 tests in 104.262s - OK

## Conclusion

Passed.

The diagnostic terminal is admin-only, constrained to explicit command forms, timeout-limited, output-limited, and audited.
