# Manual Test: Add Durable Storage

## Goal

Verify that SAAOE stores operational data persistently and does not lose records after application activity or restart.

## Storage Target

SAAOE stores operational data in:

`data/saaoe.sqlite3`

## Test Method

1. Captured baseline SQLite table counts before creating new app activity.
2. Used the running SAAOE web app to generate audit activity.
3. Captured SQLite table counts again after the new activity.
4. Restarted the application.
5. Captured SQLite table counts again after restart.
6. Queried the latest audit records to confirm persisted records were still available.

## Evidence

Baseline snapshot:

`manual-testing/durable-storage-before.txt`

After app activity:

`manual-testing/durable-storage-after-create.txt`

After restart:

`manual-testing/durable-storage-after-restart.txt`

Latest audit evidence:

`manual-testing/durable-storage-audit-evidence.txt`

## Results

Before testing, `audit_events` contained 280 records.

After app activity, `audit_events` increased to 282 records.

After restarting the app, `audit_events` increased to 285 records instead of resetting.

A later audit query showed records continuing up to ID 289, including persisted login, logout, playbook creation, and access-denied audit events.

## Conclusion

Passed.

Durable storage is working. SAAOE persisted audit records in SQLite across app activity and restart. The database continued appending records instead of losing or resetting existing data.
