# Upload retry protocol (source implementation; not deployed)

This repair adds a durable protocol for new packages marked `upload_protocol: 2`.
It does not qualify any production upload, authorize a retry, provision keys,
enable scheduling, or establish the existence of the historical B2 object.

## Intent and locking

Before transmission, `upload-intent.json` records the stable operation ID, exact
ciphertext and completion-marker names, destination, seal SHA-256, encrypted
package SHA-256/size, source machine identity and original manifest/snapshot
fingerprints. The operation ID is derived from that binding; it is never
regenerated on recovery. Changes to source or destination reject the journal.

Upload and reconciliation hold the same nonblocking POSIX `flock` on the
authoritative package's `.upload.lock`. The inode is never unlinked. A process
exit releases the kernel lock. The first-upload wrapper additionally holds an
output-directory lock across inspection, sealing and upload and refuses to seal
another package when a prior bundle package or pending stage exists.

One authoritative local package/journal is required. Do not delete, edit, roll
back, reseal, restore an older journal, or clone it to another upload location or
host to bypass a blocked operation. The local lock is not a distributed lease.

## Per-object transitions

| Durable state | Meaning | Permitted recovery |
| --- | --- | --- |
| `ready` | No transmission has been armed for this object | May send once after durable transition to `pending` |
| `pending` | A request may have been sent; no durable version ID | Never resend; use read-only reconciliation |
| `acknowledged` | The exact immutable remote version ID is durable | Verify metadata and full readback; reuse that version |

Both ciphertext and completion marker follow these transitions. `pending` is
fsynced before each transmission. Version IDs are persisted after acknowledgement.
The exact completion metadata, including its verification timestamp, is durable
before its first transmission, so retries cannot regenerate a different marker.

Each reused version must match the expected ID, bucket, object name, upload
action, length and SHA-1 metadata. Full download by version ID must match the
local SHA-256 and size. A known version that is missing or mismatched is not
replaced. The marker is sent only after ciphertext verification.

Journals are written to private temporary files, fsynced, atomically replaced,
and followed by directory fsync. Receipts use fsynced temporary files and atomic
exclusive publication, followed by directory fsync. A crash before receipt
publication leaves durable remote IDs; recovery reads those IDs without uploading
again. An already published complete receipt can be verified idempotently.

## Separate read-only reconciliation

Existing uploader permissions remain exactly `writeFiles`, `readFiles`,
`listBuckets`. Existing recovery permissions remain `readFiles`, `listBuckets`.
Neither identity is silently broadened.

The new `reconcile` command requires a separately provisioned identity with
exactly `readFiles`, `listFiles`, `listBuckets`, restricted to the same single
private bucket and authorized key prefix. No key is created or changed by this
repair. Enter its credentials privately for that invocation only. The command
performs metadata/readback operations and local journal/receipt publication; it
never uploads, deletes, hides objects, or changes bucket settings.

It queries exact object-name prefixes using
[b2_list_file_versions](https://www.backblaze.com/apidocs/b2-list-file-versions),
not just the latest filename. Multiple versions, hide/start records, unexpected
names, missing pagination fields or incomplete listings fail closed. One matching
version must pass metadata checks and full SHA-256 readback before its ID can be
adopted into the journal. A different version cannot replace a known ID.

**Zero results do not authorize resending a `pending` request:** the original
request might still complete later. Lookup failures and ambiguity likewise leave
it blocked for operator investigation. No automatic retry/reset exists.

If an object was durably `ready` and is absent, reconciliation returns
`ready_to_resume`; it sends nothing. For example, adopting a lost ciphertext
acknowledgement may leave a never-sent marker ready. Continuing that operation
with the uploader remains a separately authorized action. Repeated read-only
reconciliation sends no new objects and preserves a verified receipt's hash.

Known IDs use [b2_get_file_info](https://www.backblaze.com/apidocs/b2-get-file-info)
and download-by-ID, both available with existing `readFiles` permission.

## Legacy evidence and acceptance tests

Packages sealed before this protocol are rejected before creating lock or journal
files: `legacy_package_requires_operator_reconciliation`. The October 10 sealed
package, its ciphertext and original audit log remain untouched. Do not add the
protocol flag manually. Historical remote existence remains **unresolved** as
recorded in [the diagnosis](offhost-endpoint-diagnosis.md). Migration or disposition
requires explicit operator reconciliation and approval; this repair does not
reinterpret the historical failure as proof of absence or success.

Run `python3 -B -m unittest tests.test_offhost_retry` for reproducible isolated
crash-injection tests. In particular,
`test_process_crash_immediately_before_receipt_cannot_upload_again` exits a real
subprocess with `os._exit(73)` immediately before receipt publication. Its fake
remote persists exactly two objects. Recovery verifies and publishes the receipt
with every upload call forbidden, followed by repeated reconciliation with the
same receipt hash and still exactly two objects. It never contacts B2.

Other tests cover pre-send crashes, lost acknowledgements, matching/mismatched
objects, identical duplicate versions, unavailable lookup, uncertain absence,
write-ahead failure, concurrent upload/reconciliation exclusion, directory-sync
failure, corrupt journals, changed bindings, and legacy package preservation.
Endpoint tests verify the read-only identity's exact capabilities and reject
incomplete version listings without widening uploader permissions.

Local validation of the source repair: 75 recovery-related tests passed; the
complete 178-test application suite passed with synthetic process-only settings,
dotenv loading suppressed, and temporary application storage. All 14 portable
B2 endpoint/scope tests passed after the explicit read-only upload guard was
added. Wrapper shell syntax and both embedded Python blocks parsed successfully.
Cross-platform CI and review of this repair remain separate acceptance gates.
