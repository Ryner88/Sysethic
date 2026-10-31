# Off-host endpoint diagnosis: 2026-10-31

Production upload/readback qualification remains incomplete. No deployment or
retry is authorized by this record.

The operator's metadata-only diagnostic returned the current upload hostname
`pod-050-1045-06.backblaze.com`, rejected by the installed validator, with zero
upload requests transmitted. Backblaze documents numeric `pod-N-N-N.backblaze.com`
upload hosts: https://www.backblaze.com/apidocs/b2-get-upload-url.

An isolated reproduction confirms `B2.upload -> valid_url(uploadUrl)` rejects
that host before opening the payload or transmitting an upload. This establishes
the compatibility defect, not the exact historical hostname or rejection stage.
The original attempt did not record its endpoint or a successful remote receipt.

Historical remote object existence: **unresolved**. The verified restricted key
has exactly `writeFiles`, `readFiles`, `listBuckets`; it lacks `listFiles`. No
listing was attempted, no permissions were broadened, and no object was deleted.
Read access by ID cannot locate an unknown object ID. Reconciliation requires
separately available read-only listing access or console inspection.

Preserve unchanged:

- Log: `/home/atlas/sysethic-first-upload-q6fTjYoW.log`
- Log SHA-256: `7821cf63a9d89c1b6094f43e22a5a5bdec459686671214c8722930c1144726a7`
- Package: `/var/lib/saaoe-offhost/20261010T010740Z-a79bb5cc-aca68208acb6461e90c2c514a43902dd`
- Ciphertext size: 125361 bytes (original upload-attempt output)
- Ciphertext SHA-256: `14c55dae56260e83060484148bf9aa6ed0cd3ffbefdda7941386265ee1d644dc`

The source patch adds only the documented numeric pod host pattern alongside
existing valid Backblaze B2 hosts. It rejects malformed DNS labels, whitespace,
control characters, malformed ports, URL credentials, non-HTTPS schemes, and
nonstandard ports. Redirect handling remains unchanged and rejects redirects.
Bucket/capability/prefix checks, encryption, upload ordering, checksums, readback,
and receipt handling are unchanged.

Validation: `python3 -B -m unittest tests.test_offhost_recovery` (30 tests passed,
zero skips). Regression cases cover documented/live pod hosts, existing API and
download hosts, lookalikes, unsafe URLs, redirect rejection, and continued upload
acknowledgement integrity enforcement using synthetic fixtures only.

The installed helper remains unchanged. The timer remains disabled/inactive.
A future deployment and controlled upload each require explicit authorization.
