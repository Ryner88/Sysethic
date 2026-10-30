# First production off-host upload: bundle only

This procedure supersedes the configuration-inclusive example for this upload.
Do not read, source, seal or upload `/opt/saaoe/.env`. Do not include any
`--secret-file` or `--public-file`. No automatic upload or scheduling is enabled.

The bucket `sysethic-recovery`, disposable B2 readback and Windows age decryption
are operator-reported verified. This specific production bundle has not yet been
uploaded or independently retrieved. Bucket name alone does not identify its
bucket ID or key restrictions.

## Atlas operator: one guarded manual run

Review `scripts/saaoe_first_offhost_upload.sh` and its helper scripts first.
Then run from the authenticated terminal:

```bash
cd /home/atlas/apps/Sysethic
sudo bash scripts/saaoe_first_offhost_upload.sh
```

The script stops on failed checks. It verifies the existing bundle using the
root-owned helper, anchors its manifest and both artifact hashes, checks release
entries against the reviewed allowlist and rejects private-key markers. It
never enumerates untracked production files or opens production `.env`.
Database records are neither queried nor printed; SQLite integrity/schema checks
use a disposable copy of the snapshot.

Prompts require bucket ID, verified public recipient path (default
`/home/atlas/recipient.txt`), explicit confirmation against the independently
verified public recipient, and hidden **uploader** key credentials. Enter only
the public recipient file; private identity files stay on Windows/off Atlas.
The key must be bucket-scoped with exact capabilities `writeFiles`, `readFiles`,
`listBuckets` and exact authorized prefix `production/`. The destination is the narrower
`production/backups/`. A key restricted to the old
`sysethic/` prefix is rejected; obtain an appropriately scoped key off Atlas.

Required sudo actions: verify as saaoe, inspect private bundle metadata as saaoe,
install the root-owned off-host helper if absent, create restricted off-host
storage if absent, and run sealing/upload as saaoe with temporary credential
environment forwarding. Existing paths must match expected ownership/modes and
helper contents; they are not overwritten on mismatch. No systemd definitions
or production services are changed. Credential input is not echoed; do not use
shell tracing or paste credentials into chat. Private identity and recovery keys
must never be transferred to Atlas.

Encrypted content is exactly the four bundle artifacts, encrypted
`inventory.json`, and matching qualification evidence. It excludes production
configuration, environment files, private keys, virtual environments and
untracked files. The snapshot itself intentionally contains confidential
application data and must remain encrypted in transit/off-host and private when
restored. Filename inspection cannot prove the absence of every possible secret
literal embedded in approved source; the archive is anchored to the already
reviewed release and also checked for private-key markers.

On success, preserve the printed package path, ciphertext SHA-256/size, object
name, ciphertext and completion file IDs, receipt path and receipt SHA-256.
The object will be:

`b2://sysethic-recovery/production/backups/<package-id>/<attempt-id>/recovery.tar.gz.age`

No exact object name/hash exists until that run succeeds. B2 upload
acknowledgement checks bucket/name/length/SHA-1; complete readback checks SHA-256
and size. A completion marker is uploaded last and independently read back.
Failed uploads may leave incomplete objects but do not create a success receipt.
Never treat an incomplete object as a recovery point.

Rechecks require original bundle integrity, unchanged application PID/restarts,
active production service, disabled/inactive timer and public HTTPS success.
Record the dated output privately. If any post-upload check fails, preserve the
receipt/object for diagnosis but do not declare qualification complete.

## Transfer nonsecret receipt to Windows

Replace PACKAGE_PATH with the exact successful path; do not guess or select
`.pending-*`. Stage only the metadata receipt for authenticated transfer:

```bash
sudo bash <<'SH'
set -eu
test ! -e /home/atlas/sysethic-first-upload-receipt
test ! -L /home/atlas/sysethic-first-upload-receipt
install -d -o atlas -g atlas -m 700 /home/atlas/sysethic-first-upload-receipt
install -o atlas -g atlas -m 600 PACKAGE_PATH/upload-receipt.json /home/atlas/sysethic-first-upload-receipt/receipt.json
SH
```

Independently retain the receipt hash displayed by the successful upload, outside
Atlas and B2, before retrieval. The receipt is a trusted hash anchor, not a
publisher signature. Transfer reviewed `saaoe_windows_verify.py` and
`saaoe_recovery.py` separately from the repository, not from an unverified
recovered release. Verify their transfer hashes against the reviewed originals.

## Windows PowerShell 7: private recovery directory

Run on the independently verified Windows recovery machine with reviewed age
and Python >=3.11. Keep the private age identity and B2 read-only recovery key
there. Use an encrypted Windows volume and a new private directory. Replace
ATLAS_SSH_HOST and RECEIPT_SHA256 with authenticated/independently retained values.
Do not use PowerShell transcription or print API/credential objects.

```powershell
$ErrorActionPreference = 'Stop'
$work = Join-Path $HOME 'SysEthic-first-recovery'
if (Test-Path $work) { throw 'Use a new recovery directory' }
New-Item -ItemType Directory -Path $work | Out-Null
$who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls $work /inheritance:r /grant:r "${who}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Private ACL setup failed' }
Set-Location $work
& scp 'atlas@ATLAS_SSH_HOST:/home/atlas/sysethic-first-upload-receipt/receipt.json' '.\receipt.json'
if ($LASTEXITCODE -ne 0) { throw 'Receipt transfer failed' }
$receiptHash = 'RECEIPT_SHA256'
if ((Get-FileHash '.\receipt.json' -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receiptHash) { throw 'Receipt anchor mismatch' }
$r = Get-Content '.\receipt.json' -Raw | ConvertFrom-Json
if ($r.configuration_included -or -not $r.object_name.StartsWith('production/backups/', [StringComparison]::Ordinal)) { throw 'Wrong upload scope' }
```

## Windows: download exact object versions and independently verify

Use the separately held read-only recovery key scoped to the same bucket and
prefix with exact capabilities `readFiles`, `listBuckets`. Never use a master
key. The following follows the official
[B2 download-by-ID](https://www.backblaze.com/apidocs/b2-download-file-by-id)
and [file metadata](https://www.backblaze.com/apidocs/b2-get-file-info) APIs.

```powershell
function Assert-B2Endpoint([string]$value) {
    $u = [Uri]$value
    if ($u.Scheme -cne 'https' -or -not $u.Host.EndsWith('.backblazeb2.com') -or $u.UserInfo -or $u.Port -ne 443) { throw 'Untrusted B2 endpoint' }
}
$idSecure = Read-Host 'Recovery key ID' -AsSecureString
$keySecure = Read-Host 'Recovery application key' -AsSecureString
try {
    $id = [Net.NetworkCredential]::new('unused', $idSecure).Password
    $key = [Net.NetworkCredential]::new('unused', $keySecure).Password
    $basic = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($id + ':' + $key))
    $auth = Invoke-RestMethod -Uri 'https://api.backblazeb2.com/b2api/v4/b2_authorize_account' -Headers @{Authorization=('Basic ' + $basic)} -TimeoutSec 120 -MaximumRedirection 0
    $storage = $auth.apiInfo.storageApi
    Assert-B2Endpoint $storage.apiUrl
    Assert-B2Endpoint $storage.downloadUrl
    $allowed = $storage.allowed
    $caps = @($allowed.capabilities | Sort-Object) -join ','
    if (@($allowed.buckets).Count -ne 1 -or $allowed.buckets[0].id -cne $r.bucket_id -or $allowed.namePrefix -cne 'production/' -or $caps -cne 'listBuckets,readFiles') { throw 'Recovery key scope mismatch' }
    $headers = @{Authorization=$auth.authorizationToken}
    $body = @{accountId=$auth.accountId; bucketId=$r.bucket_id} | ConvertTo-Json -Compress
    $buckets = Invoke-RestMethod -Method Post -Uri ($storage.apiUrl + '/b2api/v2/b2_list_buckets') -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 120 -MaximumRedirection 0
    if (@($buckets.buckets).Count -ne 1 -or $buckets.buckets[0].bucketType -cne 'allPrivate' -or $buckets.buckets[0].bucketName -cne 'sysethic-recovery') { throw 'Private production bucket mismatch' }
    $metadata = Invoke-RestMethod -Method Post -Uri ($storage.apiUrl + '/b2api/v2/b2_get_file_info') -Headers $headers -ContentType 'application/json' -Body (@{fileId=$r.ciphertext_file_id} | ConvertTo-Json -Compress) -TimeoutSec 120 -MaximumRedirection 0
    if ($metadata.fileId -cne $r.ciphertext_file_id -or $metadata.bucketId -cne $r.bucket_id -or $metadata.fileName -cne $r.object_name -or $metadata.contentLength -ne $r.ciphertext_bytes) { throw 'Remote metadata mismatch' }
    foreach ($item in @(@($r.completion_file_id,'complete.json'), @($r.ciphertext_file_id,'recovery.tar.gz.age'))) {
        if (Test-Path $item[1]) { throw 'Do not overwrite a previous download' }
        $url = $storage.downloadUrl + '/b2api/v2/b2_download_file_by_id?fileId=' + [Uri]::EscapeDataString($item[0])
        Invoke-WebRequest -Uri $url -Headers $headers -OutFile $item[1] -TimeoutSec 120 -MaximumRedirection 0
    }
    if ((Get-FileHash '.\complete.json' -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.completion_sha256) { throw 'Completion checksum mismatch' }
    if ((Get-FileHash '.\recovery.tar.gz.age' -Algorithm SHA256).Hash.ToLowerInvariant() -cne $r.ciphertext_sha256 -or (Get-Item '.\recovery.tar.gz.age').Length -ne $r.ciphertext_bytes) { throw 'Ciphertext checksum/size mismatch' }
    if ((Get-FileHash '.\recovery.tar.gz.age' -Algorithm SHA1).Hash.ToLowerInvariant() -cne $metadata.contentSha1) { throw 'Provider checksum mismatch' }
    Write-Output 'Exact-version metadata, completion marker and ciphertext checks passed'
} catch {
    throw 'STOP: B2 recovery verification failed; do not decrypt or promote these files'
} finally {
    Remove-Variable id,key,basic,auth,headers,idSecure,keySecure -ErrorAction SilentlyContinue
}
```

Do not dump a caught API error or auth object; those may contain tokens. Retain
receipt SHA-256, ciphertext SHA-256, file IDs and dated success evidence only.

## Windows: decrypt to a file, never to the console, and check contents

Transfer the separately reviewed verifier and recovery helper into the private
`tools` directory; verify the recorded source hashes before execution:

```powershell
New-Item -ItemType Directory -Path '.\tools' | Out-Null
& scp 'atlas@ATLAS_SSH_HOST:/home/atlas/apps/Sysethic/scripts/saaoe_windows_verify.py' '.\tools\saaoe_windows_verify.py'
if ($LASTEXITCODE -ne 0) { throw 'Verifier transfer failed' }
& scp 'atlas@ATLAS_SSH_HOST:/home/atlas/apps/Sysethic/scripts/saaoe_recovery.py' '.\tools\saaoe_recovery.py'
if ($LASTEXITCODE -ne 0) { throw 'Helper transfer failed' }
if ((Get-FileHash '.\tools\saaoe_windows_verify.py' -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'a373d5ed0c955964e8ec33b2c8782330f3a5847aee189d88371bc9588245eaf3') { throw 'Verifier hash mismatch' }
if ((Get-FileHash '.\tools\saaoe_recovery.py' -Algorithm SHA256).Hash.ToLowerInvariant() -cne '78af78eaadbbe22fbb57d106c69492af66b3026b588c7913e30ba3306b001ae7') { throw 'Helper hash mismatch' }
```
 Substitute the existing OFF_ATLAS_IDENTITY
path. Neither command below prints application records or environment values.
Do not use PowerShell binary stdout redirection for the decrypted archive.

```powershell
if (Test-Path '.\recovery.tar.gz') { throw 'Plaintext output already exists' }
& age --decrypt --identity 'OFF_ATLAS_IDENTITY' --output '.\recovery.tar.gz' '.\recovery.tar.gz.age' 2>$null
if ($LASTEXITCODE -ne 0) { throw 'STOP: authenticated age decryption failed' }
& python '.\tools\saaoe_windows_verify.py' --archive '.\recovery.tar.gz' --receipt '.\receipt.json' --receipt-sha256 $receiptHash --output '.\verified'
if ($LASTEXITCODE -ne 0) { throw 'STOP: recovered archive verification failed' }
Remove-Item '.\recovery.tar.gz'
```

The verifier rejects configuration entries, unsafe paths/links, duplicate or
missing members, changed inventories, evidence mismatch, wrong original
manifest, release hashes, SQLite integrity and schema mismatch. It publishes a
new `verified` directory only after checks pass; it never invokes recovered
application code. A failure removes staging and does not publish success. On
Windows, confidentiality is provided by the inherited private NTFS ACLs above;
Unix modes alone are not sufficient. Verify ACLs before handling plaintext.
Keep `verified/windows-verification.json` and receipt/hash evidence privately.
Deletion is not secure erasure; decrypted data belongs on encrypted storage.

This proves retrieval, decryption and bundle consistency, not full Linux
application execution on Windows. Operational recovery still requires isolated
Linux dependency/application tests, protected configuration recovery (excluded
from this upload), retrieval using separately retained keys, approved retention,
measured RTO and authorized acceptance of data loss since the snapshot.


## Preparation evidence: 2026-10-11 UTC

Fifty applicable disposable tests passed with zero skips, including production
prefix enforcement and portable Windows verifier success/failure cases. Real
age v1.3.2 encryption was exercised in the suite; a separate disposable smoke
check also passed using Atlas's installed age 1.1.1 and a public recipient only.
No private identity was generated or used on Atlas. Shell syntax passed; actual
PowerShell/NTFS execution awaits the Windows operator (PowerShell is unavailable
on Atlas). Production remained active with PID 3429, zero restarts and HTTPS
200/phase5.13; the backup timer remained disabled/inactive.

Preparation could not freshly inspect the private production bundle or seal it
because noninteractive sudo requires the operator's password. The guarded
terminal command performs those checks before any upload. No production
ciphertext, object location or new integrity result is claimed until it runs.


## Prefix validation correction (local review only; no retry)

The reported `bucket_and_prefix_required` was emitted by the old constructor
before credential access. Bucket ID `8e1fa189581d278ca2150e1b` and destination
`production/backups/` pass that syntax check. The message alone cannot identify
what the failed invocation actually received. A bucket name with a hyphen,
empty input, whitespace/CR, or a missing trailing slash can fail it. The shell
uses quoted positional arguments and `IFS= read -r`, preserving whitespace.
Bucket/prefix values are not taken from credential environment variables.

A separate local fix adds `--key-prefix production/` while retaining
`--prefix production/backups/`. It verifies the exact returned authorized prefix
and rejects a destination outside it; capabilities and bucket restrictions are
unchanged. Errors now identify the malformed argument without echoing values.
The constructor takes a bucket ID only. The operator wrapper also verifies the
bucket name independently through B2 metadata. Do not deploy or retry yet.

Correct future CLI invocation (PACKAGE_PATH must be the verified sealed package;
credentials must already be entered privately by the authenticated operator):

```bash
/usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_offhost.py upload \
  --package PACKAGE_PATH \
  --bucket-id 8e1fa189581d278ca2150e1b \
  --key-prefix production/ \
  --prefix production/backups/
```

This requires the reviewed local fix to be installed first. The old installed
CLI does not recognize `--key-prefix`. The first-upload wrapper now passes the
same separate prefixes, and will stop on installed-helper mismatch until that
installation is reviewed. No permission changes on Backblaze are needed.
