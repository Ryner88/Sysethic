# Phase 2: manual encrypted Backblaze B2 recovery

Status: implementation and disposable tests only. No bucket, keys, upload,
production configuration recovery or independent-host decryption has been
qualified. Do not deploy these commands during review. Keep
`saaoe-backup.timer` disabled; no automatic uploader is supplied.

## Trust and limits

`saaoe_offhost.py` streams a validated bundle, optional configuration and
qualification evidence directly into age. No plaintext configuration archive
is created on Atlas. All encrypted inputs are hashed before and after sealing.
Native X25519 `age1...` recipients only; plugins, SSH and private-key recipients
are rejected. A recipient must be generated and independently confirmed outside
Atlas. Private identity files and B2 recovery/admin keys never belong on Atlas.
The uploader key is the sole credential permitted temporarily on Atlas.

The receipt SHA-256 must be retained through an independent trusted channel
outside Atlas. It anchors the ciphertext, completion marker and original
manifest. This is hash-based authentication using an externally trusted receipt,
not a digital signature or proof against a compromised source host. Encryption
alone does not authenticate who created an archive.

Limits: 128 MiB ciphertext/download/expanded contents, at most 100 configuration
and 100 evidence files, single-part uploads, no automatic retries or deletions.
Normal failures remove local staging; interruption or power loss may leave
private `.pending-*` directories for inspection. Never promote staging output.
An upload failure may leave orphaned remote objects; without a verified receipt
and marker they are not recovery points. Failed commands return nonzero and
sanitized error codes; stop and investigate, never bypass a failed check.

## 1. Independent recovery host: keys and private bucket

Use a trusted host other than Atlas, a private encrypted disk and reviewed age
installation. All commands below with identity or recovery credentials run there:

```bash
set -eu
umask 077
mkdir -m 700 "$HOME/sysethic-dr"
cd "$HOME/sysethic-dr"
age-keygen -o identity.txt
age-keygen -y identity.txt > recipient.txt
chmod 600 identity.txt recipient.txt
age --version
```

Back up `identity.txt` offline in a separately secured location and demonstrate
its availability to the authorized recovery operator. Transfer ONLY
`recipient.txt` to Atlas; confirm its public value using an independent channel.
Do not generate a private age identity on Atlas, including for a test.

In the Backblaze console create a new **private** B2 bucket. Record its bucket ID
and region externally. Do not enable lifecycle expiration until retention is
reviewed. Create two different, bucket/prefix-scoped keys using the Native API:

| Key | Exact capabilities | Bucket scope | Name prefix | Location |
| --- | --- | --- | --- | --- |
| Uploader | `writeFiles`, `readFiles`, `listBuckets` | this bucket only | `sysethic/` | temporary Atlas process |
| Recovery | `readFiles`, `listBuckets` | this bucket only | `sysethic/` | recovery host only |

Read access is needed for full ciphertext readback. `listBuckets` is required to
check that the selected bucket is still private. The code rejects additional
capabilities, multiple buckets or a different prefix. Neither key may delete
files, administer retention, change bucket privacy or create other keys.
Use separate retention administration off Atlas. Console Read/Write presets
may grant extra capabilities; use a custom Native API key instead.

For exact custom keys, run this on the independent administrative host. Supply a
scoped key-creation credential through hidden prompts. Never run under shell
tracing or log API responses. The output files contain secret keys; do not
transfer `recovery-key.json` to Atlas. Create-key bodies use v4 `bucketIds`.

```bash
python3 - <<'PY'
import base64, getpass, json, os, pathlib, urllib.request, urllib.parse
os.umask(0o077)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise RuntimeError('redirect rejected')
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def request(url, data=None, token=None):
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https' or not p.hostname.endswith('.backblazeb2.com') or p.username or p.password or p.port not in (None, 443):
        raise RuntimeError('untrusted endpoint')
    headers = {'Authorization': token, 'Content-Type': 'application/json'}
    req = urllib.request.Request(url, data=None if data is None else json.dumps(data).encode(), headers=headers)
    with opener.open(req, timeout=60) as response:
        return json.load(response)
try:
    key_id = getpass.getpass('Administrative key ID: ')
    key = getpass.getpass('Administrative application key: ')
    auth = request('https://api.backblazeb2.com/b2api/v4/b2_authorize_account',
                   token='Basic ' + base64.b64encode((key_id + ':' + key).encode()).decode())
    api = auth['apiInfo']['storageApi']['apiUrl']
    bucket = input('Private bucket ID: ').strip()
    records = request(api + '/b2api/v2/b2_list_buckets',
                      {'accountId': auth['accountId'], 'bucketId': bucket}, auth['authorizationToken'])['buckets']
    if len(records) != 1 or records[0]['bucketId'] != bucket or records[0]['bucketType'] != 'allPrivate':
        raise RuntimeError('private bucket required')
    for name, capabilities in (
        ('uploader', ['writeFiles', 'readFiles', 'listBuckets']),
        ('recovery', ['readFiles', 'listBuckets'])):
        path = pathlib.Path(name + '-key.json')
        # Reserve privately before creating a key; do not replace an existing key file.
        with path.open('x') as handle:
            response = request(api + '/b2api/v4/b2_create_key',
                {'accountId': auth['accountId'], 'keyName': 'sysethic-' + name,
                 'capabilities': capabilities, 'bucketIds': [bucket],
                 'namePrefix': 'sysethic/', 'validDurationInSeconds': 7776000},
                 auth['authorizationToken'])
            json.dump(response, handle)
            handle.flush(); os.fsync(handle.fileno())
        print('Created private credential file:', path.name)
except Exception as error:
    print('STOP: setup failed:', type(error).__name__)
    raise SystemExit(1)
PY
```

These example keys expire after 90 days. Record expiry and rotate before it.
Revoke a newly created key if private response storage failed; an empty file is
not recoverable credential evidence. Do not print key JSON to troubleshoot.
The administrator may need `writeKeys` and `listBuckets`; do not grant these to
the uploader or recovery key. API operations are documented by
[Backblaze create-key](https://www.backblaze.com/apidocs/b2-create-key),
[authorization](https://www.backblaze.com/apidocs/b2-authorize-account), and
[list-buckets](https://www.backblaze.com/apidocs/b2-list-buckets).

## 2. Atlas: proposed guarded installation, not executed

After code review, install a reviewed age binary using the operator's trusted
package process. The disposable tests used age v1.3.2; record the installed
version and binary checksum. Do not use the test double. The following require
sudo and create only recovery-tooling paths; stop if any target already exists:

```bash
sudo bash <<'SH'
set -eu
cd /home/atlas/apps/Sysethic
for target in /usr/local/lib/saaoe/saaoe_offhost.py /var/lib/saaoe-offhost /etc/saaoe-recovery; do
    test ! -e "$target" && test ! -L "$target"
done
test -f /usr/local/lib/saaoe/saaoe_recovery.py
cmp scripts/saaoe_recovery.py /usr/local/lib/saaoe/saaoe_recovery.py
command -v age
age --version
install -o root -g root -m 644 scripts/saaoe_offhost.py /usr/local/lib/saaoe/saaoe_offhost.py
install -d -o saaoe -g saaoe -m 700 /var/lib/saaoe-offhost
install -d -o root -g root -m 755 /etc/saaoe-recovery
# Only the independently generated PUBLIC recipient file, staged by the operator.
install -o root -g root -m 644 /home/atlas/recipient.txt /etc/saaoe-recovery/recipient.txt
stat -c '%U:%G %a %n' /usr/local/lib/saaoe/saaoe_offhost.py /var/lib/saaoe-offhost /etc/saaoe-recovery/recipient.txt
test "$(systemctl is-enabled saaoe-backup.timer)" = disabled
test "$(systemctl is-active saaoe-backup.timer)" = inactive
SH
```

Expected ownership: script and recipient root:root 644, storage saaoe:saaoe
700. No unit installation, daemon reload or service activation is needed.
If the installed recovery helper differs, stop for review; do not overwrite it.
Check the public recipient against the independently retained value before seal.

## 3. Manual seal: include configuration privately

This creates a NEW encrypted package from the existing immutable local bundle.
It does not read database records, load `.env`, execute application code or
modify the live database. Configuration files are streamed as opaque bytes.
The recorded configuration is contemporaneous with sealing, not necessarily
with the earlier snapshot; qualification must explicitly accept that pairing.

```bash
sudo -u saaoe /usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_offhost.py seal \
  --bundle /var/lib/saaoe-backups/20261010T010740Z-a79bb5cc \
  --output /var/lib/saaoe-offhost \
  --recipient "$(cat /etc/saaoe-recovery/recipient.txt)" \
  --manifest-sha256 461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe \
  --secret-file /opt/saaoe/.env \
  --public-file /etc/systemd/system/saaoe.service \
  --evidence-file /var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc/qualification.json \
  --age /usr/bin/age
```

Require exit 0 and `status=ok`. Use the returned path verbatim as PACKAGE_PATH
below. Never auto-select a staging directory. File modes must be 600, enclosing
directories 700, owner saaoe. `seal.json` contains artifact identities and hashes,
not configuration paths, values or configuration hashes. Original configuration
paths and hashes are inside encrypted `inventory.json`; `.env` is
`configuration/0000`, service unit `configuration/0001` for this exact command.
Any additional required assets need a separate inventory and compatibility
review before sealing; this command does not prove complete configuration.

```bash
sudo -u saaoe sha256sum PACKAGE_PATH/seal.json PACKAGE_PATH/recovery.tar.gz.age
sudo find PACKAGE_PATH -maxdepth 1 -printf '%M %u:%g %s %p\n'
```

## 4. Manual upload and verified completion

Replace PACKAGE_PATH and BUCKET_ID with recorded nonsecret values. The hidden
prompts below take the UPLOADER key only. Input goes through the authenticated
terminal, never argv, shell history or a credential file on Atlas. Do not turn
on shell tracing. Credentials exist temporarily in process memory/environment;
the Python client removes its environment entries before use.

```bash
sudo -u saaoe bash <<'SH'
set -eu
set +x
umask 077
IFS= read -rs -p 'Uploader key ID: ' SAAOE_B2_KEY_ID </dev/tty
printf '\n' >/dev/tty
IFS= read -rs -p 'Uploader application key: ' SAAOE_B2_APPLICATION_KEY </dev/tty
printf '\n' >/dev/tty
export SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY
trap 'unset SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY' EXIT
/usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_offhost.py upload \
  --package PACKAGE_PATH --bucket-id BUCKET_ID --prefix sysethic/
SH
```

Require `status=ok`; its result is the SHA-256 of `upload-receipt.json`.
Upload verifies B2's SHA-1 acknowledgement AND downloads the exact ciphertext
file version to compare SHA-256 and size. Only then is `complete.json` published
and downloaded for verification. Each attempt uses a new object prefix; partial
uploads never replace a previous recovery point. No remote object is deleted.
[B2 upload documentation](https://www.backblaze.com/apidocs/b2-upload-file).

Retain the receipt and its hash externally through separate trusted channels.
For an operator-readable metadata transfer copy only (no secrets), use:

```bash
sudo bash <<'SH'
set -eu
test ! -e /home/atlas/sysethic-dr-receipt
test ! -L /home/atlas/sysethic-dr-receipt
install -d -o atlas -g atlas -m 700 /home/atlas/sysethic-dr-receipt
install -o atlas -g atlas -m 600 PACKAGE_PATH/upload-receipt.json /home/atlas/sysethic-dr-receipt/receipt.json
SH
```

From the independent host, retrieve that metadata using authenticated SSH:

```bash
scp atlas@ATLAS_SSH_HOST:/home/atlas/sysethic-dr-receipt/receipt.json "$HOME/sysethic-dr/receipt.json"
chmod 600 "$HOME/sysethic-dr/receipt.json"
sha256sum "$HOME/sysethic-dr/receipt.json"
```

Compare with the independently recorded upload result. Preserve the receipt,
manifest anchor, source qualification record and ciphertext hashes in the
recovery register; do not rely only on mutable B2 metadata or an Atlas log.

## 5. Independent host retrieval and private decryption

Use reviewed copies of both Python helpers in a private `tools` directory on
the independent Linux host (Python >=3.11), plus age. Do not execute code taken
from an unverified recovered archive before verifying it. Replace BUCKET_ID,
RECEIPT_SHA256 and retrieved PACKAGE_ID explicitly with recorded values.

```bash
set -eu
umask 077
cd "$HOME/sysethic-dr"
mkdir -m 700 retrieved recovered
set +x
IFS= read -rs -p 'Recovery key ID: ' SAAOE_B2_KEY_ID </dev/tty
printf '\n' >/dev/tty
IFS= read -rs -p 'Recovery application key: ' SAAOE_B2_APPLICATION_KEY </dev/tty
printf '\n' >/dev/tty
export SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY
trap 'unset SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY' EXIT
python3 -B tools/saaoe_offhost.py retrieve \
  --receipt receipt.json --receipt-sha256 RECEIPT_SHA256 \
  --bucket-id BUCKET_ID --prefix sysethic/ --output retrieved
unset SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY
python3 -B tools/saaoe_offhost.py decrypt \
  --package "$HOME/sysethic-dr/retrieved/PACKAGE_ID" \
  --identity "$HOME/sysethic-dr/identity.txt" \
  --receipt-sha256 RECEIPT_SHA256 --output "$HOME/sysethic-dr/recovered"
python3 -B tools/saaoe_recovery.py verify "$HOME/sysethic-dr/recovered/PACKAGE_ID/bundle"
```

The decrypt command refuses the recorded source machine ID before opening the
identity. This prevents accidental use on Atlas, not a security boundary against
an administrator changing machine identity. Private keys must remain off Atlas.
Age authenticates ciphertext; extraction rejects links, traversal, duplicate
members, incomplete inventories and excessive expanded sizes. Original bundle
and recovered configuration hashes are checked before atomic publication.
A temporary plaintext archive exists only in the private recovery directory on
the recovery host and is removed on normal completion/failure. Secure deletion
on SSDs is not guaranteed: use encrypted storage; inspect interrupted staging
privately. Never print `.env`, credential files or decrypted inventory/config.

Require commit a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb, original manifest
anchor, release/snapshot hashes and integrity OK. Recovered plaintext is private
600 files/700 directories. Receipt download checks exact version IDs; merely
listing similarly named objects is insufficient coverage evidence.

## 6. Retrieval acceptance and configuration test gate

Record dated independent-host retrieval, ciphertext size/hash, object/version
IDs, receipt hash, successful real-age decryption and recovered artifact hashes.
Rebuild Python 3.12.3 plus pinned dependencies from the verified release in a new
venv; require versions to match the original manifest and `pip check` success.
Repeat the isolated restore and authenticated synthetic workflow procedure in
[the qualification runbook](production-recovery-qualification.md), substituting
only private recovered paths. Never restore into `/opt/saaoe` or start the
recovered production unit. The recorded unit is a recovery reference, not an
instruction to execute it on the test host.

Before testing actual protected config, audit which keys enable external
processes, mail/network actions, terminal access, privileged remediation or live
storage. Build a disposable test harness that parses config privately and
replaces all storage paths, disables external actions, uses a private network
namespace, empty capabilities, inaccessible production paths and fresh synthetic
users. Do not simply source the recovered `.env` or reuse a production account.
Verify required key availability, production encryption/signing compatibility,
config load and authorized synthetic workflows without emitting values. Until
this dedicated test passes, configuration recovery remains unqualified even if
all encrypted bytes and hashes survived retrieval.

Known-good disaster-recovery evidence requires all of: independent receipt
trust; verified complete remote version; real decryption using an off-Atlas key;
full artifact/config inventory; fresh dependency match; unchanged compatible
schema; authenticated isolated read/write and authorization checks; protected
production-config test with external actions disabled; production health/PID
unchanged; measured restoration time and approved snapshot-age/data-loss
acceptance. No live rollback is authorized by this runbook.

## 7. Retention, monitoring and withdrawal

Proposed retention: 14 daily, 8 weekly, 12 monthly, plus a separately protected
known-good pair. Retain associated encrypted configuration, receipts and evidence
for the same duration. Use separate off-Atlas administration with reviewed
deletion permissions. Do not configure a blanket lifecycle rule that expires the
protected pair. Never prune local bundles until independent retrieval coverage
is verified and the recovery register identifies the surviving remote versions.

Automation remains disabled. Future targets, not achieved guarantees: hourly
snapshots, verified upload within 30 minutes, externally alert before verified
recovery-point age exceeds two hours (RPO <=2h); RTO <=60 minutes on a usable
Atlas host and <=4h on a replacement. Measure incident declaration through
retrieval, decryption, validation and authenticated availability. Alert on job
failure, missing completion, key expiry, ciphertext mismatch and missed backups
from outside Atlas; local logs cannot detect host loss. Approve capacity/cost,
key rotation, retention and data-loss authority before scheduling.

To withdraw future-installed off-host tooling, stop operator invocations, revoke
ONLY the uploader key from the independent administrator host and remove ONLY
`/usr/local/lib/saaoe/saaoe_offhost.py` after review. Preserve packages, receipts,
keys held outside Atlas and all local backup/test evidence. No app restart,
firewall/DNS/Caddy change, timer enablement or database replacement is required.

## Implementation evidence: 2026-10-11 UTC

The complete applicable suite passed: 45 tests in 14.251 seconds, zero skips.
This comprises the local backup/qualification suites plus 23 off-host tests.
Real age v1.3.2 encrypted disposable data to a public recipient; no private age
identity was generated or used on Atlas. The temporary binary came from the
[official release](https://github.com/FiloSottile/age/releases/tag/v1.3.2);
its downloaded linux-amd64 archive SHA-256 was
`cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10`.
This records the download, not independent publisher-signature verification.

B2 authorization, private bucket enforcement, upload acknowledgement, completion
ordering, upload/download failure, checksum mismatch and recovery extraction
were exercised using disposable doubles. Hostile/incomplete archives, wrong
receipt/manifest hashes, untrusted configuration permissions and source-host
decryption all fail without publishing a recovery directory. Real cryptographic
decryption and real B2 behavior remain independent-host acceptance tests.
Sixteen documented shell blocks passed `bash -n`; new Python sources parsed
successfully. Production HTTPS returned HTTP 200/phase5.13. Service remained
active, PID 3429, NRestarts 0; backup timer remained disabled/inactive. No
production configuration, database, services or remote storage were changed.
