# SysEthic recovery: operator installation

Production: `/opt/saaoe`, service `saaoe.service`, database
`/opt/saaoe/data/saaoe.db`, commit
`a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb`, version `phase5.13`.
No production installation, backup or restore has occurred in this session.

Seventeen disposable tests passed. Unit syntax passed using a substitute
accessible interpreter. Actual production-path privileged validation remains
blocked by sudo authentication.

## Safety guarantees and limits

SQLite source is opened read-only; the destination is exclusively created.
Aliases, symlinked/permissive backup storage, and dirty tracked releases are
rejected. The service mounts the deployment read-only and hides `.env`.
The archive has an exact application-file allowlist: the audited commit has
36 regular files, excluding virtual environments, runtime logs/databases,
`.env`, untracked files and links. New application files require allowlist review.

Snapshots are validated, paired with release hashes/package versions/schema
signatures, copied for integrity checks, fsynced and published by atomic rename.
Normal failures clean staging. Termination may leave `.pending-*`, which are
never usable published backups. Storage is saaoe-owned, directories 700/files
600. Checksums detect corruption, not malicious replacement of the manifest;
retain manifest hashes independently or sign them for off-host recovery.
Configuration recovery, off-host transport, retention pruning and remote
alert delivery are not implemented. Local failure logging is insufficient.

## 1. Preflight; stop on any failure

Run from `/home/atlas/apps/Sysethic`:

```bash
python3 -B -m unittest tests.test_recovery
sudo systemd-analyze verify packaging/systemd/saaoe-backup.service packaging/systemd/saaoe-backup.timer packaging/systemd/saaoe-backup-alert.service
sudo -u saaoe git -C /opt/saaoe rev-parse HEAD
sudo -u saaoe git -C /opt/saaoe status --short --untracked-files=no
systemctl show saaoe.service --property=MainPID,NRestarts,ActiveState
curl --fail --silent --show-error http://127.0.0.1:5001/healthz
```

Require expected commit, clean tracked status, health 200. Record application
PID/restart count. Do not deploy/commit application changes for this installation;
the recovery script is installed separately from the production checkout.

## 2. Guarded installation; timer stays disabled

The block aborts if any target already exists. Inspect an existing installation
before adapting guards; never silently overwrite it.

```bash
sudo bash <<'SH'
set -eu
cd /home/atlas/apps/Sysethic
for target in /usr/local/lib/saaoe /var/lib/saaoe-backups /var/lib/saaoe-restore-tests /etc/systemd/system/saaoe-backup.service /etc/systemd/system/saaoe-backup.timer /etc/systemd/system/saaoe-backup-alert.service; do
    if test -e "$target" || test -L "$target"; then
        echo "Existing target requires inspection: $target" >&2
        exit 1
    fi
done
install -d -o root -g root -m 755 /usr/local/lib/saaoe
install -o root -g root -m 644 scripts/saaoe_recovery.py /usr/local/lib/saaoe/saaoe_recovery.py
install -d -o saaoe -g saaoe -m 700 /var/lib/saaoe-backups /var/lib/saaoe-restore-tests
install -o root -g root -m 644 packaging/systemd/saaoe-backup.service packaging/systemd/saaoe-backup.timer packaging/systemd/saaoe-backup-alert.service /etc/systemd/system/
systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/saaoe-backup.service /etc/systemd/system/saaoe-backup.timer /etc/systemd/system/saaoe-backup-alert.service
SH
sudo stat -c '%U:%G %a %n' /usr/local/lib/saaoe/saaoe_recovery.py /var/lib/saaoe-backups /var/lib/saaoe-restore-tests /etc/systemd/system/saaoe-backup.service
systemctl is-enabled saaoe-backup.timer
systemctl is-active saaoe-backup.timer
```

Expect root-owned script/units 644, saaoe-owned private directories 700; timer
disabled/inactive. Timer checks return nonzero as expected. No app restart.

## 3. Manual first backup and verification

```bash
sudo systemctl start saaoe-backup.service
sudo systemctl show saaoe-backup.service --property=Result,ExecMainStatus
sudo journalctl -u saaoe-backup.service -n 10 --no-pager
sudo find /var/lib/saaoe-backups -maxdepth 2 -printf '%M %u:%g %s bytes %p\n'
systemctl show saaoe.service --property=MainPID,NRestarts,ActiveState
curl --fail --silent --show-error http://127.0.0.1:5001/healthz
curl --fail --silent --show-error https://sysethic.cloud/healthz
```

Require success/exit 0, unchanged application PID/restart count, health 200,
expected version, private ownership/modes. Do not hash the live DB to infer
write safety: normal application traffic can change it. Read-only WAL access
may fail if usable WAL/SHM state is absent; diagnose without weakening the
mount, live file copying or `immutable=1` against production.

Set the exact published bundle ID from the job JSON output:

```bash
bundle_id=REPLACE_WITH_PUBLISHED_ID
sudo -u saaoe /opt/saaoe/venv/bin/python -B /usr/local/lib/saaoe/saaoe_recovery.py verify "/var/lib/saaoe-backups/$bundle_id"
sudo -u saaoe sha256sum "/var/lib/saaoe-backups/$bundle_id/manifest.json"
```

Preserve the manifest checksum independently. Verification checks hashes,
archive restrictions, integrity and schema on a disposable copy; no records
are displayed. Never use `.pending-*`. Stop on failure.

## 4. Isolated application test

A transient unit denies external networking, capabilities and production
config/data/runtime access. It permits writes only to the test directory and
private temporary space. Existing Python/package versions must match the
manifest. Flask test-client requests open no public listener.

```bash
sudo systemd-run --unit=saaoe-restore-check --wait --collect --pipe \
  --property=User=saaoe --property=Group=saaoe --property=UMask=0077 \
  --property=PrivateNetwork=yes --property=PrivateTmp=yes \
  --property=PrivateDevices=yes --property=NoNewPrivileges=yes \
  --property=CapabilityBoundingSet= --property=ProtectSystem=strict \
  --property=ProtectHome=yes \
  --property=InaccessiblePaths='/opt/saaoe/data /opt/saaoe/.env /opt/saaoe/logs /opt/saaoe/instance /opt/saaoe/quarantine' \
  --property=ReadOnlyPaths=/var/lib/saaoe-backups \
  --property=ReadWritePaths=/var/lib/saaoe-restore-tests \
  --property=RuntimeMaxSec=5min \
  /opt/saaoe/venv/bin/python -B /usr/local/lib/saaoe/saaoe_recovery.py \
  restore-test "/var/lib/saaoe-backups/$bundle_id" \
  --python /opt/saaoe/venv/bin/python --output /var/lib/saaoe-restore-tests
```

Require application_health=ok, application_version=phase5.13,
schema_unchanged_after_startup=true, runtime_matches_manifest=true,
unauthenticated_access=denied. The dated record includes commit and artifact
hashes. Startup only modifies a disposable copy. A schema change fails the
check and requires compatibility review. Failed tests create no success record.

This covers startup, integrity, version, unchanged schema, runtime and one
authentication guard. It does not prove Waitress transport, authenticated
workflows, fresh environment reconstruction or protected config recovery.

## 5. Scheduling and known-good evidence gate

Keep the timer disabled until first-backup and isolated-test evidence is
reviewed. No enable command is supplied before that review. The prepared
schedule is daily at 02:15 UTC with up to 15 minutes jitter.

Full known-good designation additionally requires dated authenticated workflow
checks, fresh dependency rebuild from the archive on a separate host, protected
configuration recovery, encrypted off-host upload/download verification, object
identifiers and independent manifest hashes/signatures. Preserve the designated
release/snapshot pair separately from rolling retention.

Provider/destination details and scoped credentials remain required. Inspect
VPS snapshot inventory separately; do not assume crash-consistent images replace
verified SQLite backups. Do not reuse FitTrack credentials without permission.
Encrypt bundles and separately protect required non-Git assets and `.env`; keep
private recovery keys off Atlas. Proposed retention is 14 daily, 8 weekly and
12 monthly pairs, subject to recovery targets. Upload completion markers last;
verify downloaded remote hashes before local pruning. Alert externally on failed
runs or verified uploads older than 36 hours. Local OnFailure logging is not
remote monitoring and cannot detect a powered-off VPS.

## Backup-tooling rollback only

Preserve all snapshots and test records. Do not stop `saaoe.service`:

```bash
sudo systemctl disable --now saaoe-backup.timer
sudo systemctl stop saaoe-backup.service saaoe-backup-alert.service
sudo rm -- /etc/systemd/system/saaoe-backup.service /etc/systemd/system/saaoe-backup.timer /etc/systemd/system/saaoe-backup-alert.service /usr/local/lib/saaoe/saaoe_recovery.py
sudo systemctl daemon-reload
```

Do not remove storage directories. Preserve any interrupted staging output for
diagnosis. Required sudo operations: unit validation, guarded installation and
ownership setup, daemon reload, manual backup job, private inventory, transient
sandbox creation, and tooling withdrawal only if needed. No production app
restart or direct DB write is required.

## Phase 2: manual age encryption and Backblaze B2

Follow [the encrypted off-host runbook](encrypted-offhost-recovery.md) for
review-only installation commands, independently generated public recipient,
private bucket creation, exactly scoped uploader/recovery keys, manual sealing,
verified uploads, receipt custody and independent-host retrieval/decryption.
The script is `scripts/saaoe_offhost.py`; no uploader unit or timer is installed
or enabled. Keep the existing backup timer disabled.

The verified bundle `20261010T010740Z-a79bb5cc` matches release
`a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb`. Its independently recorded
manifest SHA-256 is
`461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe`.
The authenticated synthetic recovery evidence is
`/var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc/qualification.json`.
These local results do not establish off-host coverage or protected production
configuration recovery. Configuration captured later must be explicitly paired
and tested against this snapshot. Hash authentication requires an independently
retained receipt hash; ciphertext alone does not establish publisher identity.

Run applicable disposable checks before any installation:

```bash
python3 -B -m unittest tests.test_recovery tests.test_recovery_qualification tests.test_offhost_recovery
```

Transport failures and recovery extraction use doubles with disposable data.
The real-age encryption test uses a public recipient only; it is skipped if the
reviewed temporary age binary is unavailable. Require that test to run when
claiming real encryption evidence. Actual B2 upload/readback and real decryption
must be proven on the independent recovery host before declaring disaster
recovery ready. Private age identities must never be generated on Atlas.

For the first production upload, use [the bundle-only production/Windows
procedure](first-production-offhost-upload.md). It explicitly excludes `.env`
and other configuration and uses the restricted `production/backups/` prefix.
Do not use the earlier configuration-inclusive seal example for this operation.
