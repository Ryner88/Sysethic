# SysEthic recovery qualification

Bundle: `/var/lib/saaoe-backups/20261010T010740Z-a79bb5cc`.
Commit: `a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb`.
Independently recorded manifest SHA-256:
`461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe`.

Twenty-two disposable tests pass, including the actual archived application's
synthetic signup/login/logout, dashboard, member create/read, workspace scope,
configuration create/update/readback, persisted SQLite writes and audit events,
and viewer mutation denial. These are helper self-tests, not qualification of
the private production snapshot or its fresh dependency environment.

## Isolation design

Preparation verifies the independently recorded manifest, extracts only vetted
release files, and copies no database into the networked build directory.
The dependency build sees neither production nor backup storage. The subsequent
workflow test denies networking, capabilities and production paths; it copies
the snapshot only inside that sandbox. The controller and worker check network
namespace separation and inaccessible live DB/config paths before testing.
Only a new synthetic workspace and users are exercised; records, credentials
and session tokens are never printed. Original snapshot hashes are rechecked.

Stop on any failure. Do not weaken namespace, production-path restrictions or
hash checks. Production app and timer are never started/stopped by these steps.
Run one stage at a time, reviewing results before proceeding.

## Stage 1: install separate helper and prepare release

Run from `/home/atlas/apps/Sysethic`. This installs a new root-owned helper,
leaving the installed backup script/units unchanged. Existing target paths
abort the installation and require inspection.

```bash
sudo bash <<'SH'
set -eu
cd /home/atlas/apps/Sysethic
for target in /usr/local/lib/saaoe/saaoe_qualify.py /var/lib/saaoe-qualification; do
    if test -e "$target" || test -L "$target"; then
        echo "STOP: existing qualification target: $target" >&2
        exit 1
    fi
done
install -o root -g root -m 644 scripts/saaoe_qualify.py /usr/local/lib/saaoe/saaoe_qualify.py
install -d -o saaoe -g saaoe -m 700 /var/lib/saaoe-qualification
stat -c '%U:%G %a %n' /usr/local/lib/saaoe/saaoe_qualify.py /var/lib/saaoe-qualification
host_netns=$(readlink /proc/self/ns/net)
systemd-run --unit=saaoe-qualify-prepare --wait --collect --pipe \
  -p User=saaoe -p Group=saaoe -p UMask=0077 -p PrivateNetwork=yes \
  -p PrivateTmp=yes -p PrivateDevices=yes -p NoNewPrivileges=yes \
  -p CapabilityBoundingSet= -p ProtectSystem=strict -p ProtectHome=yes \
  -p InaccessiblePaths=/opt/saaoe \
  -p ReadOnlyPaths=/var/lib/saaoe-backups \
  -p ReadWritePaths=/var/lib/saaoe-qualification -p RuntimeMaxSec=5min \
  /usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_qualify.py prepare \
  --bundle /var/lib/saaoe-backups/20261010T010740Z-a79bb5cc \
  --work /var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc \
  --host-netns "$host_netns"
SH
```

Require successful exit, expected commit, and database_copied=false.

## Stage 2: reconstruct a fresh virtual environment

This stage requires outbound HTTPS solely for dependency acquisition. All
production and backup paths are inaccessible and no DB copy is present in
its writable directory. Environment is cleared; pip ignores external user
configuration and uses the explicit public package index. No credentials are
needed. The original Python 3.12.3 and pip 24.0 must be available/reconstructible.
Missing venv support or dependency resolution failure stops qualification.
Pinned versions are verified later; upstream package artifact hashes were not
included in the original requirements, so reproducible artifact identity is
not established by version pins alone.

```bash
sudo systemd-run --unit=saaoe-qualify-build --wait --collect --pipe \
  -p User=saaoe -p Group=saaoe -p UMask=0077 \
  -p PrivateTmp=yes -p PrivateDevices=yes -p NoNewPrivileges=yes \
  -p CapabilityBoundingSet= -p ProtectSystem=strict -p ProtectHome=yes \
  -p InaccessiblePaths='/opt/saaoe /var/lib/saaoe-backups /var/lib/saaoe-restore-tests' \
  -p ReadWritePaths=/var/lib/saaoe-qualification -p RuntimeMaxSec=20min \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc \
  /bin/sh -eu -c '
    work=/var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc
    test ! -e "$work/venv"
    /usr/bin/python3 -m venv "$work/venv"
    "$work/venv/bin/python" -B -m pip --isolated --disable-pip-version-check install --no-cache-dir --index-url https://pypi.org/simple pip==24.0
    "$work/venv/bin/python" -B -m pip --isolated --disable-pip-version-check install --no-cache-dir --index-url https://pypi.org/simple -r "$work/release/requirements.txt"
    "$work/venv/bin/python" -B -m pip --isolated --disable-pip-version-check check
  '
```

Require exit 0 and no broken requirements. No runtime upgrade is performed.

## Stage 3: restored snapshot and authenticated workflow test

```bash
sudo bash <<'SH'
set -eu
host_netns=$(readlink /proc/self/ns/net)
systemd-run --unit=saaoe-qualify-workflows --wait --collect --pipe \
  -p User=saaoe -p Group=saaoe -p UMask=0077 -p PrivateNetwork=yes \
  -p PrivateTmp=yes -p PrivateDevices=yes -p NoNewPrivileges=yes \
  -p CapabilityBoundingSet= -p ProtectSystem=strict -p ProtectHome=yes \
  -p InaccessiblePaths=/opt/saaoe \
  -p ReadOnlyPaths=/var/lib/saaoe-backups \
  -p ReadWritePaths=/var/lib/saaoe-qualification -p RuntimeMaxSec=5min \
  /usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_qualify.py qualify \
  --bundle /var/lib/saaoe-backups/20261010T010740Z-a79bb5cc \
  --work /var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc \
  --host-netns "$host_netns"
SH
```

Require successful synthetic workflows, fresh_runtime_matches_manifest=true,
schema_unchanged=true, snapshot_unchanged=true, production_paths_inaccessible=true.
Evidence is saved to the private work directory's `qualification.json`.
A synthetic configuration file is recovered with mode 600 and its loaded secret
and secure-cookie behavior checked internally without displaying values.
This is not evidence of recovering actual production configuration.

## Protected production configuration recovery

The verified bundle explicitly excludes configuration. Existing encrypted or
protected configuration artifact path and decryption method/key path are still
needed. Do not paste secrets. Verify artifact authenticity, private access,
recovery-key availability, required variables and exact internal comparisons
without displaying values. Do not load original production DB/log paths into
an executable test: rewrite test-only paths before startup and keep live paths
inaccessible. Actual protected configuration recovery remains unverified until
that separate evidence exists. No new configuration backup is implied by these
synthetic tests.

## Final health checks and qualification decision

```bash
systemctl show saaoe.service --property=MainPID,NRestarts,ActiveState,SubState
curl --fail --silent --show-error --max-time 20 -w '\nHTTP %{http_code}\n' https://sysethic.cloud/healthz
systemctl show saaoe-backup.timer --property=UnitFileState,ActiveState
```

Require PID 3429, zero restarts, active/running, phase5.13 HTTP 200, timer disabled
and inactive. A pair is not designated fully known-good from synthetic tests
alone. Remaining limits include actual configuration recovery, package artifact
hash provenance, application server transport/full operational workflows,
backup age/data-loss approval, rollback execution plan and off-host recovery.
Do not execute a production rollback or enable scheduling in this procedure.
