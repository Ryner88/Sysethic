#!/bin/bash
# Operator-reviewed, manual first upload. No environment/configuration files.
set -euo pipefail
set +x
umask 077
trap 'unset SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY; echo "STOP: first upload did not complete; preserve evidence and inspect failure." >&2' ERR
[[ $EUID == 0 ]] || { echo 'Run in authenticated terminal: sudo bash scripts/saaoe_first_offhost_upload.sh'; exit 1; }
cd /home/atlas/apps/Sysethic
bundle=/var/lib/saaoe-backups/20261010T010740Z-a79bb5cc
manifest_sha=461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe
before_pid=$(systemctl show saaoe.service -p MainPID --value)
before_restarts=$(systemctl show saaoe.service -p NRestarts --value)
test "$(systemctl is-active saaoe.service)" = active
test "$(systemctl is-enabled saaoe-backup.timer)" = disabled
test "$(systemctl is-active saaoe-backup.timer)" = inactive
cmp scripts/saaoe_recovery.py /usr/local/lib/saaoe/saaoe_recovery.py
age_bin=$(command -v age)
"$age_bin" --version
sudo -u saaoe /usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_recovery.py verify "$bundle"
# Validate exact manifest anchor/commit and archive inventory; report metadata only.
sudo -u saaoe /usr/bin/python3 -B - <<'PY'
import hashlib,json,pathlib,sys,tarfile
sys.path.insert(0,'/usr/local/lib/saaoe')
import saaoe_recovery as r
b=pathlib.Path('/var/lib/saaoe-backups/20261010T010740Z-a79bb5cc')
assert r.digest(b/'manifest.json') == '461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe', 'Manifest anchor mismatch'
m=json.loads((b/'manifest.json').read_text())
assert m['commit']=='a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb', 'Release mismatch'
assert m['sha256']=={'database.sqlite3':'1fda798f1dc382df37bfd672c942bdc8665e460c0a856cb989440bfe3410bf21','release.tar.gz':'d045d5fb63ad1ba5d29805f604931cf76a862c16a92e3646457a2fccbc9d858d'}, 'Artifact anchor mismatch'
r.validate_archive(b/'release.tar.gz',m['release_files'])
with tarfile.open(b/'release.tar.gz','r:gz') as archive:
    members=archive.getmembers()
    for entry in members:
        assert entry.name in r.RELEASE_PATHS and entry.isfile(), 'Unapproved archive entry'
        parts=pathlib.PurePosixPath(entry.name).parts
        assert all(x not in ('.env','.git','venv','.venv','data','instance','credentials','keys') for x in parts), 'Sensitive archive path'
        raw=archive.extractfile(entry).read()
        assert b'AGE-SECRET-KEY-' not in raw, 'Private identity marker found'
        assert not (b'-----BEGIN ' in raw and b'PRIVATE KEY-----' in raw), 'Private key marker found'
print(json.dumps({'archive_entries':len(members),'archive_allowlist':'ok','private_key_markers':'absent','manifest_sha256':r.digest(b/'manifest.json'),'artifact_sha256':m['sha256']}))
PY
# Missing inputs are prompted through the operator terminal. Never prompt for secrets in chat.
IFS= read -r -p 'Private sysethic-recovery bucket ID: ' bucket_id </dev/tty
IFS= read -r -p 'Verified public recipient file [/home/atlas/recipient.txt]: ' recipient_path </dev/tty
recipient_path=${recipient_path:-/home/atlas/recipient.txt}
[[ -f "$recipient_path" && ! -L "$recipient_path" ]]
recipient=$(/usr/bin/python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text().strip())' "$recipient_path")
[[ "$recipient" =~ ^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$ ]]
IFS= read -r -p 'Confirm recipient against independently verified Windows public recipient (type CONFIRMED): ' confirm </dev/tty
[[ "$confirm" == CONFIRMED ]]
# Do not replace existing tooling without explicit inspection.
if [[ -e /usr/local/lib/saaoe/saaoe_offhost.py || -L /usr/local/lib/saaoe/saaoe_offhost.py ]]; then
    cmp scripts/saaoe_offhost.py /usr/local/lib/saaoe/saaoe_offhost.py
    test "$(stat -c '%U:%G %a' /usr/local/lib/saaoe/saaoe_offhost.py)" = 'root:root 644'
else
    install -o root -g root -m 644 scripts/saaoe_offhost.py /usr/local/lib/saaoe/saaoe_offhost.py
fi
if [[ -e /var/lib/saaoe-offhost || -L /var/lib/saaoe-offhost ]]; then
    test ! -L /var/lib/saaoe-offhost
    test "$(stat -c '%U:%G %a' /var/lib/saaoe-offhost)" = 'saaoe:saaoe 700'
else
    install -d -o saaoe -g saaoe -m 700 /var/lib/saaoe-offhost
fi
# Authenticate and check bucket privacy/name/exact permissions before sealing or upload.
# Credentials are hidden; no production .env is read, sourced or archived.
IFS= read -rs -p 'Restricted UPLOADER key ID: ' SAAOE_B2_KEY_ID </dev/tty
printf '\n' >/dev/tty
IFS= read -rs -p 'Restricted UPLOADER application key: ' SAAOE_B2_APPLICATION_KEY </dev/tty
printf '\n' >/dev/tty
export SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY
trap 'unset SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY' EXIT
# Credential environment is passed only to a saaoe process, not command arguments.
sudo --preserve-env=SAAOE_B2_KEY_ID,SAAOE_B2_APPLICATION_KEY -u saaoe \
  /usr/bin/python3 -B - "$bucket_id" "$recipient" "$age_bin" <<'PY'
import json,os,pathlib,sys
sys.path.insert(0,'/usr/local/lib/saaoe')
import saaoe_offhost as o
try:
    os.umask(0o077)
    transport=o.B2(sys.argv[1],'production/backups/','upload',key_prefix='production/')
    records=transport.request(transport.api+'/b2api/v2/b2_list_buckets',
        json.dumps({'accountId':transport.account_id,'bucketId':transport.bucket}).encode(),
        {'Authorization':transport.token,'Content-Type':'application/json'})['buckets']
    if len(records)!=1 or records[0].get('bucketName')!='sysethic-recovery':
        raise o.Failure('bucket_name_mismatch')
    bundle=pathlib.Path('/var/lib/saaoe-backups/20261010T010740Z-a79bb5cc')
    package=o.seal(bundle,'/var/lib/saaoe-offhost',sys.argv[2],
        '461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe',
        age=sys.argv[3],evidence_files=['/var/lib/saaoe-qualification/20261010T010740Z-a79bb5cc/qualification.json'])
    seal=json.loads((package/'seal.json').read_text())
    if seal['configuration_included']:
        raise o.Failure('configuration_must_be_excluded')
    print(json.dumps({'sealed_package':str(package),'ciphertext_sha256':seal['ciphertext_sha256'],'ciphertext_bytes':seal['ciphertext_bytes'],'configuration_included':False}),flush=True)
    receipt_hash=o.upload(package,transport)
    receipt=json.loads((package/'upload-receipt.json').read_text())
    print(json.dumps({'bucket':'sysethic-recovery','object_name':receipt['object_name'],
        'ciphertext_file_id':receipt['ciphertext_file_id'],'completion_file_id':receipt['completion_file_id'],
        'receipt_sha256':receipt_hash,'receipt_path':str(package/'upload-receipt.json'),
        'ciphertext_sha256':receipt['ciphertext_sha256'],'remote_integrity':'ok'}))
except Exception as error:
    print(json.dumps({'status':'failed','reason':str(error) if isinstance(error,o.Failure) else type(error).__name__}))
    raise SystemExit(1)
PY
unset SAAOE_B2_KEY_ID SAAOE_B2_APPLICATION_KEY
# Recheck immutable source and untouched service/timer; stop on any mismatch.
sudo -u saaoe /usr/bin/python3 -B /usr/local/lib/saaoe/saaoe_recovery.py verify "$bundle"
test "$(systemctl show saaoe.service -p MainPID --value)" = "$before_pid"
test "$(systemctl show saaoe.service -p NRestarts --value)" = "$before_restarts"
test "$(systemctl is-active saaoe.service)" = active
test "$(systemctl is-enabled saaoe-backup.timer)" = disabled
test "$(systemctl is-active saaoe-backup.timer)" = inactive
curl --fail --silent --show-error --max-time 20 -o /dev/null -w 'Public HTTPS %{http_code}\n' https://sysethic.cloud/healthz
echo 'Upload and readback passed; independently retain the receipt and hash. Windows recovery remains to run.'
