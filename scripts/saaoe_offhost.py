"""Manual age/B2 recovery transport. No production service or database writes."""
import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import urllib.parse
import urllib.request
import uuid

import saaoe_recovery as recovery

MAX_BYTES = 128 * 1024 * 1024
CAPABILITIES = {'upload': {'writeFiles', 'readFiles', 'listBuckets'},
                'recover': {'readFiles', 'listBuckets'}}


class Failure(RuntimeError):
    pass


def sha(path):
    return recovery.digest(path)


def private_file(path):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o077:
        raise Failure('private_file_required')
    if any(parent.is_symlink() for parent in path.parents):
        raise Failure('symlink_parent_rejected')
    return path


def public_file(path):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
        raise Failure('trusted_public_file_required')
    if any(parent.is_symlink() for parent in path.parents):
        raise Failure('symlink_parent_rejected')
    return path


def machine_id():
    return hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest()


def json_file(path, data):
    with Path(path).open('x') as handle:
        json.dump(data, handle, sort_keys=True, indent=2)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())


def check_hash(value):
    if not re.fullmatch(r'[a-f0-9]{64}', value or ''):
        raise Failure('sha256_required')


def seal(bundle, output, recipient, manifest_sha, secret_files=(), age='age', evidence_files=(), public_files=()):
    if not re.fullmatch(r'age1[023456789acdefghjklmnpqrstuvwxyz]{58}', recipient or ''):
        raise Failure('native_age_public_recipient_required')
    check_hash(manifest_sha)
    bundle = recovery.secure_directory(bundle)
    if sha(bundle / 'manifest.json') != manifest_sha:
        raise Failure('untrusted_manifest')
    recovery.verify(bundle)
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if not re.fullmatch(r'[a-f0-9]{40}', manifest.get('commit', '')):
        raise Failure('invalid_release_commit')
    output = recovery.secure_directory(output)
    if output == bundle or bundle in output.parents:
        raise Failure('output_must_be_separate')
    files = {f'bundle/{name}': private_file(bundle / name) for name in (
        'manifest.json', 'verification.json', 'database.sqlite3', 'release.tar.gz')}
    if len(secret_files) + len(public_files) > 100 or len(evidence_files) > 100:
        raise Failure('configuration_or_evidence_count_limit')
    for index, path in enumerate(secret_files):
        files[f'configuration/{index:04d}'] = private_file(path)
    for index, path in enumerate(public_files, start=len(secret_files)):
        files[f'configuration/{index:04d}'] = public_file(path)
    for index, source in enumerate(evidence_files):
        path = private_file(source)
        evidence = json.loads(path.read_text())
        if evidence.get('commit') != manifest['commit'] or evidence.get('bundle') != bundle.name or evidence.get('manifest_sha256', manifest_sha) != manifest_sha:
            raise Failure('evidence_release_mismatch')
        files[f'evidence/{index:04d}'] = path
    initial = {name: sha(path) for name, path in files.items()}
    if sum(path.stat().st_size for path in files.values()) > MAX_BYTES - 1024 * 1024:
        raise Failure('archive_size_limit')
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', bundle.name):
        raise Failure('unsafe_bundle_id')
    identity = bundle.name + '-' + uuid.uuid4().hex
    stage = Path(tempfile.mkdtemp(prefix='.pending-', dir=output))
    process = None
    watchdog = None
    try:
        ciphertext = stage / 'recovery.tar.gz.age'
        with ciphertext.open('xb') as encrypted:
            process = subprocess.Popen([age, '--encrypt', '--recipient', recipient],
                                       stdin=subprocess.PIPE, stdout=encrypted, stderr=subprocess.DEVNULL,
                                       env={'PATH': os.defpath})
            watchdog = threading.Timer(120, process.kill)
            watchdog.daemon = True
            watchdog.start()
            try:
                with tarfile.open(fileobj=process.stdin, mode='w|gz') as archive:
                    for name, path in files.items():
                        item = tarfile.TarInfo(name)
                        item.size = path.stat().st_size
                        item.mode = 0o600
                        with path.open('rb') as source:
                            archive.addfile(item, source)
                    metadata = json.dumps({'files': initial, 'configuration_sources': list(map(str, (*secret_files, *public_files)))}).encode()
                    item = tarfile.TarInfo('inventory.json')
                    item.size, item.mode = len(metadata), 0o600
                    archive.addfile(item, io.BytesIO(metadata))
            finally:
                process.stdin.close()
            if process.wait(timeout=120) != 0:
                raise Failure('encryption_failed')
        if ciphertext.stat().st_size > MAX_BYTES:
            raise Failure('ciphertext_size_limit')
        with ciphertext.open('rb') as handle:
            if handle.read(len(b'age-encryption.org/v1\n')) != b'age-encryption.org/v1\n':
                raise Failure('invalid_age_ciphertext')
        if {name: sha(path) for name, path in files.items()} != initial:
            raise Failure('source_changed_during_encryption')
        record = {'format': 1, 'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'package_id': identity, 'source_machine_id': machine_id(),
                  'bundle': bundle.name, 'commit': manifest['commit'],
                  'manifest_sha256': manifest_sha, 'release_sha256': manifest['sha256']['release.tar.gz'],
                  'snapshot_sha256': manifest['sha256']['database.sqlite3'],
                  'recipient_sha256': hashlib.sha256(recipient.encode()).hexdigest(),
                  'configuration_included': bool(secret_files or public_files), 'evidence_count': len(evidence_files),
                  'ciphertext_sha256': sha(ciphertext), 'ciphertext_bytes': ciphertext.stat().st_size}
        json_file(stage / 'seal.json', record)
        for path in stage.iterdir():
            recovery.sync_file(path)
        recovery.sync_directory(stage)
        stage.rename(output / identity)
        recovery.sync_directory(output)
        return output / identity
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if stage.exists():
            shutil.rmtree(stage)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('redirect_rejected')


class B2:
    def __init__(self, bucket_id, prefix, mode, key_prefix=None):
        if not isinstance(bucket_id, str) or not re.fullmatch(r'[a-zA-Z0-9]+', bucket_id):
            raise Failure('invalid_bucket_id')
        if not isinstance(prefix, str) or not re.fullmatch(r'[a-zA-Z0-9/_-]+/', prefix) or '..' in prefix:
            raise Failure('invalid_destination_prefix')
        key_prefix = prefix if key_prefix is None else key_prefix
        if not isinstance(key_prefix, str) or not re.fullmatch(r'[a-zA-Z0-9/_-]+/', key_prefix) or '..' in key_prefix:
            raise Failure('invalid_key_prefix')
        if not prefix.startswith(key_prefix):
            raise Failure('destination_outside_key_prefix')
        key_id = os.environ.pop('SAAOE_B2_KEY_ID', '')
        key = os.environ.pop('SAAOE_B2_APPLICATION_KEY', '')
        if not key_id or not key:
            raise Failure('uploader_or_recovery_credentials_required')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        basic = base64.b64encode((key_id + ':' + key).encode()).decode()
        auth = self.request('https://api.backblazeb2.com/b2api/v4/b2_authorize_account',
                            headers={'Authorization': 'Basic ' + basic})
        storage = auth['apiInfo']['storageApi']
        allowed = storage['allowed']
        buckets = allowed.get('buckets')
        if not isinstance(buckets, list) or len(buckets) != 1 or buckets[0].get('id') != bucket_id:
            raise Failure('single_bucket_key_required')
        if set(allowed['capabilities']) != CAPABILITIES[mode] or allowed.get('namePrefix') != key_prefix:
            raise Failure('minimally_scoped_key_required')
        self.account_id = auth['accountId']
        self.bucket, self.prefix = bucket_id, prefix
        self.api, self.download_url = storage['apiUrl'], storage['downloadUrl']
        self.token = auth['authorizationToken']
        self.valid_url(self.api)
        self.valid_url(self.download_url)
        bucket_response = self.request(self.api + '/b2api/v2/b2_list_buckets',
                                       json.dumps({'accountId': auth['accountId'], 'bucketId': self.bucket}).encode(),
                                       {'Authorization': self.token, 'Content-Type': 'application/json'})
        bucket_records = bucket_response.get('buckets', [])
        if len(bucket_records) != 1 or bucket_records[0].get('bucketId') != self.bucket or bucket_records[0].get('bucketType') != 'allPrivate':
            raise Failure('private_bucket_required')

    @staticmethod
    def valid_url(url):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.backblazeb2.com') or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise Failure('untrusted_b2_endpoint')

    def request(self, url, data=None, headers=None, destination=None):
        self.valid_url(url)
        request = urllib.request.Request(url, data=data, headers=headers or {})
        with self.opener.open(request, timeout=120) as response:
            if destination is None:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise Failure('oversized_api_response')
                return json.loads(raw)
            count = 0
            with Path(destination).open('xb') as handle:
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    if count > MAX_BYTES:
                        raise Failure('oversized_download')
                    handle.write(chunk)

    def upload(self, path, name):
        if not name.startswith(self.prefix):
            raise Failure('object_outside_prefix')
        url = self.request(self.api + '/b2api/v2/b2_get_upload_url',
                           json.dumps({'bucketId': self.bucket}).encode(),
                           {'Authorization': self.token, 'Content-Type': 'application/json'})
        self.valid_url(url['uploadUrl'])
        with Path(path).open('rb') as handle:
            checksum = hashlib.file_digest(handle, 'sha1').hexdigest()
            handle.seek(0)
            result = self.request(url['uploadUrl'], handle, {
                'Authorization': url['authorizationToken'], 'X-Bz-File-Name': urllib.parse.quote(name, safe=''),
                'Content-Type': 'application/octet-stream', 'Content-Length': str(Path(path).stat().st_size),
                'X-Bz-Content-Sha1': checksum})
        if result.get('bucketId') != self.bucket or result.get('fileName') != name or result.get('contentSha1') != checksum or result.get('contentLength') != Path(path).stat().st_size or not result.get('fileId'):
            raise Failure('upload_acknowledgement_mismatch')
        return result['fileId']

    def download(self, file_id, destination):
        url = self.download_url + '/b2api/v2/b2_download_file_by_id?fileId=' + urllib.parse.quote(file_id, safe='')
        self.request(url, headers={'Authorization': self.token}, destination=destination)


def upload(package, transport):
    package = recovery.secure_directory(package)
    record = json.loads(private_file(package / 'seal.json').read_text())
    ciphertext = private_file(package / 'recovery.tar.gz.age')
    if sha(ciphertext) != record['ciphertext_sha256'] or ciphertext.stat().st_size != record['ciphertext_bytes']:
        raise Failure('local_ciphertext_mismatch')
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', record['package_id']):
        raise Failure('unsafe_package_id')
    if (package / 'upload-receipt.json').exists():
        raise Failure('already_uploaded_use_existing_receipt')
    attempt_prefix = transport.prefix + record['package_id'] + '/' + uuid.uuid4().hex + '/'
    name = attempt_prefix + 'recovery.tar.gz.age'
    file_id = transport.upload(ciphertext, name)
    with tempfile.TemporaryDirectory(prefix='.readback-', dir=package) as tmp:
        downloaded = Path(tmp) / 'remote.age'
        transport.download(file_id, downloaded)
        if sha(downloaded) != record['ciphertext_sha256'] or downloaded.stat().st_size != record['ciphertext_bytes']:
            raise Failure('remote_ciphertext_mismatch')
    completion = dict(record, ciphertext_file_id=file_id, bucket_id=transport.bucket,
                      object_name=name, remote_verified_at=dt.datetime.now(dt.timezone.utc).isoformat())
    with tempfile.TemporaryDirectory(prefix='.marker-', dir=package) as tmp:
        marker = Path(tmp) / 'complete.json'
        json_file(marker, completion)
        marker_id = transport.upload(marker, attempt_prefix + 'complete.json')
        readback = Path(tmp) / 'marker-readback.json'
        transport.download(marker_id, readback)
        if sha(readback) != sha(marker):
            raise Failure('completion_marker_mismatch')
        completion.update({'completion_file_id': marker_id, 'completion_sha256': sha(marker)})
    json_file(package / 'upload-receipt.json', completion)
    recovery.sync_directory(package)
    return sha(package / 'upload-receipt.json')


def retrieve(receipt, expected_hash, output, transport):
    check_hash(expected_hash)
    receipt = private_file(receipt)
    if sha(receipt) != expected_hash:
        raise Failure('untrusted_receipt')
    record = json.loads(receipt.read_text())
    if record['bucket_id'] != transport.bucket or not record['object_name'].startswith(transport.prefix):
        raise Failure('receipt_destination_mismatch')
    output = recovery.secure_directory(output)
    stage = Path(tempfile.mkdtemp(prefix='.retrieving-', dir=output))
    try:
        marker = stage / 'complete.json'
        transport.download(record['completion_file_id'], marker)
        if sha(marker) != record['completion_sha256']:
            raise Failure('completion_marker_mismatch')
        remote_record = json.loads(marker.read_text())
        if remote_record != {key: value for key, value in record.items() if key not in {'completion_file_id', 'completion_sha256'}}:
            raise Failure('completion_marker_contents_mismatch')
        ciphertext = stage / 'recovery.tar.gz.age'
        transport.download(record['ciphertext_file_id'], ciphertext)
        if sha(ciphertext) != record['ciphertext_sha256'] or ciphertext.stat().st_size != record['ciphertext_bytes']:
            raise Failure('remote_ciphertext_mismatch')
        json_file(stage / 'receipt.json', record)
        destination = output / record['package_id']
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', record['package_id']) or destination.exists():
            raise Failure('new_retrieval_directory_required')
        for path in stage.iterdir():
            recovery.sync_file(path)
        recovery.sync_directory(stage)
        stage.rename(destination)
        recovery.sync_directory(output)
        return destination
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def decrypt(package, identity, output, receipt_sha, age='age'):
    package = recovery.secure_directory(package)
    check_hash(receipt_sha)
    receipt = private_file(package / 'receipt.json')
    if sha(receipt) != receipt_sha:
        raise Failure('untrusted_receipt')
    record = json.loads(receipt.read_text())
    if machine_id() == record['source_machine_id']:
        raise Failure('decryption_on_source_host_forbidden')
    identity = private_file(identity)
    output = recovery.secure_directory(output)
    if sha(package / 'recovery.tar.gz.age') != record['ciphertext_sha256']:
        raise Failure('ciphertext_mismatch')
    stage = Path(tempfile.mkdtemp(prefix='.decrypting-', dir=output))
    try:
        plaintext = stage / 'plaintext.tar.gz'
        with plaintext.open('xb') as handle:
            process = subprocess.Popen([age, '--decrypt', '--identity', str(identity), str(package / 'recovery.tar.gz.age')],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={'PATH': os.defpath})
            watchdog = threading.Timer(120, process.kill)
            watchdog.daemon = True
            watchdog.start()
            try:
                count = 0
                while chunk := process.stdout.read(1024 * 1024):
                    count += len(chunk)
                    if count > MAX_BYTES:
                        raise Failure('plaintext_archive_size_limit')
                    handle.write(chunk)
                if process.wait(timeout=5) != 0:
                    raise Failure('decryption_failed')
            finally:
                watchdog.cancel()
                process.stdout.close()
                if process.poll() is None:
                    process.kill()
                    process.wait()
        if plaintext.stat().st_size > MAX_BYTES:
            raise Failure('plaintext_archive_size_limit')
        with tarfile.open(plaintext, 'r|gz') as archive:
            allowed = {'inventory.json'} | {'bundle/' + name for name in ('manifest.json', 'verification.json', 'database.sqlite3', 'release.tar.gz')}
            seen, total = set(), 0
            for member in archive:
                if (member.name not in allowed and not re.fullmatch(r'(configuration|evidence)/[0-9]{4}', member.name)) or not member.isfile() or member.name in seen:
                    raise Failure('unsafe_recovery_archive')
                seen.add(member.name)
                total += member.size
                if total > MAX_BYTES:
                    raise Failure('expanded_archive_size_limit')
                target = stage / member.name
                target.parent.mkdir(mode=0o700, exist_ok=True)
                with target.open('xb') as handle:
                    shutil.copyfileobj(archive.extractfile(member), handle)
            if not allowed <= seen:
                raise Failure('incomplete_recovery_archive')
        plaintext.unlink()
        inventory = json.loads((stage / 'inventory.json').read_text())
        if set(inventory['files']) != seen - {'inventory.json'}:
            raise Failure('inventory_mismatch')
        for name, expected in inventory['files'].items():
            if sha(stage / name) != expected:
                raise Failure('recovered_file_mismatch')
        if sha(stage / 'bundle/manifest.json') != record['manifest_sha256']:
            raise Failure('recovered_manifest_mismatch')
        if bool(any(name.startswith('configuration/') for name in seen)) != record['configuration_included'] or sum(name.startswith('evidence/') for name in seen) != record['evidence_count']:
            raise Failure('recovered_configuration_or_evidence_inventory_mismatch')
        for name in seen:
            if name.startswith('evidence/'):
                evidence = json.loads((stage / name).read_text())
                if evidence.get('commit') != record['commit'] or evidence.get('bundle') != record['bundle']:
                    raise Failure('recovered_evidence_mismatch')
        recovery.verify(stage / 'bundle')
        manifest = json.loads((stage / 'bundle/manifest.json').read_text())
        if manifest['commit'] != record['commit'] or manifest['sha256']['release.tar.gz'] != record['release_sha256'] or manifest['sha256']['database.sqlite3'] != record['snapshot_sha256']:
            raise Failure('recovered_release_mismatch')
        destination = output / record['package_id']
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', record['package_id']) or destination.exists():
            raise Failure('new_recovery_directory_required')
        json_file(stage / 'recovery-evidence.json', {'recovered_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                  'package_id': record['package_id'], 'commit': record['commit'],
                  'integrity': 'ok', 'configuration_included': record['configuration_included'],
                  'application_workflows': 'not_tested'})
        for path in stage.rglob('*'):
            if path.is_file():
                recovery.sync_file(path)
        recovery.sync_directory(stage)
        stage.rename(destination)
        recovery.sync_directory(output)
        return destination
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('seal')
    command.add_argument('--bundle', required=True)
    command.add_argument('--output', required=True)
    command.add_argument('--recipient', required=True)
    command.add_argument('--manifest-sha256', required=True)
    command.add_argument('--secret-file', action='append', default=[])
    command.add_argument('--public-file', action='append', default=[])
    command.add_argument('--evidence-file', action='append', default=[])
    command.add_argument('--age', default='age')
    for name in ('upload', 'retrieve'):
        command = commands.add_parser(name)
        command.add_argument('--bucket-id', required=True)
        command.add_argument('--prefix', default='sysethic/', help='Destination object prefix')
        command.add_argument('--key-prefix', help='Exact authorized key prefix; defaults to destination prefix')
        if name == 'upload':
            command.add_argument('--package', required=True)
        else:
            command.add_argument('--receipt', required=True)
            command.add_argument('--receipt-sha256', required=True)
            command.add_argument('--output', required=True)
    command = commands.add_parser('decrypt')
    command.add_argument('--package', required=True)
    command.add_argument('--identity', required=True)
    command.add_argument('--output', required=True)
    command.add_argument('--receipt-sha256', required=True)
    command.add_argument('--age', default='age')
    args = parser.parse_args()
    if args.command == 'seal':
        result = seal(args.bundle, args.output, args.recipient, args.manifest_sha256, args.secret_file, args.age, args.evidence_file, args.public_file)
    elif args.command == 'upload':
        result = upload(args.package, B2(args.bucket_id, args.prefix, 'upload', key_prefix=args.key_prefix))
    elif args.command == 'retrieve':
        result = retrieve(args.receipt, args.receipt_sha256, args.output, B2(args.bucket_id, args.prefix, 'recover', key_prefix=args.key_prefix))
    else:
        result = decrypt(args.package, args.identity, args.output, args.receipt_sha256, args.age)
    print(json.dumps({'status': 'ok', 'result': str(result)}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        reason = str(exc) if isinstance(exc, Failure) else type(exc).__name__
        print(json.dumps({'status': 'failed', 'reason': reason}))
        raise SystemExit(1)
