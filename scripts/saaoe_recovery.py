"""Consistent SQLite snapshots paired with tracked Git releases; no secret logging."""
import argparse
import ast
from contextlib import closing
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


REQUIRED_TABLES = {'users', 'audit_events', 'response_approvals', 'playbooks', 'validation_events'}
RELEASE_PATHS = {
    'requirements.txt', 'saaoe_cli.py',
    'src/process_monitor.py', 'src/visualize_logs.py',
    'web/config.py', 'web/ethics_ui.py', 'web/plot_metrics.py',
    'web/saaoe_api.py', 'web/saaoe_cli.py',
    'web/static/sysethic.css', 'web/static/vocabulary.js',
} | {'web/templates/' + name + '.html' for name in (
    'analytics anomalies anomaly_detail approvals assets audit_logs automation '
    'base dashboard ethics files incidents join login playbooks processes reports '
    'security setup signup terminal threat_trends users validation visualization_lab'
).split()}


def secure_directory(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise RuntimeError('Symlinked directory rejected')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RuntimeError('Directory must be privately owned with mode 0700')
    return path


def release_archive(repo, commit, destination):
    entries = git(repo, 'ls-tree', '-rz', commit).split(b'\0')
    approved = []
    hashes = {}
    version = None
    with tarfile.open(destination, 'w:gz') as archive:
        for entry in entries:
            if not entry:
                continue
            metadata, raw_path = entry.split(b'\t', 1)
            path = raw_path.decode()
            if path not in RELEASE_PATHS:
                continue
            mode, kind, oid = metadata.split()
            if kind != b'blob' or mode not in (b'100644', b'100755'):
                raise RuntimeError('Release links and nonregular objects rejected')
            data = git(repo, 'cat-file', 'blob', oid.decode())
            if path == 'web/saaoe_api.py':
                for node in ast.parse(data).body:
                    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'SAAOE_VERSION' for t in node.targets):
                        version = ast.literal_eval(node.value)
            item = tarfile.TarInfo(path)
            item.size = len(data)
            item.mode = 0o600
            archive.addfile(item, io.BytesIO(data))
            approved.append(path)
            hashes[path] = hashlib.sha256(data).hexdigest()
    if not {'requirements.txt', 'web/config.py', 'web/saaoe_api.py', 'web/saaoe_cli.py'} <= set(approved) or not isinstance(version, str):
        raise RuntimeError('Release lacks required application files/version')
    return hashes, version


def validate_archive(path, hashes, extract_to=None):
    with tarfile.open(path, 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(hashes) or {m.name for m in members} != set(hashes):
            raise RuntimeError('Release inventory mismatch')
        for member in members:
            if member.name not in RELEASE_PATHS or not member.isfile():
                raise RuntimeError('Unsafe release archive member')
            data = archive.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != hashes[member.name]:
                raise RuntimeError('Release file checksum mismatch')
            if extract_to is not None:
                target = Path(extract_to) / member.name
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with target.open('xb') as handle:
                    handle.write(data)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inspect_database(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        if conn.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise RuntimeError('SQLite integrity verification failed')
        schema = conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master "
                              "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").fetchall()
        tables = {row[1] for row in schema if row[0] == 'table'}
        if not REQUIRED_TABLES <= tables:
            raise RuntimeError('Application schema preflight failed')
        return hashlib.sha256(json.dumps(schema).encode()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def snapshot(source, destination, timeout=120):
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if source.is_symlink() or not source.is_file():
        raise RuntimeError('Source must be an existing regular database')
    # Exclusive creation rejects existing destinations, hard links, and aliases.
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    source_identity = source.stat()
    deadline = time.monotonic() + timeout
    def progress(status, remaining, total):
        if time.monotonic() > deadline:
            raise TimeoutError('SQLite backup deadline exceeded')
    with closing(sqlite3.connect(Path(source).resolve().as_uri() + '?mode=ro', uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst, pages=256, progress=progress, sleep=0.1)
    after = source.stat()
    if (after.st_dev, after.st_ino) != (source_identity.st_dev, source_identity.st_ino):
        raise RuntimeError('Source database replaced during backup')


def verify(bundle):
    bundle = secure_directory(bundle)
    for name in ('manifest.json', 'database.sqlite3', 'release.tar.gz', 'verification.json'):
        path = bundle / name
        if name == 'verification.json' and not path.exists():
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError('Bundle artifact must be private and regular')
    manifest = json.loads((bundle / 'manifest.json').read_text())
    expected_names = {'database.sqlite3', 'release.tar.gz'}
    if set(manifest['sha256']) != expected_names:
        raise RuntimeError('Unexpected manifest files')
    for name, expected in manifest['sha256'].items():
        if digest(bundle / name) != expected:
            raise RuntimeError('Artifact checksum mismatch')
    validate_archive(bundle / 'release.tar.gz', manifest['release_files'])
    # Restore into disposable storage; never open production or mutate the snapshot.
    with tempfile.TemporaryDirectory(prefix='saaoe-restore-') as directory:
        restored = Path(directory) / 'restored.sqlite3'
        shutil.copyfile(bundle / 'database.sqlite3', restored)
        if inspect_database(restored) != manifest['schema_sha256']:
            raise RuntimeError('Restored schema mismatch')
    return {'verified_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'bundle': bundle.name, 'commit': manifest['commit'],
            'integrity': 'ok', 'schema_preflight': 'ok',
            'application_health': 'not_tested'}


def restore_test(bundle, python, output):
    """Run only in a network/privilege-isolated sandbox; uses disposable copies."""
    os.umask(0o077)
    bundle = secure_directory(bundle)
    record = verify(bundle)
    manifest = json.loads((bundle / 'manifest.json').read_text())
    output = secure_directory(output)
    if output == bundle or bundle in output.parents:
        raise RuntimeError('Test output must be separate from bundle')
    with tempfile.TemporaryDirectory(prefix='.restore-', dir=output) as directory:
        root = Path(directory)
        validate_archive(bundle / 'release.tar.gz', manifest['release_files'], root)
        (root / 'data').mkdir(mode=0o700)
        database = root / 'data/saaoe.db'
        shutil.copyfile(bundle / 'database.sqlite3', database)
        before = inspect_database(database)
        # Clean environment; archive never contains .env. No production config is read.
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(root),
                       'PYTHONDONTWRITEBYTECODE': '1', 'MPLCONFIGDIR': str(root / 'mpl'),
                       'SAAOE_MODE': 'production', 'SAAOE_SECRET_KEY': uuid.uuid4().hex + uuid.uuid4().hex,
                       'SAAOE_DATABASE_PATH': str(database), 'SAAOE_LOG_PATH': str(root / 'logs/test.csv'),
                       'SAAOE_HOST': '127.0.0.1', 'SAAOE_DEBUG': 'false',
                       'SAAOE_SESSION_COOKIE_SECURE': 'true', 'SAAOE_ENABLE_TERMINAL_WS': 'false',
                       'THREAT_INTEL_PATH': str(root / 'config/threat_intel.json')}
        code = '''import sys,json,importlib.metadata as m
sys.path.insert(0, sys.argv[1])
from web import saaoe_api
app = saaoe_api.create_app({'TESTING': True})
client = app.test_client()
health = client.get('/healthz')
protected = client.get('/api/users')
assert health.status_code == 200 and health.json.get('ok') is True
assert health.json.get('version') == sys.argv[2]
assert protected.status_code in (401,403)
result = {'application_health':'ok','application_version':health.json['version'],
          'unauthenticated_access':'denied','python':sys.version.split()[0],
          'packages':sorted((d.metadata['Name'],d.version) for d in m.distributions() if d.metadata['Name'])}
with open(sys.argv[3], 'x') as handle: json.dump(result,handle)
'''
        result_path = root / 'result.json'
        subprocess.run([python, '-B', '-c', code, str(root), manifest['application_version'], str(result_path)],
                       cwd=root, env=environment, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True, timeout=120)
        result = json.loads(result_path.read_text())
        if {'python': result['python'], 'packages': result['packages']} != manifest['versions']:
            raise RuntimeError('Restore runtime differs from recorded release runtime')
        after = inspect_database(database)
        if before != after:
            raise RuntimeError('Application startup changed database schema; compatibility review required')
        record.update({key: result[key] for key in ('application_health', 'application_version', 'unauthenticated_access')})
        record.update({'schema_unchanged_after_startup': True,
                       'runtime_matches_manifest': True, 'schema_sha256': after,
                       'snapshot_sha256': manifest['sha256']['database.sqlite3'],
                       'release_sha256': manifest['sha256']['release.tar.gz'],
                       'scope': 'startup-health-auth-guard; full workflows and config recovery not tested'})
    identity = bundle.name + '-' + uuid.uuid4().hex[:8] + '.json'
    with (output / identity).open('x') as handle:
        json.dump(record, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    sync_directory(output)
    print(json.dumps(record))


def sync_file(path):
    with Path(path).open('rb') as stream:
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def backup(database, repo, output, python):
    os.umask(0o077)
    repo, output = Path(repo).resolve(), Path(output).absolute()
    database = Path(database).absolute()
    if output == repo or repo in output.parents or output == database.parent or database.parent in output.parents:
        raise RuntimeError('Backup storage must be separate from deployment/database')
    commit = git(repo, 'rev-parse', 'HEAD').decode().strip()
    if git(repo, 'status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('Tracked deployment is not clean')
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = secure_directory(output)
    identity = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    stage = Path(tempfile.mkdtemp(prefix='.pending-', dir=output))
    try:
        snapshot(database, stage / 'database.sqlite3')
        schema_hash = inspect_database(stage / 'database.sqlite3')
        release_files, app_version = release_archive(repo, commit, stage / 'release.tar.gz')
        # Python distribution metadata only; do not collect environment or pip URLs.
        code = ('import sys,json,importlib.metadata as m; '
                'print(json.dumps({"python":sys.version.split()[0],"packages":'
                'sorted((d.metadata["Name"],d.version) for d in m.distributions() '
                'if d.metadata["Name"])}))')
        versions = json.loads(subprocess.check_output([python, '-B', '-c', code]))
        if git(repo, 'rev-parse', 'HEAD').decode().strip() != commit or git(repo, 'status', '--porcelain', '--untracked-files=no'):
            raise RuntimeError('Deployment changed during backup')
        manifest = {'commit': commit, 'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'schema_sha256': schema_hash, 'versions': versions,
                    'application_version': app_version, 'release_files': release_files,
                    'configuration_backup': 'not_included',
                    'sha256': {name: digest(stage / name) for name in ('database.sqlite3', 'release.tar.gz')}}
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        record = verify(stage)
        record['bundle'] = identity
        (stage / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
        for path in stage.iterdir():
            sync_file(path)
        sync_directory(stage)
        stage.rename(output / identity)
        sync_directory(output)
        print(json.dumps({'published': identity, 'commit': commit, 'integrity': 'ok',
                          'application_health': 'not_tested'}))
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('backup')
    create.add_argument('--database', required=True)
    create.add_argument('--repo', required=True)
    create.add_argument('--output', required=True)
    create.add_argument('--python', required=True)
    check = commands.add_parser('verify')
    check.add_argument('bundle')
    restore = commands.add_parser('restore-test')
    restore.add_argument('bundle')
    restore.add_argument('--python', required=True)
    restore.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.command == 'backup':
        backup(args.database, args.repo, args.output, args.python)
    elif args.command == 'restore-test':
        restore_test(args.bundle, args.python, args.output)
    else:
        os.umask(0o077)
        print(json.dumps(verify(args.bundle)))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Avoid printing arbitrary subprocess output or database values.
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__}))
        raise SystemExit(1)
