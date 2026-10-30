"""Qualification of an archived release in a fresh, isolated environment."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile

import saaoe_recovery as recovery


EXPECTED_COMMIT = 'a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb'
EXPECTED_MANIFEST = '461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe'


def require_isolation(host_netns):
    if os.readlink('/proc/self/ns/net') == host_netns:
        raise RuntimeError('Private network namespace required')
    status = Path('/proc/self/status').read_text()
    caps = next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:'))
    if int(caps, 16):
        raise RuntimeError('Effective capabilities must be empty')
    for name in ('/opt/saaoe/data/saaoe.db', '/opt/saaoe/.env'):
        try:
            fd = os.open(name, os.O_RDONLY)
        except (PermissionError, FileNotFoundError):
            continue
        else:
            os.close(fd)
            raise RuntimeError('Production path is accessible')


def checked_manifest(bundle):
    bundle = recovery.secure_directory(bundle)
    if recovery.digest(bundle / 'manifest.json') != EXPECTED_MANIFEST:
        raise RuntimeError('Manifest differs from independently recorded hash')
    recovery.verify(bundle)
    manifest = json.loads((bundle / 'manifest.json').read_text())
    if manifest['commit'] != EXPECTED_COMMIT:
        raise RuntimeError('Release commit mismatch')
    return manifest


def prepare(bundle, work, host_netns):
    require_isolation(host_netns)
    manifest = checked_manifest(bundle)
    work = Path(work).absolute()
    recovery.secure_directory(work.parent)
    work.mkdir(mode=0o700)
    recovery.secure_directory(work)
    release = work / 'release'
    release.mkdir(mode=0o700)
    recovery.validate_archive(Path(bundle) / 'release.tar.gz', manifest['release_files'], release)
    (work / 'prepared.json').write_text(json.dumps({
        'commit': manifest['commit'], 'manifest_sha256': EXPECTED_MANIFEST,
        'release_sha256': manifest['sha256']['release.tar.gz'],
        'snapshot_present_in_network_build_directory': False,
    }, indent=2) + '\n')
    print(json.dumps({'prepared': str(work), 'commit': manifest['commit'], 'database_copied': False}))


def workflow(root, expected_version, result_path):
    """Child process: only synthetic rows in a new workspace are exercised."""
    sys.path.insert(0, str(root))
    from web import saaoe_api as appmod
    app = appmod.create_app({'TESTING': True})
    database = root / 'data/saaoe.db'
    if Path(appmod.DB_PATH).resolve() != database.resolve():
        raise RuntimeError('Application database path differs from isolated copy')
    secret = (root / '.synthetic-key').read_text()
    if appmod.CONFIG.secret_key != secret or not appmod.CONFIG.session_cookie_secure:
        raise RuntimeError('Synthetic protected configuration did not recover')
    if (root / '.env').stat().st_mode & 0o077:
        raise RuntimeError('Configuration permissions are too broad')
    client = app.test_client()
    base = 'https://localhost'
    health = client.get('/healthz', base_url=base)
    if health.status_code != 200 or health.json.get('version') != expected_version:
        raise RuntimeError('Health/version mismatch')
    suffix = secrets.token_hex(6)
    admin, viewer, workspace = 'qaadmin_' + suffix, 'qaviewer_' + suffix, 'Recovery QA ' + suffix
    admin_password, viewer_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    response = client.post('/signup', base_url=base, data={
        'username': admin, 'organization': workspace,
        'password': admin_password, 'confirm': admin_password})
    if response.status_code != 302:
        raise RuntimeError('Synthetic signup failed')
    client.get('/logout', base_url=base)
    response = client.post('/login', base_url=base, data={'username': admin, 'password': admin_password})
    if response.status_code != 302:
        raise RuntimeError('Synthetic login failed')
    response = client.get('/', base_url=base)
    if response.status_code != 200:
        raise RuntimeError('Authenticated dashboard failed')
    response = client.post('/api/users', base_url=base, json={
        'username': viewer, 'password': viewer_password, 'role': 'viewer'})
    if response.status_code != 200 or not response.json.get('success'):
        raise RuntimeError('Synthetic member creation failed')
    response = client.get('/api/users', base_url=base)
    if response.status_code != 200 or {u['username'] for u in response.json['users']} != {admin, viewer}:
        raise RuntimeError('Synthetic workspace read isolation failed')
    key = 'recovery_qualification_' + suffix
    for value in ('created', 'updated'):
        response = client.post('/api/configuration', base_url=base, json={'key': key, 'value': value})
        if response.status_code != 200 or not response.json.get('success'):
            raise RuntimeError('Synthetic configuration write failed')
        response = client.get('/api/configuration', base_url=base)
        if response.status_code != 200 or not any(row['key'] == key and row['value'] == value for row in response.json['configuration']):
            raise RuntimeError('Synthetic configuration readback failed')
    client.get('/logout', base_url=base)
    if client.get('/api/users', base_url=base).status_code != 401:
        raise RuntimeError('Logout did not invalidate authentication')
    viewer_client = app.test_client()
    if viewer_client.post('/login', base_url=base, data={'username': viewer, 'password': viewer_password}).status_code != 302:
        raise RuntimeError('Synthetic viewer login failed')
    if viewer_client.post('/api/configuration', base_url=base, json={'key': key, 'value': 'forbidden'}).status_code != 403:
        raise RuntimeError('Viewer write authorization failed')
    # Prove committed persistence using a separate read-only SQLite connection.
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True) as conn:
        row = conn.execute('SELECT value FROM app_configuration WHERE updated_by=? AND key LIKE ?',
                           (admin, '%:' + key)).fetchone()
        if not row or json.loads(row[0]) != 'updated':
            raise RuntimeError('Committed synthetic write not persisted')
        count = conn.execute('SELECT COUNT(*) FROM audit_events WHERE actor=?', (admin,)).fetchone()[0]
        if count < 1:
            raise RuntimeError('Synthetic audit persistence failed')
    result = {'application_version': expected_version, 'health': 'ok',
              'synthetic_signup_login_logout': 'ok', 'authenticated_dashboard': 'ok',
              'synthetic_member_create_read': 'ok', 'workspace_read_isolation': 'ok',
              'synthetic_configuration_create_update_read': 'ok', 'committed_sqlite_persistence': 'ok',
              'synthetic_audit_persistence': 'ok', 'viewer_write_denied': 'ok',
              'synthetic_protected_configuration_recovery': 'ok',
              'production_configuration_recovery': 'not_verified'}
    Path(result_path).write_text(json.dumps(result))


def qualify(bundle, work, host_netns):
    require_isolation(host_netns)
    manifest = checked_manifest(bundle)
    work = recovery.secure_directory(work)
    python = work / 'venv/bin/python'
    if not python.is_file():
        raise RuntimeError('Fresh virtual environment is missing')
    release = work / 'release'
    for name, expected in manifest['release_files'].items():
        if recovery.digest(release / name) != expected:
            raise RuntimeError('Prepared release file changed')
    metadata = 'import json,sys,importlib.metadata as m; print(json.dumps({"python":sys.version.split()[0],"packages":sorted((d.metadata["Name"],d.version) for d in m.distributions() if d.metadata["Name"])}))'
    clean_env = {'PATH': '/usr/bin:/bin', 'HOME': str(work), 'PYTHONDONTWRITEBYTECODE': '1'}
    versions = json.loads(subprocess.check_output([str(python), '-B', '-c', metadata], env=clean_env))
    if versions != manifest['versions']:
        raise RuntimeError('Fresh runtime differs from manifest')
    with tempfile.TemporaryDirectory(prefix='.workflow-', dir=work) as temporary:
        root = Path(temporary)
        recovery.validate_archive(Path(bundle) / 'release.tar.gz', manifest['release_files'], root)
        (root / 'data').mkdir(mode=0o700)
        database = root / 'data/saaoe.db'
        shutil.copyfile(Path(bundle) / 'database.sqlite3', database)
        before = recovery.inspect_database(database)
        secret = secrets.token_urlsafe(48)
        config = '\n'.join([
            'SAAOE_MODE=production', 'SAAOE_SECRET_KEY=' + secret,
            'SAAOE_HOST=127.0.0.1', 'SAAOE_DEBUG=false', 'SAAOE_SESSION_COOKIE_SECURE=true',
            'SAAOE_ENABLE_TERMINAL_WS=false', 'SAAOE_DATABASE_PATH=' + str(database),
            'SAAOE_LOG_PATH=' + str(root / 'logs/synthetic.csv'),
            'THREAT_INTEL_PATH=' + str(root / 'config/threat_intel.json'), ''])
        (root / '.synthetic-key').write_text(secret)
        saved = root / 'config.fixture'
        saved.write_text(config)
        shutil.copyfile(saved, root / '.env')
        if recovery.digest(saved) != recovery.digest(root / '.env'):
            raise RuntimeError('Synthetic configuration copy mismatch')
        clean_env['MPLCONFIGDIR'] = str(root / 'mpl')
        clean_env['SAAOE_QUALIFY_HOST_NETNS'] = host_netns
        result_path = root / 'result.json'
        subprocess.run([str(python), '-B', str(Path(__file__).resolve()), 'worker',
                        str(root), manifest['application_version'], str(result_path)],
                       env=clean_env, cwd=root, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=True, timeout=180)
        result = json.loads(result_path.read_text())
        after = recovery.inspect_database(database)
        if before != after:
            raise RuntimeError('Workflow changed database schema')
    if recovery.digest(Path(bundle) / 'database.sqlite3') != manifest['sha256']['database.sqlite3']:
        raise RuntimeError('Original backup snapshot changed')
    result.update({'qualified_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                   'bundle': Path(bundle).name, 'commit': manifest['commit'],
                   'manifest_sha256': EXPECTED_MANIFEST, 'artifact_sha256': manifest['sha256'],
                   'fresh_runtime_matches_manifest': True, 'schema_unchanged': True,
                   'snapshot_unchanged': True, 'network_isolation': 'checked',
                   'production_paths_inaccessible': True,
                   'scope': 'synthetic workflows; production config and off-host recovery not qualified'})
    output = work / 'qualification.json'
    with output.open('x') as handle:
        json.dump(result, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    recovery.sync_directory(work)
    print(json.dumps(result))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'qualify'):
        command = commands.add_parser(name)
        command.add_argument('--bundle', required=True)
        command.add_argument('--work', required=True)
        command.add_argument('--host-netns', required=True)
    command = commands.add_parser('worker')
    command.add_argument('root')
    command.add_argument('version')
    command.add_argument('result')
    args = parser.parse_args()
    if args.command == 'worker':
        require_isolation(os.environ['SAAOE_QUALIFY_HOST_NETNS'])
        workflow(Path(args.root), args.version, args.result)
    elif args.command == 'prepare':
        prepare(args.bundle, args.work, args.host_netns)
    else:
        qualify(args.bundle, args.work, args.host_netns)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__}))
        raise SystemExit(1)
