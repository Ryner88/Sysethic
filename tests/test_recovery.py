import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recovery', Path(__file__).resolve().parents[1] / 'scripts/saaoe_recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        (self.repo / 'web').mkdir()
        for name in ('config.py', 'saaoe_cli.py'):
            (self.repo / 'web' / name).write_text('# disposable release\n')
        (self.repo / 'web/saaoe_api.py').write_text("SAAOE_VERSION = 'test-version'\n")
        (self.repo / 'requirements.txt').write_text('# fixture\n')
        for name in ('.env', 'data/secret.db', 'src/venv/secret.py', 'logs/secret.csv'):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('sensitive fixture\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        self.db = self.repo / 'data/source.db'
        self.conn = sqlite3.connect(self.db)
        self.addCleanup(self.conn.close)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA wal_autocheckpoint=0')
        for table in recovery.REQUIRED_TABLES:
            self.conn.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY)')
        self.conn.commit()
        self.output = self.root / 'backups'

    def create(self):
        recovery.backup(self.db, self.repo, self.output, sys.executable)
        return next(self.output.iterdir())

    def test_wal_snapshot_includes_committed_not_uncommitted_data(self):
        self.conn.execute('INSERT INTO users VALUES (1)')
        self.conn.commit()
        self.conn.execute('INSERT INTO users VALUES (2)')
        bundle = self.create()
        with sqlite3.connect(bundle / 'database.sqlite3') as snapshot:
            self.assertEqual(snapshot.execute('SELECT id FROM users').fetchall(), [(1,)])
        self.assertEqual(recovery.verify(bundle)['integrity'], 'ok')
        self.assertEqual(bundle.stat().st_mode & 0o777, 0o700)
        self.assertEqual((bundle / 'database.sqlite3').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((bundle / 'verification.json').read_text())['application_health'], 'not_tested')

    def test_tampered_snapshot_rejected(self):
        bundle = self.create()
        with (bundle / 'database.sqlite3').open('ab') as stream:
            stream.write(b'tampered')
        with self.assertRaisesRegex(RuntimeError, 'checksum'):
            recovery.verify(bundle)

    def test_failed_schema_check_publishes_nothing(self):
        self.conn.execute('DROP TABLE users')
        self.conn.commit()
        with self.assertRaisesRegex(RuntimeError, 'schema'):
            self.create()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_dirty_release_rejected(self):
        (self.repo / 'web/config.py').write_text('changed\n')
        with self.assertRaisesRegex(RuntimeError, 'clean'):
            self.create()
        self.assertFalse(self.output.exists())

    def test_missing_source_not_created(self):
        missing = self.root / 'missing.db'
        with self.assertRaises(RuntimeError):
            recovery.snapshot(missing, self.root / 'dest.db')
        self.assertFalse(missing.exists())

    def test_archive_excludes_even_tracked_sensitive_paths(self):
        (self.repo / 'untracked-token.txt').write_text('untracked fixture')
        bundle = self.create()
        with tarfile.open(bundle / 'release.tar.gz') as archive:
            self.assertEqual(set(archive.getnames()), {
                'requirements.txt', 'web/config.py', 'web/saaoe_cli.py', 'web/saaoe_api.py'})
            self.assertTrue(all(member.isfile() for member in archive.getmembers()))

    def test_source_aliases_and_existing_destination_rejected(self):
        before = recovery.digest(self.db)
        for destination in (self.db, self.root / 'alias.db'):
            if destination != self.db:
                destination.hardlink_to(self.db)
            with self.assertRaises(FileExistsError):
                recovery.snapshot(self.db, destination)
        self.assertEqual(recovery.digest(self.db), before)

    def test_symlink_source_rejected(self):
        link = self.root / 'linked.db'
        link.symlink_to(self.db)
        with self.assertRaises(RuntimeError):
            recovery.snapshot(link, self.root / 'copy.db')

    def test_permissive_backup_root_rejected(self):
        self.output.mkdir(mode=0o755)
        self.output.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, 'privately owned'):
            self.create()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_symlink_backup_root_rejected(self):
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        self.output.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'Symlinked'):
            self.create()

    def test_storage_inside_deployment_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'separate'):
            recovery.backup(self.db, self.repo, self.repo / 'backups', sys.executable)

    def test_archive_symlink_rejected(self):
        path = self.repo / 'web/config.py'
        path.unlink()
        path.symlink_to('/etc/passwd')
        subprocess.run(['git', '-C', str(self.repo), 'add', 'web/config.py'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'link'], check=True)
        with self.assertRaisesRegex(RuntimeError, 'links'):
            self.create()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_manifest_traversal_rejected(self):
        bundle = self.create()
        manifest = json.loads((bundle / 'manifest.json').read_text())
        manifest['sha256']['../outside'] = 'bad'
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(RuntimeError, 'Unexpected'):
            recovery.verify(bundle)

    def test_snapshot_timeout_publishes_nothing(self):
        with self.assertRaises(TimeoutError):
            recovery.snapshot(self.db, self.root / 'timed.db', timeout=-1)

    def test_failed_archive_sync_removes_staging(self):
        with patch.object(recovery, 'sync_file', side_effect=OSError('fixture')):
            with self.assertRaises(OSError):
                self.create()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_bundle_symlink_rejected(self):
        bundle = self.create()
        path = bundle / 'database.sqlite3'
        original = self.root / 'copied.db'
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaisesRegex(RuntimeError, 'private and regular'):
            recovery.verify(bundle)

    def test_restore_test_checks_version_schema_auth_and_preserves_snapshot(self):
        # A synthetic application exercises the subprocess contract without production data.
        app = self.repo / 'web/saaoe_api.py'
        app.write_text('''SAAOE_VERSION = 'test-version'
class Response:
    def __init__(self, code, data=None): self.status_code, self.json = code, data
class Client:
    def get(self, path):
        if path == '/healthz': return Response(200, {'ok':True,'version':SAAOE_VERSION})
        return Response(401)
class App:
    def test_client(self): return Client()
def create_app(config): return App()
''')
        subprocess.run(['git', '-C', str(self.repo), 'add', 'web/saaoe_api.py'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'test app'], check=True)
        bundle = self.create()
        original = recovery.digest(bundle / 'database.sqlite3')
        output = self.root / 'restore-results'
        output.mkdir(mode=0o700)
        recovery.restore_test(bundle, sys.executable, output)
        result = json.loads(next(output.glob('*.json')).read_text())
        self.assertTrue(result['schema_unchanged_after_startup'])
        self.assertEqual(result['application_health'], 'ok')
        self.assertEqual(recovery.digest(bundle / 'database.sqlite3'), original)
        self.assertFalse(list(output.glob('.restore-*')))


if __name__ == '__main__':
    unittest.main()
