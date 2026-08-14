import importlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


class InstallationStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SAAOE_ENV'] = 'development'
        os.environ['SAAOE_SECRET_KEY'] = 'test-secret'
        cls.appmod = importlib.import_module('web.saaoe_api')
        cls.cli = importlib.import_module('web.saaoe_cli')

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        os.unlink(self.tmp.name)
        self.original_db_path = self.appmod.DB_PATH
        self.appmod.DB_PATH = self.tmp.name
        self.appmod.init_db()
        self.appmod._seed_db()
        self.appmod.load_persistent_state()
        self.client = self.appmod.app.test_client()

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def test_create_app_returns_shared_app_and_healthz_is_sanitized(self):
        app = self.appmod.create_app({'TESTING': True})
        self.assertIs(app, self.appmod.app)

        response = self.client.get('/healthz')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['service'], 'saaoe')
        self.assertTrue(response.json['ok'])
        serialized = json.dumps(response.json)
        self.assertNotIn('SECRET', serialized.upper())
        self.assertNotIn('password', serialized.lower())
        self.assertNotIn(str(self.tmp.name), serialized)
        self.assertNotIn('mode', response.json)

    def test_bootstrap_admin_only_when_user_table_empty_and_sanitizes_audit(self):
        with patch('web.saaoe_cli.input', return_value='console-admin'), \
                patch('web.saaoe_cli.getpass.getpass', side_effect=['longpassword1', 'longpassword1']), \
                redirect_stdout(io.StringIO()):
            result = self.cli.bootstrap_admin(type('Args', (), {'username': None})())

        self.assertEqual(result, 0)
        admin = self.appmod.get_user_by_username('console-admin')
        self.assertEqual(admin['role'], 'admin')
        self.assertNotEqual(admin['password_hash'], 'longpassword1')
        self.assertTrue(self.appmod.check_password_hash(admin['password_hash'], 'longpassword1'))

        audit = self.appmod._db_query(
            "SELECT event_type, detail, details_json FROM audit_events WHERE event_type = ?",
            ('admin_bootstrap_created',),
        )
        self.assertEqual(len(audit), 1)
        audit_blob = json.dumps(audit)
        self.assertNotIn('longpassword1', audit_blob)
        self.assertNotIn(admin['password_hash'], audit_blob)

        with self.assertRaisesRegex(self.cli.CliError, 'allowed only while the user table is empty'):
            self.cli.bootstrap_admin(type('Args', (), {'username': 'another-admin'})())

    def test_health_local_checks_auth_contract_without_treating_404_as_success(self):
        payload = self.cli.run_health(local=True, as_json=True)
        checks = {check['name']: check for check in payload['checks']}
        self.assertIn('protected page', checks)
        self.assertIn('protected API', checks)
        self.assertTrue(checks['protected page']['ok'])
        self.assertTrue(checks['protected API']['ok'])
        self.assertNotEqual(checks['protected API']['detail'], 'status=404')

    def test_stop_refuses_pid_reuse_or_wrong_command_identity(self):
        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            pid_file.write_text(
                json.dumps({
                    'pid': os.getpid(),
                    'create_time': self.cli.psutil.Process(os.getpid()).create_time(),
                    'cmd': ['unrelated'],
                }),
                encoding='utf-8',
            )
            with patch.object(self.cli, 'PID_FILE', pid_file):
                with redirect_stdout(io.StringIO()):
                    result = self.cli.stop(type('Args', (), {'force': False})())

            self.assertEqual(result, 1)
            self.assertTrue(pid_file.exists())

    def test_stop_preserves_tampered_and_creation_time_mismatched_metadata(self):
        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            pid_file.write_text('{not-json', encoding='utf-8')
            with patch.object(self.cli, 'PID_FILE', pid_file):
                with redirect_stdout(io.StringIO()):
                    result = self.cli.stop(type('Args', (), {'force': False})())
            self.assertEqual(result, 1)
            self.assertTrue(pid_file.exists())

            proc = self.cli.psutil.Process(os.getpid())
            pid_file.write_text(
                json.dumps({
                    'pid': os.getpid(),
                    'create_time': proc.create_time() - 60,
                    'cmd': ['web.saaoe_cli', 'run', '--foreground'],
                }),
                encoding='utf-8',
            )
            with patch.object(self.cli, 'PID_FILE', pid_file):
                with redirect_stdout(io.StringIO()):
                    result = self.cli.stop(type('Args', (), {'force': False})())
            self.assertEqual(result, 1)
            self.assertTrue(pid_file.exists())


if __name__ == '__main__':
    unittest.main()
