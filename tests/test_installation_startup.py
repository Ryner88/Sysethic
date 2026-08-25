import importlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import time
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
        setup_spec = importlib.util.spec_from_file_location('setup_saaoe_script', Path('scripts/setup_saaoe.py'))
        cls.setup_script = importlib.util.module_from_spec(setup_spec)
        setup_spec.loader.exec_module(cls.setup_script)

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
        self.assertEqual(response.json['version'], self.appmod.SAAOE_VERSION)
        serialized = json.dumps(response.json)
        self.assertNotIn('SECRET', serialized.upper())
        self.assertNotIn('password', serialized.lower())
        self.assertNotIn(str(self.tmp.name), serialized)
        self.assertNotIn('mode', response.json)
        self.assertNotIn('host', response.json)
        self.assertNotIn('port', response.json)
        self.assertNotIn('environment', response.json)
        self.assertNotIn('username', serialized.lower())

    def test_generated_env_uses_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with patch.object(self.cli, 'BASE_DIR', base):
                created = self.cli._write_env_if_missing()

            env_path = base / '.env'
            self.assertTrue(created)
            self.assertTrue(env_path.exists())
            if os.name != 'nt':
                mode = stat.S_IMODE(env_path.stat().st_mode)
                self.assertEqual(mode, 0o600)
            secret_line = next(line for line in env_path.read_text(encoding='utf-8').splitlines() if line.startswith('SAAOE_SECRET_KEY='))
            self.assertGreaterEqual(len(secret_line.split('=', 1)[1]), 32)

    def test_python_310_is_rejected(self):
        with patch.object(self.cli.sys, 'version_info', (3, 10, 9)):
            with self.assertRaisesRegex(self.cli.CliError, 'Python 3.11 or newer'):
                self.cli._check_python()
        with patch.object(self.setup_script.sys, 'version_info', (3, 10, 9)), \
                redirect_stdout(io.StringIO()), \
                patch('sys.stderr', new_callable=io.StringIO) as stderr:
            self.assertEqual(self.setup_script.main([]), 2)
            self.assertIn('Python 3.11 or newer', stderr.getvalue())

    def test_start_and_run_reject_non_loopback_bind(self):
        config = type('Config', (), {'host': '0.0.0.0', 'port': 5001, 'protected_bind': False})()
        with patch('web.saaoe_cli.load_config', return_value=config):
            with self.assertRaisesRegex(self.cli.CliError, 'loopback-only'):
                self.cli.start(type('Args', (), {})())
        with patch('web.saaoe_cli.load_config', return_value=config), \
                patch('web.saaoe_cli._load_app') as load_app:
            with self.assertRaisesRegex(self.cli.CliError, 'loopback-only'):
                self.cli.run(type('Args', (), {'foreground': True})())
            load_app.assert_not_called()

    def test_ipv4_and_ipv6_health_url_construction(self):
        self.assertEqual(self.cli._health_url('127.0.0.1', 5001), 'http://127.0.0.1:5001/healthz')
        self.assertEqual(self.cli._health_url('::1', 5001), 'http://[::1]:5001/healthz')

    def test_http_health_requires_payload_ok(self):
        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return b'{"ok": false, "service": "saaoe", "version": "phase5.13"}'

        with patch('web.saaoe_cli.urllib.request.urlopen', return_value=Response()):
            ok, detail = self.cli._http_health('127.0.0.1', 5001)

        self.assertFalse(ok)
        self.assertEqual(detail, 'http://127.0.0.1:5001/healthz')

    def test_health_exit_codes(self):
        args = type('Args', (), {'local': True, 'json': False})()
        with patch('web.saaoe_cli.run_health', return_value={'healthy': True, 'status': 'healthy', 'checks': []}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.health(args), 0)
        with patch('web.saaoe_cli.run_health', return_value={'healthy': False, 'status': 'failed', 'checks': [{'name': 'database', 'ok': False}]}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.health(args), 1)
        with patch('web.saaoe_cli.run_health', return_value={'healthy': False, 'status': 'command_error', 'checks': [{'name': 'configuration', 'ok': False}]}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.health(args), 2)
        with patch('web.saaoe_cli.run_health', return_value={'healthy': False, 'status': 'failed', 'checks': [{'name': 'live endpoint', 'ok': False}]}), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.health(args), 2)

    def test_sampler_liveness_and_staleness_drive_health(self):
        time.sleep(1.2)
        self.assertTrue(self.appmod.sampler_is_healthy())
        with patch.object(self.appmod, 'SAMPLER_THREAD', None), \
                patch.object(self.appmod, 'SAMPLER_STARTED_AT', time.time() - 100), \
                patch.object(self.appmod, 'SAMPLER_LAST_SUCCESS_AT', time.time() - 100):
            self.assertFalse(self.appmod.sampler_is_healthy())
            payload = self.cli.run_health(local=True)
            sampler = next(check for check in payload['checks'] if check['name'] == 'telemetry sampler')
            self.assertFalse(sampler['ok'])

    def test_sampler_startup_grace_allows_initial_warmup_only(self):
        thread = type('Thread', (), {'is_alive': lambda self: True})()
        with patch.object(self.appmod, 'SAMPLER_THREAD', thread), \
                patch.object(self.appmod, 'SAMPLER_STARTED_AT', time.time()), \
                patch.object(self.appmod, 'SAMPLER_LAST_SUCCESS_AT', 0.0):
            self.assertTrue(self.appmod.sampler_is_healthy())

        with patch.object(self.appmod, 'SAMPLER_THREAD', thread), \
                patch.object(self.appmod, 'SAMPLER_STARTED_AT', time.time() - 100), \
                patch.object(self.appmod, 'SAMPLER_LAST_SUCCESS_AT', 0.0):
            self.assertFalse(self.appmod.sampler_is_healthy())

    def test_healthz_returns_503_when_sampler_is_unhealthy(self):
        with patch('web.saaoe_api.sampler_is_healthy', return_value=False):
            response = self.client.get('/healthz')

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json['service'], 'saaoe')
        self.assertFalse(response.json['ok'])
        self.assertEqual(response.json['version'], self.appmod.SAAOE_VERSION)
        self.assertEqual(set(response.json), {'ok', 'service', 'version'})

    def test_spoofed_healthcheck_header_cannot_bypass_audit(self):
        self.appmod.create_user('admin', 'longpassword1', 'admin')
        response = self.client.get('/api/usage', headers={'X-SAAOE-Healthcheck': '1'})
        self.assertEqual(response.status_code, 401)
        denied = self.appmod._db_query("SELECT * FROM audit_events WHERE event_type = ? AND result = ?", ('access_denied', 'denied'))
        self.assertTrue(denied)

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

    def test_bootstrap_rejects_short_and_mismatched_passwords(self):
        with patch('web.saaoe_cli.getpass.getpass', side_effect=['short', 'short']):
            with self.assertRaisesRegex(self.cli.CliError, 'at least 10'):
                self.cli.bootstrap_admin(type('Args', (), {'username': 'console-admin'})())
        with patch('web.saaoe_cli.getpass.getpass', side_effect=['longpassword1', 'longpassword2']):
            with self.assertRaisesRegex(self.cli.CliError, 'do not match'):
                self.cli.bootstrap_admin(type('Args', (), {'username': 'console-admin'})())
        self.assertFalse(self.appmod.users_exist())

    def test_bootstrap_rolls_back_user_when_audit_insert_fails(self):
        with patch('web.saaoe_cli.getpass.getpass', side_effect=['longpassword1', 'longpassword1']), \
                patch('web.saaoe_cli.json.dumps', side_effect=RuntimeError('audit serialization failed')):
            with self.assertRaisesRegex(RuntimeError, 'audit serialization failed'):
                self.cli.bootstrap_admin(type('Args', (), {'username': 'console-admin'})())
        self.assertFalse(self.appmod.users_exist())
        audits = self.appmod._db_query("SELECT * FROM audit_events WHERE event_type = ?", ('admin_bootstrap_created',))
        self.assertFalse(audits)

    def test_init_db_does_not_add_local_workspace_to_populated_multi_workspace_database(self):
        self.appmod._db_exec("DELETE FROM audit_events")
        self.appmod._db_exec("DELETE FROM organizations WHERE name = ?", ('Local Workspace',))
        self.appmod._db_exec(
            "INSERT INTO organizations (name, join_policy, join_code, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
            ('Workspace One', 'join_with_code', 'one', '2026-08-25T00:00:00', 'test'),
        )
        self.appmod._db_exec(
            "INSERT INTO organizations (name, join_policy, join_code, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
            ('Workspace Two', 'join_with_code', 'two', '2026-08-25T00:00:00', 'test'),
        )

        self.appmod.init_db()

        names = [row['name'] for row in self.appmod._db_query("SELECT name FROM organizations ORDER BY name")]
        self.assertEqual(names, ['Workspace One', 'Workspace Two'])

    def test_global_audit_events_do_not_trigger_local_workspace_backfill(self):
        self.appmod._db_exec("DELETE FROM audit_events")
        self.appmod._db_exec("DELETE FROM organizations WHERE name = ?", ('Local Workspace',))
        self.appmod._db_exec(
            "INSERT INTO organizations (name, join_policy, join_code, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
            ('Workspace One', 'join_with_code', 'one', '2026-08-25T00:00:00', 'test'),
        )
        self.appmod._db_exec(
            """
            INSERT INTO audit_events (
                organization_id, timestamp, actor, role, event_type, target,
                target_type, target_id, result, source, detail, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                None, '2026-08-25T00:00:01', 'system', 'system', 'playbook_seeded',
                'playbook:global', 'playbook', 'global', 'success', 'local',
                'global audit row', None,
            ),
        )
        self.appmod._db_exec(
            """
            INSERT INTO audit_events (
                organization_id, timestamp, actor, role, event_type, target,
                target_type, target_id, result, source, detail, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                None, '2026-08-25T00:00:02', 'anonymous', 'anonymous', 'login',
                'user:unknown', 'user', 'unknown', 'failed', 'local',
                'invalid credentials', None,
            ),
        )

        self.appmod.init_db()

        local = self.appmod._db_query("SELECT * FROM organizations WHERE name = ?", ('Local Workspace',))
        self.assertFalse(local)
        audits = self.appmod._db_query("SELECT organization_id FROM audit_events ORDER BY id")
        self.assertEqual([audit['organization_id'] for audit in audits], [None, None])

    def test_legacy_audit_events_backfill_when_organization_column_is_added(self):
        self.appmod._db_exec("DELETE FROM audit_events")
        self.appmod._db_exec("DELETE FROM organizations")
        self.appmod._db_exec("DROP TABLE audit_events")
        self.appmod._db_exec(
            """
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                source TEXT NOT NULL,
                detail TEXT
            )
            """
        )
        self.appmod._db_exec(
            """
            INSERT INTO audit_events (
                timestamp, actor, role, event_type, target, result, source, detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                '2026-08-25T00:00:01', 'system', 'system', 'playbook_seeded',
                'playbook:memory-pressure-response', 'success', 'local', 'seeded playbook',
            ),
        )
        self.appmod._db_exec(
            """
            INSERT INTO audit_events (
                timestamp, actor, role, event_type, target, result, source, detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                '2026-08-25T00:00:02', 'admin', 'admin', 'login',
                'admin', 'success', 'local', 'legacy login',
            ),
        )

        self.appmod.init_db()

        local = self.appmod._db_query("SELECT id FROM organizations WHERE name = ?", ('Local Workspace',))
        self.assertEqual(len(local), 1)
        local_id = local[0]['id']
        audit_orgs = self.appmod._db_query("SELECT event_type, organization_id FROM audit_events ORDER BY id")
        self.assertEqual(
            [(audit['event_type'], audit['organization_id']) for audit in audit_orgs],
            [('playbook_seeded', local_id), ('login', local_id)],
        )
        logs = self.appmod._audit_rows(event_type='login', organization_id=local_id)
        self.assertEqual([log['detail'] for log in logs], ['legacy login'])

    def test_legacy_audit_migration_retries_after_failure(self):
        self.appmod._db_exec("DROP TABLE audit_events")
        self.appmod._db_exec("DELETE FROM organizations")
        self.appmod._db_exec(
            """
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                source TEXT NOT NULL,
                detail TEXT
            )
            """
        )
        self.appmod._db_exec(
            """
            INSERT INTO audit_events (
                timestamp, actor, role, event_type, target, result, source, detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                '2026-08-25T00:00:03', 'admin', 'admin', 'login',
                'admin', 'success', 'local', 'retryable legacy login',
            ),
        )

        with patch.object(self.appmod, '_backfill_playbook_definitions', side_effect=RuntimeError('forced migration stop')):
            with self.assertRaisesRegex(RuntimeError, 'forced migration stop'):
                self.appmod.init_db()

        conn = self.appmod.sqlite3.connect(self.tmp.name)
        try:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()]
        finally:
            conn.close()
        self.assertNotIn('organization_id', columns)

        self.appmod.init_db()

        local = self.appmod._db_query("SELECT id FROM organizations WHERE name = ?", ('Local Workspace',))
        self.assertEqual(len(local), 1)
        logs = self.appmod._audit_rows(event_type='login', organization_id=local[0]['id'])
        self.assertEqual([log['detail'] for log in logs], ['retryable legacy login'])

    def test_health_local_checks_auth_contract_without_treating_404_as_success(self):
        self.appmod.create_user('admin', 'longpassword1', 'admin')
        before = self.appmod._db_query("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = ?", ('access_denied',))[0]['count']
        payload = self.cli.run_health(local=True)
        checks = {check['name']: check for check in payload['checks']}
        self.assertIn('protected page', checks)
        self.assertIn('protected API', checks)
        self.assertTrue(checks['protected page']['ok'])
        self.assertTrue(checks['protected API']['ok'])
        self.assertNotEqual(checks['protected API']['detail'], 'status=404')
        after = self.appmod._db_query("SELECT COUNT(*) AS count FROM audit_events WHERE event_type = ?", ('access_denied',))[0]['count']
        self.assertEqual(before, after)

    def test_status_states(self):
        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            with patch.object(self.cli, 'PID_FILE', pid_file), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.cli.status(type('Args', (), {})()), 0)
                self.assertEqual(output.getvalue().strip(), 'Stopped')

            pid_file.write_text('{not-json', encoding='utf-8')
            with patch.object(self.cli, 'PID_FILE', pid_file), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.cli.status(type('Args', (), {})()), 1)
                self.assertEqual(output.getvalue().strip(), 'Stale runtime metadata')

            pid_file.write_text(json.dumps({'pid': 123, 'create_time': 1}), encoding='utf-8')
            config = type('Config', (), {'host': '127.0.0.1', 'port': 5001})()
            proc = object()
            with patch.object(self.cli, 'PID_FILE', pid_file), \
                    patch('web.saaoe_cli._matched_process', return_value=proc), \
                    patch('web.saaoe_cli.load_config', return_value=config), \
                    patch('web.saaoe_cli._http_health', return_value=(True, 'ok')), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.cli.status(type('Args', (), {})()), 0)
                self.assertEqual(output.getvalue().strip(), 'Healthy')

            with patch.object(self.cli, 'PID_FILE', pid_file), \
                    patch('web.saaoe_cli._matched_process', return_value=proc), \
                    patch('web.saaoe_cli.load_config', return_value=config), \
                    patch('web.saaoe_cli._http_health', return_value=(False, 'bad health')), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(self.cli.status(type('Args', (), {})()), 1)
                self.assertIn('Running but unhealthy', output.getvalue())

    def test_start_rejects_port_in_use_and_failed_preflight(self):
        config = type('Config', (), {'host': '127.0.0.1', 'port': 5001, 'protected_bind': True})()
        with patch('web.saaoe_cli.load_config', return_value=config), \
                patch('web.saaoe_cli._port_available', return_value=False):
            with self.assertRaisesRegex(self.cli.CliError, 'already in use'):
                self.cli.start(type('Args', (), {})())
        failed = {'healthy': False, 'status': 'failed', 'checks': [{'name': 'database', 'ok': False}]}
        with patch('web.saaoe_cli.load_config', return_value=config), \
                patch('web.saaoe_cli._port_available', return_value=True), \
                patch('web.saaoe_cli.run_health', return_value=failed), \
                patch('web.saaoe_cli.subprocess.Popen') as popen, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(self.cli.start(type('Args', (), {})()), 1)
            popen.assert_not_called()

    def test_start_rejects_unhealthy_live_sampler(self):
        class Proc:
            pid = os.getpid()

            def __init__(self):
                self.polls = 0

            def poll(self):
                self.polls += 1
                return None if self.polls == 1 else 1

        config = type('Config', (), {'host': '127.0.0.1', 'port': 5001, 'protected_bind': True})()
        preflight = {'healthy': True, 'status': 'healthy', 'checks': []}
        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            log_file = Path(runtime) / 'saaoe.log'
            proc = Proc()
            with patch.object(self.cli, 'RUNTIME_DIR', Path(runtime)), \
                    patch.object(self.cli, 'PID_FILE', pid_file), \
                    patch.object(self.cli, 'LOG_FILE', log_file), \
                    patch.object(self.cli, 'HEALTH_TIMEOUT_SECONDS', 1), \
                    patch('web.saaoe_cli.load_config', return_value=config), \
                    patch('web.saaoe_cli._port_available', return_value=True), \
                    patch('web.saaoe_cli.run_health', return_value=preflight), \
                    patch('web.saaoe_cli.subprocess.Popen', return_value=proc), \
                    patch('web.saaoe_cli.psutil.Process') as process, \
                    patch('web.saaoe_cli._http_health', return_value=(False, 'sampler unhealthy')), \
                    patch('web.saaoe_cli.stop') as stop, \
                    patch('web.saaoe_cli.time.sleep'), \
                    redirect_stdout(io.StringIO()) as output:
                process.return_value.create_time.return_value = 1.0
                self.assertEqual(self.cli.start(type('Args', (), {})()), 1)

            stop.assert_called_once()
            self.assertIn('startup health failed', output.getvalue())

    def test_start_and_run_log_packaged_bind_after_preflight(self):
        class Proc:
            pid = os.getpid()

        config = type('Config', (), {'host': '127.0.0.1', 'port': 5097, 'protected_bind': True})()
        preflight = {'healthy': True, 'status': 'healthy', 'checks': []}
        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            log_file = Path(runtime) / 'saaoe.log'
            with patch.object(self.cli, 'RUNTIME_DIR', Path(runtime)), \
                    patch.object(self.cli, 'PID_FILE', pid_file), \
                    patch.object(self.cli, 'LOG_FILE', log_file), \
                    patch('web.saaoe_cli.load_config', return_value=config), \
                    patch('web.saaoe_cli._port_available', return_value=True), \
                    patch('web.saaoe_cli.run_health', return_value=preflight), \
                    patch('web.saaoe_cli.subprocess.Popen', return_value=Proc()), \
                    patch('web.saaoe_cli.psutil.Process') as process, \
                    patch('web.saaoe_cli._http_health', return_value=(True, 'ok')), \
                    redirect_stdout(io.StringIO()) as output:
                process.return_value.create_time.return_value = 1.0
                self.assertEqual(self.cli.start(type('Args', (), {})()), 0)
            self.assertIn('started pid=', output.getvalue())
            self.assertIn('bind=127.0.0.1:5097', output.getvalue())

        with patch('web.saaoe_cli.load_config', return_value=config), \
                patch('web.saaoe_cli._load_app') as load_app, \
                patch.dict('sys.modules', {'waitress': type('Waitress', (), {'serve': staticmethod(lambda app, host, port: None)})}), \
                redirect_stdout(io.StringIO()) as output:
            load_app.return_value.create_app.return_value = object()
            self.assertEqual(self.cli.run(type('Args', (), {'foreground': True})()), 0)
        self.assertIn('serving bind=127.0.0.1:5097', output.getvalue())

    def test_successful_verified_stop_removes_pid_file(self):
        class Proc:
            terminated = False
            killed = False

            def terminate(self):
                self.terminated = True

            def wait(self, timeout=None):
                return None

        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            pid_file.write_text(json.dumps({'pid': 123, 'create_time': 1}), encoding='utf-8')
            proc = Proc()
            with patch.object(self.cli, 'PID_FILE', pid_file), \
                    patch('web.saaoe_cli._matched_process', return_value=proc), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(self.cli.stop(), 0)
            self.assertTrue(proc.terminated)
            self.assertFalse(pid_file.exists())

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
                    result = self.cli.stop()

            self.assertEqual(result, 1)
            self.assertTrue(pid_file.exists())

    def test_stop_preserves_tampered_and_creation_time_mismatched_metadata(self):
        with tempfile.TemporaryDirectory() as runtime:
            pid_file = Path(runtime) / 'saaoe.pid.json'
            pid_file.write_text('{not-json', encoding='utf-8')
            with patch.object(self.cli, 'PID_FILE', pid_file):
                with redirect_stdout(io.StringIO()):
                    result = self.cli.stop()
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
                    result = self.cli.stop()
            self.assertEqual(result, 1)
            self.assertTrue(pid_file.exists())


if __name__ == '__main__':
    unittest.main()
