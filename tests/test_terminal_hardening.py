import importlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class TerminalHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SAAOE_ENV'] = 'development'
        os.environ['SAAOE_SECRET_KEY'] = 'test-secret'
        cls.appmod = importlib.import_module('web.saaoe_api')

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        os.unlink(self.tmp.name)
        self.original_db_path = self.appmod.DB_PATH
        self.original_commands = self.appmod.DIAGNOSTIC_COMMANDS
        self.original_timeout = self.appmod.TERMINAL_TIMEOUT_SECONDS
        self.original_output_limit = self.appmod.TERMINAL_OUTPUT_LIMIT
        self.original_path = os.environ.get('PATH', '')
        self.appmod.DB_PATH = self.tmp.name
        self.appmod.init_db()
        self.appmod._seed_db()
        self.appmod.load_persistent_state()
        self.client = self.appmod.app.test_client()
        self.client.post('/setup', data={
            'username': 'admin',
            'password': 'longpassword1',
            'confirm': 'longpassword1',
        })

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        self.appmod.DIAGNOSTIC_COMMANDS = self.original_commands
        self.appmod.TERMINAL_TIMEOUT_SECONDS = self.original_timeout
        self.appmod.TERMINAL_OUTPUT_LIMIT = self.original_output_limit
        os.environ['PATH'] = self.original_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def _add_command(self, directory, name, content):
        path = Path(directory) / name
        path.write_text(content, encoding='utf-8')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def _add_platform_command(self, directory, name, posix_content, windows_content):
        if os.name == 'nt':
            return self._add_command(directory, f'{name}.cmd', windows_content)
        return self._add_command(directory, name, posix_content)

    def test_terminal_is_admin_only_and_permission_cannot_be_delegated(self):
        response = self.client.post('/api/users', json={
            'username': 'member',
            'password': 'longpassword2',
            'role': 'viewer',
        })
        self.assertEqual(response.status_code, 200)
        member = self.appmod.get_user_by_username('member')

        response = self.client.post('/api/users', json={
            'action': 'permissions',
            'id': member['id'],
            'permissions': ['access_terminal'],
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'terminal access is admin-only')

        self.client.get('/logout')
        self.client.post('/login', data={'username': 'member', 'password': 'longpassword2'})
        self.assertEqual(self.client.get('/terminal').status_code, 403)
        self.assertEqual(self.client.get('/api/terminal/status').status_code, 403)
        self.assertEqual(self.client.post('/api/terminal/run', json={'command': 'hostname'}).status_code, 403)

        events = self.appmod._db_query(
            "SELECT event_type, result, detail FROM audit_events WHERE event_type IN (?, ?) ORDER BY id",
            ('permission_change_failed', 'access_denied')
        )
        self.assertTrue(any(row['event_type'] == 'permission_change_failed' and 'admin-only' in row['detail'] for row in events))
        self.assertTrue(any(row['event_type'] == 'access_denied' and row['result'] == 'denied' for row in events))

    def test_terminal_rejects_unapproved_commands_and_arguments_with_audit(self):
        response = self.client.get('/api/terminal/status')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json['running'])
        self.assertEqual(response.json['legacy_websocket'], 'disabled')
        self.assertIn('ps aux', response.json['allowed'])

        response = self.client.post('/api/terminal/run', json={'command': 'cat /etc/passwd'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('not enabled', response.json['error'])

        response = self.client.post('/api/terminal/run', json={'command': 'ps -ax'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('Arguments', response.json['error'])

        denied = self.client.get('/api/audit_events?event_type=terminal_command_attempted&result=denied').json['logs']
        self.assertGreaterEqual(len(denied), 2)
        self.assertTrue(all(row['actor'] == 'admin' for row in denied))
        self.assertTrue(all(row['structured_details'].get('command') for row in denied))
        self.assertTrue(all(row['structured_details'].get('shell') is False for row in denied))

    def test_terminal_rejects_shell_syntax_and_malformed_payloads_with_audit(self):
        response = self.client.post('/api/terminal/run', json={'command': 'hostname; whoami'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('Shell syntax', response.json['error'])

        response = self.client.post('/api/terminal/run', json={'command': ['hostname']})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'Command must be a string.')

        denied = self.client.get('/api/audit_events?event_type=terminal_command_attempted&result=denied').json['logs']
        details = [row['structured_details'] for row in denied]
        self.assertTrue(all(detail['timeout_seconds'] == self.appmod.TERMINAL_TIMEOUT_SECONDS for detail in details))
        self.assertTrue(all(detail['output_limit'] == self.appmod.TERMINAL_OUTPUT_LIMIT for detail in details))
        self.assertTrue(all(detail['shell'] is False for detail in details))
        self.assertTrue(any('hostname; whoami' == detail['command'] for detail in details))
        self.assertTrue(any("['hostname']" == detail['command'] for detail in details))

    def test_terminal_timeout_and_output_truncation_are_enforced_and_audited(self):
        with tempfile.TemporaryDirectory() as bin_dir:
            self._add_platform_command(
                bin_dir,
                'slowcmd',
                '#!/bin/sh\nsleep 2\necho done\n',
                '@echo off\npython -c "import time; time.sleep(2); print(\'done\')"\n',
            )
            self._add_platform_command(
                bin_dir,
                'bigcmd',
                '#!/bin/sh\nprintf "abcdefghij%.0s" $(seq 1 200)\n',
                '@echo off\npython -c "print(\'abcdefghij\' * 200, end=\'\')"\n',
            )
            os.environ['PATH'] = f"{bin_dir}:{self.original_path}"
            self.appmod.DIAGNOSTIC_COMMANDS = {
                **self.original_commands,
                'slowcmd': {()},
                'bigcmd': {()},
            }
            self.appmod.TERMINAL_TIMEOUT_SECONDS = 1
            self.appmod.TERMINAL_OUTPUT_LIMIT = 1000

            response = self.client.post('/api/terminal/run', json={'command': 'slowcmd'})
            self.assertEqual(response.status_code, 408)
            self.assertEqual(response.json['error'], 'command timed out')

            response = self.client.post('/api/terminal/run', json={'command': 'bigcmd'})
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json['truncated'])
            self.assertLessEqual(len(response.json['output']), 1021)
            self.assertTrue(response.json['output'].endswith('[output truncated]\n'))

        logs = self.client.get('/api/audit_events?event_type=terminal_command_attempted').json['logs']
        self.assertTrue(any(row['result'] == 'failed' and row['detail'] == 'timeout' for row in logs))
        self.assertTrue(any(row['result'] == 'success' and row['structured_details'].get('truncated') for row in logs))

    def test_terminal_execution_errors_are_audited(self):
        with mock.patch.object(self.appmod.subprocess, 'run', side_effect=OSError('exec denied')):
            response = self.client.post('/api/terminal/run', json={'command': 'hostname'})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json['error'], 'command execution failed')

        logs = self.client.get('/api/audit_events?event_type=terminal_command_attempted&result=failed').json['logs']
        self.assertTrue(any(
            row['detail'] == 'execution failed'
            and row['structured_details'].get('error_type') == 'OSError'
            and row['structured_details'].get('shell') is False
            for row in logs
        ))


if __name__ == '__main__':
    unittest.main()
