import importlib
import os
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch


ENABLED_ACTION_CONTRACT_CASES = {
    'create_incident_report': {
        'target': 'INC-contract',
        'invalid_target': '',
        'requester': ('analyst', 'longpassword2'),
        'approver': ('admin', 'longpassword1'),
        'executor': ('admin', 'longpassword1'),
        'platform': 'linux',
        'required_approval_role': 'analyst',
        'audit_event': 'response_action_executed',
    },
    'restart_service': {
        'target': 'saaoe-dashboard',
        'invalid_target': 'saaoe-dashboard;reboot',
        'requester': ('analyst', 'longpassword2'),
        'approver': ('admin', 'longpassword1'),
        'executor': ('admin', 'longpassword1'),
        'platform': 'linux',
        'required_approval_role': 'admin',
        'audit_event': 'response_action_executed',
    },
}


class ResponseActionRegistryTests(unittest.TestCase):
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
        self.client.post('/api/users', json={
            'username': 'analyst',
            'password': 'longpassword2',
            'role': 'analyst',
        })
        self.client.post('/api/users', json={
            'username': 'viewer',
            'password': 'longpassword3',
            'role': 'viewer',
        })
        self.client.post('/api/users', json={
            'username': 'analyst2',
            'password': 'longpassword4',
            'role': 'analyst',
        })

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def login(self, username, password):
        self.client.get('/logout')
        response = self.client.post('/login', data={'username': username, 'password': password})
        self.assertEqual(response.status_code, 302)

    def test_response_action_registry_exposes_required_metadata(self):
        manifest = self.appmod.response_action_registry_manifest()
        required_fields = {
            'stable_key',
            'safety_class',
            'input_validator',
            'request_roles',
            'required_approval_role',
            'execution_roles',
            'supported_platforms',
            'enabled',
            'executor',
        }

        self.assertEqual(set(manifest), self.appmod.RESPONSE_ACTIONS)
        for key, metadata in manifest.items():
            self.assertTrue(required_fields.issubset(metadata), key)
            self.assertEqual(metadata['stable_key'], key)
            self.assertTrue(metadata['safety_class'])
            self.assertTrue(metadata['input_validator'])
            self.assertTrue(metadata['request_roles'])
            self.assertTrue(metadata['required_approval_role'])
            self.assertTrue(metadata['execution_roles'])
            self.assertTrue(metadata['supported_platforms'])
            self.assertTrue(metadata['executor'])

    def test_enabled_registry_actions_have_executable_contract_cases(self):
        manifest = self.appmod.response_action_registry_manifest()
        enabled_actions = {key for key, metadata in manifest.items() if metadata['enabled']}

        self.assertEqual(enabled_actions, set(ENABLED_ACTION_CONTRACT_CASES))

        for action, case in ENABLED_ACTION_CONTRACT_CASES.items():
            with self.subTest(action=action):
                self.login('viewer', 'longpassword3')
                denied = self.client.post('/api/response_approvals', json={
                    'action': action,
                    'target': case['target'],
                    'dry_run': False,
                    'reason': 'viewer request should fail',
                })
                self.assertEqual(denied.status_code, 403)

                self.login(*case['requester'])
                invalid = self.client.post('/api/response_approvals', json={
                    'action': action,
                    'target': case['invalid_target'],
                    'dry_run': False,
                    'reason': 'invalid target should fail',
                })
                self.assertEqual(invalid.status_code, 400)

                request = self.client.post('/api/response_approvals', json={
                    'action': action,
                    'target': case['target'],
                    'dry_run': False,
                    'reason': 'registry contract request',
                })
                self.assertEqual(request.status_code, 200)
                approval_id = request.json['approval']['id']
                self.assertEqual(request.json['approval']['required_role'], case['required_approval_role'])

                self.login(*case['approver'])
                decision = self.client.post(
                    f'/api/response_approvals/{approval_id}',
                    json={'command': 'approve', 'reason': 'registry contract approved'},
                )
                self.assertEqual(decision.status_code, 200)

                self.login(*case['executor'])
                with patch.object(self.appmod, '_current_platform_key', return_value=case['platform']), \
                        patch.object(self.appmod, '_restart_approved_service', return_value={'executed': True, 'detail': 'restart ok'}):
                    executed = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
                self.assertEqual(executed.status_code, 200)
                logs = self.client.get(f"/api/audit_events?event_type={case['audit_event']}").json['logs']
                self.assertTrue(logs)

    def test_quarantine_file_and_block_ip_remain_registered_but_disabled(self):
        manifest = self.appmod.response_action_registry_manifest()

        for key in ('quarantine_file', 'block_ip'):
            self.assertIn(key, manifest)
            self.assertFalse(manifest[key]['enabled'])
            self.assertEqual(manifest[key]['required_approval_role'], 'admin')
            self.assertIn('admin', manifest[key]['execution_roles'])

        with self.assertRaisesRegex(ValueError, 'quarantine_file execution adapter is disabled'):
            self.appmod._execute_response_action('quarantine_file', 'README.md', dry_run=False)
        with self.assertRaisesRegex(ValueError, 'block_ip execution adapter is disabled'):
            self.appmod._execute_response_action('block_ip', '127.0.0.1', dry_run=False)

    def test_disabled_action_denies_before_executor_resolution(self):
        original = self.appmod.RESPONSE_ACTION_REGISTRY['block_ip']
        calls = []

        def fake_executor(_target):
            calls.append('called')
            return {'executed': True, 'detail': 'should not run'}

        self.appmod.RESPONSE_ACTION_REGISTRY['block_ip'] = replace(original, executor=fake_executor, enabled=False)
        try:
            with self.assertRaisesRegex(ValueError, 'block_ip execution adapter is disabled'):
                self.appmod._execute_response_action('block_ip', '127.0.0.1', dry_run=False)
        finally:
            self.appmod.RESPONSE_ACTION_REGISTRY['block_ip'] = original
        self.assertEqual(calls, [])

    def test_unsupported_platform_denies_before_adapter_call(self):
        self.login('analyst2', 'longpassword4')
        request = self.client.post('/api/response_approvals', json={
            'action': 'restart_service',
            'target': 'saaoe-dashboard',
            'dry_run': False,
            'reason': 'unsupported platform check',
        })
        self.assertEqual(request.status_code, 200)
        approval_id = request.json['approval']['id']

        self.login('admin', 'longpassword1')
        decision = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'approve before platform denial'},
        )
        self.assertEqual(decision.status_code, 200)

        calls = []

        def fake_restart(_target):
            calls.append('called')
            return {'executed': True, 'detail': 'should not run'}

        with patch.object(self.appmod, '_current_platform_key', return_value='unknown-os'), \
                patch.object(self.appmod, '_restart_approved_service', side_effect=fake_restart):
            response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})

        self.assertEqual(response.status_code, 403)
        self.assertIn('not supported on platform unknown-os', response.json['error'])
        self.assertEqual(calls, [])
        approval = self.client.get(f'/api/response_approvals/{approval_id}').json['approval']
        self.assertEqual(approval['status'], 'approved')

    def test_execution_roles_are_enforced_before_adapter_call(self):
        self.login('analyst2', 'longpassword4')
        request = self.client.post('/api/response_approvals', json={
            'action': 'restart_service',
            'target': 'saaoe-dashboard',
            'dry_run': False,
            'reason': 'execution role check',
        })
        self.assertEqual(request.status_code, 200)
        approval_id = request.json['approval']['id']

        self.login('admin', 'longpassword1')
        decision = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'admin approves restart'},
        )
        self.assertEqual(decision.status_code, 200)
        self.appmod._db_exec(
            "UPDATE response_approvals SET required_role = ? WHERE id = ?",
            ('analyst', approval_id),
        )

        calls = []

        def fake_restart(_target):
            calls.append('called')
            return {'executed': True, 'detail': 'should not run'}

        self.login('analyst', 'longpassword2')
        with patch.object(self.appmod, '_current_platform_key', return_value='linux'), \
                patch.object(self.appmod, '_restart_approved_service', side_effect=fake_restart):
            response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json['error'], 'response action execution role required')
        self.assertEqual(calls, [])
        approval = self.client.get(f'/api/response_approvals/{approval_id}').json['approval']
        self.assertEqual(approval['status'], 'approved')

    def test_registry_rejects_missing_validator_or_executor(self):
        original = self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report']
        self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = replace(original, input_validator='missing_validator')
        try:
            with self.assertRaisesRegex(ValueError, 'input validator is not configured'):
                self.appmod.approval_preview({'action': 'create_incident_report', 'target': 'INC-1'})
        finally:
            self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = original

        self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = replace(original, executor='missing_executor')
        try:
            with self.assertRaisesRegex(ValueError, 'executor is not configured'):
                self.appmod._execute_response_action('create_incident_report', 'INC-1', dry_run=False)
        finally:
            self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = original

    def test_playbooks_cannot_weaken_registry_metadata(self):
        before = self.appmod.response_action_registry_manifest()['create_incident_report']

        response = self.client.post('/api/playbooks', json={
            'name': 'Unsafe registry override attempt',
            'stable_key': 'unsafe-registry-override',
            'kind': 'incident_utility',
            'category': 'incident',
            'trigger_json': {'type': 'incident', 'event': 'report_requested'},
            'recommended_action_key': 'create_incident_report',
            'required_approval_role': 'none',
            'enabled': True,
            'steps_yaml': 'steps:\n  - action: create_report\n    report_type: incident\n',
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['playbook']['required_approval_role'], 'analyst')
        after = self.appmod.response_action_registry_manifest()['create_incident_report']
        self.assertEqual(after, before)
        self.assertTrue(after['enabled'])
        self.assertEqual(after['required_approval_role'], 'analyst')


if __name__ == '__main__':
    unittest.main()
