import importlib
import os
import tempfile
import unittest


ENABLED_ACTION_CONTRACT_CASES = {
    'create_incident_report',
    'restart_service',
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

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

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

    def test_enabled_registry_actions_have_manifest_contract_cases(self):
        manifest = self.appmod.response_action_registry_manifest()
        enabled_actions = {key for key, metadata in manifest.items() if metadata['enabled']}

        self.assertEqual(enabled_actions, ENABLED_ACTION_CONTRACT_CASES)

    def test_quarantine_file_and_block_ip_remain_registered_but_disabled(self):
        manifest = self.appmod.response_action_registry_manifest()

        for key in ('quarantine_file', 'block_ip'):
            self.assertIn(key, manifest)
            self.assertFalse(manifest[key]['enabled'])
            self.assertEqual(manifest[key]['required_approval_role'], 'admin')
            self.assertIn('admin', manifest[key]['execution_roles'])

        with self.assertRaisesRegex(ValueError, 'quarantine_file execution adapter is not available'):
            self.appmod._execute_response_action('quarantine_file', 'README.md', dry_run=False)
        with self.assertRaisesRegex(ValueError, 'block_ip execution adapter is not available'):
            self.appmod._execute_response_action('block_ip', '127.0.0.1', dry_run=False)

    def test_playbooks_cannot_weaken_registry_metadata(self):
        self.client.post('/setup', data={
            'username': 'admin',
            'password': 'longpassword1',
            'confirm': 'longpassword1',
        })
        before = self.appmod.response_action_registry_manifest()['block_ip']

        response = self.client.post('/api/playbooks', json={
            'name': 'Unsafe registry override attempt',
            'stable_key': 'unsafe-registry-override',
            'kind': 'approval_action',
            'trigger_json': {'type': 'workflow', 'event': 'block_ip_requested'},
            'recommended_action_key': 'block_ip',
            'required_approval_role': 'none',
            'enabled': True,
            'steps_yaml': 'steps:\n  - action: request_approval\n    approval: none\n',
        })

        self.assertEqual(response.status_code, 400)
        after = self.appmod.response_action_registry_manifest()['block_ip']
        self.assertEqual(after, before)
        self.assertFalse(after['enabled'])
        self.assertEqual(after['required_approval_role'], 'admin')


if __name__ == '__main__':
    unittest.main()
