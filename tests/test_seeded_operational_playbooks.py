import importlib
import os
import sys
import tempfile
import unittest


class SeededOperationalPlaybooksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(delete=False)
        cls.tmp.close()
        os.unlink(cls.tmp.name)
        os.environ['SAAOE_DB_PATH'] = cls.tmp.name
        os.environ['SAAOE_ENV'] = 'development'
        os.environ['SAAOE_SECRET_KEY'] = 'test-secret'
        sys.modules.pop('web.saaoe_api', None)
        cls.appmod = importlib.import_module('web.saaoe_api')

    @classmethod
    def tearDownClass(cls):
        try:
            os.unlink(cls.tmp.name)
        except FileNotFoundError:
            pass

    def setUp(self):
        self.client = self.appmod.app.test_client()
        if not self.appmod.get_user_by_username('admin'):
            self.client.post('/setup', data={
                'username': 'admin',
                'password': 'longpassword1',
                'confirm': 'longpassword1',
            })
        else:
            self.client.post('/login', data={'username': 'admin', 'password': 'longpassword1'})

    def test_eight_seeded_definitions_are_idempotent_and_valid(self):
        expected = {
            'runaway-cpu-process-review',
            'memory-pressure-response',
            'suspicious-network-connection-review',
            'sensitive-file-access-review',
            'human-approval-required',
            'create-incident-report',
            'quarantine-file-with-approval',
            'block-ip-with-approval',
        }
        rows = self.appmod._db_query("SELECT * FROM playbooks WHERE source = ? ORDER BY stable_key", ('seeded',))
        self.assertEqual({row['stable_key'] for row in rows}, expected)
        self.assertEqual(len(rows), 8)
        digests = {row['stable_key']: row['definition_digest'] for row in rows}

        self.appmod._seed_db()
        rows_after = self.appmod._db_query("SELECT * FROM playbooks WHERE source = ?", ('seeded',))
        self.assertEqual(len(rows_after), 8)
        self.assertEqual(digests, {row['stable_key']: row['definition_digest'] for row in rows_after})

        for row in rows_after:
            self.appmod._parse_trigger(row['trigger_json'])
            self.appmod._parse_steps_yaml(row['steps_yaml'])
            self.assertNotIn(row['recommended_action_key'], {'kill_process', 'quarantine_file', 'block_ip'})

    def test_definition_update_toggle_validation_and_matching_query(self):
        cpu = self.appmod._db_query("SELECT * FROM playbooks WHERE stable_key = ?", ('runaway-cpu-process-review',))[0]
        old_version = cpu['version']
        old_digest = cpu['definition_digest']
        response = self.client.post('/api/playbooks', json={
            'action': 'update',
            'id': cpu['id'],
            'description': 'Updated CPU review description',
        })
        self.assertEqual(response.status_code, 200)
        updated = response.json['playbook']
        self.assertEqual(updated['version'], old_version + 1)
        self.assertNotEqual(updated['definition_digest'], old_digest)

        response = self.client.post('/api/playbooks', json={'action': 'disable', 'id': cpu['id']})
        self.assertEqual(response.status_code, 200)
        anomaly = {
            'id': 'A-test-cpu',
            'organization_id': None,
            'metric': 'cpu_percent',
            'value': 99.0,
            'category': 'system',
        }
        self.assertNotIn('runaway-cpu-process-review', {pb['stable_key'] for pb in self.appmod.persisted_playbook_matches(anomaly)})

        response = self.client.post('/api/playbooks', json={'action': 'enable', 'id': cpu['id']})
        self.assertEqual(response.status_code, 200)
        self.assertIn('runaway-cpu-process-review', {pb['stable_key'] for pb in self.appmod.persisted_playbook_matches(anomaly)})

        response = self.client.post('/api/playbooks', json={
            'name': 'Bad Shell',
            'stable_key': 'bad-shell',
            'yaml': 'steps:\n  - action: shell\n    command: rm -rf /tmp/x\n',
        })
        self.assertEqual(response.status_code, 400)
        audit = self.client.get('/api/audit_events?event_type=playbook.write_rejected').json['logs']
        self.assertTrue(audit)
        self.assertIn('request_digest', audit[0]['structured_details'])
        self.assertNotIn('rm -rf', audit[0]['details_json'])

        self.client.get('/logout')
        self.appmod.create_user('viewer', 'longpassword2', 'viewer')
        self.client.post('/login', data={'username': 'viewer', 'password': 'longpassword2'})
        response = self.client.post('/api/playbooks', json={'name': 'Forbidden'})
        self.assertEqual(response.status_code, 403)

    def test_run_snapshot_survives_definition_edit(self):
        response = self.client.post('/api/validation_events', json={'event_type': 'memory_pressure'})
        self.assertEqual(response.status_code, 200)
        run = response.json['playbook_runs'][0]
        old_name = run['playbook_name']
        old_version = run['playbook_version']
        old_digest = run['definition_digest']

        pb = self.appmod._db_query("SELECT * FROM playbooks WHERE stable_key = ?", ('memory-pressure-response',))[0]
        response = self.client.post('/api/playbooks', json={
            'action': 'update',
            'id': pb['id'],
            'name': 'Memory Pressure Response Edited',
        })
        self.assertEqual(response.status_code, 200)
        stored_run = self.appmod._db_query("SELECT * FROM playbook_runs WHERE id = ?", (run['id'],))[0]
        self.assertEqual(stored_run['playbook_name'], old_name)
        self.assertEqual(stored_run['playbook_version'], old_version)
        self.assertEqual(stored_run['definition_digest'], old_digest)


if __name__ == '__main__':
    unittest.main()
