import importlib
import os
import tempfile
import unittest


class DurableStorageTests(unittest.TestCase):
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

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def restart_client(self):
        self.appmod.anomaly_rules = []
        self.appmod.playbooks = []
        self.appmod.playbook_runs = []
        self.appmod.automation_rules = []
        self.appmod.automation_history = []
        self.appmod._files_access_cache = {'timestamp': 0.0, 'payload': None}
        self.appmod.init_db()
        self.appmod._seed_db()
        self.appmod.load_persistent_state()
        client = self.appmod.app.test_client()
        client.post('/login', data={'username': 'admin', 'password': 'longpassword1'})
        return client

    def test_restart_persists_operational_records(self):
        response = self.client.post('/api/users', json={
            'username': 'analyst',
            'password': 'longpassword2',
            'role': 'analyst',
        })
        self.assertEqual(response.status_code, 200)
        analyst = self.appmod.get_user_by_username('analyst')
        response = self.client.post('/api/users', json={
            'action': 'permissions',
            'id': analyst['id'],
            'permissions': ['mutate_playbooks'],
        })
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/playbooks', json={
            'name': 'Durable Playbook',
            'metric': 'cpu_percent',
            'threshold': 80,
        })
        self.assertEqual(response.status_code, 200)
        playbook_id = response.json['playbook']['id']

        response = self.client.post('/api/automation_rules', json={
            'name': 'Durable automation',
            'field': 'severity',
            'operator': 'equals',
            'value': 'critical',
            'run_action': 'Capture Forensics Bundle',
        })
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        incident_id = response.json['incident']['id']
        anomaly_id = response.json['anomaly']['id']

        response = self.client.post('/api/incidents', json={
            'id': incident_id,
            'note': 'durable incident note',
        })
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'create_incident_report',
            'target': incident_id,
            'dry_run': True,
        })
        self.assertEqual(response.status_code, 200)
        approval_id = response.json['approval']['id']

        response = self.client.get('/api/files/access')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['access'])

        response = self.client.get('/api/reports/download.csv')
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/configuration', json={
            'key': 'retention_days',
            'value': 30,
        })
        self.assertEqual(response.status_code, 200)

        client = self.restart_client()

        users = client.get('/api/users').json['users']
        durable_user = next(user for user in users if user['username'] == 'analyst')
        self.assertEqual(durable_user['permissions'], ['mutate_playbooks'])

        playbooks = client.get('/api/playbooks').json['playbooks']
        self.assertIn(playbook_id, {playbook['id'] for playbook in playbooks})

        rules = client.get('/api/automation_rules').json['rules']
        self.assertIn('Durable automation', {rule['name'] for rule in rules})

        incidents = client.get('/api/incidents').json['incidents']
        self.assertIn(incident_id, {incident['id'] for incident in incidents})
        detail = client.get(f'/api/incidents/{incident_id}').json
        self.assertTrue(any(event['event_type'] == 'note_added' for event in detail['timeline']))

        approvals = client.get('/api/response_approvals').json['approvals']
        self.assertIn(approval_id, {approval['id'] for approval in approvals})

        anomalies = client.get('/api/anomalies').json['anomalies']
        self.assertIn(anomaly_id, {anomaly['id'] for anomaly in anomalies})

        files = client.get('/api/files/access').json['access']
        self.assertTrue(files)

        history = client.get('/api/reports/history').json['history']
        self.assertTrue(any(row['fmt'] == 'csv' for row in history))

        configuration = client.get('/api/configuration').json['configuration']
        self.assertEqual(next(row['value'] for row in configuration if row['key'] == 'retention_days'), 30)

        audits = client.get('/api/audit_events').json['logs']
        self.assertIn('configuration_updated', {event['action'] for event in audits})

    def test_api_storage_write_errors_are_json(self):
        self.appmod.DB_PATH = os.path.join('/tmp', 'missing-saaoe-dir', 'saaoe.sqlite3')
        response = self.client.post('/api/configuration', json={'key': 'x', 'value': 'y'})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json['error'], 'storage write failed')


if __name__ == '__main__':
    unittest.main()
