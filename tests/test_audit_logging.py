import importlib
import json
import os
import tempfile
import unittest


class AuditLoggingTests(unittest.TestCase):
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
        self.appmod.load_persistent_state()
        client = self.appmod.app.test_client()
        client.post('/login', data={'username': 'admin', 'password': 'longpassword1'})
        return client

    def test_audit_records_are_normalized_filterable_and_persistent(self):
        response = self.client.post('/api/validation_events', json={'event_type': 'unsupported'})
        self.assertEqual(response.status_code, 400)

        response = self.client.post('/api/response_approvals', json={'action': 'unsupported', 'target': 'host'})
        self.assertEqual(response.status_code, 400)

        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        incident_id = response.json['incident']['id']

        response = self.client.post('/api/playbooks', json={'name': 'bad threshold', 'threshold': 'not-a-number'})
        self.assertEqual(response.status_code, 400)

        response = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'create_incident_report',
            'target': incident_id,
            'dry_run': True,
        })
        self.assertEqual(response.status_code, 200)
        approval_id = response.json['approval']['id']

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)

        response = self.client.get('/api/audit_events?actor=admin&event_type=response_action_started&result=denied')
        self.assertEqual(response.status_code, 200)
        logs = response.json['logs']
        self.assertTrue(logs)
        row = logs[0]
        for key in {'timestamp', 'actor', 'role', 'event_type', 'target', 'target_type', 'target_id', 'result', 'source', 'detail', 'details_json', 'structured_details'}:
            self.assertIn(key, row)
        self.assertEqual(row['event_type'], 'response_action_started')
        self.assertEqual(row['result'], 'denied')
        self.assertEqual(row['action'], row['event_type'])
        self.assertEqual(row['outcome'], row['result'])
        self.assertEqual(row['resource'], row['target'])
        self.assertEqual(row['details'], row['detail'])
        self.assertEqual(row['target_type'], 'approval')
        self.assertIn(row['source'], {'127.0.0.1', 'localhost'})

        normalized = self.client.get('/api/audit?event_type=alert_generated&limit=1').json['logs']
        self.assertTrue(normalized)
        self.assertEqual(normalized[0]['target_type'], 'anomaly')
        self.assertTrue(normalized[0]['target_id'].startswith('validation-'))
        self.assertEqual(json.loads(normalized[0]['details_json'])['event_type'], 'cpu_pressure')

        failed = self.client.get('/api/audit_events?event_type=response_approval_failed&result=failed').json['logs']
        self.assertTrue(failed)

        failed_mutations = self.client.get('/api/audit?event_type=playbook_create_failed&result=failed').json['logs']
        self.assertTrue(failed_mutations)

        alerts = self.client.get('/api/audit_events?event_type=alert_generated').json['logs']
        self.assertTrue(any(log['target'].startswith('anomaly:') for log in alerts))

        future = self.client.get('/api/audit?start_time=2999-01-01T00:00:00').json['logs']
        self.assertEqual(future, [])

        restarted = self.restart_client()
        persisted = restarted.get('/api/audit_events?event_type=alert_generated').json['logs']
        self.assertTrue(any(log['target'].startswith('anomaly:') for log in persisted))


if __name__ == '__main__':
    unittest.main()
