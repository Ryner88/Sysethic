import importlib
import os
import sys
import tempfile
import unittest


class ControlledValidationEventCenterTests(unittest.TestCase):
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
        self.client.post('/setup', data={
            'username': 'admin',
            'password': 'longpassword1',
            'confirm': 'longpassword1',
        })

    def test_controlled_validation_events_create_traceable_workflow_artifacts(self):
        expected_playbooks = {
            'cpu_pressure': 'Runaway CPU Process Review',
            'memory_pressure': 'Memory Pressure Response',
            'suspicious_network': 'Suspicious Network Connection Review',
            'sensitive_file_access': 'Sensitive File Access Review',
        }

        created = []
        for event_type, playbook_name in expected_playbooks.items():
            response = self.client.post('/api/validation_events', json={'event_type': event_type})
            self.assertEqual(response.status_code, 200)
            payload = response.json
            created.append(payload)
            self.assertTrue(payload['controlled_validation'])
            self.assertEqual(payload['event_type'], event_type)
            self.assertTrue(payload['anomaly']['validation'])
            self.assertEqual(payload['anomaly']['indicator_type'], 'validation')
            self.assertEqual(payload['incident']['status'], 'open')
            self.assertIn(playbook_name, {run['name'] for run in payload['playbook_runs']})

            incident_detail = self.client.get(f"/api/incidents/{payload['incident']['id']}").json
            timeline_types = {event['event_type'] for event in incident_detail['timeline']}
            self.assertIn('validation_event_created', timeline_types)
            self.assertIn('validation_playbook_run_created', timeline_types)
            self.assertIn('playbook_run', timeline_types)
            self.assertEqual(incident_detail['recommended_playbook']['name'], playbook_name)

        history = self.client.get('/api/validation_events')
        self.assertEqual(history.status_code, 200)
        self.assertEqual(set(history.json['event_types']), set(expected_playbooks))
        self.assertTrue(all(row['detail'].startswith('Controlled validation input') for row in history.json['events']))

        audit_rows = self.client.get('/api/audit_events?event_type=validation_event_created').json['logs']
        self.assertGreaterEqual(len(audit_rows), 4)
        self.assertTrue(all(row['structured_details']['controlled_validation'] for row in audit_rows[-4:]))

        approvals = self.client.get('/api/response_approvals').json['approvals']
        self.assertEqual(approvals, [])

        cpu_incident = next(item for item in created if item['event_type'] == 'cpu_pressure')
        approval = self.client.post('/api/response_approvals', json={
            'incident_id': cpu_incident['incident']['id'],
            'anomaly_id': cpu_incident['anomaly']['id'],
            'action': 'kill_process',
            'target': '1',
            'dry_run': True,
        })
        self.assertEqual(approval.status_code, 200)
        self.assertEqual(approval.json['approval']['status'], 'pending')
        self.assertEqual(approval.json['approval']['required_role'], 'admin')


if __name__ == '__main__':
    unittest.main()
