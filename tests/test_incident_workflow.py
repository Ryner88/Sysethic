import importlib
import os
import tempfile
import unittest
from datetime import datetime


class IncidentWorkflowTests(unittest.TestCase):
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

    def test_incident_workflow_is_durable_and_audited(self):
        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        incident_id = response.json['incident']['id']
        anomaly_id = response.json['anomaly']['id']

        response = self.client.post(f'/api/incidents/{incident_id}/assign', json={'assignee': 'analyst-one'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['incident']['assignee'], 'analyst-one')

        response = self.client.post(f'/api/incidents/{incident_id}/status', json={'status': 'investigating'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['incident']['status'], 'investigating')

        response = self.client.post(f'/api/incidents/{incident_id}/notes', json={'note': 'triage note'})
        self.assertEqual(response.status_code, 200)

        approval = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'create_incident_report',
            'target': incident_id,
            'dry_run': True,
        })
        self.assertEqual(approval.status_code, 200)
        approval_id = approval.json['approval']['id']
        self.assertEqual(approval.json['approval']['status'], 'pending')

        self.client.post('/api/users', json={
            'username': 'admin2',
            'password': 'longpassword2',
            'role': 'admin',
        })
        self.client.get('/logout')
        self.client.post('/login', data={'username': 'admin2', 'password': 'longpassword2'})
        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'incident workflow validated'},
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/terminal/run', json={'command': 'hostname', 'incident_id': incident_id})
        self.assertIn(response.status_code, {200, 400})

        response = self.client.post(f'/api/incidents/{incident_id}/close', json={'resolution': 'contained'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['incident']['status'], 'resolved')
        self.assertIsNotNone(response.json['incident']['closed_at'])

        response = self.client.post(f'/api/incidents/{incident_id}/reopen')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['incident']['status'], 'open')
        self.assertIsNone(response.json['incident']['closed_at'])

        detail = self.client.get(f'/api/incidents/{incident_id}')
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json['incident']['incident_id'], incident_id)
        self.assertIn(anomaly_id, detail.json['incident']['linked_anomalies'])
        self.assertTrue(detail.json['recommended_playbook'])
        self.assertTrue(any(note['detail'] == 'triage note' for note in detail.json['notes']))
        timeline_types = {entry['event_type'] for entry in detail.json['timeline']}
        self.assertTrue({
            'linked_anomaly',
            'playbook_recommended',
            'approval_requested',
            'response_action_succeeded',
            'terminal_command_attempted',
            'note_added',
            'status_updated',
            'assignment_updated',
            'incident_closed',
            'incident_reopened',
        }.issubset(timeline_types))

        updated_audits = [
            row for row in self.client.get('/api/audit?event_type=incident_updated').json['logs']
            if row['target_id'] == incident_id
        ]
        closed_audits = [
            row for row in self.client.get('/api/audit?event_type=incident_closed').json['logs']
            if row['target_id'] == incident_id
        ]
        reopened_audits = [
            row for row in self.client.get('/api/audit?event_type=incident_reopened').json['logs']
            if row['target_id'] == incident_id
        ]
        self.assertTrue(updated_audits)
        self.assertTrue(closed_audits)
        self.assertTrue(reopened_audits)

        restarted = self.restart_client()
        persisted = restarted.get(f'/api/incidents/{incident_id}')
        self.assertEqual(persisted.status_code, 200)
        self.assertEqual(persisted.json['incident']['status'], 'open')
        self.assertTrue(any(note['detail'] == 'triage note' for note in persisted.json['notes']))

    def test_medium_anomaly_does_not_auto_create_incident_but_manual_path_can(self):
        org_id = self.appmod.get_user_by_username('admin')['organization_id']
        anomaly = {
            'id': 'manual-medium-anomaly',
            'organization_id': org_id,
            'timestamp': datetime.now().isoformat(),
            'metric': 'memory_percent',
            'value': 70,
            'threshold': 65,
            'severity': 'medium',
            'category': 'host',
            'confidence': 0.8,
            'rule_name': 'manual medium test',
            'indicator_type': 'validation',
            'indicator': 'manual',
            'threat_intel': {'matched': False},
            'risk_score': 40,
            'frameworks': [],
            'validation': True,
        }
        self.appmod._persist_anomaly(anomaly, organization_id=org_id)

        response = self.client.get('/api/anomalies')
        self.assertEqual(response.status_code, 200)
        incidents = self.client.get('/api/incidents').json['incidents']
        self.assertNotIn('manual-medium-anomaly', {incident.get('anomaly_id') for incident in incidents})

        response = self.client.post('/api/incidents/from_anomaly', json={'anomaly_id': 'manual-medium-anomaly'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['incident']['anomaly_id'], 'manual-medium-anomaly')


if __name__ == '__main__':
    unittest.main()
