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
        if not self.appmod.get_user_by_username('admin'):
            self.client.post('/setup', data={
                'username': 'admin',
                'password': 'longpassword1',
                'confirm': 'longpassword1',
            })
        else:
            self.client.post('/login', data={'username': 'admin', 'password': 'longpassword1'})

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
            self.assertEqual(incident_detail['playbook_runs'][0]['playbook_name'], playbook_name)
            anomaly_detail = self.client.get(f"/api/anomalies/{payload['anomaly']['id']}")
            self.assertEqual(anomaly_detail.status_code, 200)
            self.assertIn(playbook_name, {pb['name'] for pb in anomaly_detail.json['recommended_playbooks']})
            self.assertIn(playbook_name, {run['playbook_name'] for run in anomaly_detail.json['playbook_runs']})

        history = self.client.get('/api/validation_events')
        self.assertEqual(history.status_code, 200)
        self.assertEqual(set(history.json['event_types']), set(expected_playbooks))
        self.assertTrue(all(row['detail'].startswith('Controlled validation input') for row in history.json['events']))

        audit_rows = self.client.get('/api/audit_events?event_type=validation_event_created').json['logs']
        self.assertGreaterEqual(len(audit_rows), 4)
        self.assertTrue(all(row['structured_details']['controlled_validation'] for row in audit_rows[-4:]))

        approvals = self.client.get('/api/response_approvals').json['approvals']
        created_incident_ids = {item['incident']['id'] for item in created}
        self.assertFalse([approval for approval in approvals if approval.get('incident_id') in created_incident_ids])

        cpu_incident = next(item for item in created if item['event_type'] == 'cpu_pressure')
        before_runs = self.appmod._db_query("SELECT COUNT(*) AS count FROM playbook_runs WHERE anomaly_id = ?", (cpu_incident['anomaly']['id'],))[0]['count']
        incident, duplicate_runs = self.appmod.ingest_anomaly_workflow(cpu_incident['anomaly'], actor='admin', organization_id=cpu_incident['incident']['organization_id'])
        after_runs = self.appmod._db_query("SELECT COUNT(*) AS count FROM playbook_runs WHERE anomaly_id = ?", (cpu_incident['anomaly']['id'],))[0]['count']
        self.assertEqual(before_runs, after_runs)
        self.assertEqual(duplicate_runs, [])

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

    def test_approval_paths_and_report_reconstruction_stay_inside_boundary(self):
        self.appmod.create_user('analyst', 'longpassword2', 'analyst')
        self.appmod.create_user('admin2', 'longpassword3', 'admin')

        self.client.get('/logout')
        self.client.post('/login', data={'username': 'analyst', 'password': 'longpassword2'})
        event = self.client.post('/api/validation_events', json={'event_type': 'suspicious_network'}).json
        approval = self.client.post('/api/response_approvals', json={
            'incident_id': event['incident']['id'],
            'anomaly_id': event['anomaly']['id'],
            'action': 'block_ip',
            'target': '198.51.100.10',
            'dry_run': False,
        })
        self.assertEqual(approval.status_code, 200)
        approval_id = approval.json['approval']['id']

        self.client.get('/logout')
        self.client.post('/login', data={'username': 'admin2', 'password': 'longpassword3'})
        mismatch = self.client.post(f'/api/response_approvals/{approval_id}', json={
            'command': 'execute',
            'action': 'block_ip',
            'target': '198.51.100.11',
            'incident_id': event['incident']['id'],
            'anomaly_id': event['anomaly']['id'],
            'dry_run': False,
        })
        self.assertEqual(mismatch.status_code, 409)
        approved = self.client.post(f'/api/response_approvals/{approval_id}', json={
            'command': 'approve',
            'reason': 'validation escalation reviewed',
        })
        self.assertEqual(approved.status_code, 200)
        executed = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(executed.status_code, 400)
        self.assertIn('not available in Phase 4', executed.json['error'])

        rejection = self.client.post('/api/response_approvals', json={
            'incident_id': event['incident']['id'],
            'anomaly_id': event['anomaly']['id'],
            'action': 'create_incident_report',
            'target': event['incident']['id'],
            'dry_run': True,
        })
        self.assertEqual(rejection.status_code, 200)
        rejected_id = rejection.json['approval']['id']
        rejected = self.client.post(f'/api/response_approvals/{rejected_id}', json={
            'command': 'reject',
            'reason': 'report not needed',
        })
        self.assertEqual(rejected.status_code, 200)

        closed = self.client.post(f"/api/incidents/{event['incident']['id']}/close", json={'resolution': 'controlled validation path documented'})
        self.assertEqual(closed.status_code, 200)
        detail = self.client.get(f"/api/incidents/{event['incident']['id']}").json
        timeline_types = {entry['event_type'] for entry in detail['timeline']}
        self.assertIn('approval_approved', timeline_types)
        self.assertIn('approval_rejected', timeline_types)
        self.assertIn('incident_closed', timeline_types)

        report = self.client.get('/api/reports/summary')
        self.assertEqual(report.status_code, 200)
        reconstruction = next(row for row in report.json['incident_reconstructions'] if row['incident_id'] == event['incident']['id'])
        self.assertTrue(reconstruction['controlled_validation'])
        self.assertTrue(reconstruction['playbook_runs'])
        self.assertGreaterEqual(len(reconstruction['approvals']), 2)

        csv_report = self.client.get('/api/reports/download.csv').get_data(as_text=True)
        self.assertIn('incident_reconstruction', csv_report)
        self.assertIn('controlled_validation', csv_report)


if __name__ == '__main__':
    unittest.main()
