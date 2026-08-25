import importlib
import os
import tempfile
import unittest
from pathlib import Path


class PriorityFixRegressionTests(unittest.TestCase):
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
            'username': 'admin2',
            'password': 'longpassword3',
            'role': 'admin',
        })

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def login(self, username, password):
        self.client.get('/logout')
        return self.client.post('/login', data={'username': username, 'password': password})

    def test_approval_decision_returns_updated_row_and_refresh_persists_status(self):
        self.login('analyst', 'longpassword2')
        request_response = self.client.post('/api/response_approvals', json={
            'action': 'create_incident_report',
            'target': 'INC-manual',
            'dry_run': True,
            'reason': 'collect incident report',
        })
        self.assertEqual(request_response.status_code, 200)
        approval_id = request_response.json['approval']['id']

        self.login('admin2', 'longpassword3')
        missing_reason = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve'},
        )
        self.assertEqual(missing_reason.status_code, 400)
        self.assertEqual(missing_reason.json['error'], 'decision reason is required')

        decision = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'reviewed and approved'},
        )
        self.assertEqual(decision.status_code, 200)
        self.assertEqual(decision.json['approval']['status'], 'approved')
        self.assertEqual(decision.json['approval']['status_label'], 'Approved')

        refreshed = self.client.get('/api/response_approvals')
        approval = next(item for item in refreshed.json['approvals'] if item['id'] == approval_id)
        self.assertEqual(approval['status'], 'approved')
        self.assertEqual(approval['status_label'], 'Approved')

    def test_templates_include_inline_validation_and_zero_record_states(self):
        templates = {
            'approvals.html': [
                'Decision reason is required.',
                'replaceApprovalRow(data.approval)',
                "const status = a.status || 'pending';",
                "return status === 'pending' ? (approval.workflow_status || status) : status;",
                'a.status_label || status',
                'No approval requests yet.',
            ],
            'incidents.html': ['No incidents recorded yet.'],
            'reports.html': [
                'No anomaly records available for reports yet.',
                'No incident records available for reports yet.',
            ],
            'playbooks.html': [
                'No playbooks configured yet.',
                'No playbook runs recorded yet.',
            ],
            'validation.html': ['No validation events recorded yet.'],
            'audit_logs.html': ['No audit events match the current filters.'],
            'anomalies.html': ['No anomaly records match the current filters.'],
            'users.html': ['No users found in this workspace.', 'No join requests yet.'],
            'dashboard.html': [
                'No process records available yet.',
                'No telemetry log records available yet.',
                'No asset records available yet.',
            ],
            'processes.html': ['No process records available yet.'],
        }
        template_dir = Path('web/templates')
        for name, expected_strings in templates.items():
            body = (template_dir / name).read_text(encoding='utf-8')
            for expected in expected_strings:
                self.assertIn(expected, body)


if __name__ == '__main__':
    unittest.main()
