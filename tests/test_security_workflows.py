import importlib
import os
import sys
import tempfile
import unittest


class SecurityWorkflowTests(unittest.TestCase):
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

    def login(self, username, password):
        return self.client.post('/login', data={'username': username, 'password': password})

    def test_operational_security_workflow(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/setup')

        response = self.client.post('/setup', data={
            'username': 'admin',
            'password': 'longpassword1',
            'confirm': 'longpassword1',
        })
        self.assertEqual(response.status_code, 302)

        response = self.client.post('/api/users', json={
            'username': 'analyst',
            'password': 'longpassword2',
            'role': 'analyst',
        })
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/users', json={
            'username': 'viewer',
            'password': 'longpassword3',
            'role': 'viewer',
        })
        self.assertEqual(response.status_code, 200)

        self.client.get('/logout')
        self.login('viewer', 'longpassword3')
        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 403)

        self.client.get('/logout')
        self.login('analyst', 'longpassword2')
        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        incident_id = response.json['incident']['id']

        response = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'create_incident_report',
            'target': incident_id,
            'dry_run': True,
        })
        self.assertEqual(response.status_code, 200)
        approval_id = response.json['approval']['id']

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 403)

        self.client.get('/logout')
        self.login('admin', 'longpassword1')
        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'approve'})
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 200)

        response = self.client.post('/api/terminal/run', json={'command': 'hostname'})
        self.assertIn(response.status_code, {200, 400})

        response = self.client.post('/api/terminal/run', json={'command': 'cat /etc/passwd'})
        self.assertEqual(response.status_code, 400)

        response = self.client.get('/api/audit_events')
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json['logs']), 0)


if __name__ == '__main__':
    unittest.main()
