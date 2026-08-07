import importlib
import os
import tempfile
import threading
import unittest


class ResponseApprovalContractTests(unittest.TestCase):
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

    def logged_in_client(self, username, password):
        client = self.appmod.app.test_client()
        response = client.post('/login', data={'username': username, 'password': password})
        self.assertEqual(response.status_code, 302)
        return client

    def create_incident(self):
        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        return response.json['incident']['id']

    def request_report_approval_as_analyst(self, incident_id):
        self.login('analyst', 'longpassword2')
        response = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'create_incident_report',
            'target': incident_id,
            'dry_run': True,
            'reason': 'collect incident report',
        })
        self.assertEqual(response.status_code, 200)
        return response.json['approval']['id']

    def test_decisions_require_reasons_and_prevent_self_approval(self):
        incident_id = self.create_incident()
        approval_id = self.request_report_approval_as_analyst(incident_id)

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'approve'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'decision reason is required')

        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'requester tries to approve'},
        )
        self.assertEqual(response.status_code, 403)

    def test_single_terminal_decision_is_enforced_transactionally(self):
        incident_id = self.create_incident()
        approval_id = self.request_report_approval_as_analyst(incident_id)
        self.login('admin', 'longpassword1')

        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'reject', 'reason': 'insufficient evidence'},
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'second decision attempt'},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['approval']['status'], 'rejected')

    def test_unauthorized_role_cannot_decide_admin_only_action(self):
        response = self.client.post('/api/response_approvals', json={
            'action': 'kill_process',
            'target': os.getpid(),
            'dry_run': True,
            'reason': 'admin-only host action',
        })
        self.assertEqual(response.status_code, 200)
        approval_id = response.json['approval']['id']

        self.login('analyst', 'longpassword2')
        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'reject', 'reason': 'analyst cannot decide admin action'},
        )
        self.assertEqual(response.status_code, 403)

    def test_rejected_and_expired_requests_cannot_execute(self):
        incident_id = self.create_incident()
        rejected_id = self.request_report_approval_as_analyst(incident_id)
        self.login('admin', 'longpassword1')
        response = self.client.post(
            f'/api/response_approvals/{rejected_id}',
            json={'command': 'reject', 'reason': 'not approved'},
        )
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f'/api/response_approvals/{rejected_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)

        expired_id = self.request_report_approval_as_analyst(incident_id)
        self.appmod._db_exec(
            "UPDATE response_approvals SET status = ?, approved_by = ?, approver_role = ?, expires_at = ? WHERE id = ?",
            ('approved', 'admin', 'admin', '2000-01-01T00:00:00', expired_id),
        )
        self.login('admin2', 'longpassword3')
        response = self.client.post(f'/api/response_approvals/{expired_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['approval']['status'], 'expired')

    def test_deterministic_previews_are_bound_to_payload_digests(self):
        incident_id = self.create_incident()
        first_id = self.request_report_approval_as_analyst(incident_id)
        first = self.client.get(f'/api/response_approvals/{first_id}').json
        second_id = self.request_report_approval_as_analyst(incident_id)
        second = self.client.get(f'/api/response_approvals/{second_id}').json

        self.assertEqual(first['approval']['payload_digest'], second['approval']['payload_digest'])
        self.assertEqual(first['approval']['preview_digest'], second['approval']['preview_digest'])
        self.assertEqual(first['expected_preview'], second['expected_preview'])
        self.assertTrue(first['diagnostics']['payload_digest_matches'])
        self.assertTrue(first['diagnostics']['preview_digest_matches'])

        self.login('admin', 'longpassword1')
        response = self.client.post(
            f'/api/response_approvals/{first_id}',
            json={'command': 'approve', 'reason': 'validated deterministic preview'},
        )
        self.assertEqual(response.status_code, 200)
        self.appmod._db_exec(
            "UPDATE response_approvals SET preview_digest = ? WHERE id = ?",
            ('tampered-preview-digest', first_id),
        )
        response = self.client.post(f'/api/response_approvals/{first_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['error'], 'approval preview digest mismatch')

    def test_authorization_checks_digest_and_consumes_once(self):
        incident_id = self.create_incident()
        approval_id = self.request_report_approval_as_analyst(incident_id)
        self.login('admin', 'longpassword1')

        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'validated payload and requester'},
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'execute', 'target': 'tampered-target'},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['error'], 'approval target or action does not match request payload')

        audit = self.client.get('/api/audit_events?event_type=response_action_started&result=denied').json['logs'][0]
        self.assertEqual(audit['structured_details']['approval_id'], approval_id)
        self.assertEqual(audit['structured_details']['correlation_id'], f'approval:{approval_id}')
        self.assertEqual(audit['structured_details']['incident_id'], incident_id)
        self.assertEqual(audit['structured_details']['target'], incident_id)
        detail = self.client.get(f'/api/incidents/{incident_id}').json
        blocked = [event for event in detail['timeline'] if event['event_type'] == 'response_execution_blocked']
        self.assertTrue(blocked)
        self.assertEqual(blocked[-1]['structured_details']['approval_id'], approval_id)
        self.assertEqual(blocked[-1]['correlation_id'], f'approval:{approval_id}')

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['approval']['status'], 'consumed')

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)

        diagnostics = self.client.get(f'/api/response_approvals/{approval_id}').json
        self.assertTrue(diagnostics['diagnostics']['payload_digest_matches'])
        self.assertTrue(diagnostics['diagnostics']['preview_digest_matches'])
        self.assertGreaterEqual(diagnostics['diagnostics']['audit_event_count'], 4)
        self.assertGreaterEqual(diagnostics['diagnostics']['timeline_event_count'], 4)
        reconstructed_events = {event['event_type'] for event in diagnostics['reconstruction']}
        self.assertTrue({
            'response_approval_requested',
            'response_approval_approved',
            'response_execution_blocked',
            'response_action_executed',
        }.issubset(reconstructed_events))

    def test_concurrent_decisions_produce_one_winner(self):
        incident_id = self.create_incident()
        approval_id = self.request_report_approval_as_analyst(incident_id)
        client_one = self.logged_in_client('admin', 'longpassword1')
        client_two = self.logged_in_client('admin2', 'longpassword3')
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def decide(client, command, reason):
            barrier.wait()
            response = client.post(
                f'/api/response_approvals/{approval_id}',
                json={'command': command, 'reason': reason},
            )
            with lock:
                results.append((response.status_code, response.json.get('approval', {}).get('status')))

        threads = [
            threading.Thread(target=decide, args=(client_one, 'approve', 'concurrent approval')),
            threading.Thread(target=decide, args=(client_two, 'reject', 'concurrent rejection')),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(status for status, _ in results), [200, 409])
        final = self.client.get('/api/response_approvals').json['approvals']
        approval = next(row for row in final if row['id'] == approval_id)
        self.assertIn(approval['status'], {'approved', 'rejected'})
        self.assertEqual(sum(1 for status, _ in results if status == 200), 1)

    def test_host_impacting_actions_are_authorized_as_no_ops(self):
        approval = self.client.post('/api/response_approvals', json={
            'action': 'kill_process',
            'target': os.getpid(),
            'dry_run': False,
            'reason': 'validate disabled host boundary',
        })
        self.assertEqual(approval.status_code, 200)
        approval_id = approval.json['approval']['id']

        self.login('admin2', 'longpassword3')
        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'validate no-op boundary'},
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json['result']['executed'])
        self.assertIn('disabled', response.json['result']['detail'])


if __name__ == '__main__':
    unittest.main()
