import importlib
import os
import tempfile
import threading
import unittest
from unittest.mock import patch


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

    def request_restart_approval(self, incident_id=None, target='saaoe-dashboard', dry_run=False):
        response = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'restart_service',
            'target': target,
            'dry_run': dry_run,
            'reason': 'restart approved service',
        })
        self.assertEqual(response.status_code, 200)
        return response.json['approval']['id']

    def approve_as_admin2(self, approval_id):
        self.login('admin2', 'longpassword3')
        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'bounded service restart approved'},
        )
        self.assertEqual(response.status_code, 200)
        return response

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

    def test_restart_service_rejects_unapproved_targets_and_shell_syntax(self):
        response = self.client.post('/api/response_approvals', json={
            'action': 'restart_service',
            'target': 'ssh',
            'dry_run': False,
            'reason': 'unapproved target',
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn('not approved', response.json['error'])

        response = self.client.post('/api/response_approvals', json={
            'action': 'restart_service',
            'target': 'saaoe-dashboard;reboot',
            'dry_run': False,
            'reason': 'blocked shell syntax',
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn('valid service allowlist key', response.json['error'])

    def test_restart_service_executes_only_after_approved_digest_matching_request(self):
        incident_id = self.create_incident()
        approval_id = self.request_restart_approval(incident_id=incident_id)
        self.approve_as_admin2(approval_id)

        response = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'execute', 'target': 'saaoe-dashboard2'},
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['error'], 'approval target or action does not match request payload')

        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs))
            class Proc:
                returncode = 0
                stdout = 'restart ok'
            return Proc()

        with patch.object(self.appmod, '_current_platform_key', return_value='linux'), \
                patch.object(self.appmod.shutil, 'which', return_value='/bin/systemctl'), \
                patch.object(self.appmod.subprocess, 'run', side_effect=fake_run):
            response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['result']['executed'])
        self.assertEqual(response.json['result']['target'], 'saaoe-dashboard')
        self.assertEqual(calls[0][0], ['/bin/systemctl', 'restart', 'saaoe-dashboard.service'])
        self.assertFalse(calls[0][1].get('shell', False))
        self.assertEqual(calls[0][1]['timeout'], self.appmod.SERVICE_RESTART_TIMEOUT_SECONDS)

        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json['approval']['status'], 'consumed')

        detail = self.client.get(f'/api/incidents/{incident_id}').json
        self.assertTrue(any(event['event_type'] == 'response_executed' for event in detail['timeline']))
        executed = self.client.get('/api/audit_events?event_type=response_action_executed').json['logs'][0]
        self.assertEqual(executed['structured_details']['execution_result']['target'], 'saaoe-dashboard')

    def test_restart_service_execution_failure_records_recovery(self):
        incident_id = self.create_incident()
        approval_id = self.request_restart_approval(incident_id=incident_id)
        self.approve_as_admin2(approval_id)

        def fake_run(argv, **kwargs):
            class Proc:
                stdout = 'service manager output'
            proc = Proc()
            if argv[1] == 'restart':
                proc.returncode = 1
            else:
                proc.returncode = 0
            return proc

        with patch.object(self.appmod, '_current_platform_key', return_value='linux'), \
                patch.object(self.appmod.shutil, 'which', return_value='/bin/systemctl'), \
                patch.object(self.appmod.subprocess, 'run', side_effect=fake_run):
            response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})

        self.assertEqual(response.status_code, 400)
        self.assertIn('recovery start completed', response.json['error'])
        self.assertTrue(response.json['result']['rollback_attempted'])
        self.assertTrue(response.json['result']['rollback_succeeded'])
        approval = self.client.get(f'/api/response_approvals/{approval_id}').json['approval']
        self.assertEqual(approval['status'], 'consumed')

    def test_concurrent_restart_execution_consumes_once(self):
        self.login('analyst', 'longpassword2')
        approval_id = self.request_restart_approval()
        self.approve_as_admin2(approval_id)
        client_one = self.logged_in_client('admin', 'longpassword1')
        client_two = self.logged_in_client('admin2', 'longpassword3')
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def execute(client):
            barrier.wait()
            response = client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
            with lock:
                results.append(response.status_code)

        def fake_run(argv, **kwargs):
            class Proc:
                returncode = 0
                stdout = 'restart ok'
            return Proc()

        with patch.object(self.appmod, '_current_platform_key', return_value='linux'), \
                patch.object(self.appmod.shutil, 'which', return_value='/bin/systemctl'), \
                patch.object(self.appmod.subprocess, 'run', side_effect=fake_run):
            threads = [threading.Thread(target=execute, args=(client_one,)), threading.Thread(target=execute, args=(client_two,))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(sorted(results), [200, 409])


if __name__ == '__main__':
    unittest.main()
