import importlib
import json
import os
import runpy
import sqlite3
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch


class SecurityRemediationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ['SAAOE_ENV'] = 'development'
        os.environ['SAAOE_SECRET_KEY'] = 'test-secret'
        sys.modules.pop('web.saaoe_api', None)
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

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def login(self, username, password):
        self.client.get('/logout')
        response = self.client.post('/login', data={'username': username, 'password': password})
        self.assertEqual(response.status_code, 302)

    def assert_no_sentinel_in_response_or_audit(self, response, sentinel):
        self.assertNotIn(sentinel, response.get_data(as_text=True))
        audit = self.client.get('/api/audit_events').json['logs']
        self.assertNotIn(sentinel, json.dumps(audit))

    def test_legacy_ethics_ui_launcher_is_loopback_and_debug_disabled(self):
        calls = []

        def fake_run(self, **kwargs):
            calls.append(kwargs)

        with patch('flask.Flask.run', new=fake_run):
            runpy.run_module('web.ethics_ui', run_name='__main__')

        self.assertEqual(calls, [{'host': '127.0.0.1', 'port': 5000, 'debug': False}])

    def test_login_rejects_external_protocol_relative_backslash_and_control_redirects(self):
        unsafe_targets = [
            'https://attacker.example',
            '//attacker.example',
            '/\\attacker.example',
            '/safe\nSet-Cookie:bad=1',
            'dashboard',
        ]
        for target in unsafe_targets:
            with self.subTest(target=target):
                self.client.get('/logout')
                response = self.client.post(
                    '/login',
                    query_string={'next': target},
                    data={'username': 'admin', 'password': 'longpassword1'},
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.location, '/')

        self.client.get('/logout')
        response = self.client.post(
            '/login',
            query_string={'next': '/incidents'},
            data={'username': 'admin', 'password': 'longpassword1'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/incidents')

    def test_sqlite_exception_does_not_expose_raw_exception_text(self):
        sentinel = 'SENTINEL_SECRET_DB_EXCEPTION'
        with self.appmod.app.test_request_context('/api/sentinel'):
            response, status = self.appmod.storage_error(sqlite3.Error(sentinel))

        self.assertEqual(status, 500)
        self.assertEqual(response.json, {'error': 'storage operation failed'})
        self.assertNotIn(sentinel, response.get_data(as_text=True))

        with self.appmod.app.test_request_context('/sentinel'):
            response, status = self.appmod.storage_error(sqlite3.Error(sentinel))

        self.assertEqual(status, 500)
        self.assertNotIn(sentinel, str(response))

    def test_response_action_validator_exception_is_sanitized_in_http_and_audit(self):
        sentinel = 'SENTINEL_SECRET_VALIDATOR_EXCEPTION'
        original = self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report']

        def bad_validator(_target):
            raise RuntimeError(sentinel)

        self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = replace(original, input_validator=bad_validator)
        try:
            self.login('analyst', 'longpassword2')
            response = self.client.post('/api/response_approvals', json={
                'action': 'create_incident_report',
                'target': 'INC-validator',
                'dry_run': False,
                'reason': 'validator should fail safely',
            })
        finally:
            self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = original

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'response action validation failed')
        self.assert_no_sentinel_in_response_or_audit(response, sentinel)

    def test_response_action_executor_exception_is_sanitized_in_http_and_audit(self):
        sentinel = 'SENTINEL_SECRET_EXECUTOR_EXCEPTION'
        self.login('analyst', 'longpassword2')
        request = self.client.post('/api/response_approvals', json={
            'action': 'create_incident_report',
            'target': 'INC-executor',
            'dry_run': False,
            'reason': 'executor should fail safely',
        })
        self.assertEqual(request.status_code, 200)
        approval_id = request.json['approval']['id']

        self.login('admin', 'longpassword1')
        approved = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'approve executor failure test'},
        )
        self.assertEqual(approved.status_code, 200)

        original = self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report']

        def bad_executor(_target):
            raise RuntimeError(sentinel)

        self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = replace(original, executor=bad_executor)
        try:
            response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        finally:
            self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = original

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'response action execution failed')
        self.assert_no_sentinel_in_response_or_audit(response, sentinel)

    def test_json_shaped_executor_exception_is_not_treated_as_result_payload(self):
        sentinel = 'SENTINEL_SECRET_JSON_EXCEPTION'
        self.login('analyst', 'longpassword2')
        request = self.client.post('/api/response_approvals', json={
            'action': 'create_incident_report',
            'target': 'INC-json-executor',
            'dry_run': False,
            'reason': 'json executor exception should fail safely',
        })
        self.assertEqual(request.status_code, 200)
        approval_id = request.json['approval']['id']

        self.login('admin', 'longpassword1')
        approved = self.client.post(
            f'/api/response_approvals/{approval_id}',
            json={'command': 'approve', 'reason': 'approve json executor failure test'},
        )
        self.assertEqual(approved.status_code, 200)

        original = self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report']

        def bad_executor(_target):
            raise RuntimeError(f'{{"detail":"{sentinel}","output":"{sentinel}"}}')

        self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = replace(original, executor=bad_executor)
        try:
            response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        finally:
            self.appmod.RESPONSE_ACTION_REGISTRY['create_incident_report'] = original

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'response action execution failed')
        self.assertIsNone(response.json['result'])
        self.assert_no_sentinel_in_response_or_audit(response, sentinel)

    def test_playbook_validator_exception_is_sanitized_in_http_and_audit(self):
        sentinel = 'SENTINEL_SECRET_PLAYBOOK_EXCEPTION'
        self.login('admin', 'longpassword1')

        def bad_parser(_steps_yaml):
            raise RuntimeError(sentinel)

        with patch.object(self.appmod, '_parse_steps_yaml', side_effect=bad_parser):
            response = self.client.post('/api/playbooks', json={
                'name': 'Unsafe Exception Playbook',
                'stable_key': 'unsafe-exception-playbook',
                'steps_yaml': 'steps:\n  - action: review_evidence\n',
            })

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json['error'], 'playbook validation failed')
        self.assert_no_sentinel_in_response_or_audit(response, sentinel)


if __name__ == '__main__':
    unittest.main()
