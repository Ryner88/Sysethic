import importlib
import os
import tempfile
import unittest


class RuleValidationAndAuthInventoryTests(unittest.TestCase):
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
        self.client.get('/logout')

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def login(self):
        self.client.post('/login', data={'username': 'admin', 'password': 'longpassword1'})

    def audit_actions(self):
        return [row['action'] for row in self.client.get('/api/audit_events').json['logs']]

    def assert_rule_count_unchanged(self, path, before):
        after = self.client.get(path).json['rules']
        self.assertEqual(len(after), before)

    def test_public_endpoint_allowlist_is_exact(self):
        expected_public_endpoints = {'static', 'login', 'logout', 'setup', 'signup', 'join', 'health'}
        self.assertEqual(self.appmod.PUBLIC_ENDPOINTS, expected_public_endpoints)

        public_routes = {}
        for rule in self.appmod.app.url_map.iter_rules():
            if rule.endpoint in expected_public_endpoints and rule.endpoint != 'static':
                public_routes.setdefault(rule.endpoint, set()).add(rule.rule)

        self.assertEqual(public_routes, {
            'health': {'/health', '/healthz'},
            'join': {'/join'},
            'login': {'/login'},
            'logout': {'/logout'},
            'setup': {'/setup'},
            'signup': {'/signup'},
        })

    def test_anonymous_routes_are_protected_by_category(self):
        protected_pages = ['/', '/terminal', '/users']
        for path in protected_pages:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.location.startswith('/login'))

        protected_apis = ['/api/usage', '/api/users', '/api/response_approvals']
        for path in protected_apis:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 401)

        public_response = self.client.get('/healthz')
        self.assertIn(public_response.status_code, {200, 503})
        self.assertEqual(set(public_response.json), {'ok', 'service', 'version'})

    def test_automation_rule_rejects_unknown_fields_operators_actions_and_values(self):
        self.login()
        before = len(self.client.get('/api/automation_rules').json['rules'])
        invalid_payloads = [
            ({'name': 'Bad extra', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'run_action': 'Notify Analyst', 'extra': 'x'}, 'unknown automation rule fields'),
            ({'name': 'Bad field', 'field': 'owner', 'operator': 'equals', 'value': 'root', 'run_action': 'Notify Analyst'}, 'unsupported automation rule field'),
            ({'name': 'Bad operator', 'field': 'severity', 'operator': 'contains', 'value': 'critical', 'run_action': 'Notify Analyst'}, 'unsupported automation rule operator'),
            ({'name': 'Bad value', 'field': 'risk_score', 'operator': '>=', 'value': 'nan', 'run_action': 'Notify Analyst'}, 'value must be a finite number'),
            ({'name': 'Bad action', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'run_action': 'Run Anything'}, 'unsupported automation rule action'),
            ({'name': '', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'run_action': 'Notify Analyst'}, 'name is required'),
            ({'name': 'Bad bool', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'run_action': 'Notify Analyst', 'enabled': 'yes'}, 'enabled must be true or false'),
        ]

        for payload, expected_error in invalid_payloads:
            with self.subTest(expected_error=expected_error):
                response = self.client.post('/api/automation_rules', json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected_error, response.json['error'])
                self.assert_rule_count_unchanged('/api/automation_rules', before)

        self.assertIn('automation_rule_create_failed', self.audit_actions())

    def test_rule_delete_rejects_malformed_ids_without_state_change(self):
        self.login()
        cases = [
            ('/api/automation_rules', 'automation_rule_delete_failed'),
            ('/api/anomaly_rules', 'anomaly_rule_delete_failed'),
        ]
        for path, audit_action in cases:
            before = len(self.client.get(path).json['rules'])
            for bad_id in ['abc', '1.5', -1, 0, True]:
                with self.subTest(path=path, bad_id=bad_id):
                    response = self.client.post(path, json={'action': 'delete', 'id': bad_id})
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(response.json['error'], 'id must be a positive integer')
                    self.assert_rule_count_unchanged(path, before)
            self.assertIn(audit_action, self.audit_actions())

    def test_anomaly_rule_accepts_valid_metric_operator_severity_and_threshold(self):
        self.login()
        path = '/api/anomaly_rules'
        before = len(self.client.get(path).json['rules'])
        payload = {
            'metric': 'cpu_percent',
            'operator': '>',
            'threshold': 90,
            'severity': 'high',
            'enabled': True,
            'alert_in_app': True,
            'alert_email': True,
        }

        response = self.client.post(path, json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['rule']['metric'], 'cpu_percent')
        self.assertEqual(response.json['rule']['operator'], '>')
        self.assertEqual(response.json['rule']['threshold'], 90.0)
        self.assertEqual(response.json['rule']['severity'], 'high')
        self.assertTrue(response.json['rule']['enabled'])
        self.assertTrue(response.json['rule']['alert_email'])
        after = self.client.get(path).json['rules']
        self.assertEqual(len(after), before + 1)

    def test_rule_apis_reject_non_json_and_non_object_bodies(self):
        self.login()
        cases = [
            ('/api/automation_rules', 'automation_rule_create_failed'),
            ('/api/anomaly_rules', 'anomaly_rule_create_failed'),
        ]
        for path, audit_action in cases:
            before = len(self.client.get(path).json['rules'])
            for kwargs in ({'data': 'not json'}, {'json': []}):
                with self.subTest(path=path, body=kwargs):
                    response = self.client.post(path, **kwargs)
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(response.json['error'], 'request body must be a JSON object')
                    self.assert_rule_count_unchanged(path, before)
            self.assertIn(audit_action, self.audit_actions())

    def test_anomaly_rule_rejects_invalid_metric_operator_severity_and_threshold(self):
        self.login()
        before = len(self.client.get('/api/anomaly_rules').json['rules'])
        invalid_payloads = [
            ({'metric': 'load_average', 'operator': '>', 'threshold': 90, 'severity': 'high'}, 'unsupported anomaly rule metric'),
            ({'metric': 'cpu_percent', 'operator': 'between', 'threshold': 90, 'severity': 'high'}, 'unsupported anomaly rule operator'),
            ({'metric': 'cpu_percent', 'operator': '>', 'threshold': 90, 'severity': 'urgent'}, 'unsupported anomaly rule severity'),
            ({'metric': 'cpu_percent', 'operator': '>', 'threshold': 'inf', 'severity': 'high'}, 'threshold must be a finite number'),
            ({'metric': 'cpu_percent', 'operator': '>', 'threshold': 90, 'severity': 'high', 'unknown': True}, 'unknown anomaly rule fields'),
            ({'metric': 'cpu_percent', 'operator': '>', 'threshold': 90, 'severity': 'high', 'alert_email': 'yes'}, 'alert_email must be true or false'),
        ]

        for payload, expected_error in invalid_payloads:
            with self.subTest(expected_error=expected_error):
                response = self.client.post('/api/anomaly_rules', json=payload)
                self.assertEqual(response.status_code, 400)
                self.assertIn(expected_error, response.json['error'])
                self.assert_rule_count_unchanged('/api/anomaly_rules', before)

        self.assertIn('anomaly_rule_create_failed', self.audit_actions())
