import importlib
import os
import tempfile
import unittest
from datetime import datetime


class VocabularyTests(unittest.TestCase):
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

    def test_severity_and_status_aliases_and_fallbacks(self):
        severity_cases = {
            'informational': 'info', 'ok': 'info', 'success': 'info',
            'minor': 'low', 'warning': 'medium', 'warn': 'medium',
            'major': 'high', 'danger': 'high', 'severe': 'critical', 'fatal': 'critical',
        }
        for legacy, expected in severity_cases.items():
            self.assertEqual(self.appmod.normalize_severity(legacy), expected)
        self.assertEqual(self.appmod.normalize_severity('unknown'), 'info')

        status_cases = {
            'new': 'open', 'pending': 'open', 'in progress': 'investigating',
            'reviewing': 'investigating', 'pending_approval': 'waiting_for_approval',
            'closed': 'resolved', 'completed': 'resolved', 'false_positive': 'dismissed',
            'suppressed': 'dismissed', 'failure': 'failed',
        }
        for legacy, expected in status_cases.items():
            self.assertEqual(self.appmod.normalize_status(legacy), expected)
        self.assertEqual(self.appmod.normalize_status('unknown'), 'open')
        self.assertEqual(self.appmod.normalize_status('unknown', default='failed'), 'failed')

        self.assertEqual(self.appmod.severity_label('severe'), 'Critical')
        self.assertEqual(self.appmod.status_label('pending_approval'), 'Waiting for Approval')
        self.assertEqual(self.appmod.severity_class('warning'), 'severity-medium')
        self.assertEqual(self.appmod.status_class('failure'), 'status-failed')

    def test_legacy_records_are_backfilled_and_api_values_are_stable(self):
        user = self.appmod.get_user_by_username('admin')
        org_id = user['organization_id']
        now = datetime.now().isoformat()
        self.appmod._db_exec(
            """
            INSERT INTO anomalies (
                id, organization_id, timestamp, metric, value, threshold, severity, category,
                confidence, threat_intel, risk_score, frameworks, validation, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ('legacy-warning', org_id, now, 'cpu_percent', 85, 80, 'warning', 'system',
             0.8, '{}', 60, '[]', 1, now, now)
        )
        self.appmod._db_exec(
            """
            INSERT INTO incidents (
                id, organization_id, title, severity, status, owner, anomaly_id,
                linked_anomalies, created_at, updated_at, resolution
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ('legacy-incident', org_id, 'Legacy incident', 'severe', 'closed', None,
             'legacy-warning', '["legacy-warning"]', now, now, 'done')
        )

        self.appmod.init_db()
        anomaly = self.client.get('/api/anomalies?severity=warning').json['anomalies']
        legacy_anomaly = next(row for row in anomaly if row['id'] == 'legacy-warning')
        self.assertEqual(legacy_anomaly['severity'], 'medium')
        self.assertEqual(legacy_anomaly['severity_label'], 'Medium')
        self.assertEqual(legacy_anomaly['risk_level'], 'high')

        incident = self.client.get('/api/incidents/legacy-incident').json['incident']
        self.assertEqual(incident['severity'], 'critical')
        self.assertEqual(incident['status'], 'resolved')
        self.assertEqual(incident['severity_label'], 'Critical')
        self.assertEqual(incident['status_label'], 'Resolved')

        vocabulary = self.client.get('/api/vocabulary').json
        self.assertEqual(vocabulary['severities']['critical']['label'], 'Critical')
        self.assertEqual(vocabulary['statuses']['waiting_for_approval']['css_class'], 'status-waiting-for-approval')

    def test_ui_and_reports_use_shared_human_readable_vocabulary(self):
        css_response = self.client.get('/static/sysethic.css')
        javascript_response = self.client.get('/static/vocabulary.js')
        css = css_response.get_data(as_text=True)
        javascript = javascript_response.get_data(as_text=True)
        css_response.close()
        javascript_response.close()
        page = self.client.get('/incidents').get_data(as_text=True)
        for css_class in (
            'severity-info', 'severity-low', 'severity-medium', 'severity-high', 'severity-critical',
            'status-open', 'status-investigating', 'status-waiting-for-approval',
            'status-resolved', 'status-dismissed', 'status-failed',
        ):
            self.assertIn(f'.{css_class}', css)
        self.assertIn('SysEthicVocabulary', javascript)
        self.assertIn('window.SYSETHIC_VOCABULARY', page)

        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        payload = response.json
        self.assertEqual(payload['anomaly']['severity'], 'critical')
        self.assertEqual(payload['anomaly']['severity_label'], 'Critical')
        self.assertEqual(payload['anomaly']['risk_level'], 'critical')
        self.assertEqual(payload['anomaly']['risk_label'], 'Critical')
        self.assertEqual(payload['incident']['status'], 'open')
        self.assertEqual(payload['incident']['status_label'], 'Open')
        csv_report = self.client.get('/api/reports/download.csv').get_data(as_text=True)
        self.assertIn('Critical', csv_report)
        self.assertIn('Open', csv_report)


if __name__ == '__main__':
    unittest.main()
