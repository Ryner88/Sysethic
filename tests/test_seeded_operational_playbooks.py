import importlib
import os
import sys
import tempfile
import unittest


class SeededOperationalPlaybooksTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(delete=False)
        cls.tmp.close()
        os.unlink(cls.tmp.name)
        os.environ['SAAOE_DATABASE_PATH'] = cls.tmp.name
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

    def test_eight_seeded_definitions_are_idempotent_and_valid(self):
        expected = {
            'runaway-cpu-process-review',
            'memory-pressure-response',
            'suspicious-network-connection-review',
            'sensitive-file-access-review',
            'human-approval-required',
            'create-incident-report',
            'quarantine-file-with-approval',
            'block-ip-with-approval',
        }
        rows = self.appmod._db_query("SELECT * FROM playbooks WHERE source = ? ORDER BY stable_key", ('seeded',))
        self.assertEqual({row['stable_key'] for row in rows}, expected)
        self.assertEqual(len(rows), 8)
        digests = {row['stable_key']: row['definition_digest'] for row in rows}

        self.appmod._seed_db()
        rows_after = self.appmod._db_query("SELECT * FROM playbooks WHERE source = ?", ('seeded',))
        self.assertEqual(len(rows_after), 8)
        self.assertEqual(digests, {row['stable_key']: row['definition_digest'] for row in rows_after})

        for row in rows_after:
            self.appmod._parse_trigger(row['trigger_json'])
            self.appmod._parse_steps_yaml(row['steps_yaml'])
            self.assertNotIn(row['recommended_action_key'], {'kill_process', 'quarantine_file', 'block_ip'})

    def test_seed_repair_restores_missing_seeded_rows_without_extra_seeded_sources(self):
        expected = {
            'runaway-cpu-process-review',
            'memory-pressure-response',
            'suspicious-network-connection-review',
            'sensitive-file-access-review',
            'human-approval-required',
            'create-incident-report',
            'quarantine-file-with-approval',
            'block-ip-with-approval',
        }
        self.appmod._db_exec("DELETE FROM playbooks WHERE stable_key = ?", ('block-ip-with-approval',))
        self.appmod._db_exec("UPDATE playbooks SET source = ? WHERE stable_key = ?", ('seeded', 'first-run-admin-setup'))

        self.appmod._seed_db()

        rows = self.appmod._db_query("SELECT stable_key FROM playbooks WHERE source = ? ORDER BY stable_key", ('seeded',))
        self.assertEqual({row['stable_key'] for row in rows}, expected)
        self.assertEqual(len(rows), 8)
        system = self.appmod._db_query("SELECT source FROM playbooks WHERE stable_key = ?", ('first-run-admin-setup',))[0]
        self.assertEqual(system['source'], 'system')

    def test_seed_repair_preserves_existing_custom_or_system_playbook_ownership(self):
        try:
            self.appmod._db_exec("UPDATE playbooks SET source = ? WHERE stable_key = ?", ('custom', 'memory-pressure-response'))
            self.appmod._db_exec("UPDATE playbooks SET source = ? WHERE stable_key = ?", ('system', 'human-approval-required'))

            self.appmod._seed_db()

            memory = self.appmod._db_query("SELECT source FROM playbooks WHERE stable_key = ?", ('memory-pressure-response',))[0]
            approval = self.appmod._db_query("SELECT source FROM playbooks WHERE stable_key = ?", ('human-approval-required',))[0]
            self.assertEqual(memory['source'], 'custom')
            self.assertEqual(approval['source'], 'system')
            seeded_keys = {
                row['stable_key']
                for row in self.appmod._db_query("SELECT stable_key FROM playbooks WHERE source = ?", ('seeded',))
            }
            self.assertNotIn('memory-pressure-response', seeded_keys)
            self.assertNotIn('human-approval-required', seeded_keys)
        finally:
            self.appmod._db_exec("UPDATE playbooks SET source = ? WHERE stable_key IN (?, ?)", ('seeded', 'memory-pressure-response', 'human-approval-required'))


    def test_definition_update_toggle_validation_and_matching_query(self):
        cpu = self.appmod._db_query("SELECT * FROM playbooks WHERE stable_key = ?", ('runaway-cpu-process-review',))[0]
        old_version = cpu['version']
        old_digest = cpu['definition_digest']
        response = self.client.post('/api/playbooks', json={
            'action': 'update',
            'id': cpu['id'],
            'description': 'Updated CPU review description',
        })
        self.assertEqual(response.status_code, 200)
        updated = response.json['playbook']
        self.assertEqual(updated['version'], old_version + 1)
        self.assertNotEqual(updated['definition_digest'], old_digest)

        response = self.client.post('/api/playbooks', json={'action': 'disable', 'id': cpu['id']})
        self.assertEqual(response.status_code, 200)
        anomaly = {
            'id': 'A-test-cpu',
            'organization_id': None,
            'metric': 'cpu_percent',
            'value': 99.0,
            'category': 'system',
        }
        self.assertNotIn('runaway-cpu-process-review', {pb['stable_key'] for pb in self.appmod.persisted_playbook_matches(anomaly)})

        response = self.client.post('/api/playbooks', json={'action': 'enable', 'id': cpu['id']})
        self.assertEqual(response.status_code, 200)
        self.assertIn('runaway-cpu-process-review', {pb['stable_key'] for pb in self.appmod.persisted_playbook_matches(anomaly)})

        response = self.client.post('/api/playbooks', json={
            'name': 'Bad Shell',
            'stable_key': 'bad-shell',
            'yaml': 'steps:\n  - action: shell\n    command: rm -rf /tmp/x\n',
        })
        self.assertEqual(response.status_code, 400)
        audit = self.client.get('/api/audit_events?event_type=playbook.write_rejected').json['logs']
        self.assertTrue(audit)
        self.assertIn('request_digest', audit[0]['structured_details'])
        self.assertNotIn('rm -rf', audit[0]['details_json'])

        self.client.get('/logout')
        self.appmod.create_user('viewer', 'longpassword2', 'viewer')
        self.client.post('/login', data={'username': 'viewer', 'password': 'longpassword2'})
        response = self.client.post('/api/playbooks', json={'name': 'Forbidden'})
        self.assertEqual(response.status_code, 403)

    def test_run_snapshot_survives_definition_edit(self):
        response = self.client.post('/api/validation_events', json={'event_type': 'memory_pressure'})
        self.assertEqual(response.status_code, 200)
        run = response.json['playbook_runs'][0]
        old_name = run['playbook_name']
        old_version = run['playbook_version']
        old_digest = run['definition_digest']

        pb = self.appmod._db_query("SELECT * FROM playbooks WHERE stable_key = ?", ('memory-pressure-response',))[0]
        response = self.client.post('/api/playbooks', json={
            'action': 'update',
            'id': pb['id'],
            'name': 'Memory Pressure Response Edited',
        })
        self.assertEqual(response.status_code, 200)
        stored_run = self.appmod._db_query("SELECT * FROM playbook_runs WHERE id = ?", (run['id'],))[0]
        self.assertEqual(stored_run['playbook_name'], old_name)
        self.assertEqual(stored_run['playbook_version'], old_version)
        self.assertEqual(stored_run['definition_digest'], old_digest)


class PlaybookMigrationTests(unittest.TestCase):
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

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def test_registry_floor_migration_updates_completed_playbook_idempotently(self):
        pb = self.appmod._db_query("SELECT * FROM playbooks WHERE stable_key = ?", ('create-incident-report',))[0]
        weakened = dict(pb)
        weakened.update({
            'kind': 'anomaly_response',
            'category': 'system',
            'metric': 'cpu_percent',
            'operator': '>',
            'threshold': 80,
            'trigger_json': self.appmod._json_dumps({
                'type': 'anomaly',
                'metric': 'cpu_percent',
                'operator': '>',
                'threshold': 80,
                'category': 'system',
            }),
            'required_approval_role': 'none',
            'steps_yaml': 'steps:\n  - action: create_report\n    report_type: incident\n',
            'yaml': 'steps:\n  - action: create_report\n    report_type: incident\n',
            'version': 3,
            'updated_at': '2026-01-01T00:00:00',
            'updated_by': 'legacy',
        })
        old_digest = self.appmod._playbook_definition_digest(weakened)
        self.appmod._db_exec(
            """
            UPDATE playbooks
            SET kind = ?, category = ?, metric = ?, operator = ?, threshold = ?,
                trigger_json = ?, required_approval_role = ?, steps_yaml = ?, yaml = ?,
                version = ?, definition_digest = ?, updated_at = ?, updated_by = ?
            WHERE id = ?
            """,
            (
                weakened['kind'], weakened['category'], weakened['metric'], weakened['operator'],
                weakened['threshold'], weakened['trigger_json'], weakened['required_approval_role'],
                weakened['steps_yaml'], weakened['yaml'], weakened['version'], old_digest,
                weakened['updated_at'], weakened['updated_by'], pb['id'],
            )
        )
        self.appmod._db_exec(
            """
            INSERT INTO playbook_runs (
                playbook_id, playbook_stable_key, playbook_name, playbook_kind,
                playbook_version, definition_digest, name, anomaly_id, metric,
                value, threshold, action, recommended_action_key, required_approval_role,
                target, timestamp, created_at, created_by, auto, status, yaml, steps_yaml
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pb['id'], 'create-incident-report', pb['name'], 'anomaly_response',
                3, old_digest, pb['name'], 'A-historical', 'cpu_percent',
                91.0, 80.0, 'create_incident_report', 'create_incident_report', 'none',
                pb['target'], '2026-01-01T00:00:00', '2026-01-01T00:00:00',
                'system', 0, 'open', weakened['yaml'], weakened['steps_yaml'],
            )
        )

        self.appmod.init_db()
        upgraded = self.appmod._db_query("SELECT * FROM playbooks WHERE id = ?", (pb['id'],))[0]
        self.assertEqual(upgraded['required_approval_role'], 'analyst')
        self.assertEqual(upgraded['version'], 4)
        self.assertNotEqual(upgraded['definition_digest'], old_digest)
        self.assertEqual(upgraded['updated_by'], 'system')

        historical = self.appmod._db_query("SELECT * FROM playbook_runs WHERE anomaly_id = ?", ('A-historical',))[0]
        self.assertEqual(historical['definition_digest'], old_digest)
        self.assertEqual(historical['required_approval_role'], 'none')
        self.assertEqual(historical['playbook_version'], 3)

        digest_after_first = upgraded['definition_digest']
        updated_at_after_first = upgraded['updated_at']
        self.appmod.init_db()
        after_second = self.appmod._db_query("SELECT * FROM playbooks WHERE id = ?", (pb['id'],))[0]
        self.assertEqual(after_second['required_approval_role'], 'analyst')
        self.assertEqual(after_second['version'], 4)
        self.assertEqual(after_second['definition_digest'], digest_after_first)
        self.assertEqual(after_second['updated_at'], updated_at_after_first)

        anomaly = {
            'id': 'A-upgraded-floor',
            'organization_id': None,
            'timestamp': '2026-01-01T00:00:00',
            'metric': 'cpu_percent',
            'value': 95.0,
            'threshold': 80.0,
            'severity': 'high',
            'category': 'system',
            'confidence': 0.9,
            'risk_score': 85,
            'created_at': '2026-01-01T00:00:00',
            'updated_at': '2026-01-01T00:00:00',
        }
        with self.appmod.app.test_request_context('/'):
            _incident, runs = self.appmod.ingest_anomaly_workflow(anomaly, actor='system', organization_id=None, create_runs=True)
        upgraded_run = next(run for run in runs if run['playbook_stable_key'] == 'create-incident-report')
        self.assertEqual(upgraded_run['required_approval_role'], 'analyst')
        self.assertEqual(upgraded_run['status'], 'waiting_for_approval')
        self.assertEqual(upgraded_run['definition_digest'], digest_after_first)


if __name__ == '__main__':
    unittest.main()
