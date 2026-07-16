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
        response = self.client.post('/api/users', json={
            'username': 'tempuser',
            'password': 'longpassword4',
            'role': 'viewer',
        })
        self.assertEqual(response.status_code, 200)
        temp_user = self.appmod.get_user_by_username('tempuser')
        self.assertNotEqual(temp_user['password_hash'], 'longpassword4')
        self.assertTrue(self.appmod.check_password_hash(temp_user['password_hash'], 'longpassword4'))
        response = self.client.post('/api/users', json={'action': 'disable', 'id': temp_user['id']})
        self.assertEqual(response.status_code, 200)

        self.client.get('/logout')
        response = self.client.post('/signup', data={
            'username': 'requested',
            'organization': 'Requested Workspace',
            'password': 'longpassword5',
            'confirm': 'longpassword5',
        })
        self.assertEqual(response.status_code, 302)
        requested_user = self.appmod.get_user_by_username('requested')
        self.assertEqual(requested_user['role'], 'admin')
        self.assertTrue(requested_user['active'])
        response = self.client.post('/api/playbooks', json={'name': 'Requested Workspace Playbook'})
        self.assertEqual(response.status_code, 200)
        requested_playbook_id = response.json['playbook']['id']
        response = self.client.post('/api/validation_events', json={'event_type': 'memory_pressure'})
        self.assertEqual(response.status_code, 200)
        requested_incident_id = response.json['incident']['id']
        response = self.client.get('/api/audit_events')
        self.assertEqual(response.status_code, 200)
        self.assertIn('organization_created', {row['action'] for row in response.json['logs']})
        self.client.get('/logout')

        response = self.client.get('/api/usage')
        self.assertEqual(response.status_code, 401)

        self.login('viewer', 'longpassword3')
        response = self.client.get('/terminal')
        self.assertEqual(response.status_code, 403)
        response = self.client.get('/api/terminal/status')
        self.assertEqual(response.status_code, 403)
        response = self.client.post('/api/playbooks', json={'name': 'viewer mutation'})
        self.assertEqual(response.status_code, 403)
        response = self.client.post('/api/playbook_trigger', json={'id': 101})
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/automation_rules', json={'name': 'viewer mutation'})
        self.assertEqual(response.status_code, 403)
        response = self.client.get('/api/response_approvals')
        self.assertEqual(response.status_code, 403)
        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 403)

        self.client.get('/logout')
        self.login('analyst', 'longpassword2')
        response = self.client.post('/api/validation_events', json={'event_type': 'cpu_pressure'})
        self.assertEqual(response.status_code, 200)
        incident_id = response.json['incident']['id']

        self.client.get('/logout')
        self.login('viewer', 'longpassword3')
        response = self.client.post('/api/incidents', json={
            'id': incident_id,
            'note': 'regular user finding',
        })
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/incidents', json={
            'id': incident_id,
            'status': 'resolved',
        })
        self.assertEqual(response.status_code, 403)

        self.client.get('/logout')
        self.login('analyst', 'longpassword2')
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
        response = self.client.post('/api/playbook_trigger', json={'id': 101})
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/playbooks', json={'name': 'analyst mutation'})
        self.assertEqual(response.status_code, 403)
        response = self.client.post('/api/incidents', json={
            'id': incident_id,
            'note': 'validation investigation note',
        })
        self.assertEqual(response.status_code, 200)
        response = self.client.get(f'/api/incidents/{incident_id}')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(any(e['event_type'] == 'note_added' for e in response.json['timeline']))

        self.client.get('/logout')
        self.login('admin', 'longpassword1')
        response = self.client.get('/api/users')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('requested', {u['username'] for u in response.json['users']})
        response = self.client.get('/api/playbooks')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(requested_playbook_id, {pb['id'] for pb in response.json['playbooks']})
        response = self.client.get('/api/incidents')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(requested_incident_id, {i['id'] for i in response.json['incidents']})
        response = self.client.get(f'/api/incidents/{requested_incident_id}')
        self.assertEqual(response.status_code, 404)
        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'approve'})
        self.assertEqual(response.status_code, 200)
        response = self.client.post(f'/api/response_approvals/{approval_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 200)

        expired = self.client.post('/api/response_approvals', json={
            'incident_id': incident_id,
            'action': 'create_incident_report',
            'target': incident_id,
            'dry_run': True,
        })
        self.assertEqual(expired.status_code, 200)
        expired_id = expired.json['approval']['id']
        self.appmod._db_exec(
            "UPDATE response_approvals SET status = ?, expires_at = ? WHERE id = ?",
            ('approved', '2000-01-01T00:00:00', expired_id)
        )
        response = self.client.post(f'/api/response_approvals/{expired_id}', json={'command': 'execute'})
        self.assertEqual(response.status_code, 409)

        response = self.client.get('/terminal')
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/api/terminal/status')
        self.assertEqual(response.status_code, 200)
        response = self.client.post('/api/terminal/run', json={'command': 'hostname'})
        self.assertIn(response.status_code, {200, 400})

        response = self.client.post('/api/terminal/run', json={'command': 'cat /etc/passwd'})
        self.assertEqual(response.status_code, 400)

        response = self.client.get('/api/audit_events')
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json['logs']), 0)
        audit_types = {row['action'] for row in response.json['logs']}
        self.assertIn('login', audit_types)
        self.assertIn('logout', audit_types)
        self.assertIn('access_denied', audit_types)
        self.assertIn('user_created', audit_types)
        self.assertIn('user_disabled', audit_types)
        response = self.client.get('/api/audit_events?event_type=login&result=success&actor=admin')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['logs'])
        self.assertTrue(all(row['action'] == 'login' for row in response.json['logs']))

        response = self.client.get('/api/reports/download.csv')
        self.assertEqual(response.status_code, 200)
        history = self.appmod._db_query("SELECT * FROM report_history WHERE fmt = ?", ('csv',))
        self.assertTrue(history)

        with self.client.session_transaction() as sess:
            sess['last_seen_at'] = 0
        response = self.client.get('/api/usage')
        self.assertEqual(response.status_code, 401)

    def test_inactive_signup_does_not_block_admin_setup(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        os.unlink(tmp.name)
        original_db_path = self.appmod.DB_PATH
        self.appmod.DB_PATH = tmp.name
        try:
            self.appmod.init_db()
            self.appmod.create_user('pending', 'longpassword6', 'viewer', active=False)
            client = self.appmod.app.test_client()

            response = client.get('/')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, '/setup')

            response = client.get('/setup')
            self.assertEqual(response.status_code, 200)

            response = client.post('/setup', data={
                'username': 'bootstrap-admin',
                'password': 'longpassword7',
                'confirm': 'longpassword7',
            })
            self.assertEqual(response.status_code, 302)
            self.assertTrue(self.appmod.active_admin_exists())
        finally:
            self.appmod.DB_PATH = original_db_path
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass

    def test_workspace_join_modes(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        os.unlink(tmp.name)
        original_db_path = self.appmod.DB_PATH
        self.appmod.DB_PATH = tmp.name
        try:
            self.appmod.init_db()
            org_id = self.appmod.create_organization('Join Mode Workspace', created_by='owner')
            self.appmod.create_user('owner', 'longpassword8', 'admin', organization_id=org_id)
            org = self.appmod._db_query("SELECT * FROM organizations WHERE id = ?", (org_id,))[0]
            client = self.appmod.app.test_client()

            response = client.post('/join', data={
                'workspace_code': org['join_code'],
                'username': 'newuser',
                'password': 'longpassword9',
                'confirm': 'longpassword9',
            })
            self.assertEqual(response.status_code, 302)
            new_user = self.appmod.get_user_by_username('newuser')
            self.assertIsNotNone(new_user)
            self.assertEqual(new_user['role'], 'viewer')
            self.assertTrue(new_user['active'])

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            response = client.post('/api/organization', json={'name': 'Join Mode Workspace', 'join_policy': 'request_to_join'})
            self.assertEqual(response.status_code, 200)
            client.get('/logout')

            response = client.post('/join', data={
                'workspace_code': org['join_code'],
                'username': 'requestuser',
                'password': 'longpassword10',
                'confirm': 'longpassword10',
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Request sent', response.data)
            self.assertIsNone(self.appmod.get_user_by_username('requestuser'))

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            requests = client.get('/api/join_requests').json['requests']
            request_id = next(r['id'] for r in requests if r['username'] == 'requestuser')
            response = client.post('/api/join_requests', json={'id': request_id, 'action': 'approve'})
            self.assertEqual(response.status_code, 200)
            approved = self.appmod.get_user_by_username('requestuser')
            self.assertEqual(approved['role'], 'viewer')
            self.assertTrue(approved['active'])

            response = client.post('/api/organization', json={'name': 'Join Mode Workspace', 'join_policy': 'admin_invites_only'})
            self.assertEqual(response.status_code, 200)
            client.get('/logout')

            response = client.post('/join', data={
                'workspace_code': org['join_code'],
                'username': 'blockeduser',
                'password': 'longpassword11',
                'confirm': 'longpassword11',
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'admin-created invites', response.data)
            self.assertIsNone(self.appmod.get_user_by_username('blockeduser'))

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            response = client.post('/api/organization', json={'name': 'Join Mode Workspace', 'join_policy': 'open_with_code'})
            self.assertEqual(response.status_code, 200)
            client.get('/logout')
            response = client.post('/join', data={
                'workspace_code': org['join_code'],
                'username': 'openuser',
                'password': 'longpassword12',
                'confirm': 'longpassword12',
            })
            self.assertEqual(response.status_code, 302)
            open_user = self.appmod.get_user_by_username('openuser')
            self.assertEqual(open_user['role'], 'viewer')
            self.assertTrue(open_user['active'])
        finally:
            self.appmod.DB_PATH = original_db_path
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass

    def test_workspace_feature_permissions(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        os.unlink(tmp.name)
        original_db_path = self.appmod.DB_PATH
        self.appmod.DB_PATH = tmp.name
        try:
            self.appmod.init_db()
            org_id = self.appmod.create_organization('Permission Workspace', created_by='owner')
            self.appmod.create_user('owner', 'longpassword8', 'admin', organization_id=org_id)
            self.appmod.create_user('member', 'longpassword9', 'viewer', organization_id=org_id)
            member = self.appmod.get_user_by_username('member')
            client = self.appmod.app.test_client()

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            owner = self.appmod.get_user_by_username('owner')
            permission_rows = self.appmod._db_query("SELECT * FROM user_permissions WHERE user_id = ?", (owner['id'],))
            self.assertEqual(permission_rows, [])
            response = client.get('/users')
            self.assertEqual(response.status_code, 200)
            response = client.get('/terminal')
            self.assertEqual(response.status_code, 200)
            response = client.get('/api/terminal/status')
            self.assertEqual(response.status_code, 200)
            response = client.post('/api/terminal/run', json={'command': 'hostname'})
            self.assertIn(response.status_code, {200, 400})
            response = client.post('/api/playbooks', json={'name': 'admin implicit mutation'})
            self.assertEqual(response.status_code, 200)
            admin_playbook_id = response.json['playbook']['id']
            response = client.post('/api/playbooks', json={'action': 'delete', 'id': admin_playbook_id})
            self.assertEqual(response.status_code, 200)
            client.get('/logout')

            client.post('/login', data={'username': 'member', 'password': 'longpassword9'})
            response = client.get('/users')
            self.assertEqual(response.status_code, 403)
            response = client.get('/api/users')
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/playbooks', json={'name': 'forbidden'})
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/playbooks', json={'action': 'delete', 'id': 101})
            self.assertEqual(response.status_code, 403)
            response = client.get('/terminal')
            self.assertEqual(response.status_code, 403)
            response = client.get('/api/terminal/status')
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/terminal/run', json={'command': 'hostname'})
            self.assertEqual(response.status_code, 403)
            client.get('/logout')

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            response = client.post('/api/users', json={
                'action': 'permissions',
                'id': member['id'],
                'permissions': ['manage_members']
            })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['permissions'], ['manage_members'])
            client.get('/logout')

            client.post('/login', data={'username': 'member', 'password': 'longpassword9'})
            response = client.get('/users')
            self.assertEqual(response.status_code, 200)
            response = client.get('/api/users')
            self.assertEqual(response.status_code, 200)
            response = client.post('/api/users', json={
                'username': 'managed',
                'password': 'longpassword10',
                'role': 'viewer',
            })
            self.assertEqual(response.status_code, 200)
            managed = self.appmod.get_user_by_username('managed')
            response = client.post('/api/users', json={'action': 'disable', 'id': managed['id']})
            self.assertEqual(response.status_code, 200)
            response = client.post('/api/users', json={
                'action': 'permissions',
                'id': member['id'],
                'permissions': ['manage_members', 'access_terminal'],
            })
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/playbooks', json={'name': 'still forbidden'})
            self.assertEqual(response.status_code, 403)
            response = client.get('/terminal')
            self.assertEqual(response.status_code, 403)
            response = client.get('/api/terminal/status')
            self.assertEqual(response.status_code, 403)
            client.get('/logout')

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            response = client.post('/api/users', json={
                'action': 'permissions',
                'id': member['id'],
                'permissions': ['mutate_playbooks']
            })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json['permissions'], ['mutate_playbooks'])
            client.get('/logout')

            client.post('/login', data={'username': 'member', 'password': 'longpassword9'})
            response = client.get('/api/users')
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/playbooks', json={'name': 'allowed'})
            self.assertEqual(response.status_code, 200)
            playbook_id = response.json['playbook']['id']
            response = client.post('/api/playbooks', json={'action': 'delete', 'id': playbook_id})
            self.assertEqual(response.status_code, 200)
            response = client.get('/api/terminal/status')
            self.assertEqual(response.status_code, 403)
            client.get('/logout')

            client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            response = client.post('/api/users', json={
                'action': 'permissions',
                'id': member['id'],
                'permissions': []
            })
            self.assertEqual(response.status_code, 200)
            response = client.post('/api/users', json={
                'action': 'permissions',
                'id': member['id'],
                'permissions': ['access_terminal']
            })
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json['error'], 'terminal access is admin-only')
            client.get('/logout')

            client.post('/login', data={'username': 'member', 'password': 'longpassword9'})
            response = client.get('/users')
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/playbooks', json={'name': 'blocked again'})
            self.assertEqual(response.status_code, 403)
            response = client.get('/terminal')
            self.assertEqual(response.status_code, 403)
            response = client.get('/api/terminal/status')
            self.assertEqual(response.status_code, 403)
            response = client.post('/api/terminal/run', json={'command': 'hostname'})
            self.assertEqual(response.status_code, 403)

            events = self.appmod._db_query(
                "SELECT event_type, target, result, detail FROM audit_events WHERE event_type IN (?, ?, ?) ORDER BY id",
                ('permission_granted', 'permission_revoked', 'permission_change_failed')
            )
            self.assertTrue(any(e['event_type'] == 'permission_granted' and 'permission=manage_members' in e['detail'] for e in events))
            self.assertTrue(any(e['event_type'] == 'permission_granted' and 'permission=mutate_playbooks' in e['detail'] for e in events))
            self.assertTrue(any(e['event_type'] == 'permission_change_failed' and 'terminal access is admin-only' in e['detail'] for e in events))
            self.assertTrue(any(e['event_type'] == 'permission_revoked' and 'permission=manage_members' in e['detail'] for e in events))
            self.assertTrue(any(e['event_type'] == 'permission_revoked' and 'permission=mutate_playbooks' in e['detail'] for e in events))
        finally:
            self.appmod.DB_PATH = original_db_path
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass

    def test_disabling_user_revokes_existing_session(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        os.unlink(tmp.name)
        original_db_path = self.appmod.DB_PATH
        self.appmod.DB_PATH = tmp.name
        try:
            self.appmod.init_db()
            org_id = self.appmod.create_organization('Session Revocation Workspace', created_by='owner')
            self.appmod.create_user('owner', 'longpassword8', 'admin', organization_id=org_id)
            self.appmod.create_user('member', 'longpassword9', 'viewer', organization_id=org_id)
            member = self.appmod.get_user_by_username('member')
            owner_client = self.appmod.app.test_client()
            member_client = self.appmod.app.test_client()

            response = member_client.post('/login', data={'username': 'member', 'password': 'longpassword9'})
            self.assertEqual(response.status_code, 302)
            response = member_client.get('/api/usage')
            self.assertEqual(response.status_code, 200)

            owner_client.post('/login', data={'username': 'owner', 'password': 'longpassword8'})
            response = owner_client.post('/api/users', json={'action': 'disable', 'id': member['id']})
            self.assertEqual(response.status_code, 200)

            response = member_client.get('/api/usage')
            self.assertEqual(response.status_code, 401)
            disabled = self.appmod.get_user_by_username('member')
            self.assertGreater(disabled['session_version'], member['session_version'])

            response = member_client.post('/login', data={'username': 'member', 'password': 'longpassword9'})
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Invalid username or password', response.data)
        finally:
            self.appmod.DB_PATH = original_db_path
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass

    def test_invalid_usernames_are_rejected(self):
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        os.unlink(tmp.name)
        original_db_path = self.appmod.DB_PATH
        self.appmod.DB_PATH = tmp.name
        try:
            self.appmod.init_db()
            client = self.appmod.app.test_client()

            response = client.post('/setup', data={
                'username': 'x',
                'password': 'longpassword7',
                'confirm': 'longpassword7',
            })
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Username must be 3-64 characters', response.data)

            response = client.post('/setup', data={
                'username': 'bootstrap-admin',
                'password': 'longpassword7',
                'confirm': 'longpassword7',
            })
            self.assertEqual(response.status_code, 302)

            response = client.post('/api/users', json={
                'username': 'bad user',
                'password': 'longpassword8',
                'role': 'viewer',
            })
            self.assertEqual(response.status_code, 400)
            self.assertIn('Username must be 3-64 characters', response.json['error'])
        finally:
            self.appmod.DB_PATH = original_db_path
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass


if __name__ == '__main__':
    unittest.main()
