import importlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class PublicLandingTests(unittest.TestCase):
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

    def tearDown(self):
        self.appmod.DB_PATH = self.original_db_path
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def test_public_home_before_setup_and_private_routes_remain_secured(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Operational clarity.', response.data)
        self.assertIn(b'/login', response.data)
        self.assertIn(b'NOT LIVE DATA', response.data)
        self.assertEqual(self.client.get('/dashboard').location, '/setup')
        self.assertEqual(self.client.get('/api/usage').status_code, 503)

    def test_guest_home_is_public_but_dashboard_requires_login(self):
        self.appmod.create_user('admin', 'longpassword1', 'admin')
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'href="/login"', response.data)
        protected = self.client.get('/dashboard')
        self.assertEqual(protected.status_code, 302)
        self.assertIn('/login', protected.location)
        self.assertIn('/dashboard', protected.location)
        self.assertEqual(self.client.get('/api/usage').status_code, 401)

    def test_anonymous_home_does_not_query_unavailable_database(self):
        with patch.object(self.appmod, '_db_query', side_effect=sqlite3.OperationalError('database is locked')) as query:
            response = self.client.get('/')

        query.assert_not_called()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Operational clarity.', response.data)
        self.assertIn(b'href="/login"', response.data)

    def test_signed_in_home_falls_back_to_guest_links_when_database_is_unavailable(self):
        self.appmod.create_user('admin', 'longpassword1', 'admin')
        self.client.post('/login', data={'username': 'admin', 'password': 'longpassword1'})

        with patch.object(self.appmod, '_db_query', side_effect=sqlite3.OperationalError('unable to open database file')) as query:
            response = self.client.get('/')

        query.assert_called()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Operational clarity.', response.data)
        self.assertIn(b'href="/login"', response.data)
        self.assertNotIn(b'href="/dashboard"', response.data)

    def test_page_route_inventory_matches_public_and_protected_routes(self):
        document = (Path(__file__).resolve().parents[1] / 'docs' / 'method-function-list-meaning-and-design.md').read_text()
        page_routes = document.split('### Page Routes', 1)[1].split('### Telemetry APIs', 1)[0]
        self.assertIn('- `/`: public homepage.', page_routes)
        self.assertIn('- `/dashboard`: protected workspace dashboard.', page_routes)

    def test_signed_in_user_can_open_dashboard_from_home(self):
        self.appmod.create_user('admin', 'longpassword1', 'admin')
        signed_in = self.client.post('/login', data={
            'username': 'admin', 'password': 'longpassword1',
        })
        self.assertEqual(signed_in.status_code, 302)
        self.assertEqual(signed_in.location, '/dashboard')
        self.assertEqual(self.client.get('/dashboard').status_code, 200)
        self.assertIn(b'href="/dashboard"', self.client.get('/').data)
        self.client.get('/logout')
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(self.client.get('/dashboard').status_code, 302)

    def test_legacy_root_login_redirect_still_opens_dashboard(self):
        self.appmod.create_user('admin', 'longpassword1', 'admin')
        response = self.client.post('/login?next=/', data={
            'username': 'admin', 'password': 'longpassword1',
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, '/dashboard')


if __name__ == '__main__':
    unittest.main()
