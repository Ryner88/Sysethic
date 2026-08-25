import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web.config import ConfigError, load_config, startup_summary


class ConfigTests(unittest.TestCase):
    def load_with_env(self, values):
        preserved = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith('SAAOE_') and key not in {
                'TERMINAL_WS_HOST',
                'TERMINAL_WS_PORT',
                'TERMINAL_WS_SCHEME',
                'FILES_ACCESS_CACHE_TTL_SECONDS',
                'THREAT_INTEL_PATH',
            }
        }
        with patch.dict(os.environ, preserved, clear=True):
            os.environ.update(values)
            with patch('web.config.load_environment'):
                return load_config()

    def test_default_config_is_local_and_debug_off(self):
        config = self.load_with_env({})

        self.assertEqual(config.mode, 'development')
        self.assertEqual(config.host, '127.0.0.1')
        self.assertEqual(config.port, 5001)
        self.assertFalse(config.debug)
        self.assertTrue(config.protected_bind)

    def test_production_requires_secret_key(self):
        with self.assertRaisesRegex(ConfigError, 'SAAOE_SECRET_KEY is required'):
            self.load_with_env({'SAAOE_MODE': 'production'})

    def test_unknown_mode_fails_closed(self):
        with self.assertRaisesRegex(ConfigError, 'SAAOE_MODE must be one of'):
            self.load_with_env({'SAAOE_MODE': 'staging', 'SAAOE_SECRET_KEY': 'x' * 32})

    def test_production_requires_strong_secret_key(self):
        with self.assertRaisesRegex(ConfigError, 'SAAOE_SECRET_KEY must be at least 32 characters'):
            self.load_with_env({'SAAOE_MODE': 'production', 'SAAOE_SECRET_KEY': 'short-secret'})

    def test_session_cookie_secure_defaults_to_production_only(self):
        development = self.load_with_env({})
        production = self.load_with_env({
            'SAAOE_MODE': 'production',
            'SAAOE_SECRET_KEY': 'x' * 32,
        })
        local_override = self.load_with_env({
            'SAAOE_MODE': 'production',
            'SAAOE_SECRET_KEY': 'x' * 32,
            'SAAOE_SESSION_COOKIE_SECURE': 'false',
        })

        self.assertFalse(development.session_cookie_secure)
        self.assertTrue(production.session_cookie_secure)
        self.assertFalse(local_override.session_cookie_secure)

    def test_env_can_override_paths_thresholds_and_port(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            config = self.load_with_env({
                'SAAOE_MODE': 'development',
                'SAAOE_PORT': '5099',
                'SAAOE_DATABASE_PATH': str(base / 'db' / 'custom.db'),
                'SAAOE_LOG_PATH': str(base / 'logs' / 'custom.csv'),
                'SAAOE_CPU_THRESHOLD': '72',
                'SAAOE_MEMORY_THRESHOLD': '73',
                'SAAOE_DISK_THRESHOLD': '91',
                'SAAOE_NETWORK_THRESHOLD': '12345',
            })

            self.assertEqual(config.port, 5099)
            self.assertEqual(config.database_path.resolve(), (base / 'db' / 'custom.db').resolve())
            self.assertEqual(config.log_path.resolve(), (base / 'logs' / 'custom.csv').resolve())
            self.assertEqual(config.cpu_threshold, 72)
            self.assertEqual(config.memory_threshold, 73)
            self.assertEqual(config.disk_threshold, 91)
            self.assertEqual(config.network_threshold, 12345)
            self.assertTrue((base / 'db').is_dir())
            self.assertTrue((base / 'logs').is_dir())

    def test_startup_summary_includes_bind_protection_and_paths(self):
        config = self.load_with_env({})
        summary = '\n'.join(startup_summary(config))

        self.assertIn('SAAOE mode=development', summary)
        self.assertIn('127.0.0.1:5001', summary)
        self.assertIn('protected/local-only', summary)
        self.assertIn('SAAOE session_cookie_secure=false', summary)
        self.assertIn('SAAOE log_path=', summary)
        self.assertIn('SAAOE database_path=', summary)
        self.assertIn('SAAOE telemetry_thresholds=', summary)


if __name__ == '__main__':
    unittest.main()
