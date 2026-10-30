import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('qualification', ROOT / 'scripts/saaoe_qualify.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationSafetyTests(unittest.TestCase):
    def test_host_network_namespace_rejected_before_private_access(self):
        with self.assertRaisesRegex(RuntimeError, 'Private network'):
            qualification.require_isolation(os.readlink('/proc/self/ns/net'))

    def test_wrong_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'manifest.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError, 'independently recorded'):
                qualification.checked_manifest(root)

    def test_effective_capabilities_rejected(self):
        with patch.object(qualification.os, 'readlink', return_value='net:[private]'):
            with patch.object(qualification.Path, 'read_text', return_value='CapEff:\t00000001\n'):
                with self.assertRaisesRegex(RuntimeError, 'capabilities'):
                    qualification.require_isolation('net:[host]')

    def test_accessible_production_path_rejected(self):
        with patch.object(qualification.os, 'readlink', return_value='net:[private]'):
            with patch.object(qualification.Path, 'read_text', return_value='CapEff:\t00000000\n'):
                with patch.object(qualification.os, 'open', return_value=100):
                    with patch.object(qualification.os, 'close'):
                        with self.assertRaisesRegex(RuntimeError, 'Production path'):
                            qualification.require_isolation('net:[host]')

    def test_authenticated_workflows_with_archived_code_and_synthetic_data(self):
        python = ROOT / 'venv/bin/python'
        if not python.exists():
            self.skipTest('Local application test environment unavailable')
        with tempfile.TemporaryDirectory(prefix='saaoe-synthetic-') as tmp:
            root = Path(tmp)
            archive = root / 'release.tar.gz'
            files, version = qualification.recovery.release_archive(ROOT, qualification.EXPECTED_COMMIT, archive)
            qualification.recovery.validate_archive(archive, files, root)
            (root / 'data').mkdir(mode=0o700)
            secret = 'synthetic-fixture-secret-with-more-than-32-characters'
            (root / '.synthetic-key').write_text(secret)
            (root / '.env').write_text('\n'.join([
                'SAAOE_MODE=production', 'SAAOE_SECRET_KEY=' + secret,
                'SAAOE_DATABASE_PATH=' + str(root / 'data/saaoe.db'),
                'SAAOE_LOG_PATH=' + str(root / 'logs/synthetic.csv'),
                'SAAOE_ENABLE_TERMINAL_WS=false', 'SAAOE_SESSION_COOKIE_SECURE=true', '']))
            (root / '.env').chmod(0o600)
            result = root / 'result.json'
            # Direct function test on exclusively synthetic data, not a restored production copy.
            code = "import sys; sys.path.insert(0,sys.argv[1]); import saaoe_qualify; from pathlib import Path; saaoe_qualify.workflow(Path(sys.argv[2]),sys.argv[3],sys.argv[4])"
            environment = {'PATH': '/usr/bin:/bin', 'HOME': str(root),
                           'MPLCONFIGDIR': str(root / 'mpl'), 'PYTHONDONTWRITEBYTECODE': '1'}
            process = subprocess.run([str(python), '-B', '-c', code, str(ROOT / 'scripts'),
                                      str(root), version, str(result)], cwd=root, env=environment,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            self.assertEqual(process.returncode, 0, 'Synthetic workflow subprocess failed')
            metadata = json.loads(result.read_text())
            self.assertEqual(metadata['synthetic_signup_login_logout'], 'ok')
            self.assertEqual(metadata['committed_sqlite_persistence'], 'ok')
            self.assertEqual(metadata['viewer_write_denied'], 'ok')
            self.assertEqual(metadata['production_configuration_recovery'], 'not_verified')


if __name__ == '__main__':
    unittest.main()
