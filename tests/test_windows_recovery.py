"""Portable Windows verifier logic tested on disposable archives, not NTFS ACLs."""
from contextlib import closing
import io
import json
import hashlib
from pathlib import Path
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import saaoe_windows_verify as verifier


class WindowsVerifierTests(unittest.TestCase):
    def setUp(self):
        # Build already-decrypted synthetic artifacts directly. The portable verifier
        # must not require POSIX backup/sealing code or an executable age test double.
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        bundle = self.root / 'bundle'
        bundle.mkdir()
        database = bundle / 'database.sqlite3'
        with closing(sqlite3.connect(database)) as connection:
            for table in sorted(verifier.recovery.REQUIRED_TABLES):
                connection.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY)')
        release_files = {
            'requirements.txt': b'# synthetic fixture\n',
            'web/config.py': b'# synthetic fixture\n',
            'web/saaoe_cli.py': b'# synthetic fixture\n',
            'web/saaoe_api.py': b"SAAOE_VERSION = 'synthetic'\n",
        }
        with tarfile.open(bundle / 'release.tar.gz', 'w:gz') as archive:
            for name, content in release_files.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        commit = 'a' * 40
        manifest = {
            'commit': commit,
            'sha256': {name: verifier.recovery.digest(bundle / name)
                       for name in ('database.sqlite3', 'release.tar.gz')},
            'release_files': {name: hashlib.sha256(content).hexdigest()
                              for name, content in release_files.items()},
            'schema_sha256': verifier.recovery.inspect_database(database),
        }
        (bundle / 'manifest.json').write_text(json.dumps(manifest))
        (bundle / 'verification.json').write_text(json.dumps({'integrity': 'ok'}))
        evidence = self.root / 'evidence.json'
        evidence.write_text(json.dumps({'commit': commit, 'bundle': 'synthetic-bundle'}))
        files = {f'bundle/{path.name}': path for path in bundle.iterdir()}
        files['evidence/0000'] = evidence
        inventory = self.root / 'inventory.json'
        inventory.write_text(json.dumps({
            'files': {name: verifier.recovery.digest(path) for name, path in files.items()},
            'configuration_sources': [],
        }))
        files['inventory.json'] = inventory
        record = {
            'configuration_included': False, 'commit': commit, 'bundle': 'synthetic-bundle',
            'manifest_sha256': verifier.recovery.digest(bundle / 'manifest.json'),
            'snapshot_sha256': manifest['sha256']['database.sqlite3'],
            'release_sha256': manifest['sha256']['release.tar.gz'], 'evidence_count': 1,
        }
        self.receipt = self.root / 'upload-receipt.json'
        self.receipt.write_text(json.dumps(record))
        self.receipt_hash = verifier.recovery.digest(self.receipt)
        self.archive = self.root / 'archive.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, path in files.items():
                member = tarfile.TarInfo(name)
                member.size = path.stat().st_size
                with path.open('rb') as source:
                    archive.addfile(member, source)
        self.destination = self.root / 'windows-verified'
        self.enterContext(patch.object(verifier, 'RELEASE', record['commit']))
        self.enterContext(patch.object(verifier, 'MANIFEST_SHA', record['manifest_sha256']))

    def verify(self, digest=None):
        return verifier.verify_archive(self.archive,self.receipt,digest or self.receipt_hash,self.destination)

    def test_valid_configuration_free_archive(self):
        result = self.verify()
        self.assertEqual(result['integrity'],'ok')
        self.assertEqual(result['configuration_recovery'],'not_included')
        self.assertTrue((self.destination/'windows-verification.json').is_file())

    def test_untrusted_receipt_rejected(self):
        with self.assertRaisesRegex(ValueError,'Untrusted receipt'):
            self.verify('0'*64)
        self.assertFalse(self.destination.exists())

    def test_sensitive_and_traversal_entries_rejected(self):
        for name in ('configuration/0000','../escape','.env'):
            with tarfile.open(self.archive,'w:gz') as archive:
                member = tarfile.TarInfo(name); member.size = 2
                archive.addfile(member,io.BytesIO(b'{}'))
            with self.assertRaisesRegex(ValueError,'Unapproved archive'):
                self.verify()
            self.assertFalse(self.destination.exists())
            self.assertFalse(list(self.root.glob('.verifying-*')))

    def test_existing_output_is_preserved(self):
        self.destination.mkdir()
        with self.assertRaisesRegex(ValueError,'New output'):
            self.verify()
        self.assertTrue(self.destination.is_dir())
