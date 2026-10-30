"""Portable Windows verifier logic tested on disposable archives, not NTFS ACLs."""
import io
import json
import tarfile
import unittest
from unittest.mock import patch
from tests import test_offhost_recovery as fixtures
import saaoe_windows_verify as verifier


class WindowsVerifierTests(unittest.TestCase):
    def setUp(self):
        fixtures.OffhostTests.setUp(self)
        package = fixtures.offhost.seal(self.bundle,self.sealed,fixtures.RECIPIENT,self.manifest_hash,
                                        age=str(self.age),evidence_files=[self.evidence])
        self.receipt_hash = fixtures.offhost.upload(package,self.transport)
        self.receipt = package / 'upload-receipt.json'
        self.archive = self.root / 'archive.tar.gz'
        self.archive.write_bytes((package/'recovery.tar.gz.age').read_bytes()[len(fixtures.HEADER):])
        self.destination = self.root / 'windows-verified'
        record = json.loads(self.receipt.read_text())
        self.addCleanup(patch.stopall)
        patch.object(verifier,'RELEASE',record['commit']).start()
        patch.object(verifier,'MANIFEST_SHA',record['manifest_sha256']).start()

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
