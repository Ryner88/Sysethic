"""Disposable fixtures: transport/age doubles are not cryptographic validation."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import saaoe_offhost as offhost
from tests import test_recovery as recovery_fixtures

RECIPIENT = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'
HEADER = b'age-encryption.org/v1\n'


class MemoryB2:
    bucket, prefix = 'testbucket123', 'sysethic/'
    def __init__(self):
        self.objects, self.names = {}, []
        self.fail_upload = False
        self.corrupt_download = False
        self.fail_download = False
    def upload(self, path, name):
        if self.fail_upload:
            raise RuntimeError('simulated transport failure')
        identity = str(len(self.objects) + 1)
        self.objects[identity] = Path(path).read_bytes()
        self.names.append(name)
        return identity
    def download(self, identity, destination):
        if self.fail_download:
            raise RuntimeError('simulated interrupted download')
        content = self.objects[identity]
        Path(destination).write_bytes(content + (b'tampered' if self.corrupt_download else b''))


class OffhostTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.previous_umask)
        recovery_fixtures.RecoveryTests.setUp(self)
        with contextlib.redirect_stdout(io.StringIO()):
            offhost.recovery.backup(self.db, self.repo, self.output, sys.executable)
        self.bundle = next(self.output.iterdir())
        self.manifest_hash = offhost.sha(self.bundle / 'manifest.json')
        self.sealed = self.root / 'sealed'
        self.sealed.mkdir(mode=0o700)
        self.received = self.root / 'received'
        self.received.mkdir(mode=0o700)
        self.restored = self.root / 'restored'
        self.restored.mkdir(mode=0o700)
        self.secret = self.root / 'synthetic.env'
        self.secret.write_text('TEST_ONLY_SECRET=disposable-configuration-marker\n')
        self.evidence = self.root / 'qualification.json'
        self.evidence.write_text(json.dumps({'bundle': self.bundle.name, 'commit': json.loads((self.bundle / 'manifest.json').read_text())['commit'], 'manifest_sha256': self.manifest_hash, 'synthetic_test': 'ok'}))
        self.identity = self.root / 'mock-identity'
        self.identity.write_text('NOT A REAL AGE PRIVATE KEY')
        self.age = self.root / 'age-double'
        self.age.write_text('#!' + sys.executable + '\n' + '''import sys
import tarfile
+if '--decrypt' in sys.argv:
+    data=open(sys.argv[-1],'rb').read()
+    if not data.startswith(b'age-encryption.org/v1\\n'): sys.exit(1)
+    sys.stdout.buffer.write(data[len(b'age-encryption.org/v1\\n'): ])
+else:
+    sys.stdout.buffer.write(b'age-encryption.org/v1\\n' + sys.stdin.buffer.read())
+'''.replace('\n+', '\n'))
        self.age.chmod(0o700)
        self.transport = MemoryB2()

    def seal(self, age=None):
        return offhost.seal(self.bundle, self.sealed, RECIPIENT, self.manifest_hash,
                            [self.secret], age=str(age or self.age), evidence_files=[self.evidence])

    def uploaded(self):
        package = self.seal()
        receipt_hash = offhost.upload(package, self.transport)
        return package, receipt_hash

    def test_public_configuration_requires_trusted_permissions(self):
        unit = self.root / 'synthetic.service'
        unit.write_text('[Service]\nUser=synthetic\n')
        unit.chmod(0o644)
        package = offhost.seal(self.bundle, self.sealed, RECIPIENT, self.manifest_hash,
                               age=str(self.age), public_files=[unit])
        self.assertTrue(json.loads((package / 'seal.json').read_text())['configuration_included'])
        unit.chmod(0o666)
        with self.assertRaisesRegex(offhost.Failure, 'trusted_public_file'):
            offhost.seal(self.bundle, self.sealed, RECIPIENT, self.manifest_hash,
                         age=str(self.age), public_files=[unit])

    def test_evidence_for_another_release_rejected(self):
        self.evidence.write_text(json.dumps({'commit': '0' * 40, 'bundle': self.bundle.name}))
        with self.assertRaisesRegex(offhost.Failure, 'evidence_release'):
            self.seal()
        self.assertFalse(list(self.sealed.iterdir()))

    def test_missing_recipient_rejected_before_encryption(self):
        for recipient in ('', None, 'AGE-SECRET-KEY-DO-NOT-ACCEPT'):
            with self.assertRaisesRegex(offhost.Failure, 'recipient'):
                offhost.seal(self.bundle, self.sealed, recipient, self.manifest_hash, age=str(self.age))
        self.assertEqual(list(self.sealed.iterdir()), [])

    def test_untrusted_manifest_rejected(self):
        with self.assertRaisesRegex(offhost.Failure, 'untrusted_manifest'):
            offhost.seal(self.bundle, self.sealed, RECIPIENT, '0' * 64, age=str(self.age))

    def test_invalid_backup_rejected_even_with_matching_manifest_hash(self):
        manifest = json.loads((self.bundle / 'manifest.json').read_text())
        manifest['sha256']['release.tar.gz'] = '0' * 64
        (self.bundle / 'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaises(RuntimeError):
            offhost.seal(self.bundle, self.sealed, RECIPIENT, offhost.sha(self.bundle / 'manifest.json'), age=str(self.age))
        self.assertEqual(list(self.sealed.iterdir()), [])

    def test_failed_encryption_has_no_published_package(self):
        with self.assertRaises(Exception):
            self.seal('/bin/false')
        self.assertEqual(list(self.sealed.iterdir()), [])

    def test_wrong_ciphertext_header_rejected(self):
        broken = self.root / 'bad-age'
        broken.write_text('#!' + sys.executable + '\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n')
        broken.chmod(0o700)
        with self.assertRaisesRegex(offhost.Failure, 'invalid_age'):
            self.seal(broken)
        self.assertEqual(list(self.sealed.iterdir()), [])

    def test_seal_permissions_and_metadata_hide_configuration_values(self):
        package = self.seal()
        self.assertEqual(package.stat().st_mode & 0o777, 0o700)
        for file in package.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('disposable-configuration-marker', (package / 'seal.json').read_text())
        self.assertFalse(list(package.glob('*.tar.gz')))

    def test_failed_upload_never_publishes_completion(self):
        package = self.seal()
        self.transport.fail_upload = True
        with self.assertRaises(RuntimeError):
            offhost.upload(package, self.transport)
        self.assertFalse((package / 'upload-receipt.json').exists())
        self.assertEqual(self.transport.names, [])

    def test_remote_mismatch_never_publishes_completion(self):
        package = self.seal()
        self.transport.corrupt_download = True
        with self.assertRaisesRegex(offhost.Failure, 'remote_ciphertext'):
            offhost.upload(package, self.transport)
        self.assertFalse((package / 'upload-receipt.json').exists())
        self.assertFalse(any(name.endswith('complete.json') for name in self.transport.names))

    def test_incomplete_readback_never_publishes_completion(self):
        package = self.seal()
        self.transport.fail_download = True
        with self.assertRaises(RuntimeError):
            offhost.upload(package, self.transport)
        self.assertFalse(any(name.endswith('complete.json') for name in self.transport.names))

    def test_local_ciphertext_mismatch_prevents_network_calls(self):
        package = self.seal()
        with (package / 'recovery.tar.gz.age').open('ab') as file:
            file.write(b'tampered')
        with self.assertRaisesRegex(offhost.Failure, 'local_ciphertext'):
            offhost.upload(package, self.transport)
        self.assertFalse(self.transport.objects)

    def test_upload_completion_is_last_and_duplicate_upload_rejected(self):
        package, receipt_hash = self.uploaded()
        self.assertEqual(receipt_hash, offhost.sha(package / 'upload-receipt.json'))
        self.assertTrue(self.transport.names[-1].endswith('complete.json'))
        with self.assertRaisesRegex(offhost.Failure, 'already_uploaded'):
            offhost.upload(package, self.transport)

    def test_retrieval_checks_external_receipt_hash_and_cleans_failure(self):
        package, receipt_hash = self.uploaded()
        with self.assertRaisesRegex(offhost.Failure, 'untrusted_receipt'):
            offhost.retrieve(package / 'upload-receipt.json', '0' * 64, self.received, self.transport)
        self.transport.corrupt_download = True
        with self.assertRaisesRegex(offhost.Failure, 'completion_marker'):
            offhost.retrieve(package / 'upload-receipt.json', receipt_hash, self.received, self.transport)
        self.assertEqual(list(self.received.iterdir()), [])

    def test_recovery_double_roundtrip_verifies_bundle_and_private_configuration(self):
        package, receipt_hash = self.uploaded()
        retrieved = offhost.retrieve(package / 'upload-receipt.json', receipt_hash, self.received, self.transport)
        with patch.object(offhost, 'machine_id', return_value='independent-test-host'):
            restored = offhost.decrypt(retrieved, self.identity, self.restored, receipt_hash, age=str(self.age))
        self.assertEqual(offhost.sha(restored / 'bundle/database.sqlite3'), offhost.sha(self.bundle / 'database.sqlite3'))
        self.assertEqual((restored / 'configuration/0000').read_bytes(), self.secret.read_bytes())
        self.assertEqual((restored / 'evidence/0000').read_bytes(), self.evidence.read_bytes())
        self.assertEqual((restored / 'configuration/0000').stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads((restored / 'recovery-evidence.json').read_text())['integrity'], 'ok')
        self.assertFalse(list(self.restored.glob('.decrypting-*')))

    def test_source_host_decryption_rejected_before_identity_read(self):
        package, receipt_hash = self.uploaded()
        retrieved = offhost.retrieve(package / 'upload-receipt.json', receipt_hash, self.received, self.transport)
        with self.assertRaisesRegex(offhost.Failure, 'source_host_forbidden'):
            offhost.decrypt(retrieved, self.root / 'missing-identity', self.restored, receipt_hash, age=str(self.age))

    def test_failed_decryption_removes_partial_plaintext(self):
        package, receipt_hash = self.uploaded()
        retrieved = offhost.retrieve(package / 'upload-receipt.json', receipt_hash, self.received, self.transport)
        with patch.object(offhost, 'machine_id', return_value='independent-test-host'):
            with self.assertRaisesRegex(offhost.Failure, "decryption_failed"):
                offhost.decrypt(retrieved, self.identity, self.restored, receipt_hash, age='/bin/false')
        self.assertEqual(list(self.restored.iterdir()), [])

    def test_unsafe_and_incomplete_archives_fail_without_publication(self):
        package, receipt_hash = self.uploaded()
        retrieved = offhost.retrieve(package / 'upload-receipt.json', receipt_hash, self.received, self.transport)
        for name in ('../escape', 'unexpected.txt', 'inventory.json'):
            payload = io.BytesIO()
            with tarfile.open(fileobj=payload, mode='w:gz') as archive:
                member = tarfile.TarInfo(name)
                member.size = 2
                archive.addfile(member, io.BytesIO(b'{}'))
            ciphertext = retrieved / 'recovery.tar.gz.age'
            ciphertext.write_bytes(HEADER + payload.getvalue())
            receipt = retrieved / 'receipt.json'
            record = json.loads(receipt.read_text())
            record['ciphertext_sha256'] = offhost.sha(ciphertext)
            receipt.write_text(json.dumps(record))
            with patch.object(offhost, 'machine_id', return_value='independent-test-host'):
                with self.assertRaisesRegex(offhost.Failure, 'unsafe_recovery_archive|incomplete_recovery_archive'):
                    offhost.decrypt(retrieved, self.identity, self.restored, offhost.sha(receipt), age=str(self.age))
            self.assertEqual(list(self.restored.iterdir()), [])
            self.assertFalse((self.root / 'escape').exists())

    def auth_payload(self, caps=None, buckets=None, prefix='sysethic/'):
        return {'accountId': 'test-account', 'authorizationToken': 'test-token', 'apiInfo': {'storageApi': {
            'apiUrl': 'https://api001.backblazeb2.com', 'downloadUrl': 'https://f001.backblazeb2.com',
            'allowed': {'buckets': buckets if buckets is not None else [{'id': 'testbucket123'}],
                        'namePrefix': prefix, 'capabilities': caps if caps is not None else ['readFiles', 'writeFiles', 'listBuckets']}}}}

    def test_native_api_requires_exact_bucket_prefix_and_capabilities(self):
        invalid = [self.auth_payload(caps=['readFiles','writeFiles','deleteFiles']),
                   self.auth_payload(buckets=None, prefix=None), self.auth_payload(buckets=[]),
                   self.auth_payload(buckets=[{'id':'testbucket123'},{'id':'other'}])]
        for payload in invalid:
            with patch.dict(os.environ, {'SAAOE_B2_KEY_ID':'test-id','SAAOE_B2_APPLICATION_KEY':'test-key'}):
                with patch.object(offhost.B2, 'request', return_value=payload):
                    with self.assertRaises(offhost.Failure):
                        offhost.B2('testbucket123','sysethic/','upload')
        with patch.dict(os.environ, {'SAAOE_B2_KEY_ID':'test-id','SAAOE_B2_APPLICATION_KEY':'test-key'}):
            with patch.object(offhost.B2, 'request', side_effect=[self.auth_payload(), {'buckets':[{'bucketId':'testbucket123','bucketType':'allPrivate'}]}]):
                client = offhost.B2('testbucket123','sysethic/','upload')
        self.assertEqual(client.bucket, 'testbucket123')

    def test_production_prefix_requires_matching_restricted_key(self):
        records = {'buckets':[{'bucketId':'testbucket123','bucketType':'allPrivate'}]}
        with patch.dict(os.environ, {'SAAOE_B2_KEY_ID':'test-id','SAAOE_B2_APPLICATION_KEY':'test-key'}):
            with patch.object(offhost.B2, 'request', side_effect=[self.auth_payload(prefix='production/backups/'), records]):
                client = offhost.B2('testbucket123','production/backups/','upload')
        self.assertEqual(client.prefix,'production/backups/')
        with patch.dict(os.environ, {'SAAOE_B2_KEY_ID':'test-id','SAAOE_B2_APPLICATION_KEY':'test-key'}):
            with patch.object(offhost.B2, 'request', return_value=self.auth_payload()):
                with self.assertRaisesRegex(offhost.Failure,'minimally_scoped'):
                    offhost.B2('testbucket123','production/backups/','upload')

    def test_nested_destination_under_exact_authorized_prefix(self):
        bucket = '8e1fa189581d278ca2150e1b'
        auth = self.auth_payload(prefix='production/', buckets=[{'id':bucket}])
        records = {'buckets':[{'bucketId':bucket,'bucketType':'allPrivate'}]}
        with patch.dict(os.environ, {'SAAOE_B2_KEY_ID':'synthetic','SAAOE_B2_APPLICATION_KEY':'synthetic'}):
            with patch.object(offhost.B2,'request',side_effect=[auth, records]):
                client = offhost.B2(bucket,'production/backups/','upload',key_prefix='production/')
        self.assertEqual(client.prefix,'production/backups/')
        with patch.object(offhost.B2,'request',side_effect=AssertionError('Network forbidden')):
            with self.assertRaisesRegex(offhost.Failure,'destination_outside'):
                offhost.B2(bucket,'other/backups/','upload',key_prefix='production/')

    def test_invalid_configuration_rejected_before_credentials_or_network(self):
        invalid = [('', 'production/backups/', 'production/', 'invalid_bucket_id'),
                   ('sysethic-recovery','production/backups/','production/','invalid_bucket_id'),
                   ('synthetic ', 'production/backups/','production/','invalid_bucket_id'),
                   ('synthetic\r','production/backups/','production/','invalid_bucket_id'),
                   ('synthetic','production/backups','production/','invalid_destination_prefix'),
                   ('synthetic','production/backups/ ','production/','invalid_destination_prefix'),
                   ('synthetic','production/backups/','production','invalid_key_prefix'),
                   ('synthetic','production/backups/','','invalid_key_prefix')]
        with patch.object(offhost.B2,'request',side_effect=AssertionError('Network forbidden')):
            for bucket, prefix, key_prefix, reason in invalid:
                with self.assertRaisesRegex(offhost.Failure,reason):
                    offhost.B2(bucket,prefix,'upload',key_prefix=key_prefix)

    def test_public_bucket_rejected(self):
        with patch.dict(os.environ, {'SAAOE_B2_KEY_ID':'test-id','SAAOE_B2_APPLICATION_KEY':'test-key'}):
            with patch.object(offhost.B2, 'request', side_effect=[self.auth_payload(), {'buckets':[{'bucketId':'testbucket123','bucketType':'allPublic'}]}]):
                with self.assertRaisesRegex(offhost.Failure, 'private_bucket'):
                    offhost.B2('testbucket123','sysethic/','upload')

    def test_upload_acknowledgement_mismatch_rejected(self):
        client = object.__new__(offhost.B2)
        client.api, client.bucket, client.prefix, client.token = 'https://api001.backblazeb2.com', 'testbucket123', 'sysethic/', 'test-token'
        payload = self.root / 'payload.age'
        payload.write_bytes(b'test ciphertext')
        responses = [{'uploadUrl':'https://pod001.backblazeb2.com/upload','authorizationToken':'test-upload-token'}, {'bucketId':'testbucket123','fileName':'sysethic/test.age','contentSha1':'0'*40,'contentLength':15,'fileId':'test-file-id'}]
        with patch.object(client, 'request', side_effect=responses):
            with self.assertRaisesRegex(offhost.Failure, 'acknowledgement'):
                client.upload(payload,'sysethic/test.age')

    def test_untrusted_network_endpoint_rejected(self):
        for url in ('http://api001.backblazeb2.com', 'https://evil.example', 'https://backblazeb2.com.evil.example', 'https://token@api001.backblazeb2.com'):
            with self.assertRaises(offhost.Failure):
                offhost.B2.valid_url(url)

    def test_real_age_public_recipient_encryption(self):
        age = Path('/tmp/sysethic-age-test-v1.3.2/age')
        if not age.exists():
            self.skipTest('Real age executable unavailable; no private identities are generated')
        package = self.seal(age)
        ciphertext = (package / 'recovery.tar.gz.age').read_bytes()
        self.assertTrue(ciphertext.startswith(HEADER))
        self.assertNotIn(b'disposable-configuration-marker', ciphertext)
        self.assertNotIn(b'inventory.json', ciphertext)
        self.assertNotIn(b'SQLite format 3', ciphertext)


if __name__ == '__main__':
    unittest.main()
