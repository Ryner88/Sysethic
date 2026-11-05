"""Crash/retry protocol tests using disposable files and synthetic remote storage."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch
import uuid

from tests import test_offhost_recovery as fixtures

offhost = fixtures.offhost
ROOT = Path(__file__).resolve().parents[1]


class FileB2:
    """Durable fake remote across subprocess crashes; never contacts B2."""
    bucket, prefix = fixtures.MemoryB2.bucket, fixtures.MemoryB2.prefix

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, exist_ok=True)

    def upload(self, path, name):
        file_id = uuid.uuid4().hex
        data = Path(path).read_bytes()
        metadata = {'fileId': file_id, 'fileName': name, 'bucketId': self.bucket,
                    'action': 'upload', 'contentLength': len(data),
                    'contentSha1': hashlib.sha1(data).hexdigest()}
        for suffix, content in (('.data', data), ('.json', json.dumps(metadata).encode())):
            with (self.root / (file_id + suffix)).open('xb') as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        offhost.recovery.sync_directory(self.root)
        return file_id

    def info(self, file_id):
        return json.loads((self.root / (file_id + '.json')).read_text())

    def download(self, file_id, destination):
        with Path(destination).open('xb') as handle:
            handle.write((self.root / (file_id + '.data')).read_bytes())

    def versions(self, name):
        return [item for path in self.root.glob('*.json')
                if (item := json.loads(path.read_text()))['fileName'] == name]

    @property
    def count(self):
        return len(list(self.root.glob('*.json')))


@unittest.skipUnless(os.name == 'posix', 'Durable journal and upload locks require POSIX')
class UploadRetryTests(unittest.TestCase):
    def setUp(self):
        fixtures.OffhostTests.setUp(self)
        self.package = fixtures.OffhostTests.seal(self)

    def state(self):
        return json.loads((self.package / 'upload-intent.json').read_text())

    def lose_acknowledgement(self, marker=False, store=True):
        original = self.transport.upload

        def interrupted(path, name):
            if name.endswith('complete.json') == marker:
                if store:
                    original(path, name)
                raise RuntimeError('synthetic interrupted transmission')
            return original(path, name)

        with patch.object(self.transport, 'upload', side_effect=interrupted):
            with self.assertRaisesRegex(RuntimeError, 'interrupted transmission'):
                offhost.upload(self.package, self.transport)

    def test_crash_before_transmission_reuses_durable_prepared_intent(self):
        with patch.object(offhost, 'send_once', side_effect=RuntimeError('synthetic crash')):
            with self.assertRaises(RuntimeError):
                offhost.upload(self.package, self.transport)
        before = self.state()
        self.assertEqual(before['ciphertext_status'], 'ready')
        self.assertFalse(self.transport.objects)
        offhost.upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 2)
        self.assertEqual(self.state()['operation_id'], before['operation_id'])
        self.assertEqual(self.transport.names[0], before['object_name'])

    def test_uncertain_absence_never_authorizes_retransmission(self):
        self.lose_acknowledgement(store=False)
        for _ in range(2):
            with self.assertRaisesRegex(offhost.Failure, 'requires_read_only_reconciliation'):
                offhost.upload(self.package, self.transport)
            with self.assertRaisesRegex(offhost.Failure, 'absence_cannot_resolve'):
                offhost.reconcile_upload(self.package, self.transport)
        self.assertFalse(self.transport.objects)
        self.assertEqual(self.state()['ciphertext_status'], 'pending')

    def test_matching_ciphertext_reused_after_lost_ack_without_upload(self):
        self.lose_acknowledgement()
        self.assertEqual(len(self.transport.objects), 1)
        for _ in range(2):
            result = offhost.reconcile_upload(self.package, self.transport)
            self.assertEqual(result['next'], 'completion_marker')
            self.assertEqual(len(self.transport.objects), 1)
        offhost.upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 2)
        self.assertEqual(sum(name.endswith('.age') for name in self.transport.names), 1)

    def test_marker_success_with_lost_ack_recovers_without_any_upload(self):
        self.lose_acknowledgement(marker=True)
        self.assertEqual(self.state()['marker_status'], 'pending')
        with self.assertRaisesRegex(offhost.Failure, 'requires_read_only_reconciliation'):
            offhost.upload(self.package, self.transport)
        for _ in range(3):
            result = offhost.reconcile_upload(self.package, self.transport)
            self.assertEqual(result['status'], 'verified')
            self.assertEqual(result['receipt_sha256'], offhost.sha(self.package / 'upload-receipt.json'))
            self.assertEqual(len(self.transport.objects), 2)

    def test_mismatched_remote_object_rejected(self):
        self.lose_acknowledgement()
        file_id = next(iter(self.transport.objects))
        self.transport.objects[file_id] = b'mismatched synthetic ciphertext'
        with self.assertRaisesRegex(offhost.Failure, 'remote_ciphertext_metadata_mismatch'):
            offhost.reconcile_upload(self.package, self.transport)
        self.assertEqual(self.state()['ciphertext_status'], 'pending')
        self.assertEqual(len(self.transport.objects), 1)
        self.assertFalse((self.package / 'upload-receipt.json').exists())

    def test_multiple_versions_rejected_even_with_identical_content(self):
        self.lose_acknowledgement()
        self.transport.upload(self.package / 'recovery.tar.gz.age', self.state()['object_name'])
        with self.assertRaisesRegex(offhost.Failure, 'ambiguous_remote_object_versions'):
            offhost.reconcile_upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 2)
        self.assertEqual(self.state()['ciphertext_status'], 'pending')

    def test_lookup_unavailable_blocks_recovery_and_retry(self):
        self.lose_acknowledgement()
        with patch.object(self.transport, 'versions', side_effect=OSError('synthetic unavailable')):
            with self.assertRaisesRegex(offhost.Failure, 'lookup_unavailable'):
                offhost.reconcile_upload(self.package, self.transport)
        with self.assertRaisesRegex(offhost.Failure, 'requires_read_only_reconciliation'):
            offhost.upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 1)

    def test_write_ahead_state_failure_prevents_transmission(self):
        original = offhost.save_upload_intent

        def crash_after_pending(package, state):
            original(package, state)
            raise RuntimeError('synthetic crash before send')

        with patch.object(offhost, 'save_upload_intent', side_effect=crash_after_pending):
            with self.assertRaises(RuntimeError):
                offhost.upload(self.package, self.transport)
        self.assertFalse(self.transport.objects)
        self.assertEqual(self.state()['ciphertext_status'], 'pending')
        with self.assertRaisesRegex(offhost.Failure, 'requires_read_only_reconciliation'):
            offhost.upload(self.package, self.transport)

    def test_intent_and_marker_are_durable_before_each_transmission(self):
        original = self.transport.upload

        def checked_upload(path, name):
            state = self.state()
            kind = 'marker' if name.endswith('complete.json') else 'ciphertext'
            self.assertEqual(state[kind + '_status'], 'pending')
            self.assertEqual(state['binding']['ciphertext_sha256'], offhost.sha(self.package / 'recovery.tar.gz.age'))
            if kind == 'marker':
                self.assertEqual(json.loads(Path(path).read_text()), state['completion'])
            return original(path, name)

        with patch.object(self.transport, 'upload', side_effect=checked_upload):
            offhost.upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 2)

    def test_concurrent_uploads_allow_at_most_one_active_operation(self):
        entered, release = threading.Event(), threading.Event()
        original = self.transport.upload
        errors = []

        def blocked_upload(path, name):
            entered.set()
            if not release.wait(10):
                raise TimeoutError('test synchronization failed')
            return original(path, name)

        def first():
            try:
                offhost.upload(self.package, self.transport)
            except BaseException as error:
                errors.append(error)

        with patch.object(self.transport, 'upload', side_effect=blocked_upload):
            thread = threading.Thread(target=first)
            thread.start()
            try:
                self.assertTrue(entered.wait(10))
                with self.assertRaisesRegex(offhost.Failure, 'upload_operation_locked'):
                    offhost.upload(self.package, self.transport)
                with self.assertRaisesRegex(offhost.Failure, 'upload_operation_locked'):
                    offhost.reconcile_upload(self.package, self.transport)
            finally:
                release.set()
                thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(self.transport.objects), 2)

    def test_process_crash_immediately_before_receipt_cannot_upload_again(self):
        remote = self.root / 'persistent-remote'
        code = '''
import os, sys
from pathlib import Path
from unittest.mock import patch
from tests.test_offhost_retry import FileB2, offhost
os.umask(0o077)
original = offhost.atomic_json
def crash(path, data, replace=False):
    if Path(path).name == 'upload-receipt.json':
        os._exit(73)
    return original(path, data, replace=replace)
with patch.object(offhost, 'atomic_json', side_effect=crash):
    offhost.upload(Path(sys.argv[1]), FileB2(sys.argv[2]))
'''
        process = subprocess.run([sys.executable, '-B', '-c', code, str(self.package), str(remote)],
                                 cwd=ROOT, capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 73, process.stderr.decode())
        transport = FileB2(remote)
        self.assertEqual(transport.count, 2)
        self.assertEqual(self.state()['marker_status'], 'acknowledged')
        self.assertFalse((self.package / 'upload-receipt.json').exists())
        with patch.object(transport, 'upload', side_effect=AssertionError('Retransmission forbidden')):
            receipt_hash = offhost.upload(self.package, transport)
            for _ in range(3):
                result = offhost.reconcile_upload(self.package, transport)
                self.assertEqual(result['receipt_sha256'], receipt_hash)
        self.assertEqual(transport.count, 2)
        self.assertFalse(list(self.package.glob('.upload-state-*')))

    def test_changed_source_or_destination_cannot_reuse_intent(self):
        self.lose_acknowledgement()
        with patch.object(self.transport, 'prefix', 'other/'):
            with self.assertRaisesRegex(offhost.Failure, 'upload_intent_binding_mismatch'):
                offhost.upload(self.package, self.transport)
        record_path = self.package / 'seal.json'
        record = json.loads(record_path.read_text())
        record['source_machine_id'] = 'different-source'
        record_path.write_text(json.dumps(record))
        with self.assertRaisesRegex(offhost.Failure, 'upload_intent_binding_mismatch'):
            offhost.upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 1)

    def test_receipt_directory_sync_failure_leaves_complete_recoverable_receipt(self):
        original = offhost.recovery.sync_directory

        def interrupted(directory):
            if (self.package / 'upload-receipt.json').exists():
                raise OSError('synthetic directory sync failure')
            return original(directory)

        with patch.object(offhost.recovery, 'sync_directory', side_effect=interrupted):
            with self.assertRaisesRegex(OSError, 'directory sync failure'):
                offhost.upload(self.package, self.transport)
        receipt = json.loads((self.package / 'upload-receipt.json').read_text())
        self.assertEqual(receipt['operation_id'], self.state()['operation_id'])
        with patch.object(self.transport, 'upload', side_effect=AssertionError('No retransmission')):
            result = offhost.reconcile_upload(self.package, self.transport)
        self.assertEqual(result['status'], 'verified')
        self.assertEqual(len(self.transport.objects), 2)

    def test_corrupt_intent_fails_closed_without_network_mutation(self):
        self.lose_acknowledgement()
        (self.package / 'upload-intent.json').write_text('{partial')
        with self.assertRaises(json.JSONDecodeError):
            offhost.upload(self.package, self.transport)
        with self.assertRaises(json.JSONDecodeError):
            offhost.reconcile_upload(self.package, self.transport)
        self.assertEqual(len(self.transport.objects), 1)

    def test_legacy_package_is_preserved_and_requires_operator_reconciliation(self):
        record_path = self.package / 'seal.json'
        record = json.loads(record_path.read_text())
        del record['upload_protocol']
        record_path.write_text(json.dumps(record))
        before = {path.name: offhost.sha(path) for path in self.package.iterdir()}
        with self.assertRaisesRegex(offhost.Failure, 'legacy_package_requires_operator_reconciliation'):
            offhost.upload(self.package, self.transport)
        self.assertEqual(before, {path.name: offhost.sha(path) for path in self.package.iterdir()})
        self.assertFalse(self.transport.objects)


if __name__ == '__main__':
    unittest.main()
