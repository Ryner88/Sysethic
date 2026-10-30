"""Independent, configuration-free decrypted archive verification (Python 3.11+)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

import saaoe_recovery as recovery

LIMIT = 128 * 1024 * 1024
RELEASE = "a9e4ed59ae91d9964e5a5d1d7f8a2c44536222cb"
MANIFEST_SHA = "461d2e8a86620c7ee627b247d5824079abc6a851785bfe426331d429fcbca2fe"


def verify_archive(archive_path, receipt_path, receipt_sha, output):
    if not re.fullmatch('[a-f0-9]{64}', receipt_sha):
        raise ValueError('Invalid receipt anchor')
    if recovery.digest(receipt_path) != receipt_sha:
        raise ValueError('Untrusted receipt')
    receipt = json.loads(Path(receipt_path).read_text())
    if receipt['configuration_included']:
        raise ValueError('Configuration-free recovery required')
    if receipt['commit'] != RELEASE:
        raise ValueError('Unexpected release')
    if receipt['manifest_sha256'] != MANIFEST_SHA:
        raise ValueError('Unexpected original manifest')
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('New output directory required')
    if not output.parent.is_dir() or any(p.is_symlink() for p in output.parents):
        raise ValueError('Trusted existing output parent required')
    stage = Path(tempfile.mkdtemp(prefix='.verifying-', dir=output.parent))
    try:
        fixed = {'inventory.json'} | {'bundle/' + n for n in ('manifest.json', 'verification.json', 'database.sqlite3', 'release.tar.gz')}
        seen, size = set(), 0
        with tarfile.open(archive_path, 'r|gz') as archive:
            for member in archive:
                if member.name not in fixed and not re.fullmatch('evidence/[0-9]{4}', member.name):
                    raise ValueError('Unapproved archive entry')
                if not member.isfile() or member.name in seen or member.size < 0:
                    raise ValueError('Unsafe archive member')
                seen.add(member.name)
                size += member.size
                if size > LIMIT:
                    raise ValueError('Expanded archive limit')
                target = stage / member.name
                target.parent.mkdir(mode=0o700, exist_ok=True)
                with target.open('xb') as handle:
                    shutil.copyfileobj(archive.extractfile(member), handle)
        if not fixed <= seen:
            raise ValueError('Incomplete archive')
        inventory = json.loads((stage / 'inventory.json').read_text())
        if inventory.get('configuration_sources') != [] or set(inventory['files']) != seen - {'inventory.json'}:
            raise ValueError('Inventory mismatch')
        for name, digest in inventory['files'].items():
            if recovery.digest(stage / name) != digest:
                raise ValueError('Recovered file hash mismatch')
        manifest_path = stage / 'bundle/manifest.json'
        if recovery.digest(manifest_path) != receipt['manifest_sha256']:
            raise ValueError('Manifest hash mismatch')
        manifest = json.loads(manifest_path.read_text())
        expected = {'database.sqlite3': receipt['snapshot_sha256'], 'release.tar.gz': receipt['release_sha256']}
        if manifest['sha256'] != expected or manifest['commit'] != receipt['commit']:
            raise ValueError('Release pairing mismatch')
        for name, digest in expected.items():
            if recovery.digest(stage / 'bundle' / name) != digest:
                raise ValueError('Bundle artifact mismatch')
        recovery.validate_archive(stage / 'bundle/release.tar.gz', manifest['release_files'])
        schema = recovery.inspect_database(stage / 'bundle/database.sqlite3')
        if schema != manifest['schema_sha256']:
            raise ValueError('Schema mismatch')
        evidence_names = [n for n in seen if n.startswith('evidence/')]
        if len(evidence_names) != receipt['evidence_count']:
            raise ValueError('Evidence count mismatch')
        for name in evidence_names:
            evidence = json.loads((stage / name).read_text())
            if evidence.get('commit') != receipt['commit'] or evidence.get('bundle') != receipt['bundle']:
                raise ValueError('Evidence pairing mismatch')
        result = {'integrity':'ok', 'schema':'ok', 'archive_exclusions':'ok', 'commit':receipt['commit'],
                  'manifest_sha256':receipt['manifest_sha256'], 'snapshot_sha256':receipt['snapshot_sha256'],
                  'release_sha256':receipt['release_sha256'], 'configuration_recovery':'not_included',
                  'application_workflows':'not_run_on_windows'}
        (stage / 'windows-verification.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        stage.rename(output)
        return result
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('archive', 'receipt', 'receipt-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.archive, args.receipt, args.receipt_sha256, args.output)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status':'failed', 'reason':type(error).__name__}))
        raise SystemExit(1)
