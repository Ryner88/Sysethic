#!/usr/bin/env python3
"""Standard-library bootstrap entry point for SAAOE."""

import os
import subprocess
import sys
import venv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def venv_python():
    if os.name == 'nt':
        return PROJECT_ROOT / 'venv' / 'Scripts' / 'python.exe'
    return PROJECT_ROOT / 'venv' / 'bin' / 'python'


def main(argv=None):
    argv = list(argv or sys.argv[1:])
    if sys.version_info < (3, 11):
        print('Python 3.11 or newer is required.', file=sys.stderr)
        return 2
    venv_dir = PROJECT_ROOT / 'venv'
    if not venv_dir.exists():
        venv.EnvBuilder(with_pip=True).create(venv_dir)
    python = venv_python()
    subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(PROJECT_ROOT / 'requirements.txt')], check=True)
    return subprocess.run(
        [str(python), '-m', 'web.saaoe_cli', 'setup', '--skip-install', *argv],
        cwd=str(PROJECT_ROOT),
        check=False,
    ).returncode


if __name__ == '__main__':
    raise SystemExit(main())
