import argparse
import getpass
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import venv
from pathlib import Path

import psutil
from werkzeug.security import generate_password_hash

from .config import BASE_DIR, ConfigError, DEVELOPMENT_MODES, load_config


RUNTIME_DIR = BASE_DIR / 'instance' / 'runtime'
PID_FILE = RUNTIME_DIR / 'saaoe.pid.json'
LOG_FILE = RUNTIME_DIR / 'saaoe.log'
HEALTH_TIMEOUT_SECONDS = 20


class CliError(RuntimeError):
    exit_code = 2


def _load_app():
    from . import saaoe_api

    return saaoe_api


def _print(payload, as_json=False):
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        status = payload.get('status') or ('healthy' if payload.get('healthy') else 'failed')
        print(status)
        for check in payload.get('checks', []):
            result = 'ok' if check.get('ok') else 'failed'
            detail = f": {check['detail']}" if check.get('detail') else ''
            print(f"  {result} {check['name']}{detail}")


def _runtime_dir():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DIR


def _venv_python():
    if os.name == 'nt':
        return BASE_DIR / 'venv' / 'Scripts' / 'python.exe'
    return BASE_DIR / 'venv' / 'bin' / 'python'


def _check_python():
    if sys.version_info < (3, 10):
        raise CliError('Python 3.10 or newer is required.')


def _write_env_if_missing():
    env_path = BASE_DIR / '.env'
    if env_path.exists():
        return False
    secret = secrets.token_urlsafe(48)
    env_path.write_text(
        '\n'.join([
            'SAAOE_MODE=production',
            f'SAAOE_SECRET_KEY={secret}',
            'SAAOE_HOST=127.0.0.1',
            'SAAOE_PORT=5001',
            'SAAOE_DEBUG=false',
            'SAAOE_DATABASE_PATH=data/saaoe.db',
            'SAAOE_LOG_PATH=logs/system_log.csv',
            'SAAOE_SESSION_COOKIE_SECURE=false',
            'SAAOE_ENABLE_TERMINAL_WS=0',
            '',
        ]),
        encoding='utf-8',
    )
    return True


def setup(args):
    _check_python()
    for directory in (BASE_DIR / 'data', BASE_DIR / 'logs', _runtime_dir()):
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / '.write-test'
        probe.write_text('ok', encoding='utf-8')
        probe.unlink()

    venv_dir = BASE_DIR / 'venv'
    if not venv_dir.exists():
        venv.EnvBuilder(with_pip=True).create(venv_dir)
    python = _venv_python()
    if not python.exists():
        raise CliError(f'Virtual environment Python not found at {python}.')

    if not args.skip_install:
        subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(BASE_DIR / 'requirements.txt')], check=True)
    created_env = _write_env_if_missing()

    appmod = _load_app()
    appmod.create_app()
    if not _schema_current():
        raise CliError('Database schema preflight failed.')

    if not appmod.active_admin_exists():
        if sys.stdin.isatty() and not args.no_admin_prompt:
            bootstrap_admin(argparse.Namespace(username=None))
        else:
            print('No administrator exists. Run bootstrap-admin from an interactive terminal.')

    payload = run_health(local=True, as_json=True)
    if not payload['healthy'] and payload.get('status') != 'stopped':
        raise CliError('Final preflight health check failed.')
    print('setup complete')
    if created_env:
        print('.env created with production, loopback-only defaults')
    return 0


def _schema_current():
    appmod = _load_app()
    required = {'users', 'audit_events', 'response_approvals', 'playbooks', 'validation_events'}
    rows = appmod._db_query("SELECT name FROM sqlite_master WHERE type = 'table'")
    return required.issubset({row['name'] for row in rows})


def bootstrap_admin(args):
    appmod = _load_app()
    appmod.create_app()
    if appmod.users_exist():
        raise CliError('Administrator bootstrap is allowed only while the user table is empty. Use authenticated user management.')
    username = args.username or input('Administrator username: ').strip()
    username_error = appmod.validate_username(username)
    if username_error:
        raise CliError(username_error)
    password = getpass.getpass('Administrator password: ')
    confirm = getpass.getpass('Confirm password: ')
    if len(password) < 10:
        raise CliError('Password must be at least 10 characters.')
    if password != confirm:
        raise CliError('Passwords do not match.')
    org_id = appmod.create_organization('Local Workspace', created_by=username)
    now = appmod.datetime.now().isoformat()
    appmod._db_exec(
        "INSERT INTO users (username, password_hash, role, active, organization_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), 'admin', 1, org_id, now),
    )
    appmod._db_exec(
        """
        INSERT INTO audit_events (
            organization_id, timestamp, actor, role, event_type, target,
            target_type, target_id, result, source, detail, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            org_id,
            now,
            'local-console',
            'system',
            'admin_bootstrap_created',
            f'user:{username}',
            'user',
            username,
            'success',
            'local',
            'first administrator created from local console',
            json.dumps({'username': username, 'role': 'admin'}, sort_keys=True),
        ),
    )
    print('administrator created')
    return 0


def _config_checks(config):
    checks = []
    checks.append({'name': 'configuration.mode', 'ok': config.mode not in DEVELOPMENT_MODES, 'detail': config.mode})
    checks.append({'name': 'configuration.secret', 'ok': bool(config.secret_key and len(config.secret_key) >= 32), 'detail': 'strong secret configured' if config.secret_key else 'missing secret'})
    checks.append({'name': 'configuration.debug', 'ok': not config.debug, 'detail': f'debug={config.debug}'})
    checks.append({'name': 'configuration.bind', 'ok': config.protected_bind, 'detail': f'{config.host}:{config.port}'})
    return checks


def run_health(local=False, as_json=False):
    checks = []
    try:
        config = load_config()
        checks.extend(_config_checks(config))
    except ConfigError as exc:
        return {'healthy': False, 'status': 'failed', 'checks': [{'name': 'configuration', 'ok': False, 'detail': str(exc)}]}

    appmod = _load_app()
    appmod.create_app()
    try:
        checks.append({'name': 'database', 'ok': _schema_current(), 'detail': 'schema current'})
    except Exception as exc:
        checks.append({'name': 'database', 'ok': False, 'detail': str(exc)})

    recent_sample = bool(appmod.usage_ts and appmod.cpu_series)
    checks.append({'name': 'telemetry sampler', 'ok': recent_sample, 'detail': 'sample buffer populated'})

    with appmod.app.test_client() as client:
        probe_headers = {'X-SAAOE-Healthcheck': '1'}
        page = client.get('/', headers=probe_headers)
        login_redirect = page.status_code == 302 and '/login' in (page.location or '')
        setup_redirect = page.status_code == 302 and '/setup' in (page.location or '')
        checks.append({'name': 'protected page', 'ok': login_redirect or setup_redirect, 'detail': f'status={page.status_code}'})
        api = client.get('/api/usage', headers=probe_headers)
        checks.append({'name': 'protected API', 'ok': api.status_code in {401, 503} and bool(api.json.get('error')), 'detail': f'status={api.status_code}'})
        health = client.get('/healthz')
        checks.append({'name': 'application', 'ok': health.status_code == 200 and health.json.get('service') == 'saaoe', 'detail': health.json.get('version') if health.is_json else 'invalid response'})

    if not local:
        reached = _http_health(config.host, config.port)
        checks.append({'name': 'live endpoint', 'ok': reached[0], 'detail': reached[1]})

    healthy = all(check['ok'] for check in checks)
    return {'healthy': healthy, 'status': 'healthy' if healthy else 'failed', 'checks': checks}


def health(args):
    payload = run_health(local=args.local, as_json=args.json)
    _print(payload, as_json=args.json)
    if payload['healthy']:
        return 0
    if any(check['name'] == 'live endpoint' and not check['ok'] for check in payload['checks']):
        return 2
    return 1


def _http_health(host, port):
    url = f'http://{host}:{port}/healthz'
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            payload = json.loads(response.read().decode('utf-8'))
        return response.status == 200 and payload.get('service') == 'saaoe', url
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return False, f'{url}: {exc}'


def _port_available(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) != 0


def _metadata():
    if not PID_FILE.exists():
        return None
    try:
        return json.loads(PID_FILE.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {'stale': True}


def _matched_process(meta):
    if not meta or meta.get('stale'):
        return None
    try:
        proc = psutil.Process(int(meta['pid']))
        if abs(proc.create_time() - float(meta['create_time'])) > 5:
            return None
        cmdline = proc.cmdline()
        identity = ' '.join(cmdline)
        if 'web.saaoe_cli' not in identity or 'run' not in cmdline or '--foreground' not in cmdline:
            return None
        return proc
    except (KeyError, ValueError, psutil.Error):
        return None


def status(args):
    meta = _metadata()
    if not meta:
        print('Stopped')
        return 0
    proc = _matched_process(meta)
    if not proc:
        print('Stale runtime metadata')
        return 1
    config = load_config()
    ok, detail = _http_health(config.host, config.port)
    print('Healthy' if ok else f'Running but unhealthy: {detail}')
    return 0 if ok else 1


def start(args):
    config = load_config()
    if not _port_available(config.host, config.port):
        raise CliError(f'Port {config.host}:{config.port} is already in use.')
    preflight = run_health(local=True, as_json=True)
    if not preflight['healthy']:
        _print(preflight)
        return 1
    _runtime_dir()
    log_handle = LOG_FILE.open('a', encoding='utf-8')
    kwargs = {'cwd': str(BASE_DIR), 'stdout': log_handle, 'stderr': subprocess.STDOUT}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True
    proc = subprocess.Popen([sys.executable, '-m', 'web.saaoe_cli', 'run', '--foreground'], **kwargs)
    PID_FILE.write_text(json.dumps({'pid': proc.pid, 'create_time': psutil.Process(proc.pid).create_time(), 'cmd': ['web.saaoe_cli', 'run', '--foreground']}), encoding='utf-8')
    deadline = time.time() + HEALTH_TIMEOUT_SECONDS
    while time.time() < deadline:
        ok, _ = _http_health(config.host, config.port)
        if ok:
            print(f'started pid={proc.pid}')
            return 0
        if proc.poll() is not None:
            break
        time.sleep(0.5)
    stop(argparse.Namespace(force=True))
    print('startup health failed')
    return 1


def stop(args):
    meta = _metadata()
    proc = _matched_process(meta)
    if not meta:
        print('stopped')
        return 0
    if not proc:
        print('stale runtime metadata')
        return 1
    proc.terminate()
    try:
        proc.wait(timeout=8)
    except psutil.TimeoutExpired:
        proc = _matched_process(meta)
        if proc:
            proc.kill()
            proc.wait(timeout=5)
    PID_FILE.unlink(missing_ok=True)
    print('stopped')
    return 0


def run(args):
    appmod = _load_app()
    app = appmod.create_app()
    config = load_config()
    try:
        from waitress import serve
    except ImportError as exc:
        raise CliError('Waitress is required. Run setup or install pinned dependencies.') from exc
    serve(app, host=config.host, port=config.port)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='SAAOE operations CLI')
    subparsers = parser.add_subparsers(dest='command', required=True)
    setup_parser = subparsers.add_parser('setup')
    setup_parser.add_argument('--no-admin-prompt', action='store_true')
    setup_parser.add_argument('--skip-install', action='store_true', help=argparse.SUPPRESS)
    setup_parser.set_defaults(func=setup)
    admin_parser = subparsers.add_parser('bootstrap-admin')
    admin_parser.add_argument('--username')
    admin_parser.set_defaults(func=bootstrap_admin)
    subparsers.add_parser('start').set_defaults(func=start)
    subparsers.add_parser('stop').set_defaults(func=stop)
    subparsers.add_parser('status').set_defaults(func=status)
    health_parser = subparsers.add_parser('health')
    health_parser.add_argument('--json', action='store_true')
    health_parser.add_argument('--local', action='store_true', help='skip live HTTP reachability')
    health_parser.set_defaults(func=health)
    run_parser = subparsers.add_parser('run')
    run_parser.add_argument('--foreground', action='store_true', required=True)
    run_parser.set_defaults(func=run)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(str(exc), file=sys.stderr)
        return getattr(exc, 'exit_code', 2)
    except subprocess.CalledProcessError as exc:
        print(f'command failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
