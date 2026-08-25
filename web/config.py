import os
import secrets
from dataclasses import dataclass
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
LOCAL_HOSTS = {'127.0.0.1', 'localhost', '::1'}
DEVELOPMENT_MODES = {'development', 'dev', 'local'}
PRODUCTION_MODES = {'production', 'prod'}
ALLOWED_MODES = DEVELOPMENT_MODES | PRODUCTION_MODES


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class AppConfig:
    mode: str
    secret_key: str
    host: str
    port: int
    debug: bool
    database_path: Path
    log_path: Path
    cpu_threshold: float
    memory_threshold: float
    disk_threshold: float
    network_threshold: float
    session_seconds: int
    session_cookie_secure: bool
    approval_ttl_seconds: int
    terminal_ws_host: str
    terminal_ws_port: int
    terminal_ws_scheme: str
    terminal_ws_enabled: bool
    terminal_output_limit: int
    files_access_cache_ttl_seconds: int
    quarantine_dir: Path
    threat_intel_path: Path

    @property
    def protected_bind(self):
        return self.host in LOCAL_HOSTS

    @property
    def threshold_summary(self):
        return {
            'cpu_percent': self.cpu_threshold,
            'memory_percent': self.memory_threshold,
            'disk_percent': self.disk_threshold,
            'network_bytes_per_second': self.network_threshold,
        }


def _load_dotenv_file(path):
    if not path.exists():
        return
    with path.open('r', encoding='utf-8') as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


def load_environment():
    env_path = BASE_DIR / '.env'
    try:
        from dotenv import load_dotenv

        load_dotenv(env_path)
    except ImportError:
        _load_dotenv_file(env_path)


def _env(name, default=None, aliases=()):
    for key in (name, *aliases):
        value = os.environ.get(key)
        if value is not None and value != '':
            return value
    return default


def _bool_env(name, default=False):
    value = _env(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _int_env(name, default, minimum=None, maximum=None):
    raw_value = _env(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ConfigError(f'{name} must be an integer, got {raw_value!r}.') from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f'{name} must be at least {minimum}.')
    if maximum is not None and value > maximum:
        raise ConfigError(f'{name} must be at most {maximum}.')
    return value


def _float_env(name, default, minimum=None):
    raw_value = _env(name, str(default))
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ConfigError(f'{name} must be a number, got {raw_value!r}.') from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f'{name} must be at least {minimum}.')
    return value


def _path_env(name, default, aliases=()):
    raw_value = _env(name, default, aliases=aliases)
    path = Path(raw_value).expanduser()
    if not path.is_absolute():
        path = BASE_DIR / path
    return path.resolve()


def _ensure_parent(path, label):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f'Cannot create {label} directory {path.parent}: {exc}') from exc


def _ensure_dir(path, label):
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f'Cannot create {label} directory {path}: {exc}') from exc


def load_config():
    load_environment()

    mode = _env('SAAOE_MODE', aliases=('SAAOE_ENV',), default='development').strip().lower()
    if mode not in ALLOWED_MODES:
        allowed = ', '.join(sorted(ALLOWED_MODES))
        raise ConfigError(f'SAAOE_MODE must be one of: {allowed}.')
    debug = _bool_env('SAAOE_DEBUG', default=False)
    secret_key = _env('SAAOE_SECRET_KEY')
    if not secret_key:
        if mode in DEVELOPMENT_MODES:
            secret_key = secrets.token_hex(32)
        else:
            raise ConfigError('SAAOE_SECRET_KEY is required outside development mode.')
    elif mode not in DEVELOPMENT_MODES and len(secret_key) < 32:
        raise ConfigError('SAAOE_SECRET_KEY must be at least 32 characters outside development mode.')

    host = _env('SAAOE_HOST', '127.0.0.1').strip()
    if not host:
        raise ConfigError('SAAOE_HOST cannot be empty.')

    config = AppConfig(
        mode=mode,
        secret_key=secret_key,
        host=host,
        port=_int_env('SAAOE_PORT', 5001, minimum=1, maximum=65535),
        debug=debug,
        database_path=_path_env('SAAOE_DATABASE_PATH', 'data/saaoe.db', aliases=('SAAOE_DB_PATH',)),
        log_path=_path_env('SAAOE_LOG_PATH', 'logs/system_log.csv'),
        cpu_threshold=_float_env('SAAOE_CPU_THRESHOLD', 85, minimum=0),
        memory_threshold=_float_env('SAAOE_MEMORY_THRESHOLD', 85, minimum=0),
        disk_threshold=_float_env('SAAOE_DISK_THRESHOLD', 90, minimum=0),
        network_threshold=_float_env('SAAOE_NETWORK_THRESHOLD', 100000000, minimum=0),
        session_seconds=_int_env('SAAOE_SESSION_SECONDS', 28800, minimum=60),
        session_cookie_secure=_bool_env('SAAOE_SESSION_COOKIE_SECURE', default=mode not in DEVELOPMENT_MODES),
        approval_ttl_seconds=_int_env('SAAOE_APPROVAL_TTL_SECONDS', 86400, minimum=60),
        terminal_ws_host=_env('TERMINAL_WS_HOST', '127.0.0.1'),
        terminal_ws_port=_int_env('TERMINAL_WS_PORT', 8765, minimum=1, maximum=65535),
        terminal_ws_scheme=_env('TERMINAL_WS_SCHEME', 'ws'),
        terminal_ws_enabled=_bool_env('SAAOE_ENABLE_TERMINAL_WS', default=False),
        terminal_output_limit=_int_env('SAAOE_TERMINAL_OUTPUT_LIMIT', 12000, minimum=1000),
        files_access_cache_ttl_seconds=_int_env('FILES_ACCESS_CACHE_TTL_SECONDS', 15, minimum=0),
        quarantine_dir=_path_env('SAAOE_QUARANTINE_DIR', 'quarantine'),
        threat_intel_path=_path_env('THREAT_INTEL_PATH', 'config/threat_intel.json'),
    )

    _ensure_parent(config.database_path, 'database')
    _ensure_parent(config.log_path, 'log')
    _ensure_dir(config.quarantine_dir, 'quarantine')
    return config


def startup_summary(config):
    bind_status = 'protected/local-only' if config.protected_bind else 'unprotected/non-local'
    thresholds = ', '.join(f'{key}={value:g}' for key, value in config.threshold_summary.items())
    return [
        f'SAAOE mode={config.mode}',
        f'SAAOE bind={config.host}:{config.port} ({bind_status})',
        f'SAAOE debug={str(config.debug).lower()}',
        f'SAAOE session_cookie_secure={str(config.session_cookie_secure).lower()}',
        f'SAAOE log_path={config.log_path}',
        f'SAAOE database_path={config.database_path}',
        f'SAAOE telemetry_thresholds={thresholds}',
    ]
