import threading
import time
from collections import deque
from datetime import datetime, timedelta
import queue
import secrets
import sqlite3
import statistics
import json
import socket
import base64
import csv
import hashlib
import ipaddress
import io
import os
import platform
import shlex
import shutil
import socketserver
import struct
import subprocess
import uuid
from functools import wraps

import psutil
from flask import Flask, jsonify, render_template, Response, stream_with_context, request, redirect, session, url_for, g, has_request_context
import pandas as pd
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from .config import BASE_DIR as PROJECT_ROOT, ConfigError, load_config, startup_summary
except ImportError:
    from config import BASE_DIR as PROJECT_ROOT, ConfigError, load_config, startup_summary

try:
    import GPUtil  # optional
except Exception:
    GPUtil = None

# Paths and operational configuration
CONFIG = load_config()
BASE_DIR = str(PROJECT_ROOT)
SAAOE_ENV = CONFIG.mode
SAAOE_DEBUG = CONFIG.debug
SECRET_KEY = CONFIG.secret_key
LOG_PATH = str(CONFIG.log_path)
DB_PATH = str(CONFIG.database_path)
APP_HOST = CONFIG.host
APP_PORT = CONFIG.port
CPU_THRESHOLD = CONFIG.cpu_threshold
MEMORY_THRESHOLD = CONFIG.memory_threshold
DISK_THRESHOLD = CONFIG.disk_threshold
NETWORK_THRESHOLD = CONFIG.network_threshold

# --- Flask app ---
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=CONFIG.session_seconds,
)
SESSION_TIMEOUT_SECONDS = CONFIG.session_seconds

# --- Ring buffers ---
MAX_SAMPLES = 240          # ~4 minutes @ 1s
SAMPLE_INTERVAL = 1.0      # seconds

cpu_series  = deque(maxlen=MAX_SAMPLES)
mem_series  = deque(maxlen=MAX_SAMPLES)
usage_ts    = deque(maxlen=MAX_SAMPLES)

read_series = deque(maxlen=MAX_SAMPLES)    # Disk MB/s
write_series= deque(maxlen=MAX_SAMPLES)
disk_ts     = deque(maxlen=MAX_SAMPLES)

rx_series   = deque(maxlen=MAX_SAMPLES)    # Net MB/s
tx_series   = deque(maxlen=MAX_SAMPLES)
net_ts      = deque(maxlen=MAX_SAMPLES)

# Notification queue for real-time alerts
notification_queue = queue.Queue()

# init so arrays are never empty
for _ in range(2):
    now = datetime.now().strftime('%H:%M:%S')
    cpu_series.append(0.0)
    mem_series.append(psutil.virtual_memory().percent)
    usage_ts.append(now)

    read_series.append(0.0)
    write_series.append(0.0)
    disk_ts.append(now)

    rx_series.append(0.0)
    tx_series.append(0.0)
    net_ts.append(now)

# in-memory rule store (persist optional)
anomaly_rules = [
    {'id': 1, 'metric': 'cpu_percent', 'operator': '>', 'threshold': CPU_THRESHOLD, 'severity': 'critical', 'enabled': True, 'alert_in_app': True, 'alert_email': False},
    {'id': 2, 'metric': 'memory_percent', 'operator': '>', 'threshold': MEMORY_THRESHOLD, 'severity': 'high', 'enabled': True, 'alert_in_app': True, 'alert_email': False},
    {'id': 3, 'metric': 'disk_percent', 'operator': '>', 'threshold': DISK_THRESHOLD, 'severity': 'high', 'enabled': True, 'alert_in_app': True, 'alert_email': False},
    {'id': 4, 'metric': 'network_bytes_per_second', 'operator': '>', 'threshold': NETWORK_THRESHOLD, 'severity': 'medium', 'enabled': True, 'alert_in_app': True, 'alert_email': False},
]
next_rule_id = 5

playbooks = [
    {'id': 1, 'name': 'Kill runaway CPU', 'category': 'system', 'metric': 'cpu_percent', 'operator': '>', 'threshold': max(CPU_THRESHOLD, 95), 'action': 'kill_process', 'target': 'cmdline', 'enabled': True, 'auto': True, 'yaml': 'name: Kill runaway CPU\ncategory: system\nsteps:\n  - action: snapshot_process\n    target: top_cpu\n  - action: isolate_process\n    target: "{{ process.pid }}"\n  - action: notify\n    target: security-ops\n'},
    {'id': 2, 'name': 'Isolate suspicious IP', 'category': 'network', 'metric': 'memory_percent', 'operator': '>', 'threshold': max(MEMORY_THRESHOLD, 90), 'action': 'block_ip', 'target': 'external', 'enabled': True, 'auto': False, 'yaml': 'name: Isolate suspicious IP\ncategory: network\nsteps:\n  - action: block_ip\n    target: "{{ anomaly.ip }}"\n  - action: collect_connections\n    target: host\n'},
]
next_playbook_id = 3
playbook_runs = []

automation_rules = [
    {'id': 1, 'name': 'Critical containment', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'action': 'Isolate Process', 'enabled': True},
    {'id': 2, 'name': 'High risk evidence capture', 'field': 'risk_score', 'operator': '>=', 'value': '75', 'action': 'Capture Forensics Bundle', 'enabled': True},
]
next_automation_rule_id = 3
automation_history = []

THREAT_INTEL_PATH = str(CONFIG.threat_intel_path)

DIAGNOSTIC_COMMANDS = {'netstat', 'ss', 'grep', 'rg', 'ps', 'uptime', 'whoami', 'hostname'}
TERMINAL_WS_HOST = CONFIG.terminal_ws_host
TERMINAL_WS_PORT = CONFIG.terminal_ws_port
TERMINAL_WS_SCHEME = CONFIG.terminal_ws_scheme
TERMINAL_WS_STARTED = False
TERMINAL_WS_SERVER = None

FILES_ACCESS_CACHE_TTL_SECONDS = CONFIG.files_access_cache_ttl_seconds
_files_access_cache = {'timestamp': 0.0, 'payload': None}
_threat_intel_cache = {'mtime': None, 'data': None}

SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}
STATUSES = {'open', 'investigating', 'waiting_for_approval', 'resolved', 'dismissed', 'failed'}
RESPONSE_ACTIONS = {'kill_process', 'quarantine_file', 'block_ip', 'create_incident_report'}
QUARANTINE_DIR = str(CONFIG.quarantine_dir)
TERMINAL_OUTPUT_LIMIT = CONFIG.terminal_output_limit
APPROVAL_TTL_SECONDS = CONFIG.approval_ttl_seconds


def _db():
    if 'db' not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def _db_exec(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur
    finally:
        conn.close()


def _db_query(sql, params=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


@app.errorhandler(sqlite3.Error)
def storage_error(exc):
    if _is_api_request():
        return jsonify(error='storage write failed', detail=str(exc)), 500
    return render_template('login.html', error=f"Storage error: {exc}", username=''), 500


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
                active INTEGER NOT NULL DEFAULT 1,
                organization_id INTEGER,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                join_policy TEXT NOT NULL DEFAULT 'join_with_code',
                join_code TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_permissions (
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL,
                granted_by TEXT NOT NULL,
                granted_at TEXT NOT NULL,
                PRIMARY KEY (user_id, permission)
            );

            CREATE TABLE IF NOT EXISTS join_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                source TEXT NOT NULL,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS anomaly_rules (
                id INTEGER PRIMARY KEY,
                metric TEXT NOT NULL,
                operator TEXT NOT NULL,
                threshold REAL NOT NULL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                alert_in_app INTEGER NOT NULL DEFAULT 1,
                alert_email INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS playbooks (
                id INTEGER PRIMARY KEY,
                organization_id INTEGER,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                metric TEXT NOT NULL,
                operator TEXT NOT NULL,
                threshold REAL NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                auto INTEGER NOT NULL DEFAULT 0,
                yaml TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS playbook_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                playbook_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                anomaly_id TEXT,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                threshold REAL NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                auto INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                yaml TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS automation_rules (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                field TEXT NOT NULL,
                operator TEXT NOT NULL,
                value TEXT NOT NULL,
                action TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS automation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                anomaly_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                organization_id INTEGER,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                owner TEXT,
                anomaly_id TEXT,
                recommended_playbook_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolution TEXT
            );

            CREATE TABLE IF NOT EXISTS incident_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                event_type TEXT NOT NULL,
                detail TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS response_approvals (
                id TEXT PRIMARY KEY,
                organization_id INTEGER,
                incident_id TEXT,
                anomaly_id TEXT,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                approved_by TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                dry_run INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                executed_at TEXT,
                result TEXT
            );

            CREATE TABLE IF NOT EXISTS validation_events (
                id TEXT PRIMARY KEY,
                organization_id INTEGER,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                anomaly_id TEXT,
                incident_id TEXT,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id TEXT PRIMARY KEY,
                organization_id INTEGER,
                timestamp TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL,
                threshold REAL NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0,
                rule_name TEXT,
                indicator_type TEXT,
                indicator TEXT,
                threat_intel TEXT NOT NULL DEFAULT '{}',
                risk_score INTEGER NOT NULL DEFAULT 0,
                frameworks TEXT NOT NULL DEFAULT '[]',
                validation INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS file_classifications (
                path TEXT PRIMARY KEY,
                organization_id INTEGER,
                sensitivity TEXT NOT NULL,
                owner TEXT,
                classification TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER,
                generated_at TEXT NOT NULL,
                fmt TEXT NOT NULL,
                generated_by TEXT NOT NULL,
                detail TEXT
            );

            CREATE TABLE IF NOT EXISTS app_configuration (
                key TEXT PRIMARY KEY,
                organization_id INTEGER,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            """
        )
        _ensure_column(conn, 'users', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'organizations', 'join_policy', "TEXT NOT NULL DEFAULT 'join_with_code'")
        _ensure_column(conn, 'organizations', 'join_code', "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, 'join_requests', 'detail', 'TEXT')
        _ensure_column(conn, 'audit_events', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'playbooks', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'playbook_runs', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'incidents', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'incident_events', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'response_approvals', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'validation_events', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'response_approvals', 'expires_at', 'TEXT')
        _ensure_column(conn, 'file_classifications', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'app_configuration', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'report_history', 'organization_id', 'INTEGER')
        default_org = conn.execute("SELECT id FROM organizations WHERE name = ?", ('Local Workspace',)).fetchone()
        if not default_org:
            cur = conn.execute(
                "INSERT INTO organizations (name, created_at, created_by) VALUES (?, ?, ?)",
                ('Local Workspace', datetime.now().isoformat(), 'system')
            )
            default_org_id = cur.lastrowid
        else:
            default_org_id = default_org[0]
        for org in conn.execute("SELECT id FROM organizations WHERE join_code = '' OR join_code IS NULL").fetchall():
            conn.execute("UPDATE organizations SET join_code = ? WHERE id = ?", (secrets.token_urlsafe(6), org[0]))
        conn.execute("UPDATE users SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE audit_events SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE incidents SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE incident_events SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE response_approvals SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE validation_events SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE file_classifications SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE app_configuration SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE report_history SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE file_classifications SET path = 'org:' || organization_id || ':' || path WHERE path NOT LIKE 'org:%'")
        conn.execute("UPDATE app_configuration SET key = 'org:' || organization_id || ':' || key WHERE key NOT LIKE 'org:%'")
        conn.commit()
    finally:
        conn.close()


def _ensure_column(conn, table, column, definition):
    columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _table_count(name):
    rows = _db_query(f"SELECT COUNT(*) AS count FROM {name}")
    return int(rows[0]['count']) if rows else 0


def _seed_db():
    seeded_playbooks = [
        {'id': 101, 'name': 'Runaway CPU Process Review', 'category': 'system', 'metric': 'cpu_percent', 'operator': '>', 'threshold': CPU_THRESHOLD, 'action': 'kill_process', 'target': 'top_cpu', 'enabled': True, 'auto': False, 'yaml': 'name: Runaway CPU Process Review\napproval: admin\nsteps:\n  - action: snapshot_process\n  - action: request_approval\n  - action: kill_process\n'},
        {'id': 102, 'name': 'Memory Pressure Response', 'category': 'host', 'metric': 'memory_percent', 'operator': '>', 'threshold': MEMORY_THRESHOLD, 'action': 'create_incident_report', 'target': 'host', 'enabled': True, 'auto': False, 'yaml': 'name: Memory Pressure Response\napproval: analyst\nsteps:\n  - action: collect_process_snapshot\n  - action: create_incident_report\n'},
        {'id': 103, 'name': 'Suspicious Network Connection Review', 'category': 'network', 'metric': 'network_public_connection', 'operator': '>', 'threshold': 0, 'action': 'block_ip', 'target': 'remote_ip', 'enabled': True, 'auto': False, 'yaml': 'name: Suspicious Network Connection Review\napproval: admin\nsteps:\n  - action: collect_connections\n  - action: request_approval\n  - action: block_ip\n'},
        {'id': 104, 'name': 'Sensitive File Access Review', 'category': 'file', 'metric': 'sensitive_file_access', 'operator': '>', 'threshold': 0, 'action': 'quarantine_file', 'target': 'path', 'enabled': True, 'auto': False, 'yaml': 'name: Sensitive File Access Review\napproval: admin\nsteps:\n  - action: classify_file\n  - action: request_approval\n  - action: quarantine_file\n'},
        {'id': 201, 'name': 'First-Run Admin Setup', 'category': 'authentication', 'metric': 'admin_user_count', 'operator': '<=', 'threshold': 0, 'action': 'create_admin_user', 'target': 'local_console', 'enabled': True, 'auto': False, 'yaml': 'name: First-Run Admin Setup\ncategory: authentication\ntrigger:\n  event: application_start\n  condition: no_admin_user_exists\napproval: local_console\nsteps:\n  - action: verify_setup_mode\n    require:\n      admin_count: 0\n      bind_address: 127.0.0.1\n  - action: collect_admin_credentials\n    fields:\n      - username\n      - password\n  - action: hash_password\n    algorithm: werkzeug_password_hash\n  - action: create_user\n    role: admin\n    enabled: true\n  - action: create_session\n  - action: audit_event\n    event_type: first_run_admin_created\n    result: success\n'},
        {'id': 202, 'name': 'Failed Login Review', 'category': 'authentication', 'metric': 'failed_login_count', 'operator': '>=', 'threshold': 5, 'action': 'create_incident_report', 'target': 'username_or_source_ip', 'enabled': True, 'auto': False, 'yaml': 'name: Failed Login Review\ncategory: authentication\ntrigger:\n  event: login_failed\n  window_minutes: 10\n  threshold: 5\n  group_by:\n    - username\n    - source_ip\napproval: admin\nsteps:\n  - action: collect_audit_events\n    event_type: login_failed\n    window_minutes: 10\n  - action: correlate_attempts\n    fields:\n      - username\n      - source_ip\n  - action: create_incident\n    severity: medium\n    title: Repeated failed login attempts\n  - action: recommend_response\n    options:\n      - disable_user\n      - keep_account_enabled\n      - require_password_reset\n  - action: notify_admin\n'},
        {'id': 203, 'name': 'Session Timeout Enforcement', 'category': 'authentication', 'metric': 'session_expired', 'operator': '>', 'threshold': 0, 'action': 'revoke_session', 'target': 'session', 'enabled': True, 'auto': False, 'yaml': 'name: Session Timeout Enforcement\ncategory: authentication\ntrigger:\n  event: request_received\n  condition: session_expired\napproval: automatic\nsteps:\n  - action: evaluate_session_timeout\n    idle_minutes: 30\n    absolute_hours: 8\n  - action: revoke_session\n  - action: audit_event\n    event_type: session_timeout\n    result: success\n  - action: require_login\n'},
        {'id': 204, 'name': 'Unauthorized Route Access Review', 'category': 'access_control', 'metric': 'access_denied_count', 'operator': '>', 'threshold': 0, 'action': 'deny_request', 'target': 'protected_route', 'enabled': True, 'auto': False, 'yaml': 'name: Unauthorized Route Access Review\ncategory: access_control\ntrigger:\n  event: access_denied\n  targets:\n    - protected_page\n    - protected_api\napproval: automatic\nsteps:\n  - action: check_authentication\n  - action: check_permission\n    source: route_policy\n  - action: deny_request\n    status:\n      page: 302\n      api: 401_or_403\n  - action: audit_event\n    event_type: access_denied\n    include:\n      - actor\n      - role\n      - route\n      - required_permission\n'},
        {'id': 205, 'name': 'User Disablement', 'category': 'access_control', 'metric': 'user_disable_requested', 'operator': '>', 'threshold': 0, 'action': 'disable_user', 'target': 'local_user', 'enabled': True, 'auto': False, 'yaml': 'name: User Disablement\ncategory: access_control\ntrigger:\n  event: user_disable_requested\napproval: admin\nsteps:\n  - action: verify_actor_role\n    role: admin\n  - action: prevent_last_admin_disable\n  - action: disable_user\n    enabled: false\n  - action: revoke_user_sessions\n  - action: audit_event\n    event_type: user_disabled\n    result: success\n    include:\n      - actor\n      - target_user\n'},
    ]
    if _table_count('anomaly_rules') == 0:
        for rule in anomaly_rules:
            _db_exec(
                "INSERT INTO anomaly_rules (id, metric, operator, threshold, severity, enabled, alert_in_app, alert_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rule['id'], rule['metric'], rule['operator'], rule['threshold'], rule['severity'], int(rule['enabled']), int(rule['alert_in_app']), int(rule['alert_email']))
            )
    if _table_count('playbooks') == 0:
        for pb in playbooks:
            _db_exec(
                "INSERT INTO playbooks (id, name, category, metric, operator, threshold, action, target, enabled, auto, yaml) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pb['id'], pb['name'], pb['category'], pb['metric'], pb['operator'], pb['threshold'], pb['action'], pb['target'], int(pb['enabled']), int(pb['auto']), pb['yaml'])
            )
    for pb in seeded_playbooks:
        if not _db_query("SELECT id FROM playbooks WHERE name = ?", (pb['name'],)):
            _db_exec(
                "INSERT INTO playbooks (id, name, category, metric, operator, threshold, action, target, enabled, auto, yaml) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (pb['id'], pb['name'], pb['category'], pb['metric'], pb['operator'], pb['threshold'], pb['action'], pb['target'], int(pb['enabled']), int(pb['auto']), pb['yaml'])
            )
    if _table_count('automation_rules') == 0:
        for rule in automation_rules:
            _db_exec(
                "INSERT INTO automation_rules (id, name, field, operator, value, action, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rule['id'], rule['name'], rule['field'], rule['operator'], rule['value'], rule['action'], int(rule['enabled']))
            )


def _bool_row(row, key):
    return bool(row.get(key))


def _json_dumps(value):
    return json.dumps(value if value is not None else {}, sort_keys=True)


def _json_loads(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _anomaly_from_row(row):
    return {
        'id': row['id'],
        'organization_id': row.get('organization_id'),
        'timestamp': row['timestamp'],
        'metric': row['metric'],
        'value': row['value'],
        'threshold': row['threshold'],
        'severity': row['severity'],
        'category': row['category'],
        'confidence': row.get('confidence') or 0,
        'rule_name': row.get('rule_name'),
        'indicator_type': row.get('indicator_type'),
        'indicator': row.get('indicator'),
        'threat_intel': _json_loads(row.get('threat_intel'), {}),
        'risk_score': row.get('risk_score') or 0,
        'frameworks': _json_loads(row.get('frameworks'), []),
        'validation': bool(row.get('validation')),
    }


def _persist_anomaly(anomaly, organization_id=None):
    now = datetime.now().isoformat()
    organization_id = organization_id if organization_id is not None else anomaly.get('organization_id')
    anomaly['organization_id'] = organization_id
    if 'id' not in anomaly:
        _decorate_threat_intel(anomaly)
    if 'risk_score' not in anomaly:
        anomaly['risk_score'] = 0
    if 'frameworks' not in anomaly:
        anomaly['frameworks'] = []
    if 'threat_intel' not in anomaly:
        anomaly['threat_intel'] = {}
    _db_exec(
        """
        INSERT INTO anomalies (
            id, organization_id, timestamp, metric, value, threshold, severity, category,
            confidence, rule_name, indicator_type, indicator, threat_intel, risk_score,
            frameworks, validation, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            organization_id = excluded.organization_id,
            timestamp = excluded.timestamp,
            metric = excluded.metric,
            value = excluded.value,
            threshold = excluded.threshold,
            severity = excluded.severity,
            category = excluded.category,
            confidence = excluded.confidence,
            rule_name = excluded.rule_name,
            indicator_type = excluded.indicator_type,
            indicator = excluded.indicator,
            threat_intel = excluded.threat_intel,
            risk_score = excluded.risk_score,
            frameworks = excluded.frameworks,
            validation = excluded.validation,
            updated_at = excluded.updated_at
        """,
        (
            anomaly['id'], organization_id, anomaly['timestamp'], anomaly['metric'],
            float(anomaly.get('value', 0)), float(anomaly.get('threshold', 0)),
            normalize_severity(anomaly.get('severity')), anomaly.get('category') or 'system',
            float(anomaly.get('confidence', 0)), anomaly.get('rule_name'),
            anomaly.get('indicator_type'), anomaly.get('indicator'),
            _json_dumps(anomaly.get('threat_intel')), int(anomaly.get('risk_score', 0)),
            _json_dumps(anomaly.get('frameworks') or []), int(bool(anomaly.get('validation'))),
            now, now,
        )
    )
    return anomaly


def _persist_anomalies(anomalies, organization_id=None):
    for anomaly in anomalies:
        _persist_anomaly(anomaly, organization_id=organization_id)
    return anomalies


def _stored_anomalies(start=None, end=None, severity=None, organization_id=None, limit=200):
    where = []
    params = []
    if organization_id is not None:
        where.append("organization_id = ?")
        params.append(organization_id)
    if start:
        where.append("timestamp >= ?")
        params.append(start)
    if end:
        where.append("timestamp <= ?")
        params.append(end)
    if severity:
        where.append("severity = ?")
        params.append(severity)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    params.append(limit)
    return [
        _anomaly_from_row(row)
        for row in _db_query(f"SELECT * FROM anomalies {where_sql} ORDER BY timestamp DESC LIMIT ?", tuple(params))
    ]


def _playbooks_from_db(organization_id=None):
    if organization_id is None:
        rows = _db_query("SELECT * FROM playbooks ORDER BY id")
    else:
        rows = _db_query("SELECT * FROM playbooks WHERE organization_id IS NULL OR organization_id = ? ORDER BY id", (organization_id,))
    return [{
        'id': row['id'],
        'organization_id': row.get('organization_id'),
        'name': row['name'],
        'category': row['category'],
        'metric': row['metric'],
        'operator': row['operator'],
        'threshold': row['threshold'],
        'action': row['action'],
        'target': row['target'],
        'enabled': _bool_row(row, 'enabled'),
        'auto': _bool_row(row, 'auto'),
        'yaml': row['yaml'],
    } for row in rows]


def _playbook_runs_from_db(organization_id=None, playbook_ids=None, limit=100):
    where = []
    params = []
    if organization_id is not None:
        where.append("(organization_id IS NULL OR organization_id = ?)")
        params.append(organization_id)
    if playbook_ids:
        placeholders = ','.join(['?'] * len(playbook_ids))
        where.append(f"playbook_id IN ({placeholders})")
        params.extend(playbook_ids)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    params.append(limit)
    rows = _db_query(f"SELECT * FROM playbook_runs {where_sql} ORDER BY id DESC LIMIT ?", tuple(params))
    return list(reversed(rows))


def _automation_rules_from_db():
    return [{
        'id': row['id'],
        'name': row['name'],
        'field': row['field'],
        'operator': row['operator'],
        'value': row['value'],
        'action': row['action'],
        'enabled': _bool_row(row, 'enabled'),
    } for row in _db_query("SELECT * FROM automation_rules ORDER BY id")]


def _anomaly_rules_from_db():
    return [{
        'id': row['id'],
        'metric': row['metric'],
        'operator': row['operator'],
        'threshold': row['threshold'],
        'severity': row['severity'],
        'enabled': _bool_row(row, 'enabled'),
        'alert_in_app': _bool_row(row, 'alert_in_app'),
        'alert_email': _bool_row(row, 'alert_email'),
    } for row in _db_query("SELECT * FROM anomaly_rules ORDER BY id")]


def load_persistent_state():
    global anomaly_rules, next_rule_id, playbooks, next_playbook_id, playbook_runs
    global automation_rules, next_automation_rule_id, automation_history

    anomaly_rules = []
    for row in _db_query("SELECT * FROM anomaly_rules ORDER BY id"):
        anomaly_rules.append({
            'id': row['id'],
            'metric': row['metric'],
            'operator': row['operator'],
            'threshold': row['threshold'],
            'severity': row['severity'],
            'enabled': _bool_row(row, 'enabled'),
            'alert_in_app': _bool_row(row, 'alert_in_app'),
            'alert_email': _bool_row(row, 'alert_email'),
        })
    next_rule_id = (max([r['id'] for r in anomaly_rules]) + 1) if anomaly_rules else 1

    playbooks = []
    for row in _db_query("SELECT * FROM playbooks ORDER BY id"):
        playbooks.append({
            'id': row['id'],
            'organization_id': row.get('organization_id'),
            'name': row['name'],
            'category': row['category'],
            'metric': row['metric'],
            'operator': row['operator'],
            'threshold': row['threshold'],
            'action': row['action'],
            'target': row['target'],
            'enabled': _bool_row(row, 'enabled'),
            'auto': _bool_row(row, 'auto'),
            'yaml': row['yaml'],
        })
    next_playbook_id = (max([p['id'] for p in playbooks]) + 1) if playbooks else 1

    playbook_runs = []
    for row in _db_query("SELECT * FROM playbook_runs ORDER BY id DESC LIMIT 100"):
        playbook_runs.append({
            'id': row['id'],
            'organization_id': row.get('organization_id'),
            'playbook_id': row['playbook_id'],
            'name': row['name'],
            'anomaly_id': row['anomaly_id'],
            'metric': row['metric'],
            'value': row['value'],
            'threshold': row['threshold'],
            'action': row['action'],
            'target': row['target'],
            'timestamp': row['timestamp'],
            'auto': _bool_row(row, 'auto'),
            'status': row['status'],
            'yaml': row['yaml'],
        })
    playbook_runs = list(reversed(playbook_runs))

    automation_rules = []
    for row in _db_query("SELECT * FROM automation_rules ORDER BY id"):
        automation_rules.append({
            'id': row['id'],
            'name': row['name'],
            'field': row['field'],
            'operator': row['operator'],
            'value': row['value'],
            'action': row['action'],
            'enabled': _bool_row(row, 'enabled'),
        })
    next_automation_rule_id = (max([r['id'] for r in automation_rules]) + 1) if automation_rules else 1

    automation_history = _db_query("SELECT * FROM automation_history ORDER BY id DESC LIMIT 100")
    automation_history = list(reversed(automation_history))


def users_exist():
    return _table_count('users') > 0


def active_admin_exists():
    rows = _db_query("SELECT COUNT(*) AS count FROM users WHERE role = ? AND active = 1", ('admin',))
    return int(rows[0]['count']) > 0 if rows else False


def normalize_join_policy(policy):
    policy = str(policy or '').strip()
    if policy == 'open_with_code':
        return 'join_with_code'
    if policy == 'invite_only':
        return 'admin_invites_only'
    if policy in {'join_with_code', 'request_to_join', 'admin_invites_only'}:
        return policy
    return 'join_with_code'


def create_organization(name, created_by='system'):
    name = str(name or '').strip() or 'Local Workspace'
    existing = get_organization_by_name(name)
    if existing:
        return existing['id']
    now = datetime.now().isoformat()
    join_code = secrets.token_urlsafe(6)
    _db_exec(
        "INSERT INTO organizations (name, join_policy, join_code, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
        (name, 'join_with_code', join_code, now, created_by)
    )
    rows = _db_query("SELECT id FROM organizations WHERE name = ?", (name,))
    return rows[0]['id']


def get_organization_by_name(name):
    rows = _db_query("SELECT * FROM organizations WHERE name = ?", (str(name or '').strip(),))
    return rows[0] if rows else None


def get_organization_by_code(code):
    rows = _db_query("SELECT * FROM organizations WHERE join_code = ?", (str(code or '').strip(),))
    return rows[0] if rows else None


def organization_for_user(user):
    org_id = user.get('organization_id') if user else None
    if not org_id:
        return None
    rows = _db_query("SELECT * FROM organizations WHERE id = ?", (org_id,))
    return rows[0] if rows else None


def get_user_by_username(username):
    rows = _db_query("SELECT * FROM users WHERE username = ?", (username,))
    return rows[0] if rows else None


def get_user_by_id(user_id):
    rows = _db_query("SELECT * FROM users WHERE id = ?", (user_id,))
    return rows[0] if rows else None


def create_user(username, password, role='admin', active=True, organization_id=None):
    now = datetime.now().isoformat()
    if organization_id is None:
        org = _db_query("SELECT id FROM organizations ORDER BY id LIMIT 1")
        organization_id = org[0]['id'] if org else create_organization('Local Workspace')
    _db_exec(
        "INSERT INTO users (username, password_hash, role, active, organization_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (username, generate_password_hash(password), role, int(bool(active)), organization_id, now)
    )


def audit_event(event_type, target, result='success', detail='', actor=None, role=None, organization_id=None):
    user = current_user()
    actor = actor or (user['username'] if user else 'anonymous')
    role = role or (user['role'] if user else 'anonymous')
    organization_id = organization_id if organization_id is not None else (user.get('organization_id') if user else None)
    source = request.remote_addr if has_request_context() else 'local'
    _db_exec(
        "INSERT INTO audit_events (organization_id, timestamp, actor, role, event_type, target, result, source, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (organization_id, datetime.now().isoformat(), actor, role, event_type, target, result, source, detail)
    )


def normalize_severity(value, default='medium'):
    value = str(value or default).lower().replace('-', '_').replace(' ', '_')
    return value if value in SEVERITIES else default


def normalize_status(value, default='open'):
    value = str(value or default).lower().replace('-', '_').replace(' ', '_')
    return value if value in STATUSES else default


def _incident_event(incident_id, event_type, detail, actor=None, organization_id=None):
    user = current_user()
    actor = actor or (user['username'] if user else 'system')
    if organization_id is None:
        if user:
            organization_id = user.get('organization_id')
        else:
            incident = _db_query("SELECT organization_id FROM incidents WHERE id = ?", (incident_id,))
            organization_id = incident[0].get('organization_id') if incident else None
    _db_exec(
        "INSERT INTO incident_events (organization_id, incident_id, timestamp, actor, event_type, detail) VALUES (?, ?, ?, ?, ?, ?)",
        (organization_id, incident_id, datetime.now().isoformat(), actor, event_type, detail)
    )


def _recommended_playbook(anomaly):
    for pb in playbooks:
        if pb.get('enabled') and pb.get('metric') == anomaly.get('metric'):
            try:
                if op_eval(float(anomaly.get('value', 0)), pb.get('operator'), float(pb.get('threshold', 0))):
                    return pb
            except (TypeError, ValueError):
                continue
    for pb in playbooks:
        if pb.get('enabled') and pb.get('category') == anomaly.get('category'):
            return pb
    return None


def create_incident_from_anomaly(anomaly, actor='system', organization_id=None):
    if organization_id is None:
        user = current_user()
        organization_id = user.get('organization_id') if user else anomaly.get('organization_id')
    _persist_anomaly(anomaly, organization_id=organization_id)
    existing = _db_query("SELECT * FROM incidents WHERE anomaly_id = ? AND organization_id IS ?", (anomaly['id'], organization_id))
    if existing:
        return existing[0]
    now = datetime.now().isoformat()
    incident_id = f"SA-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    pb = _recommended_playbook(anomaly)
    title = f"{normalize_severity(anomaly.get('severity')).title()} {anomaly.get('metric')} anomaly"
    _db_exec(
        "INSERT INTO incidents (id, organization_id, title, severity, status, owner, anomaly_id, recommended_playbook_id, created_at, updated_at, resolution) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, organization_id, title, normalize_severity(anomaly.get('severity')), 'open', None, anomaly['id'], pb['id'] if pb else None, now, now, None)
    )
    _incident_event(incident_id, 'incident_created', f"Linked anomaly {anomaly['id']}", actor=actor, organization_id=organization_id)
    if pb:
        _incident_event(incident_id, 'playbook_recommended', f"Recommended {pb['name']}", actor=actor, organization_id=organization_id)
    audit_event('incident_created', f"incident:{incident_id}", 'success', title, actor=actor, role='system' if actor == 'system' else None)
    return _db_query("SELECT * FROM incidents WHERE id = ?", (incident_id,))[0]


def _validation_anomalies(organization_id=None):
    anomalies = []
    if organization_id is None:
        rows = _db_query("SELECT * FROM validation_events WHERE anomaly_id IS NOT NULL ORDER BY created_at DESC LIMIT 100")
    else:
        rows = _db_query(
            "SELECT * FROM validation_events WHERE anomaly_id IS NOT NULL AND organization_id = ? ORDER BY created_at DESC LIMIT 100",
            (organization_id,)
        )
    for row in rows:
        if row['event_type'] == 'cpu_pressure':
            metric, value, severity, category = 'cpu_percent', 96.0, 'critical', 'system'
        elif row['event_type'] == 'memory_pressure':
            metric, value, severity, category = 'memory_percent', 91.0, 'high', 'host'
        elif row['event_type'] == 'suspicious_network':
            metric, value, severity, category = 'network_public_connection', 1.0, 'high', 'network'
        else:
            metric, value, severity, category = 'sensitive_file_access', 1.0, 'high', 'file'
        anomaly = {
            'id': row['anomaly_id'],
            'organization_id': row.get('organization_id'),
            'timestamp': row['created_at'],
            'metric': metric,
            'value': value,
            'threshold': 0.0 if value == 1.0 else value - 5,
            'severity': severity,
            'category': category,
            'confidence': 0.95,
            'rule_name': f"Controlled validation: {row['event_type']}",
            'indicator_type': 'validation',
            'indicator': row['event_type'],
            'threat_intel': {'matched': False, 'confidence': 0, 'source': 'controlled validation event', 'tags': ['validation']},
            'risk_score': 90 if severity == 'critical' else 76,
            'frameworks': ['NIST DE.CM-1', 'CIS 8.16'],
            'validation': True,
        }
        anomalies.append(anomaly)
    return anomalies


init_db()
_seed_db()
load_persistent_state()

# --- Background sampler ---

def sampler():
    last_disk = psutil.disk_io_counters()
    last_net  = psutil.net_io_counters()
    last_time = time.time()

    psutil.cpu_percent(interval=None)  # establish baseline

    while True:
        now = time.time()
        elapsed = max(1e-6, now - last_time)
        now_dt = datetime.now().strftime('%H:%M:%S')

        # CPU/MEM
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent

        # Disk deltas -> MB/s
        cur_disk = psutil.disk_io_counters()
        read_mbs  = (cur_disk.read_bytes  - last_disk.read_bytes ) / (1024*1024) / elapsed
        write_mbs = (cur_disk.write_bytes - last_disk.write_bytes) / (1024*1024) / elapsed
        last_disk = cur_disk

        # Net deltas -> MB/s
        cur_net = psutil.net_io_counters()
        rx_mbs = (cur_net.bytes_recv - last_net.bytes_recv) / (1024*1024) / elapsed
        tx_mbs = (cur_net.bytes_sent - last_net.bytes_sent) / (1024*1024) / elapsed
        last_net = cur_net

        # Push
        cpu_series.append(float(cpu));   mem_series.append(float(mem));   usage_ts.append(now_dt)
        read_series.append(float(read_mbs)); write_series.append(float(write_mbs)); disk_ts.append(now_dt)
        rx_series.append(float(rx_mbs));     tx_series.append(float(tx_mbs));       net_ts.append(now_dt)

        # Check for anomalies
        if len(cpu_series) > 10:  # need some data
            cpu_std = statistics.stdev(cpu_series) if len(set(cpu_series)) > 1 else 1
            cpu_mean = statistics.mean(cpu_series)
            mem_std = statistics.stdev(mem_series) if len(set(mem_series)) > 1 else 1
            mem_mean = statistics.mean(mem_series)
            
            if cpu > cpu_mean + 2 * cpu_std:
                severity = 'critical' if cpu > cpu_mean + 3 * cpu_std else 'high'
                notification_queue.put({
                    'type': 'anomaly',
                    'severity': severity,
                    'metric': 'cpu_percent',
                    'value': cpu,
                    'timestamp': datetime.now().isoformat()
                })
            if mem > mem_mean + 2 * mem_std:
                severity = 'critical' if mem > mem_mean + 3 * mem_std else 'high'
                notification_queue.put({
                    'type': 'anomaly',
                    'severity': severity,
                    'metric': 'memory_percent',
                    'value': mem,
                    'timestamp': datetime.now().isoformat()
                })

        last_time = now
        time.sleep(SAMPLE_INTERVAL)

threading.Thread(target=sampler, daemon=True).start()

# --- Lightweight caches for expensive endpoints ---
_PROCS_CACHE = {"data": None, "ts": 0.0}
_PROCS_TTL   = 2.0  # seconds


def _top_procs(n=5):
    global _PROCS_CACHE
    now = time.time()
    if _PROCS_CACHE["data"] and (now - _PROCS_CACHE["ts"] < _PROCS_TTL):
        return _PROCS_CACHE["data"]

    procs = []
    for p in psutil.process_iter(attrs=['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
        try:
            info = p.info
            cpu = float(info.get('cpu_percent') or 0.0)
            rss = info.get('memory_info').rss if info.get('memory_info') else 0
            procs.append({
                'pid': int(info.get('pid')), 'name': (info.get('name') or 'proc')[:40],
                'user': info.get('username') or 'unknown',
                'cpu': cpu, 'mem_mb': float(rss) / (1024*1024)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    cpu_top = sorted(procs, key=lambda x: x['cpu'], reverse=True)[:n]
    mem_top = sorted(procs, key=lambda x: x['mem_mb'], reverse=True)[:n]
    data = {'cpu_top': cpu_top, 'mem_top': mem_top, 'total_processes': len(procs), 'ts': datetime.now().strftime('%H:%M:%S')}
    _PROCS_CACHE = {"data": data, "ts": now}
    return data


def _read_temps():
    temps = []
    try:
        sensors = psutil.sensors_temperatures(fahrenheit=False)  # may not exist on win
        for label, entries in sensors.items():
            vals = [e.current for e in entries if getattr(e, 'current', None) is not None]
            if vals:
                temps.append({'label': label, 'current': float(max(vals))})
    except Exception:
        pass
    return temps


def _read_gpus():
    gpus = []
    if not GPUtil:
        return {'available': False, 'gpus': []}
    try:
        for g in GPUtil.getGPUs():
            gpus.append({
                'id': int(getattr(g, 'id', 0)),
                'name': getattr(g, 'name', 'GPU'),
                'load': float(getattr(g, 'load', 0.0) * 100.0),
                'mem_used_mb': float(getattr(g, 'memoryUsed', 0.0)),
                'mem_total_mb': float(getattr(g, 'memoryTotal', 0.0)),
                'temp': float(getattr(g, 'temperature', 0.0) or 0.0)
            })
        return {'available': bool(gpus), 'gpus': gpus}
    except Exception:
        return {'available': False, 'gpus': []}


def _anomaly_id(anomaly):
    raw = f"{anomaly.get('timestamp')}|{anomaly.get('metric')}|{anomaly.get('value'):.4f}|{anomaly.get('category')}"
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()[:12]


def _load_threat_intel():
    if not os.path.exists(THREAT_INTEL_PATH):
        return {'ips': {}, 'domains': {}, 'hashes': {}}
    try:
        with open(THREAT_INTEL_PATH, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
        return {
            'ips': data.get('ips', {}),
            'domains': data.get('domains', {}),
            'hashes': data.get('hashes', {}),
        }
    except (OSError, json.JSONDecodeError):
        return {'ips': {}, 'domains': {}, 'hashes': {}}


def _get_cached_threat_intel():
    try:
        mtime = os.path.getmtime(THREAT_INTEL_PATH)
    except OSError:
        mtime = None

    if _threat_intel_cache['data'] is None or _threat_intel_cache['mtime'] != mtime:
        _threat_intel_cache['data'] = _load_threat_intel()
        _threat_intel_cache['mtime'] = mtime
    return _threat_intel_cache['data']


def _threat_lookup(indicator_type, indicator):
    feed = _get_cached_threat_intel().get(f'{indicator_type}s', {})
    hit = feed.get(str(indicator).lower()) or feed.get(str(indicator))
    if not hit:
        return {'matched': False, 'confidence': 0, 'source': 'local feed: no match', 'tags': []}
    return {'matched': True, **hit}


def _is_public_ip(ip_value):
    try:
        parsed = ipaddress.ip_address(ip_value)
        return parsed.is_global
    except ValueError:
        return False


def _process_hash(pid):
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        if not exe or not os.path.isfile(exe):
            return None
        digest = hashlib.sha256()
        with open(exe, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except (psutil.Error, OSError, PermissionError):
        return None


def _current_indicators():
    indicators = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and _is_public_ip(conn.raddr.ip):
                indicators.append({'type': 'ip', 'value': conn.raddr.ip, 'pid': conn.pid})
    except (psutil.Error, OSError):
        pass

    if indicators:
        return indicators

    for proc in _top_procs(n=3).get('cpu_top', []):
        digest = _process_hash(proc['pid'])
        if digest:
            indicators.append({'type': 'hash', 'value': digest, 'pid': proc['pid']})
            break
    return indicators


def _local_ipv4_addresses():
    addresses = []
    for interface, entries in psutil.net_if_addrs().items():
        for entry in entries:
            if getattr(entry, 'family', None) == socket.AF_INET:
                addresses.append({
                    'interface': interface,
                    'address': entry.address,
                    'netmask': entry.netmask,
                    'is_loopback': entry.address.startswith('127.')
                })
    return addresses


def _local_connection_summary():
    established = []
    listening = 0
    try:
        proc_map = {p.pid: p.info['name'] for p in psutil.process_iter(attrs=['pid', 'name'])}
        for conn in psutil.net_connections(kind='inet'):
            status = getattr(conn, 'status', '') or ''
            if status == 'LISTEN':
                listening += 1
            if conn.raddr and status == 'ESTABLISHED':
                established.append({
                    'pid': conn.pid,
                    'process': proc_map.get(conn.pid, f"pid-{conn.pid}") if conn.pid else 'unknown',
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'local_port': conn.laddr.port if conn.laddr else None,
                    'public': _is_public_ip(conn.raddr.ip),
                })
    except (psutil.Error, OSError):
        pass
    return {'listening': listening, 'established': established[:12]}


def _bytes_to_gb(value):
    return round(float(value) / (1024 ** 3), 2)


def _decorate_threat_intel(anomaly):
    indicators = _current_indicators()
    selected = indicators[int(hashlib.sha1(_anomaly_id(anomaly).encode('utf-8')).hexdigest(), 16) % len(indicators)] if indicators else None
    indicator_type = selected['type'] if selected else 'none'
    indicator = selected['value'] if selected else 'no live indicator'
    threat = _threat_lookup(indicator_type, indicator) if selected else {'matched': False, 'confidence': 0, 'source': 'no live network or process hash indicator', 'tags': []}
    severity_weight = {'critical': 30, 'high': 18, 'medium': 10, 'low': 4}.get(anomaly.get('severity'), 8)
    confidence_weight = int(float(anomaly.get('confidence', 0)) * 25)
    risk_score = min(100, severity_weight + confidence_weight + int(threat['confidence'] * 0.45))
    anomaly.update({
        'id': _anomaly_id(anomaly),
        'indicator_type': indicator_type,
        'indicator': indicator,
        'threat_intel': threat,
        'risk_score': risk_score,
        'frameworks': _framework_map(anomaly, risk_score),
    })
    return anomaly


def _framework_map(anomaly, risk_score):
    metric = anomaly.get('metric', '')
    mappings = ['NIST DE.CM-1', 'CIS 8.16']
    if 'cpu' in metric or 'memory' in metric:
        mappings.extend(['NIST DE.AE-2', 'CIS 8.11'])
    if risk_score >= 75:
        mappings.extend(['NIST RS.MI-1', 'CIS 8.17'])
    return mappings


def _load_telemetry_df(start=None, end=None):
    if not os.path.exists(LOG_PATH):
        return pd.DataFrame()

    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    if df.empty:
        return df

    if start:
        df = df[df['timestamp'] >= pd.to_datetime(start)]
    if end:
        df = df[df['timestamp'] <= pd.to_datetime(end)]
    return df


def _detect_stat_anomalies(df):
    anomalies = []
    for col in ['cpu_percent', 'memory_percent']:
        if col not in df.columns:
            continue
        mean_val = df[col].mean()
        std_val = df[col].std() if len(df) > 1 else 0
        if std_val == 0:
            continue
        thresh = mean_val + 2 * std_val
        high = df[df[col] > thresh]
        for _, row in high.iterrows():
            z = (row[col] - mean_val) / std_val
            severity_value = 'critical' if z > 3 else 'high'
            anomalies.append({
                'timestamp': row['timestamp'].isoformat(),
                'metric': col,
                'value': float(row[col]),
                'threshold': float(thresh),
                'severity': severity_value,
                'category': 'system' if col != 'memory_percent' else 'host',
                'confidence': min(1.0, abs(z) / 5)
            })
    return anomalies


def _detect_rule_anomalies(df):
    anomalies = []
    for rule in anomaly_rules:
        if not rule.get('enabled'):
            continue
        metric = rule['metric']
        if metric not in df.columns or df.empty:
            continue
        rvalue = df[metric].iloc[-1]
        if op_eval(rvalue, rule['operator'], rule['threshold']):
            anomalies.append({
                'timestamp': datetime.now().isoformat(),
                'metric': metric,
                'value': float(rvalue),
                'threshold': float(rule['threshold']),
                'severity': rule['severity'],
                'category': 'custom',
                'confidence': 0.9,
                'rule_name': f"Custom {metric} {rule['operator']} {rule['threshold']}"
            })
    return anomalies


def _load_anomalies(start=None, end=None, severity=None, apply_automation=True, organization_id=None):
    df = _load_telemetry_df(start=start, end=end)
    if df.empty:
        _persist_anomalies(_validation_anomalies(organization_id), organization_id=organization_id)
        stored = _stored_anomalies(start=start, end=end, severity=severity, organization_id=organization_id)
        if apply_automation:
            apply_playbooks(stored)
            apply_automation_rules(stored)
            for anomaly in stored:
                if normalize_severity(anomaly.get('severity')) in {'high', 'critical'}:
                    create_incident_from_anomaly(anomaly, organization_id=organization_id)
        return stored[:200]

    anomalies = _detect_stat_anomalies(df) + _detect_rule_anomalies(df)

    decorated = [_decorate_threat_intel(a) for a in anomalies] + _validation_anomalies(organization_id)
    _persist_anomalies(decorated, organization_id=organization_id)
    sorted_list = _stored_anomalies(start=start, end=end, severity=None, organization_id=organization_id)
    if apply_automation:
        apply_playbooks(sorted_list)
        apply_automation_rules(sorted_list)
        for anomaly in sorted_list:
            if normalize_severity(anomaly.get('severity')) in {'high', 'critical'}:
                create_incident_from_anomaly(anomaly, organization_id=organization_id)
    if severity:
        sorted_list = [a for a in sorted_list if a.get('severity') == severity]
    return sorted_list[:200]


def _audit_rows(limit=100, actor=None, event_type=None, result=None, start=None, end=None, organization_id=None):
    where = []
    params = []
    if organization_id is not None:
        where.append("organization_id = ?")
        params.append(organization_id)
    if actor:
        where.append("actor = ?")
        params.append(actor)
    if event_type:
        where.append("event_type = ?")
        params.append(event_type)
    if result:
        where.append("result = ?")
        params.append(result)
    if start:
        where.append("timestamp >= ?")
        params.append(start)
    if end:
        where.append("timestamp <= ?")
        params.append(end)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    params.append(limit)
    logs = []
    for row in _db_query(
        f"SELECT timestamp, actor, role, event_type, target, result, source, detail FROM audit_events {where_sql} ORDER BY id DESC LIMIT ?",
        tuple(params)
    ):
        severity = 'warning' if row['result'] in {'denied', 'failed'} else 'info'
        detail = row.get('detail') or f"actor {row['actor']}"
        logs.append({
            'timestamp': row['timestamp'],
            'actor': row['actor'],
            'role': row['role'],
            'event_type': row['event_type'],
            'target': row['target'],
            'result': row['result'],
            'source': row.get('source') or 'local',
            'detail': detail,
            'action': row['event_type'],
            'severity': severity,
            'outcome': row['result'],
            'resource': row['target'],
            'details': detail,
        })
    include_metric_logs = (
        organization_id is None and
        (not actor or actor == 'system') and
        (not event_type or event_type == 'metric_sample') and
        (not result or result in {'allowed', 'flagged'})
    )
    if include_metric_logs and os.path.exists(LOG_PATH):
        df = pd.read_csv(LOG_PATH, parse_dates=['timestamp']).tail(limit)
        if start:
            df = df[df['timestamp'] >= pd.to_datetime(start)]
        if end:
            df = df[df['timestamp'] <= pd.to_datetime(end)]
        for _, row in df.iterrows():
            sev = 'warning' if row.get('cpu_percent', 0) > 70 else 'info'
            outcome = 'flagged' if sev == 'warning' else 'allowed'
            detail = f"CPU {row.get('cpu_percent', 0):.1f}%, memory {row.get('memory_percent', 0):.1f}%"
            logs.append({
                'timestamp': row['timestamp'].isoformat(),
                'actor': 'system',
                'role': 'system',
                'event_type': 'metric_sample',
                'target': 'host.telemetry',
                'result': outcome,
                'source': LOG_PATH,
                'detail': detail,
                'action': 'metric_sample',
                'severity': sev,
                'outcome': outcome,
                'resource': 'host.telemetry',
                'details': detail
            })
    return sorted(logs, key=lambda x: x['timestamp'], reverse=True)[:limit]


def _report_summary():
    user = current_user()
    org_id = user.get('organization_id') if user else None
    anomalies = _load_anomalies(apply_automation=False, organization_id=org_id)
    audits = _audit_rows(organization_id=org_id)
    return {
        'generated_at': datetime.now().isoformat(),
        'anomaly_count': len(anomalies),
        'critical_count': len([a for a in anomalies if a['severity'] == 'critical']),
        'high_risk_count': len([a for a in anomalies if a['risk_score'] >= 75]),
        'audit_count': len(audits),
        'frameworks': {
            'NIST': ['DE.CM-1', 'DE.AE-2', 'RS.MI-1'],
            'CIS': ['8.11', '8.16', '8.17']
        },
        'anomalies': anomalies[:50],
        'audits': audits[-50:],
    }


def _csv_response(summary):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['report_generated_at', summary['generated_at']])
    writer.writerow([])
    writer.writerow(['type', 'timestamp', 'severity', 'metric_or_action', 'value_or_outcome', 'risk_score', 'frameworks'])
    for a in summary['anomalies']:
        writer.writerow(['anomaly', a['timestamp'], a['severity'], a['metric'], f"{a['value']:.2f}", a['risk_score'], '; '.join(a['frameworks'])])
    for log in summary['audits']:
        writer.writerow(['audit', log['timestamp'], log['severity'], log['action'], log['outcome'], '', 'NIST AU; CIS 8'])
    return Response(buf.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=security-compliance-report.csv'})


def _pdf_bytes(lines):
    escaped = [line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)') for line in lines]
    content = "BT /F1 10 Tf 40 780 Td 14 TL " + " T* ".join(f"({line})" for line in escaped) + " ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj",
        f"5 0 obj << /Length {len(content.encode('utf-8'))} >> stream\n{content}\nendstream endobj",
    ]
    pdf = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf.encode('utf-8')))
        pdf += obj + "\n"
    xref = len(pdf.encode('utf-8'))
    pdf += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n"
    pdf += "".join(f"{off:010d} 00000 n \n" for off in offsets[1:])
    pdf += f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    return pdf.encode('utf-8')


def _pdf_response(summary):
    lines = [
        'SAAOE Security Compliance Report',
        f"Generated: {summary['generated_at']}",
        f"Anomalies: {summary['anomaly_count']}  Critical: {summary['critical_count']}  High Risk: {summary['high_risk_count']}",
        'Framework Mapping: NIST DE.CM-1, DE.AE-2, RS.MI-1 | CIS 8.11, 8.16, 8.17',
        '',
        'Top Anomalies:',
    ]
    for a in summary['anomalies'][:28]:
        lines.append(f"{a['timestamp'][:19]} {a['severity']} {a['metric']}={a['value']:.2f} risk={a['risk_score']} {','.join(a['frameworks'][:2])}")
    return Response(_pdf_bytes(lines[:48]), mimetype='application/pdf', headers={'Content-Disposition': 'attachment; filename=security-compliance-report.pdf'})


def automation_matches(rule, anomaly):
    current = anomaly.get(rule.get('field'))
    expected = rule.get('value')
    op = rule.get('operator')
    if op == 'equals':
        return str(current).lower() == str(expected).lower()
    try:
        current_num = float(current)
        expected_num = float(expected)
    except (TypeError, ValueError):
        return False
    return op_eval(current_num, op, expected_num)


def apply_automation_rules(anomalies):
    seen = {(h.get('rule_id'), h.get('anomaly_id')) for h in _db_query("SELECT rule_id, anomaly_id FROM automation_history")}
    for anomaly in anomalies[:25]:
        for rule in _automation_rules_from_db():
            if not rule.get('enabled') or (rule['id'], anomaly['id']) in seen:
                continue
            if automation_matches(rule, anomaly):
                entry = {
                    'id': len(automation_history) + 1,
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'anomaly_id': anomaly['id'],
                    'action': rule['action'],
                    'timestamp': datetime.now().isoformat(),
                    'status': 'executed',
                    'details': f"{rule['field']} {rule['operator']} {rule['value']} matched {anomaly['metric']}"
                }
                cur = _db_exec(
                    "INSERT INTO automation_history (rule_id, rule_name, anomaly_id, action, timestamp, status, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (entry['rule_id'], entry['rule_name'], entry['anomaly_id'], entry['action'], entry['timestamp'], entry['status'], entry['details'])
                )
                entry['id'] = cur.lastrowid
                automation_history.append(entry)
                notification_queue.put({'type': 'automation_action', 'rule': rule['name'], 'details': entry})


def _timeline_for_anomaly(anomaly_id):
    stored = _db_query("SELECT * FROM anomalies WHERE id = ?", (anomaly_id,))
    anomaly = _anomaly_from_row(stored[0]) if stored else next((a for a in _load_anomalies(apply_automation=False) if a['id'] == anomaly_id), None)
    if not anomaly:
        return None, []
    center = pd.to_datetime(anomaly['timestamp'])
    events = []
    if os.path.exists(LOG_PATH):
        df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
        window = df[(df['timestamp'] >= center - pd.Timedelta(minutes=10)) & (df['timestamp'] <= center + pd.Timedelta(minutes=10))]
        for _, row in window.iterrows():
            events.append({'time': row['timestamp'].isoformat(), 'lane': 'system', 'title': 'Metric sample', 'detail': f"CPU {row['cpu_percent']:.1f}% Memory {row['memory_percent']:.1f}%"})
    events.extend([
        {'time': center.isoformat(), 'lane': 'anomaly', 'title': 'Anomaly detected', 'detail': f"{anomaly['severity']} {anomaly['metric']} risk {anomaly['risk_score']}"},
    ])
    if abs((pd.Timestamp.now(tz=center.tz) - center).total_seconds()) <= 900:
        for proc in _top_procs(n=3).get('cpu_top', []):
            events.append({'time': datetime.now().isoformat(), 'lane': 'process', 'title': 'Live top process', 'detail': f"PID {proc['pid']} {proc['name']} CPU {proc['cpu']:.1f}% RAM {proc['mem_mb']:.1f} MB"})
        for indicator in _current_indicators()[:3]:
            events.append({'time': datetime.now().isoformat(), 'lane': 'network', 'title': 'Live indicator', 'detail': f"{indicator['type']} {indicator['value']} from PID {indicator.get('pid') or 'unknown'}"})
    return anomaly, sorted(events, key=lambda x: x['time'])


def _validate_terminal_command(command):
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return None, str(exc)
    if not parts:
        return None, 'Enter a diagnostic command.'
    if os.path.basename(parts[0]) != parts[0]:
        return None, 'Command paths are blocked. Use an enabled diagnostic command name only.'
    base = parts[0]
    if base not in DIAGNOSTIC_COMMANDS:
        return None, f"Command '{base}' is not enabled. Allowed: {', '.join(sorted(DIAGNOSTIC_COMMANDS))}"
    if any(token.startswith('/') or '..' in token for token in parts[1:]):
        return None, 'Absolute paths and parent directory traversal are blocked in browser diagnostics.'
    executable = shutil.which(base)
    if not executable:
        return None, f"Command '{base}' is not installed on this host."
    return [executable, *parts[1:]], None


def _run_terminal_command(command):
    args, error = _validate_terminal_command(command)
    if error:
        audit_event('terminal_command', f"command:{command}", 'denied', error)
        return {'success': False, 'error': error, 'output': ''}, 400
    try:
        proc = subprocess.run(
            args,
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=12,
            check=False,
        )
        output = proc.stdout or ''
        truncated = len(output) > TERMINAL_OUTPUT_LIMIT
        if truncated:
            output = output[:TERMINAL_OUTPUT_LIMIT] + '\n[output truncated]\n'
        result = 'success' if proc.returncode == 0 else 'failed'
        audit_event('terminal_command', f"command:{args[0]}", result, f"exit={proc.returncode}")
        return {'success': proc.returncode == 0, 'returncode': proc.returncode, 'output': output, 'truncated': truncated}, 200
    except subprocess.TimeoutExpired:
        audit_event('terminal_command', f"command:{args[0]}", 'failed', 'timeout')
        return {'success': False, 'error': 'command timed out', 'output': ''}, 408


def _approval_row(approval_id):
    user = current_user()
    if user:
        rows = _db_query(
            "SELECT * FROM response_approvals WHERE id = ? AND organization_id = ?",
            (approval_id, user.get('organization_id'))
        )
    else:
        rows = _db_query("SELECT * FROM response_approvals WHERE id = ?", (approval_id,))
    return rows[0] if rows else None


def _approval_expired(approval, now=None):
    expires_at = approval.get('expires_at')
    if not expires_at:
        return False
    now = now or datetime.now()
    try:
        return now > datetime.fromisoformat(expires_at)
    except ValueError:
        return True


def _dry_run_response_action(action, target):
    if action == 'kill_process':
        pid = int(target)
        proc = psutil.Process(pid)
        return f"Would terminate PID {pid} ({proc.name()})"
    if action == 'quarantine_file':
        path = os.path.abspath(os.path.join(BASE_DIR, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not path.startswith(BASE_DIR + os.sep):
            raise ValueError('quarantine target must be inside the SAAOE project directory')
        if not os.path.isfile(path):
            raise ValueError('quarantine target file does not exist')
        return f"Would move {os.path.relpath(path, BASE_DIR)} to quarantine/"
    if action == 'block_ip':
        ipaddress.ip_address(target)
        return 'Firewall block is not enabled on this host; execution will fail closed unless an OS adapter is configured.'
    if action == 'create_incident_report':
        return 'Would create an incident report record.'
    raise ValueError('unsupported response action')


def _execute_response_action(action, target, dry_run=True):
    preview = _dry_run_response_action(action, target)
    if dry_run:
        return {'executed': False, 'detail': preview}
    if action == 'kill_process':
        pid = int(target)
        if pid == os.getpid():
            raise ValueError('refusing to terminate the SAAOE process')
        proc = psutil.Process(pid)
        proc.terminate()
        return {'executed': True, 'detail': f"Terminate signal sent to PID {pid} ({proc.name()})"}
    if action == 'quarantine_file':
        path = os.path.abspath(os.path.join(BASE_DIR, target)) if not os.path.isabs(target) else os.path.abspath(target)
        if not path.startswith(BASE_DIR + os.sep):
            raise ValueError('quarantine target must be inside the SAAOE project directory')
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        dest = os.path.join(QUARANTINE_DIR, f"{uuid.uuid4().hex}_{os.path.basename(path)}")
        shutil.move(path, dest)
        return {'executed': True, 'detail': f"Moved {os.path.relpath(path, BASE_DIR)} to {os.path.relpath(dest, BASE_DIR)}"}
    if action == 'create_incident_report':
        return {'executed': True, 'detail': 'Incident report action recorded.'}
    if action == 'block_ip':
        raise ValueError('firewall adapter is not configured; action failed closed')
    raise ValueError('unsupported response action')


def _ws_send(sock, text):
    payload = text.encode('utf-8')
    if len(payload) < 126:
        header = struct.pack('!BB', 0x81, len(payload))
    elif len(payload) < 65536:
        header = struct.pack('!BBH', 0x81, 126, len(payload))
    else:
        header = struct.pack('!BBQ', 0x81, 127, len(payload))
    sock.sendall(header + payload)


def _recv_exact(sock, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def _ws_recv(sock):
    header = _recv_exact(sock, 2)
    if header is None:
        return None
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if opcode == 0x8:
        return None
    if length == 126:
        extended = _recv_exact(sock, 2)
        if extended is None:
            return None
        length = struct.unpack('!H', extended)[0]
    elif length == 127:
        extended = _recv_exact(sock, 8)
        if extended is None:
            return None
        length = struct.unpack('!Q', extended)[0]
    mask = _recv_exact(sock, 4)
    payload = _recv_exact(sock, length)
    if mask is None or payload is None:
        return None
    data = bytearray(payload)
    for i in range(length):
        data[i] ^= mask[i % 4]
    return data.decode('utf-8', errors='replace')


class TerminalWebSocketServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class TerminalWebSocketHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(2048).decode('utf-8', errors='ignore')
        key_line = next((line for line in data.splitlines() if line.lower().startswith('sec-websocket-key:')), None)
        if not key_line:
            return
        key = key_line.split(':', 1)[1].strip()
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.request.sendall((
            'HTTP/1.1 101 Switching Protocols\r\n'
            'Upgrade: websocket\r\n'
            'Connection: Upgrade\r\n'
            f'Sec-WebSocket-Accept: {accept}\r\n\r\n'
        ).encode('utf-8'))
        _ws_send(self.request, 'Legacy diagnostic WebSocket is disabled. Use the platform-owner console.\n')


def start_terminal_ws():
    global TERMINAL_WS_SERVER, TERMINAL_WS_STARTED
    if TERMINAL_WS_STARTED:
        return
    try:
        TERMINAL_WS_SERVER = TerminalWebSocketServer((TERMINAL_WS_HOST, TERMINAL_WS_PORT), TerminalWebSocketHandler)
        threading.Thread(target=TERMINAL_WS_SERVER.serve_forever, daemon=True).start()
        TERMINAL_WS_STARTED = True
    except OSError:
        pass


def current_user():
    if hasattr(g, 'current_user'):
        return g.current_user
    user_id = session.get('user_id')
    if not user_id:
        g.current_user = None
        return None
    user = get_user_by_id(user_id)
    if not user or not user.get('active'):
        session.clear()
        g.current_user = None
        return None
    g.current_user = user
    return user


def _is_api_request():
    return request.path.startswith('/api/') or request.path == '/health'


def _auth_failed(status, message):
    if _is_api_request():
        return jsonify(error=message), status
    if status == 401:
        return redirect(url_for('login', next=request.full_path if request.query_string else request.path))
    return render_template('login.html', error=message, username=''), status


ROLES = {'viewer': 1, 'analyst': 2, 'admin': 3, 'system': 4}
PERMISSIONS = {'manage_members', 'mutate_playbooks', 'access_terminal'}

PUBLIC_ENDPOINTS = {'static', 'login', 'logout', 'setup', 'signup', 'join', 'health'}

ADMIN_ENDPOINTS = {
    'automation_page',
    'api_automation_rules',
    'api_reports_download',
}

SYSTEM_ONLY_ENDPOINTS = {
    'api_test_anomaly',
}

ANALYST_ENDPOINTS = {
    'approvals_page',
    'validation_page',
    'api_response_approvals',
    'api_response_approval_detail',
}

ANALYST_MUTATION_ENDPOINTS = {
    'api_response_approvals',
    'api_validation_events',
}

ADMIN_MUTATION_ENDPOINTS = {
    'api_anomaly_rules',
    'api_organization',
    'api_configuration',
}


def _role_allows(user, minimum_role):
    return ROLES.get(user.get('role'), 0) >= ROLES[minimum_role]


def _minimum_role_for_request(endpoint):
    if endpoint in SYSTEM_ONLY_ENDPOINTS:
        return 'system'
    if endpoint in ADMIN_ENDPOINTS:
        return 'admin'
    if endpoint in ANALYST_ENDPOINTS:
        return 'analyst'
    if request.method != 'GET' and endpoint in ANALYST_MUTATION_ENDPOINTS:
        return 'analyst'
    if request.method != 'GET' and endpoint in ADMIN_MUTATION_ENDPOINTS:
        return 'admin'
    return 'viewer'


def get_user_permissions(user_id):
    rows = _db_query("SELECT permission FROM user_permissions WHERE user_id = ?", (user_id,))
    return {row['permission'] for row in rows}


def _config_storage_key(organization_id, key):
    return f"org:{organization_id}:{key}"


def _config_public_key(organization_id, key):
    prefix = f"org:{organization_id}:"
    return key[len(prefix):] if key.startswith(prefix) else key


def _configuration_rows(organization_id):
    prefix = f"org:{organization_id}:%"
    rows = _db_query(
        "SELECT key, value, updated_at, updated_by FROM app_configuration WHERE key LIKE ? ORDER BY key",
        (prefix,)
    )
    return [{
        'key': _config_public_key(organization_id, row['key']),
        'value': _json_loads(row.get('value'), row.get('value')),
        'updated_at': row['updated_at'],
        'updated_by': row['updated_by'],
    } for row in rows]


def _file_classification_storage_path(organization_id, path):
    return f"org:{organization_id}:{path}"


def _file_classification_public_path(organization_id, path):
    prefix = f"org:{organization_id}:"
    return path[len(prefix):] if path.startswith(prefix) else path


def _user_has_permission(user, permission):
    if not user:
        return False
    if user.get('role') == 'admin' and permission in PERMISSIONS:
        return True
    permissions = getattr(g, 'user_permissions', None)
    if permissions is None:
        permissions = get_user_permissions(user['id'])
        g.user_permissions = permissions
    return permission in permissions


def require_permission(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not _user_has_permission(user, permission):
                audit_event('access_denied', request.endpoint or fn.__name__, 'denied', f"{permission} required")
                return _auth_failed(403, f"{permission.replace('_', ' ').capitalize()} required")
            return fn(*args, **kwargs)
        return wrapper
    return decorator


@app.before_request
def require_authentication():
    endpoint = request.endpoint or ''
    if endpoint in PUBLIC_ENDPOINTS:
        return None

    if not active_admin_exists():
        if endpoint == 'setup':
            return None
        if _is_api_request():
            return jsonify(error='first workspace setup required'), 503
        return redirect(url_for('setup'))

    user = current_user()
    if not user:
        audit_event('access_denied', endpoint or request.path, 'denied', 'authentication required', actor='anonymous', role='anonymous')
        return _auth_failed(401, 'authentication required')

    last_seen_at = session.get('last_seen_at')
    if last_seen_at is not None:
        try:
            idle_seconds = time.time() - float(last_seen_at)
        except (TypeError, ValueError):
            idle_seconds = SESSION_TIMEOUT_SECONDS + 1
        if idle_seconds > SESSION_TIMEOUT_SECONDS:
            audit_event('logout', f"user:{user['username']}", 'success', 'session timed out')
            session.clear()
            g.current_user = None
            return _auth_failed(401, 'session timed out')
    session['last_seen_at'] = time.time()

    minimum_role = _minimum_role_for_request(endpoint)
    if not _role_allows(user, minimum_role):
        label = 'platform owner' if minimum_role == 'system' else ('workspace admin' if minimum_role == 'admin' else 'regular user')
        audit_event('access_denied', endpoint, 'denied', f"{label} role required")
        return _auth_failed(403, f"{label} role required")

    return None


@app.context_processor
def inject_auth_context():
    user = current_user()
    organization = organization_for_user(user)

    def can(minimum_role):
        return bool(user and _role_allows(user, minimum_role))

    def has_permission(permission):
        return bool(user and _user_has_permission(user, permission))

    return {
        'current_user': user,
        'current_organization': organization,
        'users_configured': users_exist(),
        'admin_configured': active_admin_exists(),
        'can': can,
        'has_permission': has_permission,
    }


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user.get('role') != 'admin':
            audit_event('access_denied', request.endpoint or fn.__name__, 'denied', 'workspace admin role required')
            return _auth_failed(403, 'workspace admin role required')
        return fn(*args, **kwargs)
    return wrapper


# --- Routes ---
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if active_admin_exists():
        return redirect(url_for('dashboard'))
    error = None
    username = ''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        organization = request.form.get('organization', '').strip() or 'Local Workspace'
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username:
            error = 'Username is required.'
        elif len(password) < 10:
            error = 'Password must be at least 10 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            org_id = create_organization(organization, created_by=username)
            create_user(username, password, 'admin', organization_id=org_id)
            user = get_user_by_username(username)
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['last_seen_at'] = time.time()
            audit_event('user_created', f"user:{username}", 'success', 'first workspace owner created', actor=username, role='admin')
            audit_event('login', f"user:{username}", 'success', 'first workspace session started', actor=username, role='admin')
            return redirect(url_for('dashboard'))
    return render_template('setup.html', error=error, username=username)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not active_admin_exists():
        return redirect(url_for('setup'))
    error = None
    username = ''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = get_user_by_username(username)
        if user and user.get('active') and check_password_hash(user['password_hash'], password):
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['last_seen_at'] = time.time()
            _db_exec("UPDATE users SET last_login_at = ? WHERE id = ?", (datetime.now().isoformat(), user['id']))
            audit_event('login', f"user:{username}", 'success', 'interactive login', actor=username, role=user['role'])
            next_url = request.args.get('next') or url_for('dashboard')
            if not next_url.startswith('/'):
                next_url = url_for('dashboard')
            return redirect(next_url)
        audit_event('login', f"user:{username or 'unknown'}", 'failed', 'invalid credentials', actor=username or 'anonymous', role='anonymous')
        error = 'Invalid username or password.'
    return render_template('login.html', error=error, username=username)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    message = None
    username = ''
    organization = ''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        organization = request.form.get('organization', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username:
            error = 'Username is required.'
        elif not organization:
            error = 'Workspace name is required.'
        elif get_organization_by_name(organization):
            error = 'Workspace name is already in use.'
        elif len(password) < 10:
            error = 'Password must be at least 10 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif get_user_by_username(username):
            error = 'That username is already registered.'
        else:
            org_id = create_organization(organization, created_by=username)
            create_user(username, password, 'admin', active=True, organization_id=org_id)
            user = get_user_by_username(username)
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['last_seen_at'] = time.time()
            audit_event('organization_created', f"organization:{organization}", 'success', 'workspace created', actor=username, role='admin')
            audit_event('user_created', f"user:{username}", 'success', 'workspace admin created', actor=username, role='admin')
            audit_event('login', f"user:{username}", 'success', 'signup session started', actor=username, role='admin')
            return redirect(url_for('dashboard'))
    return render_template('signup.html', error=error, message=message, username=username, organization=organization)


@app.route('/join', methods=['GET', 'POST'])
def join():
    error = None
    message = None
    username = ''
    workspace_code = request.args.get('code', '').strip()
    if request.method == 'POST':
        workspace_code = request.form.get('workspace_code', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        organization = get_organization_by_code(workspace_code)
        if not workspace_code:
            error = 'Workspace code is required.'
        elif not organization:
            error = 'Workspace code was not found.'
        elif not username:
            error = 'Username is required.'
        elif get_user_by_username(username):
            error = 'That username is already registered.'
        elif _db_query("SELECT id FROM join_requests WHERE username = ? AND status = ?", (username, 'pending')):
            error = 'There is already a pending join request for that username.'
        elif len(password) < 10:
            error = 'Password must be at least 10 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        if not error:
            policy = normalize_join_policy(organization.get('join_policy'))
            if policy == 'admin_invites_only':
                audit_event('join_denied', f"organization:{organization['id']}", 'denied', 'admin-invites-only workspace', actor=username or 'anonymous', role='anonymous', organization_id=organization['id'])
                error = 'This workspace only accepts admin-created invites. Ask a Workspace Admin to add you.'
            elif policy == 'request_to_join':
                _db_exec(
                    "INSERT INTO join_requests (organization_id, username, password_hash, status, requested_at, detail) VALUES (?, ?, ?, ?, ?, ?)",
                    (organization['id'], username, generate_password_hash(password), 'pending', datetime.now().isoformat(), 'requested via workspace code')
                )
                audit_event('join_requested', f"user:{username}", 'success', 'workspace join request submitted', actor=username, role='viewer', organization_id=organization['id'])
                message = 'Request sent. A Workspace Admin must approve your request before you can access this workspace.'
                username = ''
            else:
                create_user(username, password, 'viewer', active=True, organization_id=organization['id'])
                user = get_user_by_username(username)
                session.clear()
                session.permanent = True
                session['user_id'] = user['id']
                session['last_seen_at'] = time.time()
                audit_event('user_created', f"user:{username}", 'success', 'joined workspace with code', actor=username, role='viewer', organization_id=organization['id'])
                audit_event('login', f"user:{username}", 'success', 'join session started', actor=username, role='viewer', organization_id=organization['id'])
                return redirect(url_for('dashboard'))
    return render_template('join.html', error=error, message=message, username=username, workspace_code=workspace_code)


@app.route('/logout')
def logout():
    user = current_user()
    if user:
        audit_event('logout', f"user:{user['username']}", 'success', 'interactive logout')
    else:
        audit_event('logout', 'user:anonymous', 'success', 'logout requested without active session', actor='anonymous', role='anonymous')
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/processes')
def processes():
    return render_template('processes.html')

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/visualization-lab')
def visualization_lab():
    return render_template('visualization_lab.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/audit-logs')
def audit_logs():
    return render_template('audit_logs.html')

@app.route('/ethics')
def ethics():
    return render_template('ethics.html')

@app.route('/files')
def files():
    return render_template('files.html')

@app.route('/terminal')
def terminal_page():
    user = current_user()
    if not _user_has_permission(user, 'access_terminal'):
        audit_event('access_denied', 'terminal_page', 'denied', 'access_terminal permission required')
        return _auth_failed(403, 'Access terminal permission required')
    return render_template('terminal.html')

@app.route('/reports')
def reports_page():
    return render_template('reports.html')

@app.route('/automation')
def automation_page():
    return render_template('automation.html')

@app.route('/incidents')
def incidents_page():
    return render_template('incidents.html')

@app.route('/approvals')
def approvals_page():
    return render_template('approvals.html')

@app.route('/validation')
def validation_page():
    return render_template('validation.html')

@app.route('/users')
def users_page():
    user = current_user()
    if not _user_has_permission(user, 'manage_members'):
        audit_event('access_denied', 'users_page', 'denied', 'manage_members permission required')
        return _auth_failed(403, 'Manage members permission required')
    return render_template('users.html')

@app.route('/api/users', methods=['GET', 'POST'])
@require_permission('manage_members')
def api_users():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        users = _db_query(
            "SELECT id, username, role, active, created_at, last_login_at FROM users WHERE organization_id = ? ORDER BY username",
            (org_id,)
        )
        for user_row in users:
            user_row['permissions'] = sorted(get_user_permissions(user_row['id']))
        return jsonify(users=users)

    payload = request.json or {}
    action = payload.get('action', 'create')
    if action == 'permissions':
        if user.get('role') != 'admin':
            audit_event('access_denied', 'api_users.permissions', 'denied', 'workspace admin required for permission changes')
            return jsonify(error='workspace admin role required for permission changes'), 403
        uid = int(payload.get('id', 0))
        requested_permissions = payload.get('permissions') or []
        if not isinstance(requested_permissions, list):
            return jsonify(error='permissions must be an array'), 400
        invalid_permissions = [p for p in requested_permissions if p not in PERMISSIONS]
        if invalid_permissions:
            return jsonify(error=f"invalid permissions: {', '.join(invalid_permissions)}"), 400
        target = get_user_by_id(uid)
        if not target:
            return jsonify(error='user not found'), 404
        if target.get('organization_id') != org_id:
            audit_event('access_denied', f"user:{target['username']}", 'denied', 'cross-workspace permission change blocked')
            return jsonify(error='user not found'), 404
        existing = get_user_permissions(uid)
        requested = set(requested_permissions)
        to_add = requested - existing
        to_remove = existing - requested
        now = datetime.now().isoformat()
        for perm in to_add:
            _db_exec(
                "INSERT OR IGNORE INTO user_permissions (user_id, permission, granted_by, granted_at) VALUES (?, ?, ?, ?)",
                (uid, perm, user['username'], now)
            )
            audit_event('permission_granted', f"user:{target['username']}", 'success', f"permission={perm}; target={target['username']}; workspace={org_id}", actor=user['username'], role=user['role'], organization_id=org_id)
        for perm in to_remove:
            _db_exec("DELETE FROM user_permissions WHERE user_id = ? AND permission = ?", (uid, perm))
            audit_event('permission_revoked', f"user:{target['username']}", 'success', f"permission={perm}; target={target['username']}; workspace={org_id}", actor=user['username'], role=user['role'], organization_id=org_id)
        return jsonify(success=True, permissions=sorted(requested))

    if action == 'disable':
        uid = int(payload.get('id', 0))
        target = get_user_by_id(uid)
        if not target:
            return jsonify(error='user not found'), 404
        if target.get('organization_id') != org_id:
            audit_event('access_denied', f"user:{target['username']}", 'denied', 'cross-workspace user disable blocked')
            return jsonify(error='user not found'), 404
        if target['id'] == session.get('user_id'):
            return jsonify(error='cannot disable current user'), 400
        _db_exec("UPDATE users SET active = 0 WHERE id = ?", (uid,))
        audit_event('user_disabled', f"user:{target['username']}", 'success', 'workspace admin disabled member')
        return jsonify(success=True)

    if action == 'enable':
        uid = int(payload.get('id', 0))
        target = get_user_by_id(uid)
        if not target:
            return jsonify(error='user not found'), 404
        if target.get('organization_id') != org_id:
            audit_event('access_denied', f"user:{target['username']}", 'denied', 'cross-workspace user enable blocked')
            return jsonify(error='user not found'), 404
        _db_exec("UPDATE users SET active = 1 WHERE id = ?", (uid,))
        audit_event('user_enabled', f"user:{target['username']}", 'success', 'workspace admin enabled member')
        return jsonify(success=True)

    username = str(payload.get('username', '')).strip()
    password = str(payload.get('password', ''))
    role = str(payload.get('role', 'viewer')).strip()
    if role not in {'admin', 'analyst', 'viewer'}:
        return jsonify(error='invalid role'), 400
    if not username:
        return jsonify(error='username is required'), 400
    if len(password) < 10:
        return jsonify(error='password must be at least 10 characters'), 400
    if get_user_by_username(username):
        return jsonify(error='username already exists'), 409
    create_user(username, password, role, organization_id=org_id)
    audit_event('user_created', f"user:{username}", 'success', f"role={role}")
    return jsonify(success=True)


@app.route('/api/organization', methods=['GET', 'POST'])
def api_organization():
    user = current_user()
    organization = organization_for_user(user)
    if not organization:
        return jsonify(error='workspace not found'), 404
    if request.method == 'GET':
        organization['join_policy'] = normalize_join_policy(organization.get('join_policy'))
        return jsonify(organization=organization)
    if user.get('role') != 'admin':
        audit_event('access_denied', 'api_organization', 'denied', 'workspace admin required')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    name = str(payload.get('name', '')).strip()
    join_policy = normalize_join_policy(payload.get('join_policy', organization.get('join_policy') or 'join_with_code'))
    if join_policy not in {'join_with_code', 'request_to_join', 'admin_invites_only'}:
        return jsonify(error='unsupported join policy'), 400
    if not name:
        return jsonify(error='workspace name is required'), 400
    existing = get_organization_by_name(name)
    if existing and existing['id'] != organization['id']:
        return jsonify(error='workspace name is already in use'), 409
    _db_exec("UPDATE organizations SET name = ?, join_policy = ? WHERE id = ?", (name, join_policy, organization['id']))
    audit_event('organization_updated', f"organization:{organization['id']}", 'success', f"name={name}; join_policy={join_policy}")
    return jsonify(success=True, organization=organization_for_user(user))


@app.route('/api/configuration', methods=['GET', 'POST'])
def api_configuration():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        return jsonify(configuration=_configuration_rows(org_id))
    if user.get('role') != 'admin':
        audit_event('access_denied', 'api_configuration', 'denied', 'workspace admin required')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    key = str(payload.get('key', '')).strip()
    if not key:
        return jsonify(error='configuration key is required'), 400
    value = payload.get('value')
    now = datetime.now().isoformat()
    storage_key = _config_storage_key(org_id, key)
    _db_exec(
        """
        INSERT INTO app_configuration (key, organization_id, value, updated_at, updated_by)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            organization_id = excluded.organization_id,
            value = excluded.value,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        """,
        (storage_key, org_id, _json_dumps(value), now, user['username'])
    )
    audit_event('configuration_updated', f"configuration:{key}", 'success', f"key={key}")
    return jsonify(success=True, configuration=_configuration_rows(org_id))


@app.route('/api/join_requests', methods=['GET', 'POST'])
@require_admin
def api_join_requests():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        rows = _db_query(
            "SELECT id, username, status, requested_at, decided_at, decided_by, detail FROM join_requests WHERE organization_id = ? ORDER BY requested_at DESC",
            (org_id,)
        )
        return jsonify(requests=rows)

    payload = request.json or {}
    request_id = int(payload.get('id', 0))
    action = str(payload.get('action', '')).strip()
    rows = _db_query("SELECT * FROM join_requests WHERE id = ? AND organization_id = ?", (request_id, org_id))
    if not rows:
        return jsonify(error='join request not found'), 404
    join_request = rows[0]
    if join_request['status'] != 'pending':
        return jsonify(error='join request has already been decided'), 409
    now = datetime.now().isoformat()
    if action == 'approve':
        if get_user_by_username(join_request['username']):
            _db_exec(
                "UPDATE join_requests SET status = ?, decided_at = ?, decided_by = ?, detail = ? WHERE id = ?",
                ('denied', now, user['username'], 'username already exists', request_id)
            )
            return jsonify(error='username already exists'), 409
        _db_exec(
            "INSERT INTO users (username, password_hash, role, active, organization_id, created_at) VALUES (?, ?, ?, 1, ?, ?)",
            (join_request['username'], join_request['password_hash'], 'viewer', org_id, now)
        )
        _db_exec(
            "UPDATE join_requests SET status = ?, decided_at = ?, decided_by = ? WHERE id = ?",
            ('approved', now, user['username'], request_id)
        )
        audit_event('join_request_approved', f"user:{join_request['username']}", 'success', 'regular user added to workspace')
        return jsonify(success=True)
    if action == 'deny':
        _db_exec(
            "UPDATE join_requests SET status = ?, decided_at = ?, decided_by = ? WHERE id = ?",
            ('denied', now, user['username'], request_id)
        )
        audit_event('join_request_denied', f"user:{join_request['username']}", 'success', 'workspace join request denied')
        return jsonify(success=True)
    return jsonify(error='unsupported action'), 400


@app.route('/api/usage')
def api_usage():
    return jsonify({'cpu': list(cpu_series), 'memory': list(mem_series), 'timestamps': list(usage_ts)})

@app.route('/api/disk')
def api_disk():
    return jsonify({'read': list(read_series), 'write': list(write_series), 'timestamps': list(disk_ts)})

@app.route('/api/net')
def api_net():
    return jsonify({'rx': list(rx_series), 'tx': list(tx_series), 'timestamps': list(net_ts)})

@app.route('/api/visualization_lab')
def api_visualization_lab():
    """
    Aggregates SAAOE system metrics into a visualization-friendly payload.
    This powers the Visualization Lab timeline, heatmap, scatterplot, and replay views.
    """
    usage = {
        'cpu': list(cpu_series),
        'memory': list(mem_series),
        'timestamps': list(usage_ts)
    }

    disk = {
        'read': list(read_series),
        'write': list(write_series),
        'timestamps': list(disk_ts)
    }

    net = {
        'rx': list(rx_series),
        'tx': list(tx_series),
        'timestamps': list(net_ts)
    }

    points = []
    timestamps = list(usage_ts)
    cpu_values = list(cpu_series)
    mem_values = list(mem_series)
    rx_values = list(rx_series)
    tx_values = list(tx_series)
    cpu_mean = statistics.mean(cpu_values) if cpu_values else 0.0
    cpu_std = statistics.stdev(cpu_values) if len(set(cpu_values)) > 1 else 0.0
    mem_mean = statistics.mean(mem_values) if mem_values else 0.0
    mem_std = statistics.stdev(mem_values) if len(set(mem_values)) > 1 else 0.0

    def visualization_risk(cpu, memory, rx, tx):
        composite = min(100.0, (cpu * 0.45) + (memory * 0.35) + ((rx + tx) * 8.0))
        relative_score = 0.0
        if cpu_std:
            relative_score = max(relative_score, min(100.0, ((cpu - cpu_mean) / cpu_std) * 35.0))
        if mem_std:
            relative_score = max(relative_score, min(100.0, ((memory - mem_mean) / mem_std) * 35.0))

        threshold_score = 0.0
        if cpu >= CPU_THRESHOLD or memory >= MEMORY_THRESHOLD:
            threshold_score = 90.0
        elif cpu >= (CPU_THRESHOLD * 0.85) or memory >= (MEMORY_THRESHOLD * 0.85):
            threshold_score = 70.0
        elif cpu >= (CPU_THRESHOLD * 0.65) or memory >= (MEMORY_THRESHOLD * 0.65):
            threshold_score = 45.0

        score = max(composite, relative_score, threshold_score)
        if score >= 85:
            return score, 'critical'
        if score >= 65:
            return score, 'high'
        if score >= 40:
            return score, 'medium'
        return score, 'low'

    for i, timestamp in enumerate(timestamps):
        cpu = float(cpu_values[i]) if i < len(cpu_values) else 0.0
        memory = float(mem_values[i]) if i < len(mem_values) else 0.0
        rx = float(rx_values[i]) if i < len(rx_values) else 0.0
        tx = float(tx_values[i]) if i < len(tx_values) else 0.0

        anomaly_score, risk_level = visualization_risk(cpu, memory, rx, tx)

        points.append({
            'timestamp': timestamp,
            'cpu': round(cpu, 2),
            'memory': round(memory, 2),
            'network': round(rx + tx, 4),
            'anomaly_score': round(anomaly_score, 2),
            'risk_level': risk_level
        })

    heatmap = []
    for point in points[-60:]:
        heatmap.append({
            'label': point['timestamp'],
            'value': point['anomaly_score'],
            'risk_level': point['risk_level']
        })

    return jsonify({
        'usage': usage,
        'disk': disk,
        'net': net,
        'points': points,
        'heatmap': heatmap,
        'summary': {
            'samples': len(points),
            'latest_cpu': cpu_values[-1] if cpu_values else 0,
            'latest_memory': mem_values[-1] if mem_values else 0,
            'latest_anomaly_score': points[-1]['anomaly_score'] if points else 0,
            'critical_windows': len([p for p in points if p['risk_level'] == 'critical'])
        }
    })

@app.route('/api/terminal/status')
def api_terminal_status():
    user = current_user()
    if not _user_has_permission(user, 'access_terminal'):
        audit_event('access_denied', 'api_terminal_status', 'denied', 'access_terminal permission required')
        return jsonify(error='Access terminal permission required'), 403
    return jsonify(
        host=TERMINAL_WS_HOST,
        port=TERMINAL_WS_PORT,
        websocket_url=f'{TERMINAL_WS_SCHEME}://{TERMINAL_WS_HOST}:{TERMINAL_WS_PORT}',
        running=TERMINAL_WS_STARTED,
        allowed=sorted(DIAGNOSTIC_COMMANDS),
    )

@app.route('/api/terminal/run', methods=['POST'])
@require_permission('access_terminal')
def api_terminal_run():
    payload = request.json or {}
    command = payload.get('command', '')
    result, status = _run_terminal_command(command)
    return jsonify(result), status

@app.route('/api/local_machine')
def api_local_machine():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(BASE_DIR)
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    users = []
    try:
        users = [{'name': u.name, 'terminal': u.terminal, 'started': datetime.fromtimestamp(u.started).isoformat()} for u in psutil.users()]
    except (psutil.Error, OSError):
        pass
    connections = _local_connection_summary()
    return jsonify({
        'hostname': socket.gethostname(),
        'fqdn': socket.getfqdn(),
        'platform': platform.platform(),
        'os': {'system': platform.system(), 'release': platform.release(), 'version': platform.version()},
        'python': platform.python_version(),
        'boot_time': boot_time.isoformat(),
        'uptime_seconds': int((datetime.now() - boot_time).total_seconds()),
        'cpu': {
            'percent': psutil.cpu_percent(interval=0.05),
            'cores_logical': psutil.cpu_count(logical=True),
            'cores_physical': psutil.cpu_count(logical=False),
        },
        'memory': {
            'percent': memory.percent,
            'used_gb': _bytes_to_gb(memory.used),
            'total_gb': _bytes_to_gb(memory.total),
        },
        'disk': {
            'path': BASE_DIR,
            'percent': disk.percent,
            'used_gb': _bytes_to_gb(disk.used),
            'total_gb': _bytes_to_gb(disk.total),
        },
        'network': {
            'addresses': _local_ipv4_addresses(),
            'listening_ports': connections['listening'],
            'established': connections['established'],
            'public_connections': len([c for c in connections['established'] if c['public']]),
        },
        'processes': {'count': len(psutil.pids())},
        'users': users,
        'detected_at': datetime.now().isoformat(),
    })

@app.route('/api/procs/top')
def api_procs_top():
    return jsonify(_top_procs(n=5))

@app.route('/api/procs')
def api_procs():
    from flask import request
    limit = int(request.args.get('limit', 12))
    data = _top_procs(n=limit)
    # Format for JS
    rows = []
    for cpu_proc in data['cpu_top']:
        rows.append({**cpu_proc, 'type': 'cpu'})
    for mem_proc in data['mem_top']:
        if mem_proc not in rows:  # avoid duplicates
            rows.append({**mem_proc, 'type': 'mem'})
    return jsonify(rows=rows[:limit], total_processes=data.get('total_processes', len(rows)), updated=data['ts'])

@app.route('/api/temps')
def api_temps():
    return jsonify({'temps': _read_temps()})

@app.route('/api/gpu')
def api_gpu():
    return jsonify(_read_gpus())

@app.route('/anomalies')
def anomalies_page():
    return render_template('anomalies.html')

@app.route('/anomalies/<anomaly_id>')
def anomaly_detail_page(anomaly_id):
    return render_template('anomaly_detail.html', anomaly_id=anomaly_id)

@app.route('/api/anomalies')
def api_anomalies():
    user = current_user()
    return jsonify(anomalies=_load_anomalies(
        start=request.args.get('start'),
        end=request.args.get('end'),
        severity=request.args.get('severity'),
        organization_id=user.get('organization_id') if user else None
    ))

@app.route('/api/anomalies/heatmap')
def api_anomalies_heatmap():
    user = current_user()
    anomalies = _load_anomalies(apply_automation=False, organization_id=user.get('organization_id') if user else None)
    now = pd.Timestamp.now()
    buckets = []
    for hour in range(23, -1, -1):
        start = now - pd.Timedelta(hours=hour + 1)
        end = now - pd.Timedelta(hours=hour)
        label = end.strftime('%H:00')
        row = {'hour': label, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for anomaly in anomalies:
            ts = pd.to_datetime(anomaly['timestamp'])
            if start <= ts < end:
                row[anomaly.get('severity', 'low')] = row.get(anomaly.get('severity', 'low'), 0) + 1
        buckets.append(row)
    return jsonify(buckets=buckets)

@app.route('/api/anomalies/<anomaly_id>')
def api_anomaly_detail(anomaly_id):
    anomaly, events = _timeline_for_anomaly(anomaly_id)
    user = current_user()
    if anomaly and anomaly.get('organization_id') not in {None, user.get('organization_id')}:
        anomaly = None
    if not anomaly:
        return jsonify(error='not found'), 404
    return jsonify(anomaly=anomaly, timeline=events)

@app.route('/api/incidents', methods=['GET', 'POST'])
def api_incidents():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        rows = _db_query(
            "SELECT * FROM incidents WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
            (org_id, int(request.args.get('limit', 100)))
        )
        return jsonify(incidents=rows)
    payload = request.json or {}
    if user['role'] != 'admin':
        allowed = {'id', 'note'}
        if set(payload.keys()) - allowed or not str(payload.get('note', '')).strip():
            audit_event('access_denied', 'api_incidents', 'denied', 'workspace admin required for incident management')
            return jsonify(error='workspace admin role required'), 403
    incident_id = payload.get('id')
    rows = _db_query("SELECT * FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, org_id))
    if not rows:
        return jsonify(error='incident not found'), 404
    updates = []
    params = []
    if 'status' in payload:
        updates.append('status = ?')
        params.append(normalize_status(payload.get('status')))
    if 'owner' in payload:
        updates.append('owner = ?')
        params.append(payload.get('owner') or None)
    if 'resolution' in payload:
        updates.append('resolution = ?')
        params.append(payload.get('resolution') or None)
    note = str(payload.get('note', '')).strip()
    if not updates and not note:
        return jsonify(error='no supported update fields'), 400
    now = datetime.now().isoformat()
    if updates:
        updates.append('updated_at = ?')
        params.append(now)
        params.append(incident_id)
        _db_exec(f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?", tuple(params))
    else:
        _db_exec("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
    detail = {k: payload[k] for k in payload if k not in {'id', 'note'}}
    if detail:
        _incident_event(incident_id, 'incident_updated', json.dumps(detail))
    if note:
        _incident_event(incident_id, 'note_added', note)
    audit_detail = 'incident fields updated'
    if note and not detail:
        audit_detail = 'incident note added'
    elif note:
        audit_detail = 'incident fields updated; note added'
    audit_event('incident_updated', f"incident:{incident_id}", 'success', audit_detail)
    return jsonify(success=True, incident=_db_query("SELECT * FROM incidents WHERE id = ?", (incident_id,))[0])


@app.route('/api/incidents/<incident_id>')
def api_incident_detail(incident_id):
    org_id = current_user().get('organization_id')
    rows = _db_query("SELECT * FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, org_id))
    if not rows:
        return jsonify(error='incident not found'), 404
    events = _db_query("SELECT * FROM incident_events WHERE incident_id = ? AND organization_id = ? ORDER BY timestamp", (incident_id, org_id))
    approvals = _db_query("SELECT * FROM response_approvals WHERE incident_id = ? AND organization_id = ? ORDER BY created_at DESC", (incident_id, org_id))
    return jsonify(incident=rows[0], timeline=events, approvals=approvals)


@app.route('/api/validation_events', methods=['GET', 'POST'])
def api_validation_events():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        return jsonify(events=_db_query(
            "SELECT * FROM validation_events WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100",
            (org_id,)
        ))
    if user['role'] == 'viewer':
        audit_event('access_denied', 'api_validation_events', 'denied', 'regular user cannot create validation events')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    event_type = payload.get('event_type', 'cpu_pressure')
    if event_type not in {'cpu_pressure', 'memory_pressure', 'suspicious_network', 'sensitive_file_access'}:
        audit_event('validation_event_failed', 'api_validation_events', 'failed', f"unsupported event_type={event_type}")
        return jsonify(error='unsupported validation event type'), 400
    event_id = f"VE-{uuid.uuid4().hex[:10]}"
    anomaly_id = f"validation-{event_id.lower()}"
    now = datetime.now().isoformat()
    _db_exec(
        "INSERT INTO validation_events (id, organization_id, event_type, status, anomaly_id, incident_id, created_by, created_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event_id, org_id, event_type, 'created', anomaly_id, None, user['username'], now, payload.get('detail', 'controlled validation event'))
    )
    anomaly = next(a for a in _validation_anomalies(org_id) if a['id'] == anomaly_id)
    _persist_anomaly(anomaly, organization_id=org_id)
    audit_event('alert_generated', f"anomaly:{anomaly_id}", 'success', f"{event_type} severity={anomaly['severity']}")
    incident = create_incident_from_anomaly(anomaly, actor=user['username'], organization_id=org_id)
    _db_exec("UPDATE validation_events SET incident_id = ?, status = ? WHERE id = ?", (incident['id'], 'incident_created', event_id))
    audit_event('validation_event_created', f"validation_event:{event_id}", 'success', event_type)
    notification_queue.put({'type': 'validation_event', 'event_type': event_type, 'anomaly_id': anomaly_id, 'incident_id': incident['id']})
    return jsonify(success=True, event_id=event_id, anomaly=anomaly, incident=incident)


@app.route('/api/response_approvals', methods=['GET', 'POST'])
def api_response_approvals():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        return jsonify(approvals=_db_query(
            "SELECT * FROM response_approvals WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100",
            (org_id,)
        ))
    if user['role'] == 'viewer':
        audit_event('access_denied', 'api_response_approvals', 'denied', 'regular user cannot request approvals')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    action = payload.get('action')
    target = str(payload.get('target', '')).strip()
    if action not in RESPONSE_ACTIONS:
        audit_event('response_approval_failed', 'api_response_approvals', 'failed', f"unsupported action={action}")
        return jsonify(error='unsupported response action'), 400
    if not target:
        audit_event('response_approval_failed', 'api_response_approvals', 'failed', 'target is required')
        return jsonify(error='target is required'), 400
    try:
        preview = _dry_run_response_action(action, target)
    except Exception as exc:
        audit_event('response_approval_failed', f"response_action:{action}", 'failed', str(exc))
        return jsonify(error=str(exc)), 400
    if payload.get('incident_id'):
        incident = _db_query("SELECT id FROM incidents WHERE id = ? AND organization_id = ?", (payload.get('incident_id'), org_id))
        if not incident:
            audit_event('response_approval_failed', f"incident:{payload.get('incident_id')}", 'failed', 'incident not found')
            return jsonify(error='incident not found'), 404
    approval_id = f"RA-{uuid.uuid4().hex[:10]}"
    now = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(seconds=APPROVAL_TTL_SECONDS)).isoformat()
    _db_exec(
        "INSERT INTO response_approvals (id, organization_id, incident_id, anomaly_id, action, target, requested_by, approved_by, status, reason, dry_run, created_at, updated_at, expires_at, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (approval_id, org_id, payload.get('incident_id'), payload.get('anomaly_id'), action, target, user['username'], None, 'pending', payload.get('reason'), int(bool(payload.get('dry_run', True))), now, now, expires_at, preview)
    )
    if payload.get('incident_id'):
        _incident_event(payload.get('incident_id'), 'approval_requested', f"{action} target={target}", organization_id=org_id)
        _db_exec("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ? AND organization_id = ?", ('waiting_for_approval', now, payload.get('incident_id'), org_id))
    audit_event('response_approval_requested', f"approval:{approval_id}", 'success', f"{action} target={target}")
    return jsonify(success=True, approval=_approval_row(approval_id), preview=preview)


@app.route('/api/response_approvals/<approval_id>', methods=['POST'])
@require_admin
def api_response_approval_detail(approval_id):
    approval = _approval_row(approval_id)
    if not approval:
        return jsonify(error='approval not found'), 404
    payload = request.json or {}
    command = payload.get('command')
    user = current_user()
    now = datetime.now().isoformat()
    if command in {'approve', 'reject'}:
        if command == 'approve' and _approval_expired(approval, datetime.fromisoformat(now)):
            _db_exec("UPDATE response_approvals SET status = ?, updated_at = ? WHERE id = ?", ('expired', now, approval_id))
            if approval.get('incident_id'):
                _incident_event(approval['incident_id'], 'approval_expired', f"{approval['action']} target={approval['target']}")
            audit_event('response_approval_expired', f"approval:{approval_id}", 'denied', approval['action'])
            return jsonify(error='approval request has expired', approval=_approval_row(approval_id)), 409
        status = 'approved' if command == 'approve' else 'rejected'
        _db_exec(
            "UPDATE response_approvals SET status = ?, approved_by = ?, updated_at = ? WHERE id = ?",
            (status, user['username'], now, approval_id)
        )
        if approval.get('incident_id'):
            _incident_event(approval['incident_id'], f"approval_{status}", f"{approval['action']} target={approval['target']}")
        audit_event(f"response_approval_{status}", f"approval:{approval_id}", 'success', approval['action'])
        return jsonify(success=True, approval=_approval_row(approval_id))
    if command == 'execute':
        if approval['status'] != 'approved':
            audit_event('response_action_started', f"approval:{approval_id}", 'denied', 'approval must be approved before execution')
            return jsonify(error='approval must be approved before execution'), 409
        if _approval_expired(approval, datetime.fromisoformat(now)):
            _db_exec("UPDATE response_approvals SET status = ?, updated_at = ? WHERE id = ?", ('expired', now, approval_id))
            if approval.get('incident_id'):
                _incident_event(approval['incident_id'], 'approval_expired', f"{approval['action']} target={approval['target']}")
            audit_event('response_action_started', f"approval:{approval_id}", 'denied', 'approval expired')
            return jsonify(error='approval request has expired', approval=_approval_row(approval_id)), 409
        try:
            audit_event('response_action_started', f"approval:{approval_id}", 'success', approval['action'])
            result = _execute_response_action(approval['action'], approval['target'], dry_run=bool(approval['dry_run']))
            status = 'executed_dry_run' if approval['dry_run'] else 'executed'
            _db_exec(
                "UPDATE response_approvals SET status = ?, executed_at = ?, updated_at = ?, result = ? WHERE id = ?",
                (status, now, now, result['detail'], approval_id)
            )
            if approval.get('incident_id'):
                _incident_event(approval['incident_id'], 'response_executed', result['detail'])
            audit_event('response_action_executed', f"approval:{approval_id}", 'success', result['detail'])
            return jsonify(success=True, result=result, approval=_approval_row(approval_id))
        except Exception as exc:
            _db_exec(
                "UPDATE response_approvals SET status = ?, updated_at = ?, result = ? WHERE id = ?",
                ('failed', now, str(exc), approval_id)
            )
            if approval.get('incident_id'):
                _incident_event(approval['incident_id'], 'response_failed', str(exc))
            audit_event('response_action_executed', f"approval:{approval_id}", 'failed', str(exc))
            return jsonify(error=str(exc), approval=_approval_row(approval_id)), 400
    audit_event('response_approval_failed', f"approval:{approval_id}", 'failed', f"unsupported command={command}")
    return jsonify(error='unsupported command'), 400

def op_eval(value, operator, threshold):
    if operator == '>': return value > threshold
    if operator == '<': return value < threshold
    if operator == '>=': return value >= threshold
    if operator == '<=': return value <= threshold
    return False

def apply_playbooks(anomalies):
    seen = {(r.get('playbook_id'), r.get('anomaly_id')) for r in _playbook_runs_from_db(limit=1000)}
    for anomaly in anomalies:
        for pb in _playbooks_from_db(anomaly.get('organization_id')):
            if not pb.get('enabled', False):
                continue
            if anomaly.get('metric') != pb.get('metric'):
                continue
            if op_eval(anomaly.get('value', 0), pb.get('operator'), pb.get('threshold')):
                if (pb['id'], anomaly.get('id')) in seen:
                    continue
                run_entry = {
                    'playbook_id': pb['id'],
                    'name': pb['name'],
                    'anomaly_id': anomaly.get('id'),
                    'metric': anomaly['metric'],
                    'value': anomaly['value'],
                    'threshold': pb['threshold'],
                    'action': pb['action'],
                    'target': pb['target'],
                    'timestamp': datetime.now().isoformat(),
                    'auto': pb.get('auto', False),
                    'status': 'executed' if pb.get('auto') else 'ready',
                    'yaml': pb.get('yaml', '')
                }
                cur = _db_exec(
                    "INSERT INTO playbook_runs (organization_id, playbook_id, name, anomaly_id, metric, value, threshold, action, target, timestamp, auto, status, yaml) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (anomaly.get('organization_id'), run_entry['playbook_id'], run_entry['name'], run_entry['anomaly_id'], run_entry['metric'], run_entry['value'], run_entry['threshold'], run_entry['action'], run_entry['target'], run_entry['timestamp'], int(run_entry['auto']), run_entry['status'], run_entry['yaml'])
                )
                run_entry['id'] = cur.lastrowid
                run_entry['organization_id'] = anomaly.get('organization_id')
                playbook_runs.append(run_entry)
                seen.add((pb['id'], anomaly.get('id')))
                if pb.get('auto'):
                    notification_queue.put({
                        'type': 'playbook_trigger',
                        'playbook': pb['name'],
                        'details': run_entry
                    })


def _workspace_playbooks(organization_id):
    return _playbooks_from_db(organization_id)


@app.route('/api/playbooks', methods=['GET', 'POST'])
def api_playbooks():
    global next_playbook_id
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        scoped_playbooks = _workspace_playbooks(org_id)
        scoped_ids = {pb['id'] for pb in scoped_playbooks}
        scoped_runs = _playbook_runs_from_db(org_id, scoped_ids)
        return jsonify(playbooks=scoped_playbooks, runs=scoped_runs)
    if not _user_has_permission(user, 'mutate_playbooks'):
        audit_event('access_denied', 'api_playbooks', 'denied', 'mutate_playbooks permission required')
        return jsonify(error='Mutate playbooks permission required'), 403
    payload = request.json or {}
    if payload.get('action') == 'delete':
        pid = int(payload.get('id', 0))
        pb = next((item for item in playbooks if item['id'] == pid), None)
        if not pb or pb.get('organization_id') != org_id:
            audit_event('playbook_delete_failed', f"playbook:{pid}", 'failed', 'workspace playbook not found')
            return jsonify(error='workspace playbook not found'), 404
        _db_exec("DELETE FROM playbooks WHERE id = ? AND organization_id = ?", (pid, org_id))
        load_persistent_state()
        audit_event('playbook_deleted', f"playbook:{pid}", 'success', 'playbook deleted')
        return jsonify(success=True, playbooks=_workspace_playbooks(org_id))
    new_pb = {
        'id': next_playbook_id,
        'organization_id': org_id,
        'name': payload.get('name', 'New Playbook'),
        'category': payload.get('category', 'system'),
        'metric': payload.get('metric', 'cpu_percent'),
        'operator': payload.get('operator', '>'),
        'threshold': float(payload.get('threshold', 90)),
        'action': payload.get('action_type', 'block_ip'),
        'target': payload.get('target', 'external'),
        'enabled': bool(payload.get('enabled', True)),
        'auto': bool(payload.get('auto', False)),
        'yaml': payload.get('yaml', '')
    }
    _db_exec(
        "INSERT INTO playbooks (id, organization_id, name, category, metric, operator, threshold, action, target, enabled, auto, yaml) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (new_pb['id'], new_pb['organization_id'], new_pb['name'], new_pb['category'], new_pb['metric'], new_pb['operator'], new_pb['threshold'], new_pb['action'], new_pb['target'], int(new_pb['enabled']), int(new_pb['auto']), new_pb['yaml'])
    )
    playbooks.append(new_pb)
    next_playbook_id += 1
    audit_event('playbook_created', f"playbook:{new_pb['id']}", 'success', new_pb['name'])
    return jsonify(success=True, playbook=new_pb, playbooks=_workspace_playbooks(org_id))

@app.route('/api/playbook_trigger', methods=['POST'])
def api_playbook_trigger():
    payload = request.json or {}
    org_id = current_user().get('organization_id')
    available_playbooks = _workspace_playbooks(org_id)
    pb_id = int(payload.get('id', 0) or 0)
    anomaly = None
    if payload.get('anomaly_id'):
        anomaly = next((a for a in _load_anomalies(apply_automation=False) if a['id'] == payload.get('anomaly_id')), None)
    pb = next((x for x in available_playbooks if x['id'] == pb_id), None)
    if not pb and anomaly:
        pb = next((x for x in available_playbooks if x.get('enabled') and x.get('category') == anomaly.get('category')), None)
    if not pb and anomaly:
        pb = next((x for x in available_playbooks if x.get('enabled') and x.get('metric') == anomaly.get('metric')), None)
    if not pb:
        audit_event('playbook_trigger_failed', f"playbook:{pb_id or 'auto'}", 'failed', f"anomaly={payload.get('anomaly_id') or 'manual'}")
        return jsonify(success=False, message='Playbook not found'), 404
    run_entry = {
        'id': len(playbook_runs)+1,
        'organization_id': org_id,
        'playbook_id': pb['id'],
        'name': pb['name'],
        'metric': payload.get('metric') or (anomaly or {}).get('metric', 'n/a'),
        'value': payload.get('value') or (anomaly or {}).get('value', 0),
        'threshold': pb['threshold'],
        'action': pb['action'],
        'target': pb['target'],
        'timestamp': datetime.now().isoformat(),
        'auto': False,
        'status': 'manual_triggered',
        'anomaly_id': payload.get('anomaly_id'),
        'yaml': pb.get('yaml', '')
    }
    cur = _db_exec(
        "INSERT INTO playbook_runs (organization_id, playbook_id, name, anomaly_id, metric, value, threshold, action, target, timestamp, auto, status, yaml) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_entry['organization_id'], run_entry['playbook_id'], run_entry['name'], run_entry['anomaly_id'], run_entry['metric'], run_entry['value'], run_entry['threshold'], run_entry['action'], run_entry['target'], run_entry['timestamp'], int(run_entry['auto']), run_entry['status'], run_entry['yaml'])
    )
    run_entry['id'] = cur.lastrowid
    playbook_runs.append(run_entry)
    audit_event('playbook_triggered', f"playbook:{pb['id']}", 'success', f"anomaly={payload.get('anomaly_id') or 'manual'}")
    notification_queue.put({'type':'playbook_manual_trigger','playbook':pb['name'],'details':run_entry})
    return jsonify(success=True, run=run_entry)

@app.route('/api/threat_intel/lookup')
def api_threat_intel_lookup():
    indicator_type = request.args.get('type', 'ip')
    indicator = request.args.get('indicator', '')
    return jsonify(indicator_type=indicator_type, indicator=indicator, result=_threat_lookup(indicator_type, indicator))

@app.route('/api/reports/summary')
def api_reports_summary():
    return jsonify(_report_summary())


@app.route('/api/reports/history')
def api_reports_history():
    user = current_user()
    return jsonify(history=_db_query(
        "SELECT id, generated_at, fmt, generated_by, detail FROM report_history WHERE organization_id = ? ORDER BY generated_at DESC LIMIT 100",
        (user.get('organization_id'),)
    ))


@app.route('/api/reports/download.<fmt>')
def api_reports_download(fmt):
    summary = _report_summary()
    if fmt == 'csv':
        user = current_user()
        _db_exec(
            "INSERT INTO report_history (organization_id, generated_at, fmt, generated_by, detail) VALUES (?, ?, ?, ?, ?)",
            (user.get('organization_id') if user else None, summary['generated_at'], fmt, user['username'] if user else 'system', 'security compliance CSV')
        )
        audit_event('report_downloaded', 'reports:csv', 'success', 'security compliance CSV')
        return _csv_response(summary)
    if fmt == 'pdf':
        user = current_user()
        _db_exec(
            "INSERT INTO report_history (organization_id, generated_at, fmt, generated_by, detail) VALUES (?, ?, ?, ?, ?)",
            (user.get('organization_id') if user else None, summary['generated_at'], fmt, user['username'] if user else 'system', 'security compliance PDF')
        )
        audit_event('report_downloaded', 'reports:pdf', 'success', 'security compliance PDF')
        return _pdf_response(summary)
    audit_event('report_download_failed', f"reports:{fmt}", 'failed', 'unsupported format')
    return jsonify(error='unsupported format'), 400

@app.route('/api/automation_rules', methods=['GET', 'POST'])
def api_automation_rules():
    global next_automation_rule_id
    if request.method == 'GET':
        return jsonify(
            rules=_automation_rules_from_db(),
            history=list(reversed(_db_query("SELECT * FROM automation_history ORDER BY id DESC LIMIT 100")))
        )
    payload = request.json or {}
    if payload.get('action') == 'delete':
        rid = int(payload.get('id', 0))
        if not _db_query("SELECT id FROM automation_rules WHERE id = ?", (rid,)):
            audit_event('automation_rule_delete_failed', f"automation_rule:{rid}", 'failed', 'automation rule not found')
            return jsonify(error='automation rule not found'), 404
        _db_exec("DELETE FROM automation_rules WHERE id = ?", (rid,))
        load_persistent_state()
        audit_event('automation_rule_deleted', f"automation_rule:{rid}", 'success', 'automation rule deleted')
        return jsonify(success=True, rules=_automation_rules_from_db())
    rule = {
        'id': next_automation_rule_id,
        'name': payload.get('name', 'New automation rule'),
        'field': payload.get('field', 'severity'),
        'operator': payload.get('operator', 'equals'),
        'value': payload.get('value', 'critical'),
        'action': payload.get('run_action', 'Isolate Process'),
        'enabled': bool(payload.get('enabled', True)),
    }
    _db_exec(
        "INSERT INTO automation_rules (id, name, field, operator, value, action, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rule['id'], rule['name'], rule['field'], rule['operator'], rule['value'], rule['action'], int(rule['enabled']))
    )
    automation_rules.append(rule)
    next_automation_rule_id += 1
    audit_event('automation_rule_created', f"automation_rule:{rule['id']}", 'success', rule['name'])
    return jsonify(success=True, rule=rule, rules=_automation_rules_from_db())

@app.route('/api/notifications')
def api_notifications():
    def generate():
        while True:
            try:
                msg = notification_queue.get(timeout=30)  # wait up to 30s
                yield f"data: {json.dumps(msg)}\n\n"
            except queue.Empty:
                yield "data: {\"type\": \"ping\"}\n\n"  # keep connection alive
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/anomaly_rules', methods=['GET', 'POST'])
def api_anomaly_rules():
    global next_rule_id
    if request.method == 'GET':
        return jsonify(rules=_anomaly_rules_from_db())

    payload = request.json or {}
    if 'action' in payload and payload['action'] == 'delete':
        rid = int(payload.get('id', 0))
        if not _db_query("SELECT id FROM anomaly_rules WHERE id = ?", (rid,)):
            audit_event('anomaly_rule_delete_failed', f"anomaly_rule:{rid}", 'failed', 'anomaly rule not found')
            return jsonify(error='anomaly rule not found'), 404
        _db_exec("DELETE FROM anomaly_rules WHERE id = ?", (rid,))
        load_persistent_state()
        audit_event('anomaly_rule_deleted', f"anomaly_rule:{rid}", 'success', 'anomaly rule deleted')
        return jsonify(success=True, rules=_anomaly_rules_from_db())

    rule = {
        'id': next_rule_id,
        'metric': payload.get('metric', 'cpu_percent'),
        'operator': payload.get('operator', '>'),
        'threshold': float(payload.get('threshold', 90)),
        'severity': payload.get('severity', 'high'),
        'enabled': bool(payload.get('enabled', True)),
        'alert_in_app': bool(payload.get('alert_in_app', True)),
        'alert_email': bool(payload.get('alert_email', False))
    }
    _db_exec(
        "INSERT INTO anomaly_rules (id, metric, operator, threshold, severity, enabled, alert_in_app, alert_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (rule['id'], rule['metric'], rule['operator'], rule['threshold'], rule['severity'], int(rule['enabled']), int(rule['alert_in_app']), int(rule['alert_email']))
    )
    anomaly_rules.append(rule)
    next_rule_id += 1
    audit_event('anomaly_rule_created', f"anomaly_rule:{rule['id']}", 'success', f"{rule['metric']} {rule['operator']} {rule['threshold']}")
    return jsonify(success=True, rule=rule, rules=_anomaly_rules_from_db())

@app.route('/api/system_health')
def api_system_health():
    return jsonify({'health': 'Operational'})

@app.route('/api/test_anomaly')
def api_test_anomaly():
    notification_queue.put({
        'type': 'anomaly',
        'severity': 'critical',
        'metric': 'cpu_percent',
        'value': 95.0,
        'timestamp': datetime.now().isoformat()
    })
    audit_event('alert_generated', 'anomaly:cpu_percent', 'success', 'manual critical anomaly notification')
    return jsonify({'status': 'test anomaly sent'})

@app.route('/api/logs')
def api_logs():
    if not os.path.exists(LOG_PATH):
        return jsonify(logs=[])
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    logs = df.tail(20).to_dict(orient='records')
    return jsonify(logs=logs)

@app.route('/api/audit_events')
def api_audit_events():
    user = current_user()
    return jsonify(logs=_audit_rows(
        limit=int(request.args.get('limit', 200)),
        actor=request.args.get('actor') or None,
        event_type=request.args.get('event_type') or None,
        result=request.args.get('result') or None,
        start=request.args.get('start') or None,
        end=request.args.get('end') or None,
        organization_id=user.get('organization_id') if user else None,
    ))

@app.route('/api/audit_summary')
def api_audit_summary():
    user = current_user()
    rows = _audit_rows(limit=200, organization_id=user.get('organization_id') if user else None)
    warnings = len([r for r in rows if r['severity'] == 'warning'])
    denied = len([r for r in rows if r['outcome'] == 'denied'])
    return jsonify(summary=f"{len(rows)} telemetry audit events, {warnings} warnings, {denied} denied outcomes")

@app.route('/api/ai_alerts')
def api_ai_alerts():
    anomalies = _load_anomalies(apply_automation=False)
    if not anomalies:
        return jsonify(alerts="No anomaly alerts from current telemetry")
    critical = len([a for a in anomalies if a['severity'] == 'critical'])
    high_risk = len([a for a in anomalies if a['risk_score'] >= 75])
    return jsonify(alerts=f"{len(anomalies)} telemetry anomalies, {critical} critical, {high_risk} high risk")

@app.route('/api/security/alerts')
def api_security_alerts():
    alerts = []
    for anomaly in _load_anomalies(apply_automation=False)[:50]:
        alerts.append({
            'id': anomaly['id'],
            'time': anomaly['timestamp'],
            'event': f"{anomaly['metric']} anomaly",
            'severity': anomaly['severity'],
            'source': anomaly.get('indicator', 'local telemetry'),
            'status': 'open' if anomaly['risk_score'] >= 75 else 'investigating',
            'title': f"{anomaly['severity'].title()} {anomaly['metric']} anomaly",
            'process': anomaly.get('indicator', 'local telemetry'),
            'confidence': round(float(anomaly.get('confidence', 0)) * 100),
            'recommendation': 'Trigger matching playbook' if anomaly['risk_score'] >= 75 else 'Review correlated telemetry',
            'risk_score': anomaly['risk_score'],
        })
    return jsonify(alerts=alerts)

@app.route('/api/files/access')
def api_files_access():
    user = current_user()
    org_id = user.get('organization_id') if user else None
    now = time.time()
    if _files_access_cache['payload'] is not None and now - _files_access_cache['timestamp'] < FILES_ACCESS_CACHE_TTL_SECONDS:
        return jsonify(_files_access_cache['payload'])

    files = []
    roots = [BASE_DIR]
    sensitive_markers = ('secret', 'credential', 'token', 'key', '.env', 'private')
    confidential_markers = ('log', 'audit', 'config', 'conf', 'csv')
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {'.git', 'venv', '__pycache__'}]
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                lowered = path.lower()
                if any(marker in lowered for marker in sensitive_markers):
                    sensitivity = 'restricted'
                    mac = 'owner only'
                elif any(marker in lowered for marker in confidential_markers):
                    sensitivity = 'confidential'
                    mac = 'read only'
                elif path.endswith(('.py', '.html', '.css', '.md', '.txt')):
                    sensitivity = 'internal'
                    mac = 'read write'
                else:
                    sensitivity = 'public'
                    mac = 'read only'
                files.append({
                    'time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'filename': filename,
                    'path': os.path.relpath(path, BASE_DIR),
                    'sensitivity': sensitivity,
                    'owner': str(stat.st_uid),
                    'mac': mac,
                    'accesses': 0,
                    'size': stat.st_size,
                    'action': 'stat',
                    'classification': sensitivity,
                })
    updated_at = datetime.now().isoformat()
    for item in files:
        storage_path = _file_classification_storage_path(org_id, item['path'])
        _db_exec(
            """
            INSERT INTO file_classifications (path, organization_id, sensitivity, owner, classification, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                organization_id = excluded.organization_id,
                sensitivity = excluded.sensitivity,
                owner = excluded.owner,
                classification = excluded.classification,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            """,
            (storage_path, org_id, item['sensitivity'], item['owner'], item['classification'], updated_at, user['username'] if user else 'system')
        )
    prefix = _file_classification_storage_path(org_id, '')
    rows = _db_query(
        "SELECT path, sensitivity, owner, classification, updated_at FROM file_classifications WHERE organization_id = ? AND path LIKE ? ORDER BY updated_at DESC LIMIT 200",
        (org_id, f"{prefix}%")
    )
    payload = {'access': [{
        'time': row['updated_at'],
        'filename': os.path.basename(_file_classification_public_path(org_id, row['path'])),
        'path': _file_classification_public_path(org_id, row['path']),
        'sensitivity': row['sensitivity'],
        'owner': row.get('owner'),
        'mac': 'owner only' if row['sensitivity'] == 'restricted' else ('read write' if row['sensitivity'] == 'internal' else 'read only'),
        'accesses': 0,
        'size': 0,
        'action': 'classification',
        'classification': row['classification'],
    } for row in rows]}
    _files_access_cache['payload'] = payload
    _files_access_cache['timestamp'] = now
    return jsonify(payload)

@app.route('/api/audit/stats')
def api_audit_stats():
    if not os.path.exists(LOG_PATH):
        return jsonify(stats={'total': 0, 'today': 0})
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    total = len(df)
    today = len(df[df['timestamp'].dt.date == pd.Timestamp.now().date()])
    return jsonify(stats={'total': total, 'today': today})

@app.route('/health')
def health():
    return jsonify({'ok': True})

@app.route('/assets')
def assets_page():
    return render_template('assets.html')

@app.route('/threat-trends')
def threat_trends_page():
    return render_template('threat_trends.html')

@app.route('/playbooks')
def playbooks_page():
    return render_template('playbooks.html')

@app.route('/api/assets')
def api_assets():
    cpu = psutil.cpu_percent(interval=0.05)
    mem = psutil.virtual_memory().percent
    health = 'critical' if cpu > CPU_THRESHOLD or mem > MEMORY_THRESHOLD else ('warning' if cpu > (CPU_THRESHOLD * 0.8) or mem > (MEMORY_THRESHOLD * 0.8) else 'good')
    addrs = []
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            if getattr(entry, 'family', None) == socket.AF_INET and entry.address != '127.0.0.1':
                addrs.append(entry.address)
    local = {
        'name': socket.gethostname(),
        'ip': addrs[0] if addrs else '127.0.0.1',
        'health': health,
        'active_processes': len(psutil.pids()),
        'vuln_scan': f"live health: CPU {cpu:.1f}% / memory {mem:.1f}%"
    }
    return jsonify(assets=[local])

@app.route('/api/threat_trends')
def api_threat_trends():
    anomalies = _load_anomalies(apply_automation=False)
    if not anomalies:
        return jsonify(trends=[])
    buckets = {}
    for anomaly in anomalies:
        day = pd.to_datetime(anomaly['timestamp']).strftime('%Y-%m-%d')
        buckets.setdefault(day, {'day': day, 'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
        buckets[day]['count'] += 1
        buckets[day][anomaly.get('severity', 'low')] += 1
    data = [buckets[key] for key in sorted(buckets)]
    return jsonify(trends=data)

@app.route('/api/net_graph')
def api_net_graph():
    connections = []
    try:
        proc_map = {p.pid: p.info['name'] for p in psutil.process_iter(attrs=['pid', 'name'])}
        for c in psutil.net_connections(kind='inet'):
            if c.raddr and getattr(c, 'status', None) == 'ESTABLISHED' and c.pid in proc_map:
                proc_name = proc_map.get(c.pid, f'pid-{c.pid}')
                connections.append((c.pid, proc_name, c.raddr.ip))
    except Exception:
        pass

    nodes = []
    links = []
    seen_nodes = set()
    for pid, proc, ip in connections[:40]:
        proc_id = f'proc-{pid}'
        ext_id = f'ext-{ip}'
        if proc_id not in seen_nodes:
            nodes.append({'id': proc_id, 'label': proc, 'type': 'process'})
            seen_nodes.add(proc_id)
        if ext_id not in seen_nodes:
            nodes.append({'id': ext_id, 'label': ip, 'type': 'ip'})
            seen_nodes.add(ext_id)
        threat = _threat_lookup('ip', ip)
        links.append({'source': proc_id, 'target': ext_id, 'score': threat['confidence'] / 100 if threat['matched'] else 0.0})

    return jsonify(graph={'nodes':nodes,'links':links})

if __name__ == '__main__':
    if CONFIG.terminal_ws_enabled:
        start_terminal_ws()
    for line in startup_summary(CONFIG):
        print(line)
    if not CONFIG.protected_bind:
        print('WARNING: SAAOE is not bound to a loopback address. Use authentication, TLS, and network controls before exposing it.')
    app.run(host=APP_HOST, port=APP_PORT, debug=SAAOE_DEBUG)
