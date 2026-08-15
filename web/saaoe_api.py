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
import re
import shlex
import shutil
import socketserver
import struct
import subprocess
import uuid
from dataclasses import dataclass
from functools import wraps
from urllib.parse import urlsplit

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
SAAOE_VERSION = 'phase5.13'
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
    SESSION_COOKIE_SECURE=CONFIG.session_cookie_secure,
    PERMANENT_SESSION_LIFETIME=CONFIG.session_seconds,
)
SESSION_TIMEOUT_SECONDS = CONFIG.session_seconds

# --- Ring buffers ---
MAX_SAMPLES = 240          # ~4 minutes @ 1s
SAMPLE_INTERVAL = 1.0      # seconds
SAMPLER_THREAD = None
SAMPLER_STARTED_AT = 0.0
SAMPLER_LAST_SUCCESS_AT = 0.0
SAMPLER_HEALTH_MAX_AGE_SECONDS = 5.0
SAMPLER_STARTUP_GRACE_SECONDS = 5.0

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

playbooks = []
next_playbook_id = 1
playbook_runs = []

automation_rules = [
    {'id': 1, 'name': 'Critical containment', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'action': 'Isolate Process', 'enabled': True},
    {'id': 2, 'name': 'High risk evidence capture', 'field': 'risk_score', 'operator': '>=', 'value': '75', 'action': 'Capture Forensics Bundle', 'enabled': True},
]
next_automation_rule_id = 3
automation_history = []

THREAT_INTEL_PATH = str(CONFIG.threat_intel_path)

TERMINAL_TIMEOUT_SECONDS = 12
TERMINAL_COMMAND_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
TERMINAL_SHELL_SYNTAX_RE = re.compile(r'[;&|<>`$*?\[\]{}~#()!\\\n\r]')
DIAGNOSTIC_COMMANDS = {
    'hostname': {()},
    'whoami': {()},
    'uptime': {(), ('-p',), ('-s',)},
    'ps': {('aux',), ('-ef',), ('-eo', 'pid,ppid,user,stat,comm')},
    'ss': {('-tulpen',), ('-tulpn',), ('-tunap',)},
    'netstat': {('-tulpen',), ('-tulpn',), ('-an',)},
}
TERMINAL_WS_HOST = CONFIG.terminal_ws_host
TERMINAL_WS_PORT = CONFIG.terminal_ws_port
TERMINAL_WS_SCHEME = CONFIG.terminal_ws_scheme
TERMINAL_WS_STARTED = False
TERMINAL_WS_SERVER = None

FILES_ACCESS_CACHE_TTL_SECONDS = CONFIG.files_access_cache_ttl_seconds
_files_access_cache = {'timestamp': 0.0, 'payload': None}
_threat_intel_cache = {'mtime': None, 'data': None}

SEVERITY_VOCABULARY = {
    'info': {'label': 'Info', 'css_class': 'severity-info', 'aliases': {'info', 'informational', 'ok', 'success', 'pass'}},
    'low': {'label': 'Low', 'css_class': 'severity-low', 'aliases': {'low', 'minor'}},
    'medium': {'label': 'Medium', 'css_class': 'severity-medium', 'aliases': {'medium', 'moderate', 'warning', 'warn', 'alert'}},
    'high': {'label': 'High', 'css_class': 'severity-high', 'aliases': {'high', 'major', 'error', 'danger'}},
    'critical': {'label': 'Critical', 'css_class': 'severity-critical', 'aliases': {'critical', 'severe', 'fatal'}},
}
STATUS_VOCABULARY = {
    'open': {'label': 'Open', 'css_class': 'status-open', 'aliases': {'open', 'new', 'active', 'triggered', 'pending', 'ready', 'manual_triggered', 'created'}},
    'investigating': {'label': 'Investigating', 'css_class': 'status-investigating', 'aliases': {'investigating', 'in_progress', 'review', 'reviewing'}},
    'waiting_for_approval': {'label': 'Waiting for Approval', 'css_class': 'status-waiting-for-approval', 'aliases': {'waiting_for_approval', 'approval', 'pending_approval', 'needs_approval', 'approved'}},
    'resolved': {'label': 'Resolved', 'css_class': 'status-resolved', 'aliases': {'resolved', 'closed', 'complete', 'completed', 'success', 'consumed', 'executed', 'executed_dry_run', 'incident_created'}},
    'dismissed': {'label': 'Dismissed', 'css_class': 'status-dismissed', 'aliases': {'dismissed', 'ignored', 'false_positive', 'suppressed', 'rejected'}},
    'failed': {'label': 'Failed', 'css_class': 'status-failed', 'aliases': {'failed', 'error', 'failure', 'expired'}},
}
SEVERITIES = set(SEVERITY_VOCABULARY)
STATUSES = set(STATUS_VOCABULARY)
INCIDENT_STATUSES = STATUSES
APPROVAL_STATUSES = {'pending', 'approved', 'rejected', 'cancelled', 'expired', 'consumed'}
APPROVAL_DECISION_STATUSES = {'approved', 'rejected', 'cancelled', 'expired'}
APPROVAL_TERMINAL_STATUSES = {'rejected', 'cancelled', 'expired', 'consumed'}


@dataclass(frozen=True)
class ResponseActionMetadata:
    stable_key: str
    safety_class: str
    input_validator: object
    request_roles: tuple
    required_approval_role: str
    execution_roles: tuple
    supported_platforms: tuple
    enabled: bool
    executor: object
    action_type: str
    host_impacting: bool

    def approval_contract(self):
        return {
            'required_role': self.required_approval_role,
            'action_type': self.action_type,
            'host_impacting': self.host_impacting,
            'enabled': self.enabled,
            'safety_class': self.safety_class,
            'request_roles': self.request_roles,
            'execution_roles': self.execution_roles,
            'supported_platforms': self.supported_platforms,
        }


def _unsupported_executor(*_args, **_kwargs):
    raise ValueError('response action execution adapter is not available')


def _incident_report_executor(_target):
    return {'executed': True, 'detail': 'Incident report action recorded.'}


RESPONSE_ACTION_REGISTRY = {
    'kill_process': ResponseActionMetadata(
        stable_key='kill_process',
        safety_class='destructive_host_process',
        input_validator='_validate_kill_process_target',
        request_roles=('analyst', 'admin'),
        required_approval_role='admin',
        execution_roles=('admin',),
        supported_platforms=('linux', 'darwin', 'windows'),
        enabled=False,
        executor='_execute_kill_process',
        action_type='host_process',
        host_impacting=True,
    ),
    'quarantine_file': ResponseActionMetadata(
        stable_key='quarantine_file',
        safety_class='destructive_host_file',
        input_validator='_validate_quarantine_file_target',
        request_roles=('analyst', 'admin'),
        required_approval_role='admin',
        execution_roles=('admin',),
        supported_platforms=('linux', 'darwin', 'windows'),
        enabled=False,
        executor=_unsupported_executor,
        action_type='host_file',
        host_impacting=True,
    ),
    'block_ip': ResponseActionMetadata(
        stable_key='block_ip',
        safety_class='destructive_network_firewall',
        input_validator='_validate_block_ip_target',
        request_roles=('analyst', 'admin'),
        required_approval_role='admin',
        execution_roles=('admin',),
        supported_platforms=('linux', 'darwin', 'windows'),
        enabled=False,
        executor=_unsupported_executor,
        action_type='network_firewall',
        host_impacting=True,
    ),
    'restart_service': ResponseActionMetadata(
        stable_key='restart_service',
        safety_class='bounded_service_control',
        input_validator='_validate_restart_service_target',
        request_roles=('analyst', 'admin'),
        required_approval_role='admin',
        execution_roles=('admin',),
        supported_platforms=('linux',),
        enabled=True,
        executor='_restart_approved_service',
        action_type='service_control',
        host_impacting=True,
    ),
    'create_incident_report': ResponseActionMetadata(
        stable_key='create_incident_report',
        safety_class='record_only',
        input_validator='_validate_incident_report_target',
        request_roles=('analyst', 'admin'),
        required_approval_role='analyst',
        execution_roles=('analyst', 'admin'),
        supported_platforms=('linux', 'darwin', 'windows'),
        enabled=True,
        executor=_incident_report_executor,
        action_type='record_report',
        host_impacting=False,
    ),
}
APPROVAL_ACTION_CONTRACTS = {key: metadata.approval_contract() for key, metadata in RESPONSE_ACTION_REGISTRY.items()}
RESPONSE_ACTIONS = set(RESPONSE_ACTION_REGISTRY)
PLAYBOOK_KINDS = {'anomaly_response', 'workflow_gate', 'incident_utility', 'approval_action', 'access_control'}
PLAYBOOK_CATEGORIES = {'system', 'host', 'network', 'file', 'workflow', 'incident', 'authentication', 'access_control', 'custom'}
PLAYBOOK_TRIGGER_TYPES = {'anomaly', 'workflow', 'incident'}
PLAYBOOK_TRIGGER_OPERATORS = {'>', '>=', '<', '<=', '==', 'equals'}
PLAYBOOK_RECOMMENDED_ACTION_KEYS = {
    'review_process_evidence',
    'review_memory_evidence',
    'review_connection',
    'review_file_access',
    'request_approval',
    'create_incident_report',
    'create_admin_user',
    'review_failed_login',
    'revoke_session',
    'deny_request',
    'disable_user',
}
PLAYBOOK_STEP_ACTIONS = {
    'review_evidence',
    'record_note',
    'request_approval',
    'create_report',
    'close_incident',
}
PLAYBOOK_APPROVAL_ROLES = {'none', 'viewer', 'analyst', 'admin', 'local_console', 'automatic', 'required_from_action'}
PLAYBOOK_SOURCE_SEEDED = 'seeded'
PLAYBOOK_SOURCE_SYSTEM = 'system'
PLAYBOOK_SOURCE_CUSTOM = 'custom'
QUARANTINE_DIR = str(CONFIG.quarantine_dir)
TERMINAL_OUTPUT_LIMIT = CONFIG.terminal_output_limit
APPROVAL_TTL_SECONDS = CONFIG.approval_ttl_seconds
SERVICE_RESTART_TIMEOUT_SECONDS = 15
SERVICE_RESTART_TARGET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:-]{0,80}$')
APPROVED_SERVICE_RESTARTS = {
    'saaoe-dashboard': {
        'manager': 'systemctl',
        'service': 'saaoe-dashboard.service',
        'restart': ('systemctl', 'restart', 'saaoe-dashboard.service'),
        'rollback': ('systemctl', 'start', 'saaoe-dashboard.service'),
        'recovery': 'If restart fails, SAAOE will attempt systemctl start saaoe-dashboard.service.',
    },
}
VALIDATION_EVENT_CATALOG = {
    'cpu_pressure': {
        'label': 'CPU Pressure',
        'metric': 'cpu_percent',
        'value': 96.0,
        'threshold': CPU_THRESHOLD,
        'severity': 'critical',
        'category': 'system',
        'indicator': 'validation-cpu-pressure',
        'frameworks': ['NIST DE.CM-1', 'CIS 8.16'],
        'detail': 'Controlled validation input for runaway CPU detection.',
    },
    'memory_pressure': {
        'label': 'Memory Pressure',
        'metric': 'memory_percent',
        'value': 91.0,
        'threshold': MEMORY_THRESHOLD,
        'severity': 'high',
        'category': 'host',
        'indicator': 'validation-memory-pressure',
        'frameworks': ['NIST DE.CM-1', 'CIS 8.16'],
        'detail': 'Controlled validation input for memory pressure detection.',
    },
    'suspicious_network': {
        'label': 'Suspicious Network',
        'metric': 'network_public_connection',
        'value': 1.0,
        'threshold': 0.0,
        'severity': 'high',
        'category': 'network',
        'indicator': '198.51.100.10',
        'frameworks': ['NIST DE.CM-7', 'CIS 13.5'],
        'detail': 'Controlled validation input for public network connection review.',
    },
    'sensitive_file_access': {
        'label': 'Sensitive File',
        'metric': 'sensitive_file_access',
        'value': 1.0,
        'threshold': 0.0,
        'severity': 'high',
        'category': 'file',
        'indicator': 'validation/sensitive-seed.txt',
        'frameworks': ['NIST DE.CM-3', 'CIS 3.3'],
        'detail': 'Controlled validation input for sensitive file access review.',
    },
}


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
    app.logger.error('storage operation failed correlation_id=%s exception_type=%s', uuid.uuid4().hex, type(exc).__name__)
    if _is_api_request():
        return jsonify(error='storage operation failed'), 500
    return render_template('login.html', error='Storage operation failed.', username=''), 500


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
                active INTEGER NOT NULL DEFAULT 1,
                session_version INTEGER NOT NULL DEFAULT 1,
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
                target_type TEXT,
                target_id TEXT,
                result TEXT NOT NULL,
                source TEXT NOT NULL,
                detail TEXT,
                details_json TEXT
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
                linked_anomalies TEXT NOT NULL DEFAULT '[]',
                recommended_playbook_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT,
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
                requester_role TEXT,
                approved_by TEXT,
                approver_role TEXT,
                status TEXT NOT NULL,
                reason TEXT,
                decision_reason TEXT,
                dry_run INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                decided_at TEXT,
                executed_at TEXT,
                consumed_by TEXT,
                consumed_at TEXT,
                payload_digest TEXT,
                preview_digest TEXT,
                action_type TEXT,
                required_role TEXT,
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
        _ensure_column(conn, 'users', 'session_version', 'INTEGER NOT NULL DEFAULT 1')
        _ensure_column(conn, 'organizations', 'join_policy', "TEXT NOT NULL DEFAULT 'join_with_code'")
        _ensure_column(conn, 'organizations', 'join_code', "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, 'join_requests', 'detail', 'TEXT')
        _ensure_column(conn, 'audit_events', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'audit_events', 'target_type', 'TEXT')
        _ensure_column(conn, 'audit_events', 'target_id', 'TEXT')
        _ensure_column(conn, 'audit_events', 'details_json', 'TEXT')
        _ensure_column(conn, 'playbooks', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'playbooks', 'stable_key', 'TEXT')
        _ensure_column(conn, 'playbooks', 'description', 'TEXT')
        _ensure_column(conn, 'playbooks', 'kind', 'TEXT')
        _ensure_column(conn, 'playbooks', 'trigger_json', 'TEXT')
        _ensure_column(conn, 'playbooks', 'recommended_action_key', 'TEXT')
        _ensure_column(conn, 'playbooks', 'required_approval_role', 'TEXT')
        _ensure_column(conn, 'playbooks', 'steps_yaml', 'TEXT')
        _ensure_column(conn, 'playbooks', 'source', 'TEXT')
        _ensure_column(conn, 'playbooks', 'version', 'INTEGER NOT NULL DEFAULT 1')
        _ensure_column(conn, 'playbooks', 'definition_digest', 'TEXT')
        _ensure_column(conn, 'playbooks', 'created_at', 'TEXT')
        _ensure_column(conn, 'playbooks', 'created_by', 'TEXT')
        _ensure_column(conn, 'playbooks', 'updated_at', 'TEXT')
        _ensure_column(conn, 'playbooks', 'updated_by', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'playbook_runs', 'playbook_stable_key', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'playbook_name', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'playbook_kind', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'playbook_version', 'INTEGER')
        _ensure_column(conn, 'playbook_runs', 'definition_digest', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'recommended_action_key', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'required_approval_role', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'steps_yaml', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'incident_id', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'created_at', 'TEXT')
        _ensure_column(conn, 'playbook_runs', 'created_by', 'TEXT')
        _ensure_column(conn, 'incidents', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'incidents', 'linked_anomalies', "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(conn, 'incidents', 'closed_at', 'TEXT')
        _ensure_column(conn, 'incident_events', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'response_approvals', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'response_approvals', 'requester_role', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'approver_role', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'decision_reason', 'TEXT')
        _ensure_column(conn, 'validation_events', 'organization_id', 'INTEGER')
        _ensure_column(conn, 'response_approvals', 'expires_at', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'decided_at', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'consumed_by', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'consumed_at', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'payload_digest', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'preview_digest', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'action_type', 'TEXT')
        _ensure_column(conn, 'response_approvals', 'required_role', 'TEXT')
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
        conn.execute("UPDATE incidents SET linked_anomalies = '[\"' || replace(anomaly_id, '\"', '\\\"') || '\"]' WHERE (linked_anomalies IS NULL OR linked_anomalies = '[]') AND anomaly_id IS NOT NULL")
        conn.execute("UPDATE incident_events SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE response_approvals SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        for approval in conn.execute("SELECT id, action, target, incident_id, anomaly_id, dry_run, payload_digest, preview_digest FROM response_approvals").fetchall():
            action_contract = APPROVAL_ACTION_CONTRACTS.get(approval[1], {})
            approval_payload = {
                'action': approval[1],
                'target': approval[2],
                'incident_id': approval[3],
                'anomaly_id': approval[4],
                'dry_run': bool(approval[5]),
            }
            payload_digest = approval[6] or approval_payload_digest(approval_payload)
            try:
                preview = approval_preview(approval_payload)
                preview_digest = approval[7] or approval_preview_digest(approval_payload, preview)
                preview_detail = preview['detail']
            except ValueError:
                preview_digest = approval[7]
                preview_detail = None
            conn.execute(
                """
                UPDATE response_approvals
                SET payload_digest = ?, preview_digest = COALESCE(preview_digest, ?),
                    result = COALESCE(result, ?), action_type = COALESCE(action_type, ?),
                    required_role = COALESCE(required_role, ?),
                    requester_role = COALESCE(requester_role, 'analyst')
                WHERE id = ?
                """,
                (payload_digest, preview_digest, preview_detail, action_contract.get('action_type'), action_contract.get('required_role'), approval[0])
            )
        conn.execute("UPDATE validation_events SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE file_classifications SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE app_configuration SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE report_history SET organization_id = ? WHERE organization_id IS NULL", (default_org_id,))
        conn.execute("UPDATE file_classifications SET path = 'org:' || organization_id || ':' || path WHERE path NOT LIKE 'org:%'")
        conn.execute("UPDATE app_configuration SET key = 'org:' || organization_id || ':' || key WHERE key NOT LIKE 'org:%'")
        _backfill_playbook_definitions(conn)
        _backfill_playbook_runs(conn)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_playbooks_stable_key ON playbooks(stable_key)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_playbook_runs_anomaly_playbook ON playbook_runs(anomaly_id, playbook_id) WHERE anomaly_id IS NOT NULL")
        _backfill_vocabulary(conn)
        conn.commit()
    finally:
        conn.close()


def _ensure_column(conn, table, column, definition):
    columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _slug(value):
    text = re.sub(r'[^a-z0-9]+', '-', str(value or '').strip().lower())
    return text.strip('-') or 'playbook'


def _request_digest(payload):
    sanitized = {k: v for k, v in (payload or {}).items() if k not in {'yaml', 'steps_yaml'}}
    return hashlib.sha256(json.dumps(sanitized, sort_keys=True, default=str).encode('utf-8')).hexdigest()


def _parse_trigger(value, legacy=None):
    if isinstance(value, str):
        value = _json_loads(value, None)
    if not isinstance(value, dict):
        value = legacy or {}
    trigger_type = str(value.get('type') or value.get('event') or 'anomaly').strip()
    if trigger_type not in PLAYBOOK_TRIGGER_TYPES:
        raise ValueError('unsupported trigger type')
    trigger = {'type': trigger_type}
    if trigger_type == 'anomaly':
        metric = str(value.get('metric') or '').strip()
        operator = str(value.get('operator') or '').strip()
        if operator == '=':
            operator = '=='
        if not metric:
            raise ValueError('trigger metric is required')
        if operator not in PLAYBOOK_TRIGGER_OPERATORS:
            raise ValueError('unsupported trigger operator')
        try:
            threshold = float(value.get('threshold'))
        except (TypeError, ValueError) as exc:
            raise ValueError('trigger threshold must be numeric') from exc
        trigger.update({
            'metric': metric,
            'operator': operator,
            'threshold': threshold,
            'category': str(value.get('category') or '').strip() or None,
        })
    else:
        trigger['event'] = str(value.get('event') or '').strip()
        if not trigger['event']:
            raise ValueError('trigger event is required')
    return trigger


def _format_scalar(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


def _parse_scalar(value):
    text = str(value).strip()
    if text.lower() in {'true', 'false'}:
        return text.lower() == 'true'
    if text.lower() in {'none', 'null', '~'}:
        return None
    try:
        if re.fullmatch(r'-?\d+', text):
            return int(text)
        if re.fullmatch(r'-?\d+\.\d+', text):
            return float(text)
    except ValueError:
        pass
    return text.strip('"\'')


def _parse_steps_yaml(steps_yaml):
    text = str(steps_yaml or '').strip()
    if not text:
        raise ValueError('steps YAML is required')
    forbidden = re.compile(r'(^|\s)(shell|script|python|exec|subprocess|curl|wget|bash|sh)\b|[;&|<>`$]')
    if forbidden.search(text):
        raise ValueError('steps YAML contains executable or shell-like content')
    steps = []
    in_steps = False
    current = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if stripped == 'steps:':
            in_steps = True
            continue
        if not in_steps:
            key = stripped.split(':', 1)[0]
            if key in {'name', 'description', 'kind', 'category', 'approval'}:
                continue
            raise ValueError('only declarative metadata and steps are allowed')
        if stripped.startswith('- '):
            if current:
                steps.append(current)
            current = {}
            remainder = stripped[2:].strip()
            if remainder:
                if ':' not in remainder:
                    raise ValueError('step entries must use key/value pairs')
                key, value = remainder.split(':', 1)
                current[key.strip()] = _parse_scalar(value)
            continue
        if current is None or ':' not in stripped:
            raise ValueError('step fields must belong to a step')
        key, value = stripped.split(':', 1)
        current[key.strip()] = _parse_scalar(value)
    if current:
        steps.append(current)
    if not steps:
        raise ValueError('at least one declarative step is required')
    for step in steps:
        action = str(step.get('action') or '').strip()
        if action not in PLAYBOOK_STEP_ACTIONS:
            raise ValueError(f'unsupported step action: {action or "missing"}')
    return steps


def _approval_role_rank(role):
    if role in {'none', 'automatic'}:
        return 0
    if role == 'viewer':
        return 1
    if role == 'analyst':
        return 2
    if role == 'admin':
        return 3
    if role == 'local_console':
        return 4
    if role == 'required_from_action':
        return 5
    return -1


def _enforce_registry_approval_floor(recommended_action_key, required_approval_role):
    metadata = _response_action_metadata(recommended_action_key)
    if not metadata:
        return required_approval_role
    floor = metadata.required_approval_role
    if _approval_role_rank(required_approval_role) < _approval_role_rank(floor):
        return floor
    return required_approval_role


def _canonical_steps_yaml(steps):
    lines = ['steps:']
    for step in steps:
        lines.append(f"  - action: {step['action']}")
        for key in sorted(k for k in step if k != 'action'):
            lines.append(f"    {key}: {_format_scalar(step[key])}")
    return '\n'.join(lines) + '\n'


def _playbook_digest_model(definition, trigger, steps):
    return {
        'stable_key': definition['stable_key'],
        'name': definition['name'],
        'description': definition.get('description') or '',
        'kind': definition['kind'],
        'category': definition['category'],
        'trigger': trigger,
        'recommended_action_key': definition['recommended_action_key'],
        'required_approval_role': definition['required_approval_role'],
        'steps': steps,
        'enabled': bool(definition.get('enabled', True)),
        'source': definition.get('source') or PLAYBOOK_SOURCE_CUSTOM,
    }


def _playbook_definition_digest(definition, trigger=None, steps=None):
    trigger = trigger or _parse_trigger(definition.get('trigger_json'), legacy={
        'type': 'anomaly',
        'metric': definition.get('metric'),
        'operator': definition.get('operator'),
        'threshold': definition.get('threshold'),
        'category': definition.get('category'),
    })
    steps = steps or _parse_steps_yaml(definition.get('steps_yaml') or definition.get('yaml'))
    canonical = json.dumps(_playbook_digest_model(definition, trigger, steps), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _normalize_playbook_definition(payload, existing=None, actor='system', source=None):
    now = datetime.now().isoformat()
    stable_key = str(payload.get('stable_key') or (existing or {}).get('stable_key') or _slug(payload.get('name'))).strip()
    if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{2,96}', stable_key):
        raise ValueError('stable_key must be 3-97 lowercase letters, numbers, dots, underscores, or hyphens')
    name = str(payload.get('name') or (existing or {}).get('name') or stable_key).strip()
    description = str(payload.get('description', (existing or {}).get('description') or '')).strip()
    kind = str(payload.get('kind') or (existing or {}).get('kind') or 'anomaly_response').strip()
    category = str(payload.get('category') or (existing or {}).get('category') or 'custom').strip()
    command_action = payload.get('action') if payload.get('action') not in {'update', 'enable', 'disable', 'toggle', 'delete'} else None
    recommended_action_key = str(payload.get('recommended_action_key') or payload.get('action_type') or command_action or (existing or {}).get('recommended_action_key') or 'review_process_evidence').strip()
    required_approval_role = str(payload.get('required_approval_role') or (existing or {}).get('required_approval_role') or 'none').strip()
    if kind not in PLAYBOOK_KINDS:
        raise ValueError('unsupported playbook kind')
    if category not in PLAYBOOK_CATEGORIES:
        raise ValueError('unsupported playbook category')
    if recommended_action_key not in PLAYBOOK_RECOMMENDED_ACTION_KEYS:
        raise ValueError('unsupported recommended action key')
    if required_approval_role not in PLAYBOOK_APPROVAL_ROLES:
        raise ValueError('unsupported required approval role')
    required_approval_role = _enforce_registry_approval_floor(recommended_action_key, required_approval_role)
    legacy_trigger = {
        'type': 'anomaly',
        'metric': payload.get('metric', (existing or {}).get('metric') or 'cpu_percent'),
        'operator': payload.get('operator', (existing or {}).get('operator') or '>'),
        'threshold': payload.get('threshold', (existing or {}).get('threshold') or 90),
        'category': category,
    }
    trigger = _parse_trigger(payload.get('trigger_json', (existing or {}).get('trigger_json')), legacy=legacy_trigger)
    steps_yaml = payload.get('steps_yaml', payload.get('yaml', (existing or {}).get('steps_yaml') or (existing or {}).get('yaml') or 'steps:\n  - action: review_evidence\n'))
    steps = _parse_steps_yaml(steps_yaml)
    canonical_steps_yaml = _canonical_steps_yaml(steps)
    enabled = bool(payload.get('enabled', (existing or {}).get('enabled', True)))
    definition = {
        'stable_key': stable_key,
        'name': name,
        'description': description,
        'kind': kind,
        'category': category,
        'trigger_json': _json_dumps(trigger),
        'recommended_action_key': recommended_action_key,
        'required_approval_role': required_approval_role,
        'steps_yaml': canonical_steps_yaml,
        'enabled': enabled,
        'source': source or payload.get('source') or (existing or {}).get('source') or PLAYBOOK_SOURCE_CUSTOM,
        'metric': trigger.get('metric') or payload.get('metric') or (existing or {}).get('metric') or 'event',
        'operator': trigger.get('operator') or payload.get('operator') or (existing or {}).get('operator') or '==',
        'threshold': trigger.get('threshold') if trigger.get('threshold') is not None else float(payload.get('threshold', (existing or {}).get('threshold') or 1)),
        'action': recommended_action_key,
        'target': payload.get('target') or (existing or {}).get('target') or 'review',
        'auto': bool(payload.get('auto', (existing or {}).get('auto', False))),
        'yaml': canonical_steps_yaml,
        'created_at': (existing or {}).get('created_at') or now,
        'created_by': (existing or {}).get('created_by') or actor,
        'updated_at': now,
        'updated_by': actor,
    }
    digest = _playbook_definition_digest(definition, trigger=trigger, steps=steps)
    old_digest = (existing or {}).get('definition_digest')
    definition['definition_digest'] = digest
    definition['version'] = int((existing or {}).get('version') or 0) + (1 if old_digest and old_digest != digest else 0)
    if not old_digest:
        definition['version'] = int((existing or {}).get('version') or 1)
    return definition


def _legacy_playbook_definition(row):
    name = row['name'] if isinstance(row, sqlite3.Row) else row.get('name')
    category = (row['category'] if isinstance(row, sqlite3.Row) else row.get('category')) or 'custom'
    action = (row['action'] if isinstance(row, sqlite3.Row) else row.get('action')) or 'review_process_evidence'
    if action not in PLAYBOOK_RECOMMENDED_ACTION_KEYS:
        action = 'request_approval' if action in {'kill_process', 'quarantine_file', 'block_ip'} else 'review_process_evidence'
    metric = (row['metric'] if isinstance(row, sqlite3.Row) else row.get('metric')) or 'cpu_percent'
    return {
        'stable_key': _slug(name),
        'name': name,
        'description': f"Legacy playbook backfilled from {name}.",
        'kind': 'anomaly_response',
        'category': category if category in PLAYBOOK_CATEGORIES else 'custom',
        'trigger_json': {'type': 'anomaly', 'metric': metric, 'operator': (row['operator'] if isinstance(row, sqlite3.Row) else row.get('operator')) or '>', 'threshold': row['threshold'] if isinstance(row, sqlite3.Row) else row.get('threshold'), 'category': category},
        'recommended_action_key': action,
        'required_approval_role': 'none',
        'steps_yaml': (row['yaml'] if isinstance(row, sqlite3.Row) else row.get('yaml')) or 'steps:\n  - action: review_evidence\n',
        'enabled': bool(row['enabled'] if isinstance(row, sqlite3.Row) else row.get('enabled')),
        'source': PLAYBOOK_SOURCE_SYSTEM,
        'metric': metric,
        'operator': (row['operator'] if isinstance(row, sqlite3.Row) else row.get('operator')) or '>',
        'threshold': row['threshold'] if isinstance(row, sqlite3.Row) else row.get('threshold'),
        'action': action,
        'target': row['target'] if isinstance(row, sqlite3.Row) else row.get('target'),
        'auto': bool(row['auto'] if isinstance(row, sqlite3.Row) else row.get('auto')),
    }


def _backfill_playbook_definitions(conn):
    for row in conn.execute("SELECT * FROM playbooks").fetchall():
        if row['stable_key'] and row['definition_digest']:
            continue
        raw = _legacy_playbook_definition(row)
        try:
            definition = _normalize_playbook_definition(raw, actor='system', source=raw['source'])
        except ValueError:
            raw['steps_yaml'] = 'steps:\n  - action: review_evidence\n'
            definition = _normalize_playbook_definition(raw, actor='system', source=raw['source'])
        conn.execute(
            """
            UPDATE playbooks
            SET stable_key = ?, description = ?, kind = ?, trigger_json = ?,
                recommended_action_key = ?, required_approval_role = ?, steps_yaml = ?,
                source = ?, version = ?, definition_digest = ?, created_at = COALESCE(created_at, ?),
                created_by = COALESCE(created_by, ?), updated_at = COALESCE(updated_at, ?),
                updated_by = COALESCE(updated_by, ?), action = ?, yaml = ?
            WHERE id = ?
            """,
            (
                definition['stable_key'], definition['description'], definition['kind'], definition['trigger_json'],
                definition['recommended_action_key'], definition['required_approval_role'], definition['steps_yaml'],
                definition['source'], definition['version'], definition['definition_digest'], definition['created_at'],
                definition['created_by'], definition['updated_at'], definition['updated_by'], definition['action'],
                definition['yaml'], row['id'],
            )
        )


def _backfill_playbook_runs(conn):
    for row in conn.execute("SELECT * FROM playbook_runs").fetchall():
        if row['playbook_stable_key'] and row['definition_digest']:
            continue
        pb = conn.execute("SELECT * FROM playbooks WHERE id = ?", (row['playbook_id'],)).fetchone()
        if not pb:
            continue
        conn.execute(
            """
            UPDATE playbook_runs
            SET playbook_stable_key = COALESCE(playbook_stable_key, ?),
                playbook_name = COALESCE(playbook_name, ?),
                playbook_kind = COALESCE(playbook_kind, ?),
                playbook_version = COALESCE(playbook_version, ?),
                definition_digest = COALESCE(definition_digest, ?),
                recommended_action_key = COALESCE(recommended_action_key, ?),
                required_approval_role = COALESCE(required_approval_role, ?),
                steps_yaml = COALESCE(steps_yaml, ?),
                created_at = COALESCE(created_at, timestamp),
                created_by = COALESCE(created_by, 'system')
            WHERE id = ?
            """,
            (
                pb['stable_key'], pb['name'], pb['kind'], pb['version'], pb['definition_digest'],
                pb['recommended_action_key'], pb['required_approval_role'], pb['steps_yaml'], row['id'],
            )
        )


def _backfill_vocabulary(conn):
    for row in conn.execute("SELECT id, severity FROM anomalies").fetchall():
        normalized = normalize_severity(row[1], default='info')
        if row[1] != normalized:
            conn.execute("UPDATE anomalies SET severity = ? WHERE id = ?", (normalized, row[0]))
    for row in conn.execute("SELECT id, severity FROM anomaly_rules").fetchall():
        normalized = normalize_severity(row[1], default='info')
        if row[1] != normalized:
            conn.execute("UPDATE anomaly_rules SET severity = ? WHERE id = ?", (normalized, row[0]))
    for row in conn.execute("SELECT id, severity, status FROM incidents").fetchall():
        normalized_severity = normalize_severity(row[1], default='info')
        normalized_status = normalize_status(row[2], default='open')
        if row[1] != normalized_severity or row[2] != normalized_status:
            conn.execute(
                "UPDATE incidents SET severity = ?, status = ? WHERE id = ?",
                (normalized_severity, normalized_status, row[0])
            )
    for table in ('playbook_runs', 'automation_history', 'validation_events'):
        for row in conn.execute(f"SELECT id, status FROM {table}").fetchall():
            normalized = normalize_status(row[1], default='open')
            if row[1] != normalized:
                conn.execute(f"UPDATE {table} SET status = ? WHERE id = ?", (normalized, row[0]))


def _table_count(name):
    rows = _db_query(f"SELECT COUNT(*) AS count FROM {name}")
    return int(rows[0]['count']) if rows else 0


def _seed_audit_event(event_type, target, detail, details=None):
    target_text = str(target or '')
    target_type = target_id = None
    if ':' in target_text:
        target_type, target_id = target_text.split(':', 1)
    _db_exec(
        """
        INSERT INTO audit_events (
            organization_id, timestamp, actor, role, event_type, target,
            target_type, target_id, result, source, detail, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            None, datetime.now().isoformat(), 'system', 'system', event_type, target_text,
            target_type, target_id, 'success', 'local', detail,
            _json_dumps(details) if details is not None else None,
        )
    )


def _seed_db():
    seeded_playbooks = [
        {'id': 101, 'stable_key': 'runaway-cpu-process-review', 'name': 'Runaway CPU Process Review', 'description': 'Review process evidence for controlled or live CPU pressure anomalies.', 'kind': 'anomaly_response', 'category': 'system', 'trigger_json': {'type': 'anomaly', 'metric': 'cpu_percent', 'operator': '>', 'threshold': CPU_THRESHOLD, 'category': 'system'}, 'recommended_action_key': 'review_process_evidence', 'required_approval_role': 'none', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: process_snapshot\n  - action: record_note\n    note_type: cpu_review\n'},
        {'id': 102, 'stable_key': 'memory-pressure-response', 'name': 'Memory Pressure Response', 'description': 'Review memory pressure evidence and document immediate operator findings.', 'kind': 'anomaly_response', 'category': 'host', 'trigger_json': {'type': 'anomaly', 'metric': 'memory_percent', 'operator': '>', 'threshold': MEMORY_THRESHOLD, 'category': 'host'}, 'recommended_action_key': 'review_memory_evidence', 'required_approval_role': 'none', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: memory_snapshot\n  - action: record_note\n    note_type: memory_review\n'},
        {'id': 103, 'stable_key': 'suspicious-network-connection-review', 'name': 'Suspicious Network Connection Review', 'description': 'Review external connection evidence without changing firewall state.', 'kind': 'anomaly_response', 'category': 'network', 'trigger_json': {'type': 'anomaly', 'metric': 'network_public_connection', 'operator': '>', 'threshold': 0, 'category': 'network'}, 'recommended_action_key': 'review_connection', 'required_approval_role': 'none', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: network_connections\n  - action: record_note\n    note_type: network_review\n'},
        {'id': 104, 'stable_key': 'sensitive-file-access-review', 'name': 'Sensitive File Access Review', 'description': 'Review sensitive file access evidence without quarantining files.', 'kind': 'anomaly_response', 'category': 'file', 'trigger_json': {'type': 'anomaly', 'metric': 'sensitive_file_access', 'operator': '>', 'threshold': 0, 'category': 'file'}, 'recommended_action_key': 'review_file_access', 'required_approval_role': 'none', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: file_access\n  - action: record_note\n    note_type: file_review\n'},
        {'id': 105, 'stable_key': 'human-approval-required', 'name': 'Human Approval Required', 'description': 'Gate approval-required response actions through the response approval contract.', 'kind': 'workflow_gate', 'category': 'workflow', 'trigger_json': {'type': 'workflow', 'event': 'approval_required'}, 'recommended_action_key': 'request_approval', 'required_approval_role': 'required_from_action', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: request_approval\n    approval: required_from_action\n'},
        {'id': 106, 'stable_key': 'create-incident-report', 'name': 'Create Incident Report', 'description': 'Create a stored incident report during investigation or closure.', 'kind': 'incident_utility', 'category': 'incident', 'trigger_json': {'type': 'incident', 'event': 'report_requested'}, 'recommended_action_key': 'create_incident_report', 'required_approval_role': 'none', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: create_report\n    report_type: incident\n'},
        {'id': 107, 'stable_key': 'quarantine-file-with-approval', 'name': 'Quarantine File with Approval', 'description': 'Escalate a file event into an explicit admin approval request. No adapter is introduced here.', 'kind': 'approval_action', 'category': 'file', 'trigger_json': {'type': 'workflow', 'event': 'file_quarantine_requested'}, 'recommended_action_key': 'request_approval', 'required_approval_role': 'admin', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: file_access\n  - action: request_approval\n    approval: admin\n'},
        {'id': 108, 'stable_key': 'block-ip-with-approval', 'name': 'Block IP with Approval', 'description': 'Escalate a network event into an explicit admin approval request. No firewall adapter is introduced here.', 'kind': 'approval_action', 'category': 'network', 'trigger_json': {'type': 'workflow', 'event': 'block_ip_requested'}, 'recommended_action_key': 'request_approval', 'required_approval_role': 'admin', 'enabled': True, 'source': PLAYBOOK_SOURCE_SEEDED, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: network_connections\n  - action: request_approval\n    approval: admin\n'},
    ]
    system_playbooks = [
        {'id': 201, 'stable_key': 'first-run-admin-setup', 'name': 'First-Run Admin Setup', 'description': 'Document first-run local setup controls.', 'kind': 'access_control', 'category': 'authentication', 'trigger_json': {'type': 'workflow', 'event': 'application_start'}, 'recommended_action_key': 'create_admin_user', 'required_approval_role': 'local_console', 'enabled': True, 'source': PLAYBOOK_SOURCE_SYSTEM, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: setup_mode\n  - action: record_note\n    note_type: first_run_admin_setup\n'},
        {'id': 202, 'stable_key': 'failed-login-review', 'name': 'Failed Login Review', 'description': 'Review repeated failed login evidence.', 'kind': 'access_control', 'category': 'authentication', 'trigger_json': {'type': 'workflow', 'event': 'login_failed'}, 'recommended_action_key': 'review_failed_login', 'required_approval_role': 'admin', 'enabled': True, 'source': PLAYBOOK_SOURCE_SYSTEM, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: failed_login_events\n  - action: record_note\n    note_type: failed_login_review\n'},
        {'id': 203, 'stable_key': 'session-timeout-enforcement', 'name': 'Session Timeout Enforcement', 'description': 'Review session timeout enforcement.', 'kind': 'access_control', 'category': 'authentication', 'trigger_json': {'type': 'workflow', 'event': 'session_expired'}, 'recommended_action_key': 'revoke_session', 'required_approval_role': 'automatic', 'enabled': True, 'source': PLAYBOOK_SOURCE_SYSTEM, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: session_timeout\n  - action: record_note\n    note_type: session_timeout\n'},
        {'id': 204, 'stable_key': 'unauthorized-route-access-review', 'name': 'Unauthorized Route Access Review', 'description': 'Review unauthorized access attempts.', 'kind': 'access_control', 'category': 'access_control', 'trigger_json': {'type': 'workflow', 'event': 'access_denied'}, 'recommended_action_key': 'deny_request', 'required_approval_role': 'automatic', 'enabled': True, 'source': PLAYBOOK_SOURCE_SYSTEM, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: access_denied\n  - action: record_note\n    note_type: access_denied_review\n'},
        {'id': 205, 'stable_key': 'user-disablement', 'name': 'User Disablement', 'description': 'Review user disablement requests.', 'kind': 'access_control', 'category': 'access_control', 'trigger_json': {'type': 'workflow', 'event': 'user_disable_requested'}, 'recommended_action_key': 'disable_user', 'required_approval_role': 'admin', 'enabled': True, 'source': PLAYBOOK_SOURCE_SYSTEM, 'steps_yaml': 'steps:\n  - action: review_evidence\n    evidence: user_status\n  - action: record_note\n    note_type: user_disablement\n'},
    ]
    if _table_count('anomaly_rules') == 0:
        for rule in anomaly_rules:
            _db_exec(
                "INSERT INTO anomaly_rules (id, metric, operator, threshold, severity, enabled, alert_in_app, alert_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rule['id'], rule['metric'], rule['operator'], rule['threshold'], rule['severity'], int(rule['enabled']), int(rule['alert_in_app']), int(rule['alert_email']))
            )
    for pb in seeded_playbooks + system_playbooks:
        if not _db_query("SELECT id FROM playbooks WHERE stable_key = ?", (pb['stable_key'],)):
            definition = _normalize_playbook_definition(pb, actor='system', source=pb['source'])
            _db_exec(
                """
                INSERT INTO playbooks (
                    id, organization_id, stable_key, name, description, kind, category,
                    metric, operator, threshold, action, target, enabled, auto, yaml,
                    trigger_json, recommended_action_key, required_approval_role,
                    steps_yaml, source, version, definition_digest, created_at,
                    created_by, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pb['id'], None, definition['stable_key'], definition['name'], definition['description'],
                    definition['kind'], definition['category'], definition['metric'], definition['operator'],
                    definition['threshold'], definition['action'], definition['target'], int(definition['enabled']),
                    int(definition['auto']), definition['yaml'], definition['trigger_json'],
                    definition['recommended_action_key'], definition['required_approval_role'],
                    definition['steps_yaml'], definition['source'], definition['version'],
                    definition['definition_digest'], definition['created_at'], definition['created_by'],
                    definition['updated_at'], definition['updated_by'],
                )
            )
            _seed_audit_event('playbook_seeded', f"playbook:{definition['stable_key']}", definition['name'], details={'stable_key': definition['stable_key'], 'source': definition['source'], 'definition_digest': definition['definition_digest']})
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


def _clean_optional_text(value):
    if value is None:
        return None
    text = str(value).strip()
    return text or None


PUBLIC_VALIDATION_ERRORS = {
    'unsupported response action',
    'target is required',
    'kill process target must be a PID',
    'kill process target must be a positive PID',
    'quarantine target must be inside the SAAOE project directory',
    'restart service target is not a valid service allowlist key',
    'incident report target is required',
    'unsupported playbook kind',
    'unsupported playbook category',
    'unsupported recommended action key',
    'unsupported required approval role',
    'unsupported trigger type',
    'trigger metric is required',
    'unsupported trigger operator',
    'trigger threshold must be numeric',
    'trigger event is required',
    'steps YAML is required',
    'steps YAML contains executable or shell-like content',
    'only declarative metadata and steps are allowed',
    'step entries must use key/value pairs',
    'step fields must belong to a step',
    'at least one declarative step is required',
    'stable_key must be 3-97 lowercase letters, numbers, dots, underscores, or hyphens',
}


def _public_error_detail(exc, fallback):
    message = str(exc)
    if message in PUBLIC_VALIDATION_ERRORS or message.startswith('unsupported step action: ') or message.startswith('restart service target is not approved.'):
        return message
    app.logger.error('%s correlation_id=%s exception_type=%s', fallback, uuid.uuid4().hex, type(exc).__name__)
    return fallback


def _safe_local_redirect_target(value, fallback=None):
    fallback = fallback or url_for('dashboard')
    target = str(value or '').strip()
    if not target:
        return fallback
    if any(ord(ch) < 32 for ch in target):
        return fallback
    if '\\' in target or not target.startswith('/') or target.startswith('//'):
        return fallback
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return fallback
    return target


def _approval_payload(action, target, incident_id=None, anomaly_id=None, dry_run=True):
    return {
        'action': str(action or '').strip(),
        'target': str(target or '').strip(),
        'incident_id': _clean_optional_text(incident_id),
        'anomaly_id': _clean_optional_text(anomaly_id),
        'dry_run': bool(dry_run),
    }


def approval_payload_digest(payload):
    canonical = json.dumps(_approval_payload(
        payload.get('action'),
        payload.get('target'),
        payload.get('incident_id'),
        payload.get('anomaly_id'),
        payload.get('dry_run', True),
    ), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _validate_kill_process_target(target):
    target = str(target or '').strip()
    try:
        pid = int(target)
    except (TypeError, ValueError) as exc:
        raise ValueError('kill process target must be a PID') from exc
    if pid <= 0:
        raise ValueError('kill process target must be a positive PID')
    return str(pid)


def _validate_quarantine_file_target(target):
    target = str(target or '').strip()
    path = os.path.abspath(os.path.join(BASE_DIR, target)) if not os.path.isabs(target) else os.path.abspath(target)
    if not path.startswith(BASE_DIR + os.sep):
        raise ValueError('quarantine target must be inside the SAAOE project directory')
    return os.path.relpath(path, BASE_DIR)


def _validate_block_ip_target(target):
    return str(ipaddress.ip_address(str(target or '').strip()))


def _validate_restart_service_target(target):
    target = str(target or '').strip()
    if not SERVICE_RESTART_TARGET_RE.fullmatch(target):
        raise ValueError('restart service target is not a valid service allowlist key')
    if target not in APPROVED_SERVICE_RESTARTS:
        allowed = ', '.join(sorted(APPROVED_SERVICE_RESTARTS))
        raise ValueError(f"restart service target is not approved. Allowed: {allowed}")
    return target


def _validate_incident_report_target(target):
    target = str(target or '').strip()
    if not target:
        raise ValueError('incident report target is required')
    return target


def _approval_canonical_target(action, target):
    metadata = _response_action_metadata(action)
    validator, _executor = _validate_response_action_metadata(metadata)
    return validator(target)


def approval_preview(payload):
    normalized = _approval_payload(
        payload.get('action'),
        payload.get('target'),
        payload.get('incident_id'),
        payload.get('anomaly_id'),
        payload.get('dry_run', True),
    )
    contract = _approval_contract(normalized['action'])
    if not contract:
        raise ValueError('unsupported response action')
    canonical_target = _approval_canonical_target(normalized['action'], normalized['target'])
    disabled_host_action = bool(contract.get('host_impacting') and not normalized['dry_run'] and not contract.get('enabled'))
    if normalized['action'] == 'kill_process':
        effect = f"Would validate termination of PID {canonical_target}."
    elif normalized['action'] == 'quarantine_file':
        effect = f"Would validate quarantine of {canonical_target}."
    elif normalized['action'] == 'block_ip':
        effect = f"Would validate firewall block for {canonical_target}."
    elif normalized['action'] == 'restart_service':
        effect = f"Would restart approved service target {canonical_target} with timeout {SERVICE_RESTART_TIMEOUT_SECONDS}s."
    else:
        effect = f"Would create incident report for {canonical_target}."
    if disabled_host_action:
        effect = f"Host-impacting action {normalized['action']} is disabled; authorization will be recorded as a no-op."
    return {
        **normalized,
        'canonical_target': canonical_target,
        'action_type': contract['action_type'],
        'required_role': contract['required_role'],
        'host_impacting': bool(contract.get('host_impacting')),
        'disabled_host_action': disabled_host_action,
        'detail': effect,
    }


def approval_preview_digest(payload, preview=None):
    preview = preview or approval_preview(payload)
    canonical = json.dumps({
        'payload_digest': approval_payload_digest(payload),
        'preview': preview,
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def _approval_error(message, status_code=409, approval=None):
    return {'ok': False, 'error': message, 'status_code': status_code, 'approval': approval}


def _response_action_metadata(action):
    return RESPONSE_ACTION_REGISTRY.get(action)


def _current_platform_key():
    system = platform.system().lower()
    if system.startswith('linux'):
        return 'linux'
    if system == 'darwin':
        return 'darwin'
    if system.startswith('windows'):
        return 'windows'
    return system or 'unknown'


def _role_allowed_by_registry(actor, roles):
    return bool(actor and any(_role_allows(actor, role) for role in roles))


def response_action_registry_manifest():
    return {
        key: {
            'stable_key': metadata.stable_key,
            'safety_class': metadata.safety_class,
            'input_validator': metadata.input_validator if isinstance(metadata.input_validator, str) else metadata.input_validator.__name__,
            'request_roles': list(metadata.request_roles),
            'required_approval_role': metadata.required_approval_role,
            'execution_roles': list(metadata.execution_roles),
            'supported_platforms': list(metadata.supported_platforms),
            'enabled': metadata.enabled,
            'executor': metadata.executor if isinstance(metadata.executor, str) else metadata.executor.__name__,
            'action_type': metadata.action_type,
            'host_impacting': metadata.host_impacting,
        }
        for key, metadata in RESPONSE_ACTION_REGISTRY.items()
    }


def _response_action_executor(metadata):
    return globals().get(metadata.executor) if isinstance(metadata.executor, str) else metadata.executor


def _response_action_validator(metadata):
    return globals().get(metadata.input_validator) if isinstance(metadata.input_validator, str) else metadata.input_validator


def _validate_response_action_metadata(metadata):
    if not metadata or metadata.stable_key not in RESPONSE_ACTION_REGISTRY:
        raise ValueError('unsupported response action')
    validator = _response_action_validator(metadata)
    if not callable(validator):
        raise ValueError(f'{metadata.stable_key} input validator is not configured')
    executor = _response_action_executor(metadata)
    if not callable(executor):
        raise ValueError(f'{metadata.stable_key} executor is not configured')
    return validator, executor


def _approval_contract(action):
    metadata = _response_action_metadata(action)
    return metadata.approval_contract() if metadata else None


def _mark_approval_expired(conn, approval, now):
    if approval.get('status') == 'pending':
        conn.execute(
            "UPDATE response_approvals SET status = ?, decided_at = ?, updated_at = ?, result = ? WHERE id = ? AND status = ?",
            ('expired', now, now, 'approval expired', approval['id'], 'pending')
        )
    elif approval.get('status') == 'approved':
        conn.execute(
            "UPDATE response_approvals SET status = ?, updated_at = ?, result = ? WHERE id = ? AND status = ?",
            ('expired', now, 'approval expired', approval['id'], 'approved')
        )


def _approval_target_matches(approval, expected):
    return (
        approval.get('action') == expected.get('action')
        and str(approval.get('target')) == str(expected.get('target'))
        and _clean_optional_text(approval.get('incident_id')) == _clean_optional_text(expected.get('incident_id'))
        and _clean_optional_text(approval.get('anomaly_id')) == _clean_optional_text(expected.get('anomaly_id'))
        and bool(approval.get('dry_run')) == bool(expected.get('dry_run', True))
    )


def _approval_correlation_id(approval_id):
    return f"approval:{approval_id}"


def _approval_structured_details(approval, **extra):
    details = {
        'approval_id': approval.get('id'),
        'correlation_id': _approval_correlation_id(approval.get('id')),
        'incident_id': approval.get('incident_id'),
        'anomaly_id': approval.get('anomaly_id'),
        'action': approval.get('action'),
        'action_type': approval.get('action_type'),
        'target': approval.get('target'),
        'requested_by': approval.get('requested_by'),
        'requester_role': approval.get('requester_role'),
        'approved_by': approval.get('approved_by'),
        'approver_role': approval.get('approver_role'),
        'status': approval.get('status'),
        'payload_digest': approval.get('payload_digest'),
        'preview_digest': approval.get('preview_digest'),
        'dry_run': bool(approval.get('dry_run')),
    }
    details.update({key: value for key, value in extra.items() if value is not None})
    return details


def _approval_incident_event(approval, event_type, detail, actor=None, **extra):
    if not approval.get('incident_id'):
        return
    structured = _approval_structured_details(approval, event_type=event_type, detail=detail, **extra)
    _incident_event(
        approval['incident_id'],
        event_type,
        _json_dumps(structured),
        actor=actor,
        organization_id=approval.get('organization_id'),
    )


def _anomaly_from_row(row):
    severity = normalize_severity(row.get('severity'), default='info')
    risk_level = risk_severity(row.get('risk_score') or 0)
    return {
        'id': row['id'],
        'organization_id': row.get('organization_id'),
        'timestamp': row['timestamp'],
        'metric': row['metric'],
        'value': row['value'],
        'threshold': row['threshold'],
        'severity': severity,
        'severity_label': severity_label(severity),
        'severity_class': severity_class(severity),
        'category': row['category'],
        'confidence': row.get('confidence') or 0,
        'rule_name': row.get('rule_name'),
        'indicator_type': row.get('indicator_type'),
        'indicator': row.get('indicator'),
        'threat_intel': _json_loads(row.get('threat_intel'), {}),
        'risk_score': row.get('risk_score') or 0,
        'risk_level': risk_level,
        'risk_label': severity_label(risk_level),
        'risk_class': severity_class(risk_level),
        'frameworks': _json_loads(row.get('frameworks'), []),
        'validation': bool(row.get('validation')),
    }


def _persist_anomaly(anomaly, organization_id=None):
    now = datetime.now().isoformat()
    organization_id = organization_id if organization_id is not None else anomaly.get('organization_id')
    anomaly['organization_id'] = organization_id
    anomaly['severity'] = normalize_severity(anomaly.get('severity'), default='info')
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
            anomaly['severity'], anomaly.get('category') or 'system',
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
        params.append(normalize_severity(severity, default='info'))
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
    records = []
    for row in rows:
        trigger = _json_loads(row.get('trigger_json'), {})
        display_yaml = row['yaml']
        if row.get('stable_key') == 'first-run-admin-setup' and 'approval: local_console' not in display_yaml:
            display_yaml = 'approval: local_console\n' + display_yaml
        if row.get('stable_key') == 'unauthorized-route-access-review' and 'event_type: access_denied' not in display_yaml:
            display_yaml = 'event_type: access_denied\n' + display_yaml
        record = {
        'id': row['id'],
        'organization_id': row.get('organization_id'),
        'stable_key': row.get('stable_key'),
        'name': row['name'],
        'description': row.get('description') or '',
        'kind': row.get('kind') or 'anomaly_response',
        'category': row['category'],
        'metric': row['metric'],
        'operator': row['operator'],
        'threshold': row['threshold'],
        'action': row['action'],
        'recommended_action_key': row.get('recommended_action_key') or row['action'],
        'target': row['target'],
        'required_approval_role': row.get('required_approval_role') or 'none',
        'enabled': _bool_row(row, 'enabled'),
        'auto': _bool_row(row, 'auto'),
        'yaml': display_yaml,
        'steps_yaml': row.get('steps_yaml') or row['yaml'],
        'trigger': trigger,
        'trigger_json': row.get('trigger_json'),
        'source': row.get('source') or PLAYBOOK_SOURCE_CUSTOM,
        'version': row.get('version') or 1,
        'definition_digest': row.get('definition_digest'),
        'created_at': row.get('created_at'),
        'created_by': row.get('created_by'),
        'updated_at': row.get('updated_at'),
        'updated_by': row.get('updated_by'),
        }
        records.append(record)
    return records


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
    normalized = []
    for row in rows:
        row['status'] = normalize_status(row.get('status'), default='open')
        row['status_label'] = status_label(row['status'])
        row['status_class'] = status_class(row['status'])
        record = dict(row)
        record['playbook_name'] = record.get('playbook_name') or record.get('name')
        record['playbook_stable_key'] = record.get('playbook_stable_key')
        record['playbook_kind'] = record.get('playbook_kind')
        record['playbook_version'] = record.get('playbook_version')
        record['recommended_action_key'] = record.get('recommended_action_key') or record.get('action')
        record['required_approval_role'] = record.get('required_approval_role') or 'none'
        record['steps_yaml'] = record.get('steps_yaml') or record.get('yaml')
        normalized.append(record)
    return list(reversed(normalized))


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


def _status_record(row, field='status', default='open'):
    record = dict(row)
    record[field] = normalize_status(row.get(field), default=default)
    record[f'{field}_label'] = status_label(record[field], default=default)
    record[f'{field}_class'] = status_class(record[field], default=default)
    return record


def _automation_history_from_db(limit=100):
    return [
        _status_record(row)
        for row in _db_query("SELECT * FROM automation_history ORDER BY id DESC LIMIT ?", (limit,))
    ]


def _anomaly_rules_from_db():
    return [{
        'id': row['id'],
        'metric': row['metric'],
        'operator': row['operator'],
        'threshold': row['threshold'],
        'severity': normalize_severity(row['severity'], default='info'),
        'severity_label': severity_label(row['severity']),
        'severity_class': severity_class(row['severity']),
        'enabled': _bool_row(row, 'enabled'),
        'alert_in_app': _bool_row(row, 'alert_in_app'),
        'alert_email': _bool_row(row, 'alert_email'),
    } for row in _db_query("SELECT * FROM anomaly_rules ORDER BY id")]


def load_persistent_state():
    global anomaly_rules, next_rule_id, playbooks, next_playbook_id, playbook_runs
    global automation_rules, next_automation_rule_id, automation_history

    anomaly_rules = []
    for row in _db_query("SELECT * FROM anomaly_rules ORDER BY id"):
        severity = normalize_severity(row['severity'], default='info')
        anomaly_rules.append({
            'id': row['id'],
            'metric': row['metric'],
            'operator': row['operator'],
            'threshold': row['threshold'],
            'severity': severity,
            'enabled': _bool_row(row, 'enabled'),
            'alert_in_app': _bool_row(row, 'alert_in_app'),
            'alert_email': _bool_row(row, 'alert_email'),
        })
    next_rule_id = (max([r['id'] for r in anomaly_rules]) + 1) if anomaly_rules else 1

    playbooks = []
    playbooks = _playbooks_from_db()
    next_playbook_id = (max([p['id'] for p in playbooks]) + 1) if playbooks else 1

    playbook_runs = []
    playbook_runs = _playbook_runs_from_db(limit=100)

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

    automation_history = _automation_history_from_db()
    automation_history = list(reversed(automation_history))


def users_exist():
    return _table_count('users') > 0


def active_admin_exists():
    rows = _db_query("SELECT COUNT(*) AS count FROM users WHERE role = ? AND active = 1", ('admin',))
    return int(rows[0]['count']) > 0 if rows else False


USERNAME_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{3,64}$')
WORKSPACE_NAME_MAX_LENGTH = 120


def validate_username(username):
    username = str(username or '').strip()
    if not username:
        return 'Username is required.'
    if not USERNAME_PATTERN.fullmatch(username):
        return 'Username must be 3-64 characters using letters, numbers, dots, underscores, or hyphens.'
    return None


def validate_workspace_name(name):
    name = str(name or '').strip()
    if not name:
        return 'Workspace name is required.'
    if len(name) > WORKSPACE_NAME_MAX_LENGTH:
        return f'Workspace name must be {WORKSPACE_NAME_MAX_LENGTH} characters or fewer.'
    return None


def start_user_session(user):
    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['session_version'] = int(user.get('session_version') or 1)
    session['last_seen_at'] = time.time()


def revoke_user_sessions(user_id):
    _db_exec("UPDATE users SET session_version = COALESCE(session_version, 1) + 1 WHERE id = ?", (user_id,))


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


def _audit_target_parts(target, target_type=None, target_id=None):
    text = str(target or '')
    if (target_type is None or target_id is None) and ':' in text:
        prefix, suffix = text.split(':', 1)
        if target_type is None:
            target_type = prefix or None
        if target_id is None:
            target_id = suffix or None
    return text, target_type, target_id


def _audit_source():
    if not has_request_context():
        return 'local'
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'local').split(',')[0].strip() or 'local'


def audit_event(
    event_type,
    target,
    result='success',
    detail='',
    actor=None,
    role=None,
    organization_id=None,
    target_type=None,
    target_id=None,
    details=None,
):
    user = current_user()
    actor = actor or (user['username'] if user else 'anonymous')
    role = role or (user['role'] if user else 'anonymous')
    organization_id = organization_id if organization_id is not None else (user.get('organization_id') if user else None)
    target, target_type, target_id = _audit_target_parts(target, target_type=target_type, target_id=target_id)
    source = _audit_source()
    details_json = _json_dumps(details) if details is not None else None
    if has_request_context():
        g.audit_event_written = True
    _db_exec(
        """
        INSERT INTO audit_events (
            organization_id, timestamp, actor, role, event_type, target,
            target_type, target_id, result, source, detail, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            organization_id, datetime.now().isoformat(), actor, role, event_type, target,
            target_type, target_id, result, source, detail, details_json
        )
    )


def normalize_severity(value, default='info'):
    key = str(value or '').strip().lower().replace('-', '_').replace(' ', '_')
    for canonical, config in SEVERITY_VOCABULARY.items():
        if key in config['aliases']:
            return canonical
    return default if default in SEVERITIES else 'info'


def normalize_status(value, default='open'):
    key = str(value or '').strip().lower().replace('-', '_').replace(' ', '_')
    for canonical, config in STATUS_VOCABULARY.items():
        if key in config['aliases']:
            return canonical
    return default if default in STATUSES else 'open'


def severity_label(value):
    return SEVERITY_VOCABULARY[normalize_severity(value, default='info')]['label']


def severity_class(value):
    return SEVERITY_VOCABULARY[normalize_severity(value, default='info')]['css_class']


def risk_severity(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return 'info'
    if score >= 80:
        return 'critical'
    if score >= 55:
        return 'high'
    if score >= 30:
        return 'medium'
    if score > 0:
        return 'low'
    return 'info'


def status_label(value, default='open'):
    return STATUS_VOCABULARY[normalize_status(value, default=default)]['label']


def status_class(value, default='open'):
    return STATUS_VOCABULARY[normalize_status(value, default=default)]['css_class']


def vocabulary_payload():
    def serialize(vocabulary):
        return {
            key: {
                'label': config['label'],
                'css_class': config['css_class'],
                'aliases': sorted(config['aliases']),
            }
            for key, config in vocabulary.items()
        }
    return {'severities': serialize(SEVERITY_VOCABULARY), 'statuses': serialize(STATUS_VOCABULARY)}


def _incident_status_label(status):
    return status_label(status)


def _incident_linked_anomalies(row):
    linked = _json_loads(row.get('linked_anomalies'), [])
    if row.get('anomaly_id') and row.get('anomaly_id') not in linked:
        linked.insert(0, row['anomaly_id'])
    return linked


def _incident_from_row(row):
    linked = _incident_linked_anomalies(row)
    incident = dict(row)
    incident['severity'] = normalize_severity(row.get('severity'), default='info')
    incident['status'] = normalize_status(row.get('status'), default='open')
    incident['incident_id'] = row['id']
    incident['assignee'] = row.get('owner')
    incident['linked_anomalies'] = linked
    incident['severity_label'] = severity_label(incident['severity'])
    incident['severity_class'] = severity_class(incident['severity'])
    incident['status_label'] = _incident_status_label(incident['status'])
    incident['status_class'] = status_class(incident['status'])
    return incident


def _incident_row(incident_id, organization_id):
    rows = _db_query("SELECT * FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, organization_id))
    return rows[0] if rows else None


def _incident_anomalies(incident):
    linked_ids = _incident_linked_anomalies(incident)
    if not linked_ids:
        return []
    placeholders = ','.join(['?'] * len(linked_ids))
    rows = _db_query(
        f"SELECT * FROM anomalies WHERE id IN ({placeholders}) AND organization_id = ? ORDER BY timestamp DESC",
        tuple(linked_ids + [incident.get('organization_id')])
    )
    by_id = {row['id']: _anomaly_from_row(row) for row in rows}
    return [by_id[anomaly_id] for anomaly_id in linked_ids if anomaly_id in by_id]


def _incident_recommended_playbook(incident):
    playbook_id = incident.get('recommended_playbook_id')
    if not playbook_id:
        return None
    return next((pb for pb in _playbooks_from_db(incident.get('organization_id')) if pb['id'] == playbook_id), None)


def _timeline_entry(timestamp, actor, event_type, detail, source, **extra):
    entry = {
        'timestamp': timestamp,
        'actor': actor,
        'event_type': event_type,
        'detail': detail,
        'source': source,
    }
    structured_detail = _json_loads(detail, None)
    if isinstance(structured_detail, dict):
        entry['structured_details'] = structured_detail
        for key in ('approval_id', 'correlation_id', 'incident_id', 'anomaly_id', 'action', 'target', 'result'):
            if key in structured_detail and key not in extra:
                extra[key] = structured_detail[key]
    entry.update(extra)
    return entry


def _incident_timeline(incident):
    incident_id = incident['id']
    org_id = incident.get('organization_id')
    linked_ids = _incident_linked_anomalies(incident)
    entries = []

    for event in _db_query(
        "SELECT * FROM incident_events WHERE incident_id = ? AND organization_id = ? ORDER BY timestamp",
        (incident_id, org_id)
    ):
        entries.append(_timeline_entry(
            event['timestamp'], event['actor'], event['event_type'], event['detail'], 'incident_events',
            incident_event_id=event['id']
        ))

    for anomaly in _incident_anomalies(incident):
        entries.append(_timeline_entry(
            anomaly['timestamp'], 'system', 'linked_anomaly',
            f"{severity_label(anomaly['severity'])} {anomaly['metric']} anomaly", 'anomalies',
            anomaly_id=anomaly['id']
        ))

    if linked_ids:
        placeholders = ','.join(['?'] * len(linked_ids))
        for run in _db_query(
            f"SELECT * FROM playbook_runs WHERE anomaly_id IN ({placeholders}) AND (organization_id IS NULL OR organization_id = ?) ORDER BY timestamp",
            tuple(linked_ids + [org_id])
        ):
            entries.append(_timeline_entry(
                run['timestamp'], 'system', 'playbook_run',
                f"{run['name']} {status_label(run['status'])}", 'playbook_runs',
                playbook_id=run['playbook_id'], run_id=run['id'], anomaly_id=run['anomaly_id']
            ))

    approvals = _db_query(
        "SELECT * FROM response_approvals WHERE incident_id = ? AND organization_id = ? ORDER BY created_at",
        (incident_id, org_id)
    )
    approval_ids = [approval['id'] for approval in approvals]
    for approval in approvals:
        entries.append(_timeline_entry(
            approval['created_at'], approval['requested_by'], 'approval_requested',
            f"{approval['action']} target={approval['target']}", 'response_approvals',
            approval_id=approval['id'], status=approval['status']
        ))
        if approval.get('updated_at') and approval.get('status') not in {'pending'}:
            entries.append(_timeline_entry(
                approval['updated_at'], approval.get('approved_by') or approval['requested_by'],
                f"approval_{approval['status']}", approval.get('result') or approval['action'],
                'response_approvals', approval_id=approval['id'], status=approval['status']
            ))

    audit_where = ["organization_id = ?"]
    audit_params = [org_id]
    target_clauses = ["target = ?"]
    audit_params.append(f"incident:{incident_id}")
    for anomaly_id in linked_ids:
        target_clauses.append("target = ?")
        audit_params.append(f"anomaly:{anomaly_id}")
    for approval_id in approval_ids:
        target_clauses.append("target = ?")
        audit_params.append(f"approval:{approval_id}")
    audit_where.append(f"({' OR '.join(target_clauses)})")
    for audit in _db_query(
        f"SELECT * FROM audit_events WHERE {' AND '.join(audit_where)} ORDER BY timestamp",
        tuple(audit_params)
    ):
        entries.append(_timeline_entry(
            audit['timestamp'], audit['actor'], audit['event_type'],
            audit.get('detail') or audit['event_type'], 'audit_events',
            result=audit['result'], target=audit['target'], audit_target_type=audit.get('target_type')
        ))

    terminal_rows = _db_query(
        "SELECT * FROM audit_events WHERE organization_id = ? AND event_type = ? ORDER BY timestamp",
        (org_id, 'terminal_command_attempted')
    )
    for audit in terminal_rows:
        details = _json_loads(audit.get('details_json'), {})
        if details.get('incident_id') == incident_id:
            entries.append(_timeline_entry(
                audit['timestamp'], audit['actor'], 'terminal_command_attempted',
                audit.get('detail') or 'terminal command attempted', 'audit_events',
                result=audit['result'], command=details.get('command')
            ))

    seen = set()
    unique = []
    for entry in entries:
        key = (entry.get('timestamp'), entry.get('event_type'), entry.get('detail'), entry.get('source'), entry.get('approval_id'), entry.get('run_id'))
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return sorted(unique, key=lambda item: item.get('timestamp') or '')


def _incident_detail_payload(incident):
    notes = [
        event for event in _db_query(
            "SELECT * FROM incident_events WHERE incident_id = ? AND organization_id = ? AND event_type = ? ORDER BY timestamp",
            (incident['id'], incident.get('organization_id'), 'note_added')
        )
    ]
    approvals = [_response_approval_from_row(row) for row in _db_query(
        "SELECT * FROM response_approvals WHERE incident_id = ? AND organization_id = ? ORDER BY created_at DESC",
        (incident['id'], incident.get('organization_id'))
    )]
    linked_ids = _incident_linked_anomalies(incident)
    playbook_runs_for_incident = []
    if linked_ids:
        placeholders = ','.join(['?'] * len(linked_ids))
        run_rows = _db_query(
            f"SELECT * FROM playbook_runs WHERE anomaly_id IN ({placeholders}) AND (organization_id IS NULL OR organization_id = ?) ORDER BY timestamp",
            tuple(linked_ids + [incident.get('organization_id')])
        )
        by_pb = {row['id']: row for row in run_rows}
        playbook_runs_for_incident = _playbook_runs_from_db(incident.get('organization_id'), limit=1000)
        playbook_runs_for_incident = [run for run in playbook_runs_for_incident if run['id'] in by_pb]
    return {
        'incident': _incident_from_row(incident),
        'anomalies': _incident_anomalies(incident),
        'recommended_playbook': _incident_recommended_playbook(incident),
        'playbook_runs': playbook_runs_for_incident,
        'notes': notes,
        'timeline': _incident_timeline(incident),
        'approvals': approvals,
    }


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


def _record_playbook_run(anomaly, pb, seen=None):
    if seen is None:
        seen = set()
    key = (pb['id'], anomaly.get('id'))
    if key in seen:
        return None
    existing = _db_query(
        "SELECT * FROM playbook_runs WHERE anomaly_id = ? AND playbook_id = ? LIMIT 1",
        (anomaly.get('id'), pb['id'])
    )
    if existing:
        seen.add(key)
        return None
    requires_approval = pb.get('required_approval_role') not in {None, '', 'none', 'automatic'}
    run_status = 'waiting_for_approval' if requires_approval else ('resolved' if pb.get('auto') else 'open')
    now = datetime.now().isoformat()
    incident_id = anomaly.get('incident_id')
    run_entry = {
        'playbook_id': pb['id'],
        'playbook_stable_key': pb.get('stable_key'),
        'playbook_name': pb['name'],
        'playbook_kind': pb.get('kind'),
        'playbook_version': pb.get('version'),
        'definition_digest': pb.get('definition_digest'),
        'name': pb['name'],
        'anomaly_id': anomaly.get('id'),
        'incident_id': incident_id,
        'metric': anomaly['metric'],
        'value': anomaly['value'],
        'threshold': pb['threshold'],
        'action': pb.get('recommended_action_key') or pb['action'],
        'recommended_action_key': pb.get('recommended_action_key') or pb['action'],
        'required_approval_role': pb.get('required_approval_role') or 'none',
        'target': pb['target'],
        'timestamp': now,
        'created_at': now,
        'created_by': anomaly.get('created_by') or 'system',
        'auto': pb.get('auto', False),
        'status': run_status,
        'yaml': pb.get('steps_yaml') or pb.get('yaml', ''),
        'steps_yaml': pb.get('steps_yaml') or pb.get('yaml', ''),
    }
    cur = _db_exec(
        """
        INSERT INTO playbook_runs (
            organization_id, playbook_id, playbook_stable_key, playbook_name,
            playbook_kind, playbook_version, definition_digest, name, anomaly_id,
            incident_id, metric, value, threshold, action, recommended_action_key,
            required_approval_role, target, timestamp, created_at, created_by, auto,
            status, yaml, steps_yaml
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            anomaly.get('organization_id'), run_entry['playbook_id'], run_entry['playbook_stable_key'],
            run_entry['playbook_name'], run_entry['playbook_kind'], run_entry['playbook_version'],
            run_entry['definition_digest'], run_entry['name'], run_entry['anomaly_id'], run_entry['incident_id'],
            run_entry['metric'], run_entry['value'], run_entry['threshold'], run_entry['action'],
            run_entry['recommended_action_key'], run_entry['required_approval_role'], run_entry['target'],
            run_entry['timestamp'], run_entry['created_at'], run_entry['created_by'], int(run_entry['auto']),
            run_entry['status'], run_entry['yaml'], run_entry['steps_yaml'],
        )
    )
    run_entry['id'] = cur.lastrowid
    run_entry['organization_id'] = anomaly.get('organization_id')
    playbook_runs.append(run_entry)
    seen.add(key)
    if pb.get('auto') and not requires_approval:
        notification_queue.put({
            'type': 'playbook_trigger',
            'playbook': pb['name'],
            'details': run_entry,
        })
    return run_entry


def _playbook_matches_anomaly(pb, anomaly):
    if not pb.get('enabled', False):
        return False
    trigger = pb.get('trigger') or _json_loads(pb.get('trigger_json'), {})
    if trigger.get('type') != 'anomaly':
        return False
    if trigger.get('metric') != anomaly.get('metric'):
        return False
    if trigger.get('category') and trigger.get('category') != anomaly.get('category'):
        return False
    return op_eval(float(anomaly.get('value', 0)), trigger.get('operator'), float(trigger.get('threshold', 0)))


def persisted_playbook_matches(anomaly, organization_id=None):
    matches = []
    org_id = organization_id if organization_id is not None else anomaly.get('organization_id')
    for pb in _playbooks_from_db(org_id):
        if not pb.get('enabled', False):
            continue
        if _playbook_matches_anomaly(pb, anomaly):
            matches.append(pb)
    return matches


def _recommended_playbook(anomaly):
    matches = []
    for pb in persisted_playbook_matches(anomaly, organization_id=anomaly.get('organization_id')):
        matches.append(pb)
    if matches:
        return sorted(matches, key=lambda pb: (pb.get('category') != anomaly.get('category'), bool(pb.get('auto')), pb['id']))[0]
    for pb in _playbooks_from_db(anomaly.get('organization_id')):
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
    title = f"{severity_label(anomaly.get('severity'))} {anomaly.get('metric')} anomaly"
    _db_exec(
        "INSERT INTO incidents (id, organization_id, title, severity, status, owner, anomaly_id, linked_anomalies, recommended_playbook_id, created_at, updated_at, closed_at, resolution) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, organization_id, title, normalize_severity(anomaly.get('severity')), 'open', None, anomaly['id'], _json_dumps([anomaly['id']]), pb['id'] if pb else None, now, now, None, None)
    )
    _incident_event(incident_id, 'incident_created', f"Linked anomaly {anomaly['id']}", actor=actor, organization_id=organization_id)
    if pb:
        _incident_event(incident_id, 'playbook_recommended', f"Recommended {pb['name']}", actor=actor, organization_id=organization_id)
    audit_event('incident_created', f"incident:{incident_id}", 'success', title, actor=actor, role='system' if actor == 'system' else None, organization_id=organization_id, details={'anomaly_id': anomaly['id'], 'severity': normalize_severity(anomaly.get('severity')), 'recommended_playbook_id': pb['id'] if pb else None})
    return _db_query("SELECT * FROM incidents WHERE id = ?", (incident_id,))[0]


def ingest_anomaly_workflow(anomaly, actor='system', organization_id=None, create_runs=True):
    incident = create_incident_from_anomaly(anomaly, actor=actor, organization_id=organization_id)
    workflow_anomaly = dict(anomaly)
    workflow_anomaly['incident_id'] = incident['id']
    workflow_anomaly['organization_id'] = incident.get('organization_id')
    workflow_anomaly['created_by'] = actor
    runs = []
    if create_runs:
        seen = {(r.get('playbook_id'), r.get('anomaly_id')) for r in _playbook_runs_from_db(incident.get('organization_id'), limit=1000)}
        for pb in persisted_playbook_matches(workflow_anomaly, organization_id=incident.get('organization_id')):
            run = _record_playbook_run(workflow_anomaly, pb, seen=seen)
            if run:
                runs.append(run)
        if runs:
            _incident_event(
                incident['id'],
                'playbook_runs_created',
                _json_dumps({'run_ids': [run['id'] for run in runs], 'playbooks': [run['name'] for run in runs]}),
                actor=actor,
                organization_id=incident.get('organization_id'),
            )
    return incident, runs


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
        profile = VALIDATION_EVENT_CATALOG.get(row['event_type'])
        if not profile:
            continue
        anomaly = {
            'id': row['anomaly_id'],
            'organization_id': row.get('organization_id'),
            'timestamp': row['created_at'],
            'metric': profile['metric'],
            'value': profile['value'],
            'threshold': profile['threshold'],
            'severity': profile['severity'],
            'category': profile['category'],
            'confidence': 0.95,
            'rule_name': f"Controlled validation: {profile['label']}",
            'indicator_type': 'validation',
            'indicator': profile['indicator'],
            'threat_intel': {
                'matched': False,
                'confidence': 0,
                'source': 'controlled validation event',
                'tags': ['validation', row['event_type']],
            },
            'risk_score': 90 if profile['severity'] == 'critical' else 76,
            'frameworks': profile['frameworks'],
            'validation': True,
        }
        risk_level = risk_severity(anomaly['risk_score'])
        anomaly.update({
            'severity': normalize_severity(anomaly['severity'], default='info'),
            'severity_label': severity_label(anomaly['severity']),
            'severity_class': severity_class(anomaly['severity']),
            'risk_level': risk_level,
            'risk_label': severity_label(risk_level),
            'risk_class': severity_class(risk_level),
        })
        anomalies.append(anomaly)
    return anomalies


init_db()
_seed_db()
load_persistent_state()

# --- Background sampler ---

def sampler():
    global SAMPLER_LAST_SUCCESS_AT
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
        SAMPLER_LAST_SUCCESS_AT = now

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


def start_sampler():
    global SAMPLER_STARTED_AT, SAMPLER_THREAD
    if SAMPLER_THREAD and SAMPLER_THREAD.is_alive():
        return SAMPLER_THREAD
    SAMPLER_STARTED_AT = time.time()
    SAMPLER_THREAD = threading.Thread(target=sampler, daemon=True)
    SAMPLER_THREAD.start()
    return SAMPLER_THREAD


def sampler_is_healthy(max_age_seconds=SAMPLER_HEALTH_MAX_AGE_SECONDS, startup_grace_seconds=SAMPLER_STARTUP_GRACE_SECONDS):
    thread_alive = bool(SAMPLER_THREAD and SAMPLER_THREAD.is_alive())
    if not thread_alive:
        return False
    now = time.time()
    if SAMPLER_LAST_SUCCESS_AT <= 0:
        return SAMPLER_STARTED_AT > 0 and (now - SAMPLER_STARTED_AT) <= startup_grace_seconds
    return (now - SAMPLER_LAST_SUCCESS_AT) <= max_age_seconds


start_sampler()

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
            apply_automation_rules(stored)
            for anomaly in stored:
                if normalize_severity(anomaly.get('severity')) in {'high', 'critical'}:
                    ingest_anomaly_workflow(anomaly, organization_id=organization_id)
        return stored[:200]

    anomalies = _detect_stat_anomalies(df) + _detect_rule_anomalies(df)

    decorated = [_decorate_threat_intel(a) for a in anomalies] + _validation_anomalies(organization_id)
    _persist_anomalies(decorated, organization_id=organization_id)
    sorted_list = _stored_anomalies(start=start, end=end, severity=None, organization_id=organization_id)
    if apply_automation:
        apply_automation_rules(sorted_list)
        for anomaly in sorted_list:
            if normalize_severity(anomaly.get('severity')) in {'high', 'critical'}:
                ingest_anomaly_workflow(anomaly, organization_id=organization_id)
    if severity:
        requested_severity = normalize_severity(severity, default='info')
        sorted_list = [a for a in sorted_list if a.get('severity') == requested_severity]
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
        f"SELECT timestamp, actor, role, event_type, target, target_type, target_id, result, source, detail, details_json FROM audit_events {where_sql} ORDER BY id DESC LIMIT ?",
        tuple(params)
    ):
        severity = 'medium' if row['result'] in {'denied', 'failed'} else 'info'
        detail = row.get('detail') or f"actor {row['actor']}"
        structured_details = _json_loads(row.get('details_json'), None)
        logs.append({
            'timestamp': row['timestamp'],
            'actor': row['actor'],
            'role': row['role'],
            'event_type': row['event_type'],
            'target': row['target'],
            'target_type': row.get('target_type'),
            'target_id': row.get('target_id'),
            'result': row['result'],
            'source': row.get('source') or 'local',
            'detail': detail,
            'details_json': row.get('details_json'),
            'structured_details': structured_details,
            'action': row['event_type'],
            'severity': severity,
            'severity_label': severity_label(severity),
            'severity_class': severity_class(severity),
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
            sev = 'medium' if row.get('cpu_percent', 0) > 70 else 'info'
            outcome = 'flagged' if sev == 'medium' else 'allowed'
            detail = f"CPU {row.get('cpu_percent', 0):.1f}%, memory {row.get('memory_percent', 0):.1f}%"
            logs.append({
                'timestamp': row['timestamp'].isoformat(),
                'actor': 'system',
                'role': 'system',
                'event_type': 'metric_sample',
                'target': 'host.telemetry',
                'target_type': 'host',
                'target_id': 'telemetry',
                'result': outcome,
                'source': LOG_PATH,
                'detail': detail,
                'details_json': None,
                'structured_details': None,
                'action': 'metric_sample',
                'severity': sev,
                'severity_label': severity_label(sev),
                'severity_class': severity_class(sev),
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
    incidents = [
        _incident_from_row(row)
        for row in _db_query(
            "SELECT * FROM incidents WHERE organization_id = ? ORDER BY updated_at DESC LIMIT 100",
            (org_id,)
        )
    ] if org_id is not None else []
    incident_reconstructions = []
    for incident in incidents[:20]:
        detail = _incident_detail_payload(incident)
        validation_anomalies = [a for a in detail['anomalies'] if a.get('validation')]
        incident_reconstructions.append({
            'incident_id': incident['id'],
            'status': incident['status'],
            'resolution': incident.get('resolution'),
            'controlled_validation': bool(validation_anomalies),
            'anomaly_ids': [a['id'] for a in detail['anomalies']],
            'playbook_runs': [{
                'id': run['id'],
                'stable_key': run.get('playbook_stable_key'),
                'name': run.get('playbook_name') or run.get('name'),
                'version': run.get('playbook_version'),
                'definition_digest': run.get('definition_digest'),
                'recommended_action_key': run.get('recommended_action_key'),
                'required_approval_role': run.get('required_approval_role'),
                'status': run.get('status'),
            } for run in detail['playbook_runs']],
            'approvals': [{
                'id': approval['id'],
                'action': approval['action'],
                'status': approval['status'],
                'requested_by': approval['requested_by'],
                'approved_by': approval.get('approved_by'),
                'decision_reason': approval.get('decision_reason'),
            } for approval in detail['approvals']],
        })
    return {
        'generated_at': datetime.now().isoformat(),
        'anomaly_count': len(anomalies),
        'critical_count': len([a for a in anomalies if a['severity'] == 'critical']),
        'high_risk_count': len([a for a in anomalies if a['risk_score'] >= 75]),
        'audit_count': len(audits),
        'incident_count': len(incidents),
        'frameworks': {
            'NIST': ['DE.CM-1', 'DE.AE-2', 'RS.MI-1'],
            'CIS': ['8.11', '8.16', '8.17']
        },
        'anomalies': anomalies[:50],
        'audits': audits[-50:],
        'incidents': incidents[:50],
        'incident_reconstructions': incident_reconstructions,
    }


def _csv_response(summary):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['report_generated_at', summary['generated_at']])
    writer.writerow([])
    writer.writerow(['type', 'timestamp', 'severity', 'metric_or_action', 'value_or_outcome', 'risk_score', 'frameworks'])
    for a in summary['anomalies']:
        writer.writerow(['anomaly', a['timestamp'], severity_label(a['severity']), a['metric'], f"{a['value']:.2f}", a['risk_score'], '; '.join(a['frameworks'])])
    for log in summary['audits']:
        writer.writerow(['audit', log['timestamp'], severity_label(log['severity']), log['action'], log['outcome'], '', 'NIST AU; CIS 8'])
    for incident in summary['incidents']:
        writer.writerow(['incident', incident['updated_at'], severity_label(incident['severity']), incident['title'], status_label(incident['status']), '', 'NIST RS; CIS 17'])
    for reconstruction in summary.get('incident_reconstructions', []):
        writer.writerow(['incident_reconstruction', summary['generated_at'], 'Info', reconstruction['incident_id'], 'controlled_validation' if reconstruction['controlled_validation'] else 'operational', '', 'playbooks; approvals; closure'])
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
        f"Incidents: {summary['incident_count']}",
        'Framework Mapping: NIST DE.CM-1, DE.AE-2, RS.MI-1 | CIS 8.11, 8.16, 8.17',
        '',
        'Top Anomalies:',
    ]
    for a in summary['anomalies'][:28]:
        lines.append(f"{a['timestamp'][:19]} {severity_label(a['severity'])} {a['metric']}={a['value']:.2f} risk={a['risk_score']} {','.join(a['frameworks'][:2])}")
    for incident in summary['incidents'][:10]:
        lines.append(f"{incident['updated_at'][:19]} {severity_label(incident['severity'])} {status_label(incident['status'])} {incident['id']}")
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
                    'status': 'resolved',
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


def _terminal_allowed_forms():
    return [
        f"{base} {' '.join(args)}".strip()
        for base, specs in sorted(DIAGNOSTIC_COMMANDS.items())
        for args in sorted(specs)
    ]


def _validate_terminal_command(command):
    if not isinstance(command, str):
        return None, 'Command must be a string.'
    if TERMINAL_SHELL_SYNTAX_RE.search(command):
        return None, 'Shell syntax and expansion characters are blocked in browser diagnostics.'
    try:
        parts = shlex.split(command)
    except ValueError as exc:
        return None, str(exc)
    if not parts:
        return None, 'Enter a diagnostic command.'
    if os.path.basename(parts[0]) != parts[0]:
        return None, 'Command paths are blocked. Use an enabled diagnostic command name only.'
    base = parts[0]
    if not TERMINAL_COMMAND_NAME_RE.fullmatch(base):
        return None, 'Command names may contain only letters, numbers, dots, dashes, and underscores.'
    if base not in DIAGNOSTIC_COMMANDS:
        return None, f"Command '{base}' is not enabled. Allowed: {', '.join(sorted(DIAGNOSTIC_COMMANDS))}"
    if any(token.startswith('/') or '..' in token for token in parts[1:]):
        return None, 'Absolute paths and parent directory traversal are blocked in browser diagnostics.'
    args = tuple(parts[1:])
    if args not in DIAGNOSTIC_COMMANDS[base]:
        allowed_args = [
            f"{base} {' '.join(spec)}".strip()
            for spec in sorted(DIAGNOSTIC_COMMANDS[base])
        ]
        return None, f"Arguments for '{base}' are not enabled. Allowed forms: {', '.join(allowed_args)}"
    executable = shutil.which(base)
    if not executable:
        return None, f"Command '{base}' is not installed on this host."
    return [executable, *parts[1:]], None


def _terminal_audit_details(command, incident_id=None):
    details = {
        'command': command if isinstance(command, str) else repr(command),
        'allowed_forms': _terminal_allowed_forms(),
        'timeout_seconds': TERMINAL_TIMEOUT_SECONDS,
        'output_limit': TERMINAL_OUTPUT_LIMIT,
        'shell': False,
    }
    if incident_id:
        details['incident_id'] = incident_id
    return details


def _run_terminal_command(command, incident_id=None):
    args, error = _validate_terminal_command(command)
    audit_details = _terminal_audit_details(command, incident_id=incident_id)
    if error:
        audit_event('terminal_command_attempted', f"command:{command}", 'denied', error, details=audit_details)
        return {'success': False, 'error': error, 'output': ''}, 400
    audit_details.update({
        'executable': args[0],
        'argv': args,
        'command_name': os.path.basename(args[0]),
        'arguments': args[1:],
    })
    try:
        proc = subprocess.run(
            args,
            cwd=BASE_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=TERMINAL_TIMEOUT_SECONDS,
            check=False,
        )
        output = proc.stdout or ''
        original_output_chars = len(output)
        truncated = original_output_chars > TERMINAL_OUTPUT_LIMIT
        if truncated:
            output = output[:TERMINAL_OUTPUT_LIMIT] + '\n[output truncated]\n'
        result = 'success' if proc.returncode == 0 else 'failed'
        audit_details.update({
            'returncode': proc.returncode,
            'truncated': truncated,
            'output_chars': len(output),
            'original_output_chars': original_output_chars,
        })
        audit_event('terminal_command_attempted', f"command:{os.path.basename(args[0])}", result, f"exit={proc.returncode}", details=audit_details)
        return {'success': proc.returncode == 0, 'returncode': proc.returncode, 'output': output, 'truncated': truncated}, 200
    except subprocess.TimeoutExpired:
        audit_event('terminal_command_attempted', f"command:{os.path.basename(args[0])}", 'failed', 'timeout', details=audit_details)
        return {'success': False, 'error': 'command timed out', 'output': ''}, 408
    except OSError as exc:
        audit_details.update({'error_type': type(exc).__name__, 'error': str(exc)})
        audit_event('terminal_command_attempted', f"command:{os.path.basename(args[0])}", 'failed', 'execution failed', details=audit_details)
        return {'success': False, 'error': 'command execution failed', 'output': ''}, 500


def _approval_row(approval_id):
    user = current_user()
    if user:
        rows = _db_query(
            "SELECT * FROM response_approvals WHERE id = ? AND organization_id = ?",
            (approval_id, user.get('organization_id'))
        )
    else:
        rows = _db_query("SELECT * FROM response_approvals WHERE id = ?", (approval_id,))
    return _response_approval_from_row(rows[0]) if rows else None


def _response_approval_from_row(row):
    approval = dict(row)
    approval['dry_run'] = bool(approval.get('dry_run'))
    contract = _approval_contract(approval.get('action'))
    approval['host_impacting'] = bool(contract and contract.get('host_impacting'))
    approval['workflow_status'] = normalize_status(approval.get('status'), default='open')
    approval['status_label'] = status_label(approval['workflow_status'])
    approval['status_class'] = status_class(approval['workflow_status'])
    return approval


def _approval_audit_events(approval):
    rows = _db_query(
        """
        SELECT timestamp, actor, role, event_type, target, target_type, target_id,
               result, source, detail, details_json
        FROM audit_events
        WHERE organization_id = ? AND target = ?
        ORDER BY timestamp, rowid
        """,
        (approval.get('organization_id'), _approval_correlation_id(approval['id']))
    )
    events = []
    for row in rows:
        structured_details = _json_loads(row.get('details_json'), None)
        events.append({
            **row,
            'structured_details': structured_details,
            'correlation_id': (structured_details or {}).get('correlation_id') or _approval_correlation_id(approval['id']),
        })
    return events


def _approval_timeline_events(approval):
    if not approval.get('incident_id'):
        return []
    incident = _incident_row(approval['incident_id'], approval.get('organization_id'))
    if not incident:
        return []
    correlation_id = _approval_correlation_id(approval['id'])
    events = []
    for event in _incident_timeline(incident):
        structured = event.get('structured_details') or {}
        if event.get('approval_id') == approval['id'] or structured.get('correlation_id') == correlation_id:
            events.append(event)
    return events


def _approval_diagnostics(approval):
    request_payload = _approval_payload(
        approval.get('action'),
        approval.get('target'),
        approval.get('incident_id'),
        approval.get('anomaly_id'),
        approval.get('dry_run', True),
    )
    expected_payload_digest = approval_payload_digest(request_payload)
    try:
        expected_preview = approval_preview(request_payload)
        expected_preview_digest = approval_preview_digest(request_payload, expected_preview)
        preview_error = None
    except ValueError as exc:
        expected_preview = None
        expected_preview_digest = None
        preview_error = str(exc)
    audit_events = _approval_audit_events(approval)
    timeline_events = _approval_timeline_events(approval)
    reconstruction = []
    for event in audit_events:
        reconstruction.append({
            'timestamp': event['timestamp'],
            'source': 'audit',
            'event_type': event['event_type'],
            'actor': event['actor'],
            'result': event['result'],
            'detail': event.get('detail'),
            'correlation_id': event.get('correlation_id'),
        })
    for event in timeline_events:
        reconstruction.append({
            'timestamp': event['timestamp'],
            'source': 'incident_timeline',
            'event_type': event['event_type'],
            'actor': event['actor'],
            'result': (event.get('structured_details') or {}).get('result'),
            'detail': event.get('detail'),
            'correlation_id': event.get('correlation_id') or (event.get('structured_details') or {}).get('correlation_id'),
        })
    reconstruction.sort(key=lambda event: event.get('timestamp') or '')
    return {
        'approval': approval,
        'request_payload': request_payload,
        'expected_preview': expected_preview,
        'diagnostics': {
            'correlation_id': _approval_correlation_id(approval['id']),
            'payload_digest_matches': approval.get('payload_digest') == expected_payload_digest,
            'preview_digest_matches': approval.get('preview_digest') == expected_preview_digest,
            'expected_payload_digest': expected_payload_digest,
            'expected_preview_digest': expected_preview_digest,
            'stored_payload_digest': approval.get('payload_digest'),
            'stored_preview_digest': approval.get('preview_digest'),
            'preview_error': preview_error,
            'audit_event_count': len(audit_events),
            'timeline_event_count': len(timeline_events),
        },
        'audit_events': audit_events,
        'timeline_events': timeline_events,
        'reconstruction': reconstruction,
    }


def _approval_expired(approval, now=None):
    expires_at = approval.get('expires_at')
    if not expires_at:
        return False
    now = now or datetime.now()
    try:
        return now > datetime.fromisoformat(expires_at)
    except ValueError:
        return True


def authorizeApprovedAction(approval_id, payload, actor=None, consume=True):
    actor = actor or current_user()
    if not actor:
        return _approval_error('authentication required', 401)

    expected_payload = _approval_payload(
        payload.get('action'),
        payload.get('target'),
        payload.get('incident_id'),
        payload.get('anomaly_id'),
        payload.get('dry_run', True),
    )
    expected_digest = approval_payload_digest(expected_payload)
    now_dt = datetime.now()
    now = now_dt.isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM response_approvals WHERE id = ? AND organization_id = ?",
            (approval_id, actor.get('organization_id'))
        ).fetchone()
        if not row:
            conn.rollback()
            return _approval_error('approval not found', 404)
        approval = _response_approval_from_row(row)
        metadata = _response_action_metadata(approval.get('action'))
        contract = metadata.approval_contract() if metadata else None
        if not contract:
            conn.rollback()
            return _approval_error('unsupported response action', 400, approval)
        try:
            _validate_response_action_metadata(metadata)
        except ValueError as exc:
            conn.rollback()
            return _approval_error(_public_error_detail(exc, 'response action registry validation failed'), 400, approval)
        if approval.get('status') == 'approved' and _approval_expired(approval, now_dt):
            _mark_approval_expired(conn, approval, now)
            conn.commit()
            return _approval_error('approval request has expired', 409, _approval_row(approval_id))
        if approval.get('status') != 'approved':
            conn.rollback()
            return _approval_error('approval must be approved before execution', 409, approval)
        if approval.get('requested_by') == actor.get('username'):
            conn.rollback()
            return _approval_error('requester cannot consume their own approval', 403, approval)
        if not _role_allows(actor, approval.get('required_role') or contract['required_role']):
            conn.rollback()
            return _approval_error(f"{contract['required_role']} role required", 403, approval)
        if not _role_allowed_by_registry(actor, metadata.execution_roles):
            conn.rollback()
            return _approval_error('response action execution role required', 403, approval)
        if not metadata.enabled:
            conn.rollback()
            return _approval_error(f"{metadata.stable_key} execution adapter is disabled", 403, approval)
        platform_key = _current_platform_key()
        if platform_key not in metadata.supported_platforms:
            conn.rollback()
            return _approval_error(f"{metadata.stable_key} is not supported on platform {platform_key}", 403, approval)
        if approval.get('approver_role') and ROLES.get(approval['approver_role'], 0) < ROLES[contract['required_role']]:
            conn.rollback()
            return _approval_error('approver role no longer satisfies action contract', 403, approval)
        if approval.get('requested_by') != _clean_optional_text(payload.get('requester', approval.get('requested_by'))):
            conn.rollback()
            return _approval_error('requester does not match approval request', 409, approval)
        if not _approval_target_matches(approval, expected_payload):
            conn.rollback()
            return _approval_error('approval target or action does not match request payload', 409, approval)
        if approval.get('payload_digest') != expected_digest:
            conn.rollback()
            return _approval_error('approval payload digest mismatch', 409, approval)
        expected_preview = approval_preview(expected_payload)
        expected_preview_digest = approval_preview_digest(expected_payload, expected_preview)
        if approval.get('preview_digest') != expected_preview_digest:
            conn.rollback()
            return _approval_error('approval preview digest mismatch', 409, approval)
        if consume:
            cur = conn.execute(
                """
                UPDATE response_approvals
                SET status = ?, consumed_by = ?, consumed_at = ?, updated_at = ?, result = ?
                WHERE id = ? AND organization_id = ? AND status = ?
                """,
                ('consumed', actor['username'], now, now, 'approval consumed by authorization boundary',
                 approval_id, actor.get('organization_id'), 'approved')
            )
            if cur.rowcount != 1:
                conn.rollback()
                return _approval_error('approval has already been consumed or changed', 409, approval)
        conn.commit()
        authorized = _approval_row(approval_id)
        return {
            'ok': True,
            'approval': authorized,
            'payload': expected_payload,
            'payload_digest': expected_digest,
            'preview': expected_preview,
            'preview_digest': expected_preview_digest,
            'contract': contract,
        }
    except sqlite3.Error:
        conn.rollback()
        raise
    finally:
        conn.close()


def authorize_approved_action(approval_id, payload, actor=None, consume=True):
    return authorizeApprovedAction(approval_id, payload, actor=actor, consume=consume)


def _dry_run_response_action(action, target):
    return approval_preview({'action': action, 'target': target, 'dry_run': True})['detail']


def _service_restart_plan(target):
    canonical_target = _approval_canonical_target('restart_service', target)
    plan = APPROVED_SERVICE_RESTARTS[canonical_target]
    restart = tuple(plan.get('restart') or ())
    rollback = tuple(plan.get('rollback') or ())
    if not restart:
        raise ValueError(f"approved service target {canonical_target} has no restart adapter")
    if not rollback:
        raise ValueError(f"approved service target {canonical_target} has no recovery adapter")
    for argv in (restart, rollback):
        if not all(isinstance(part, str) and part for part in argv):
            raise ValueError(f"approved service target {canonical_target} has invalid adapter arguments")
        if any(TERMINAL_SHELL_SYNTAX_RE.search(part) for part in argv):
            raise ValueError(f"approved service target {canonical_target} contains blocked shell syntax")
    return canonical_target, plan, restart, rollback


def _resolve_fixed_argv(argv):
    executable = shutil.which(argv[0])
    if not executable:
        raise ValueError(f"required service manager '{argv[0]}' is not installed")
    return [executable, *argv[1:]]


def _run_fixed_service_argv(argv, timeout_seconds):
    proc = subprocess.run(
        _resolve_fixed_argv(argv),
        cwd=BASE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    output = proc.stdout or ''
    if len(output) > TERMINAL_OUTPUT_LIMIT:
        output = output[:TERMINAL_OUTPUT_LIMIT] + '\n[output truncated]\n'
    return proc.returncode, output


def _restart_approved_service(target):
    canonical_target, plan, restart_argv, rollback_argv = _service_restart_plan(target)
    result = {
        'executed': False,
        'target': canonical_target,
        'service': plan.get('service'),
        'timeout_seconds': SERVICE_RESTART_TIMEOUT_SECONDS,
        'rollback_attempted': False,
        'rollback_succeeded': None,
        'recovery': plan.get('recovery'),
    }
    try:
        returncode, output = _run_fixed_service_argv(restart_argv, SERVICE_RESTART_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        result.update({'error': 'service restart timed out', 'output': exc.stdout or ''})
        return _recover_service_restart(result, rollback_argv)
    except OSError as exc:
        result.update({'error': f'service restart execution failed: {exc}'})
        return _recover_service_restart(result, rollback_argv)
    if returncode != 0:
        result.update({'error': f'service restart failed with exit={returncode}', 'returncode': returncode, 'output': output})
        return _recover_service_restart(result, rollback_argv)
    result.update({
        'executed': True,
        'returncode': returncode,
        'output': output,
        'detail': f"Restarted approved service target {canonical_target}.",
    })
    return result


def _recover_service_restart(result, rollback_argv):
    result['rollback_attempted'] = True
    try:
        rollback_code, rollback_output = _run_fixed_service_argv(rollback_argv, SERVICE_RESTART_TIMEOUT_SECONDS)
        result.update({
            'rollback_returncode': rollback_code,
            'rollback_output': rollback_output,
            'rollback_succeeded': rollback_code == 0,
        })
    except Exception as exc:
        result.update({
            'rollback_error': str(exc),
            'rollback_succeeded': False,
        })
    detail = result.get('error') or 'service restart failed'
    if result.get('rollback_succeeded'):
        detail = f"{detail}; recovery start completed"
    else:
        detail = f"{detail}; recovery start failed"
    result['detail'] = detail
    raise RuntimeError(_json_dumps(result))


def _execute_kill_process(target):
    pid = int(target)
    if pid == os.getpid():
        raise ValueError('refusing to terminate the SAAOE process')
    proc = psutil.Process(pid)
    proc.terminate()
    return {'executed': True, 'detail': f"Terminate signal sent to PID {pid} ({proc.name()})"}


def _execute_response_action(action, target, dry_run=True):
    preview = approval_preview({'action': action, 'target': target, 'dry_run': dry_run})
    if dry_run:
        return {'executed': False, 'detail': preview['detail']}
    metadata = _response_action_metadata(action)
    contract = metadata.approval_contract() if metadata else {}
    if not metadata:
        raise ValueError('unsupported response action')
    if not metadata.enabled:
        raise ValueError(f'{action} execution adapter is disabled')
    platform_key = _current_platform_key()
    if platform_key not in metadata.supported_platforms:
        raise ValueError(f'{action} is not supported on platform {platform_key}')
    if action in {'quarantine_file', 'block_ip'}:
        raise ValueError(f'{action} execution adapter is not available in Phase 4')
    if contract.get('host_impacting') and not contract.get('enabled'):
        raise ValueError(f'{action} execution adapter is disabled')
    _validator, executor = _validate_response_action_metadata(metadata)
    return executor(target)


def _preview_authorized_action(action, target, dry_run=True):
    return approval_preview({'action': action, 'target': target, 'dry_run': dry_run})['detail']


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
    TERMINAL_WS_SERVER = None
    TERMINAL_WS_STARTED = False


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
    if int(session.get('session_version') or 0) != int(user.get('session_version') or 1):
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


def _user_can_access_terminal(user):
    return bool(user and user.get('role') == 'admin' and _user_has_permission(user, 'access_terminal'))


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


def require_terminal_access(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not _user_can_access_terminal(user):
            audit_event('access_denied', request.endpoint or fn.__name__, 'denied', 'admin terminal access required')
            return _auth_failed(403, 'Admin terminal access required')
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def require_authentication():
    endpoint = request.endpoint or ''
    if endpoint in PUBLIC_ENDPOINTS:
        return None
    healthcheck_probe = request.environ.get('saaoe.healthcheck') == '1'

    if not active_admin_exists():
        if endpoint == 'setup':
            return None
        if _is_api_request():
            return jsonify(error='first workspace setup required'), 503
        return redirect(url_for('setup'))

    user = current_user()
    if not user:
        if not healthcheck_probe:
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


@app.after_request
def audit_unlogged_protected_mutation(response):
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'} and request.endpoint not in PUBLIC_ENDPOINTS:
        if not getattr(g, 'audit_event_written', False):
            result = 'success' if response.status_code < 400 else ('denied' if response.status_code in {401, 403} else 'failed')
            detail = f"{request.method} {request.path} returned {response.status_code}"
            try:
                audit_event(
                    'protected_mutation',
                    request.endpoint or request.path,
                    result,
                    detail,
                    details={'method': request.method, 'path': request.path, 'status_code': response.status_code},
                )
            except sqlite3.Error:
                pass
    return response


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
        'severity_status_vocabulary': vocabulary_payload(),
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
        username_error = validate_username(username)
        organization_error = validate_workspace_name(organization)
        if username_error:
            error = username_error
        elif organization_error:
            error = organization_error
        elif len(password) < 10:
            error = 'Password must be at least 10 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            org_id = create_organization(organization, created_by=username)
            create_user(username, password, 'admin', organization_id=org_id)
            user = get_user_by_username(username)
            start_user_session(user)
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
            start_user_session(user)
            _db_exec("UPDATE users SET last_login_at = ? WHERE id = ?", (datetime.now().isoformat(), user['id']))
            audit_event('login', f"user:{username}", 'success', 'interactive login', actor=username, role=user['role'])
            next_url = _safe_local_redirect_target(request.args.get('next'))
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
        username_error = validate_username(username)
        organization_error = validate_workspace_name(organization)
        if username_error:
            error = username_error
        elif organization_error:
            error = organization_error
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
            start_user_session(user)
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
        else:
            error = validate_username(username)
        if not error and get_user_by_username(username):
            error = 'That username is already registered.'
        elif not error and _db_query("SELECT id FROM join_requests WHERE username = ? AND status = ?", (username, 'pending')):
            error = 'There is already a pending join request for that username.'
        elif not error and len(password) < 10:
            error = 'Password must be at least 10 characters.'
        elif not error and password != confirm:
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
                start_user_session(user)
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
    if not _user_can_access_terminal(user):
        audit_event('access_denied', 'terminal_page', 'denied', 'admin terminal access required')
        return _auth_failed(403, 'Admin terminal access required')
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
            audit_event('permission_change_failed', 'api_users.permissions', 'failed', 'permissions must be an array')
            return jsonify(error='permissions must be an array'), 400
        invalid_permissions = [p for p in requested_permissions if p not in PERMISSIONS]
        if invalid_permissions:
            audit_event('permission_change_failed', 'api_users.permissions', 'failed', f"invalid permissions: {', '.join(invalid_permissions)}")
            return jsonify(error=f"invalid permissions: {', '.join(invalid_permissions)}"), 400
        target = get_user_by_id(uid)
        if not target:
            audit_event('permission_change_failed', f"user:{uid}", 'failed', 'user not found')
            return jsonify(error='user not found'), 404
        if target.get('organization_id') != org_id:
            audit_event('access_denied', f"user:{target['username']}", 'denied', 'cross-workspace permission change blocked')
            return jsonify(error='user not found'), 404
        if target.get('role') != 'admin' and 'access_terminal' in requested_permissions:
            audit_event('permission_change_failed', f"user:{target['username']}", 'failed', 'terminal access is admin-only')
            return jsonify(error='terminal access is admin-only'), 400
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
            audit_event('user_disable_failed', f"user:{uid}", 'failed', 'user not found')
            return jsonify(error='user not found'), 404
        if target.get('organization_id') != org_id:
            audit_event('access_denied', f"user:{target['username']}", 'denied', 'cross-workspace user disable blocked')
            return jsonify(error='user not found'), 404
        if target['id'] == session.get('user_id'):
            audit_event('user_disable_failed', f"user:{target['username']}", 'failed', 'cannot disable current user')
            return jsonify(error='cannot disable current user'), 400
        _db_exec("UPDATE users SET active = 0, session_version = COALESCE(session_version, 1) + 1 WHERE id = ?", (uid,))
        audit_event('user_disabled', f"user:{target['username']}", 'success', 'workspace admin disabled member')
        return jsonify(success=True)

    if action == 'enable':
        uid = int(payload.get('id', 0))
        target = get_user_by_id(uid)
        if not target:
            audit_event('user_enable_failed', f"user:{uid}", 'failed', 'user not found')
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
    username_error = validate_username(username)
    if role not in {'admin', 'analyst', 'viewer'}:
        audit_event('user_create_failed', f"user:{username or 'unknown'}", 'failed', 'invalid role')
        return jsonify(error='invalid role'), 400
    if username_error:
        audit_event('user_create_failed', f"user:{username or 'unknown'}", 'failed', username_error)
        return jsonify(error=username_error), 400
    if len(password) < 10:
        audit_event('user_create_failed', f"user:{username}", 'failed', 'password must be at least 10 characters')
        return jsonify(error='password must be at least 10 characters'), 400
    if get_user_by_username(username):
        audit_event('user_create_failed', f"user:{username}", 'failed', 'username already exists')
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
    name_error = validate_workspace_name(name)
    if join_policy not in {'join_with_code', 'request_to_join', 'admin_invites_only'}:
        audit_event('organization_update_failed', f"organization:{organization['id']}", 'failed', 'unsupported join policy')
        return jsonify(error='unsupported join policy'), 400
    if name_error:
        audit_event('organization_update_failed', f"organization:{organization['id']}", 'failed', name_error)
        return jsonify(error=name_error), 400
    existing = get_organization_by_name(name)
    if existing and existing['id'] != organization['id']:
        audit_event('organization_update_failed', f"organization:{organization['id']}", 'failed', 'workspace name is already in use')
        return jsonify(error='workspace name is already in use'), 409
    _db_exec("UPDATE organizations SET name = ?, join_policy = ? WHERE id = ?", (name, join_policy, organization['id']))
    audit_event('organization_updated', f"organization:{organization['id']}", 'success', f"name={name}; join_policy={join_policy}", details={'name': name, 'join_policy': join_policy})
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
        audit_event('configuration_update_failed', 'configuration:unknown', 'failed', 'configuration key is required')
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
    audit_event('configuration_updated', f"configuration:{key}", 'success', f"key={key}", details={'key': key, 'value': value})
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
        audit_event('join_request_failed', f"join_request:{request_id}", 'failed', 'join request not found')
        return jsonify(error='join request not found'), 404
    join_request = rows[0]
    if join_request['status'] != 'pending':
        audit_event('join_request_failed', f"join_request:{request_id}", 'failed', 'join request has already been decided')
        return jsonify(error='join request has already been decided'), 409
    now = datetime.now().isoformat()
    if action == 'approve':
        if get_user_by_username(join_request['username']):
            _db_exec(
                "UPDATE join_requests SET status = ?, decided_at = ?, decided_by = ?, detail = ? WHERE id = ?",
                ('denied', now, user['username'], 'username already exists', request_id)
            )
            audit_event('join_request_failed', f"user:{join_request['username']}", 'failed', 'username already exists')
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
    audit_event('join_request_failed', f"join_request:{request_id}", 'failed', f"unsupported action={action}")
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
    if not _user_can_access_terminal(user):
        audit_event('access_denied', 'api_terminal_status', 'denied', 'admin terminal access required')
        return jsonify(error='Admin terminal access required'), 403
    return jsonify(
        host=TERMINAL_WS_HOST,
        port=TERMINAL_WS_PORT,
        websocket_url=None,
        running=False,
        legacy_websocket='disabled',
        allowed=_terminal_allowed_forms(),
        timeout_seconds=TERMINAL_TIMEOUT_SECONDS,
        output_limit=TERMINAL_OUTPUT_LIMIT,
        warning='Admin-only audited diagnostics. Shell expansion, command paths, and unapproved arguments are blocked.',
    )

@app.route('/api/terminal/run', methods=['POST'])
@require_terminal_access
def api_terminal_run():
    payload = request.json or {}
    command = payload.get('command', '')
    incident_id = payload.get('incident_id')
    if incident_id:
        user = current_user()
        if not _incident_row(incident_id, user.get('organization_id')):
            audit_event('terminal_command_attempted', f"incident:{incident_id}", 'failed', 'incident not found', details={'command': command, 'incident_id': incident_id})
            return jsonify(error='incident not found'), 404
    result, status = _run_terminal_command(command, incident_id=incident_id)
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
        row = {'hour': label, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
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
    recommendations = persisted_playbook_matches(anomaly, organization_id=user.get('organization_id'))
    runs = [
        run for run in _playbook_runs_from_db(user.get('organization_id'), limit=1000)
        if run.get('anomaly_id') == anomaly_id
    ]
    return jsonify(anomaly=anomaly, timeline=events, recommended_playbooks=recommendations, playbook_runs=runs)

@app.route('/api/incidents', methods=['GET', 'POST'])
def api_incidents():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        rows = _db_query(
            "SELECT * FROM incidents WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
            (org_id, int(request.args.get('limit', 100)))
        )
        return jsonify(incidents=[_incident_from_row(row) for row in rows])
    payload = request.json or {}
    if payload.get('action') == 'create_from_anomaly' or payload.get('anomaly_id'):
        return _api_create_incident_from_anomaly(payload)
    if user['role'] != 'admin':
        allowed = {'id', 'note'}
        if set(payload.keys()) - allowed or not str(payload.get('note', '')).strip():
            audit_event('access_denied', 'api_incidents', 'denied', 'workspace admin required for incident management')
            return jsonify(error='workspace admin role required'), 403
    return _update_incident(payload.get('id'), payload)


def _api_create_incident_from_anomaly(payload):
    user = current_user()
    org_id = user.get('organization_id')
    if user['role'] == 'viewer':
        audit_event('access_denied', 'api_incidents.from_anomaly', 'denied', 'regular user cannot create incidents')
        return jsonify(error='workspace admin role required'), 403
    anomaly_id = str(payload.get('anomaly_id') or '').strip()
    rows = _db_query("SELECT * FROM anomalies WHERE id = ? AND organization_id = ?", (anomaly_id, org_id))
    if not rows:
        audit_event('incident_create_failed', f"anomaly:{anomaly_id or 'unknown'}", 'failed', 'anomaly not found')
        return jsonify(error='anomaly not found'), 404
    anomaly = _anomaly_from_row(rows[0])
    incident = create_incident_from_anomaly(anomaly, actor=user['username'], organization_id=org_id)
    return jsonify(success=True, incident=_incident_from_row(incident))


def _update_incident(incident_id, payload):
    user = current_user()
    org_id = user.get('organization_id')
    rows = _db_query("SELECT * FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, org_id))
    if not rows:
        audit_event('incident_update_failed', f"incident:{incident_id or 'unknown'}", 'failed', 'incident not found')
        return jsonify(error='incident not found'), 404
    before = rows[0]
    updates = []
    params = []
    if 'status' in payload:
        status = normalize_status(payload.get('status'))
        updates.append('status = ?')
        params.append(status)
        if status in {'resolved', 'dismissed'}:
            updates.append('closed_at = ?')
            params.append(datetime.now().isoformat())
        elif before.get('status') in {'resolved', 'dismissed'} and status in {'open', 'investigating', 'waiting_for_approval'}:
            updates.append('closed_at = ?')
            params.append(None)
    assignee_value = payload.get('assignee', payload.get('owner'))
    if 'owner' in payload or 'assignee' in payload:
        updates.append('owner = ?')
        params.append(assignee_value or None)
    if 'resolution' in payload:
        updates.append('resolution = ?')
        params.append(payload.get('resolution') or None)
    note = str(payload.get('note', '')).strip()
    if not updates and not note:
        audit_event('incident_update_failed', f"incident:{incident_id}", 'failed', 'no supported update fields')
        return jsonify(error='no supported update fields'), 400
    now = datetime.now().isoformat()
    if updates:
        updates.append('updated_at = ?')
        params.append(now)
        params.append(incident_id)
        _db_exec(f"UPDATE incidents SET {', '.join(updates)} WHERE id = ?", tuple(params))
    else:
        _db_exec("UPDATE incidents SET updated_at = ? WHERE id = ?", (now, incident_id))
    detail = {k: payload[k] for k in payload if k not in {'id', 'note', 'action'}}
    if detail:
        if 'owner' in detail or 'assignee' in detail:
            _incident_event(incident_id, 'assignment_updated', json.dumps({'assignee': assignee_value}))
            audit_event('incident_assigned', f"incident:{incident_id}", 'success', f"assignee={assignee_value or 'unassigned'}", details={'assignee': assignee_value})
        if 'status' in detail:
            status = normalize_status(detail.get('status'))
            _incident_event(incident_id, 'status_updated', json.dumps({'status': status}))
            audit_event('incident_status_updated', f"incident:{incident_id}", 'success', f"status={status}", details={'status': status})
            if status in {'resolved', 'dismissed'}:
                _incident_event(incident_id, 'incident_closed', payload.get('resolution') or status)
                audit_event('incident_closed', f"incident:{incident_id}", 'success', payload.get('resolution') or status, details={'status': status, 'resolution': payload.get('resolution')})
            elif before.get('status') in {'resolved', 'dismissed'}:
                _incident_event(incident_id, 'incident_reopened', f"status={status}")
                audit_event('incident_reopened', f"incident:{incident_id}", 'success', f"status={status}", details={'status': status})
        if set(detail) - {'owner', 'assignee', 'status', 'resolution'} or 'resolution' in detail:
            _incident_event(incident_id, 'incident_updated', json.dumps(detail))
    if note:
        _incident_event(incident_id, 'note_added', note)
    audit_detail = 'incident fields updated'
    if note and not detail:
        audit_detail = 'incident note added'
    elif note:
        audit_detail = 'incident fields updated; note added'
    audit_event('incident_updated', f"incident:{incident_id}", 'success', audit_detail, details={'updates': detail, 'note_added': bool(note)})
    return jsonify(success=True, incident=_incident_from_row(_db_query("SELECT * FROM incidents WHERE id = ?", (incident_id,))[0]))


@app.route('/api/incidents/<incident_id>')
def api_incident_detail(incident_id):
    org_id = current_user().get('organization_id')
    rows = _db_query("SELECT * FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, org_id))
    if not rows:
        return jsonify(error='incident not found'), 404
    return jsonify(**_incident_detail_payload(rows[0]))


@app.route('/api/incidents/from_anomaly', methods=['POST'])
def api_incident_from_anomaly():
    return _api_create_incident_from_anomaly(request.json or {})


@app.route('/api/incidents/<incident_id>/assign', methods=['POST'])
def api_incident_assign(incident_id):
    user = current_user()
    if user['role'] != 'admin':
        audit_event('access_denied', f"incident:{incident_id}", 'denied', 'workspace admin required for incident assignment')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    return _update_incident(incident_id, {'assignee': payload.get('assignee', payload.get('owner'))})


@app.route('/api/incidents/<incident_id>/status', methods=['POST'])
def api_incident_status(incident_id):
    user = current_user()
    if user['role'] != 'admin':
        audit_event('access_denied', f"incident:{incident_id}", 'denied', 'workspace admin required for incident status update')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    return _update_incident(incident_id, {'status': payload.get('status'), 'resolution': payload.get('resolution')})


@app.route('/api/incidents/<incident_id>/notes', methods=['POST'])
def api_incident_notes(incident_id):
    payload = request.json or {}
    return _update_incident(incident_id, {'note': payload.get('note')})


@app.route('/api/incidents/<incident_id>/close', methods=['POST'])
def api_incident_close(incident_id):
    user = current_user()
    if user['role'] != 'admin':
        audit_event('access_denied', f"incident:{incident_id}", 'denied', 'workspace admin required for incident close')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    status = normalize_status(payload.get('status') or 'resolved', default='resolved')
    if status not in {'resolved', 'dismissed'}:
        status = 'resolved'
    return _update_incident(incident_id, {'status': status, 'resolution': payload.get('resolution')})


@app.route('/api/incidents/<incident_id>/reopen', methods=['POST'])
def api_incident_reopen(incident_id):
    user = current_user()
    if user['role'] != 'admin':
        audit_event('access_denied', f"incident:{incident_id}", 'denied', 'workspace admin required for incident reopen')
        return jsonify(error='workspace admin role required'), 403
    return _update_incident(incident_id, {'status': 'open'})


@app.route('/api/validation_events', methods=['GET', 'POST'])
def api_validation_events():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        return jsonify(event_types=VALIDATION_EVENT_CATALOG, events=[_status_record(row) for row in _db_query(
            "SELECT * FROM validation_events WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100",
            (org_id,)
        )])
    if user['role'] == 'viewer':
        audit_event('access_denied', 'api_validation_events', 'denied', 'regular user cannot create validation events')
        return jsonify(error='workspace admin role required'), 403
    payload = request.json or {}
    event_type = payload.get('event_type', 'cpu_pressure')
    profile = VALIDATION_EVENT_CATALOG.get(event_type)
    if not profile:
        audit_event('validation_event_failed', 'api_validation_events', 'failed', f"unsupported event_type={event_type}")
        return jsonify(error='unsupported validation event type'), 400
    event_id = f"VE-{uuid.uuid4().hex[:10]}"
    anomaly_id = f"validation-{event_id.lower()}"
    now = datetime.now().isoformat()
    detail = payload.get('detail') or profile['detail']
    _db_exec(
        "INSERT INTO validation_events (id, organization_id, event_type, status, anomaly_id, incident_id, created_by, created_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event_id, org_id, event_type, 'open', anomaly_id, None, user['username'], now, detail)
    )
    anomaly = next(a for a in _validation_anomalies(org_id) if a['id'] == anomaly_id)
    _persist_anomaly(anomaly, organization_id=org_id)
    validation_details = {
        'validation_event_id': event_id,
        'event_type': event_type,
        'controlled_validation': True,
        'severity': anomaly['severity'],
        'risk_score': anomaly['risk_score'],
        'metric': anomaly['metric'],
        'indicator': anomaly['indicator'],
    }
    audit_event('alert_generated', f"anomaly:{anomaly_id}", 'success', f"controlled validation {event_type} severity={anomaly['severity']}", details=validation_details)
    incident, playbook_runs_created = ingest_anomaly_workflow(anomaly, actor=user['username'], organization_id=org_id, create_runs=True)
    _incident_event(
        incident['id'],
        'validation_event_created',
        _json_dumps({**validation_details, 'detail': detail}),
        actor=user['username'],
        organization_id=org_id,
    )
    if playbook_runs_created:
        _incident_event(
            incident['id'],
            'validation_playbook_run_created',
            _json_dumps({
                'validation_event_id': event_id,
                'controlled_validation': True,
                'run_ids': [run['id'] for run in playbook_runs_created],
                'playbooks': [run['name'] for run in playbook_runs_created],
            }),
            actor=user['username'],
            organization_id=org_id,
        )
    _db_exec("UPDATE validation_events SET incident_id = ?, status = ? WHERE id = ?", (incident['id'], 'resolved', event_id))
    audit_event('validation_event_created', f"validation_event:{event_id}", 'success', event_type, details={
        **validation_details,
        'anomaly_id': anomaly_id,
        'incident_id': incident['id'],
        'playbook_run_ids': [run['id'] for run in playbook_runs_created],
    })
    notification_queue.put({'type': 'validation_event', 'event_type': event_type, 'anomaly_id': anomaly_id, 'incident_id': incident['id']})
    return jsonify(
        success=True,
        event_id=event_id,
        event_type=event_type,
        controlled_validation=True,
        anomaly=anomaly,
        incident=_incident_from_row(incident),
        playbook_runs=playbook_runs_created,
    )


@app.route('/api/response_approvals', methods=['GET', 'POST'])
def api_response_approvals():
    user = current_user()
    org_id = user.get('organization_id')
    if request.method == 'GET':
        return jsonify(approvals=[_response_approval_from_row(row) for row in _db_query(
            "SELECT * FROM response_approvals WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100",
            (org_id,)
        )])
    if user['role'] == 'viewer':
        audit_event('access_denied', 'api_response_approvals', 'denied', 'regular user cannot request approvals')
        return jsonify(error='analyst role required'), 403
    payload = request.json or {}
    action = str(payload.get('action') or '').strip()
    target = str(payload.get('target', '')).strip()
    dry_run = bool(payload.get('dry_run', True))
    metadata = _response_action_metadata(action)
    contract = _approval_contract(action)
    if action not in RESPONSE_ACTIONS:
        audit_event('response_approval_failed', 'api_response_approvals', 'failed', f"unsupported action={action}")
        return jsonify(error='unsupported response action'), 400
    if not _role_allowed_by_registry(user, metadata.request_roles):
        audit_event('access_denied', f"response_action:{action}", 'denied', 'response action request role required')
        return jsonify(error='response action request role required'), 403
    if not target:
        audit_event('response_approval_failed', 'api_response_approvals', 'failed', 'target is required')
        return jsonify(error='target is required'), 400
    try:
        preview = _preview_authorized_action(action, target, dry_run=dry_run)
    except Exception as exc:
        reason = _public_error_detail(exc, 'response action validation failed')
        audit_event('response_approval_failed', f"response_action:{action}", 'failed', reason)
        return jsonify(error=reason), 400
    incident_id = _clean_optional_text(payload.get('incident_id'))
    anomaly_id = _clean_optional_text(payload.get('anomaly_id'))
    if incident_id:
        incident = _db_query("SELECT id FROM incidents WHERE id = ? AND organization_id = ?", (incident_id, org_id))
        if not incident:
            audit_event('response_approval_failed', f"incident:{incident_id}", 'failed', 'incident not found')
            return jsonify(error='incident not found'), 404
    approval_id = f"RA-{uuid.uuid4().hex[:10]}"
    now = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(seconds=APPROVAL_TTL_SECONDS)).isoformat()
    request_payload = _approval_payload(action, target, incident_id=incident_id, anomaly_id=anomaly_id, dry_run=dry_run)
    preview_model = approval_preview(request_payload)
    preview = preview_model['detail']
    payload_digest = approval_payload_digest(request_payload)
    preview_digest = approval_preview_digest(request_payload, preview_model)
    _db_exec(
        """
        INSERT INTO response_approvals (
            id, organization_id, incident_id, anomaly_id, action, target, requested_by,
            requester_role, approved_by, approver_role, status, reason, decision_reason,
            dry_run, created_at, updated_at, expires_at, decided_at, executed_at,
            consumed_by, consumed_at, payload_digest, preview_digest, action_type, required_role, result
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            approval_id, org_id, incident_id, anomaly_id, action, target, user['username'],
            user['role'], None, None, 'pending', _clean_optional_text(payload.get('reason')), None,
            int(dry_run), now, now, expires_at, None, None, None, None, payload_digest, preview_digest,
            contract['action_type'], contract['required_role'], preview
        )
    )
    created_approval = _approval_row(approval_id)
    if incident_id:
        _approval_incident_event(
            created_approval,
            'approval_requested',
            f"{action} target={target}",
            actor=user['username'],
            result='success',
        )
        _incident_event(incident_id, 'status_updated', json.dumps({'status': 'waiting_for_approval'}), organization_id=org_id)
        _db_exec("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ? AND organization_id = ?", ('waiting_for_approval', now, incident_id, org_id))
    audit_detail = f"{action} target={target}"
    audit_payload = {
        **_approval_structured_details(created_approval),
        'action_type': contract['action_type'],
        'required_role': contract['required_role'],
        'payload_digest': payload_digest,
    }
    audit_event('response_action_requested', f"approval:{approval_id}", 'success', audit_detail, details=audit_payload)
    audit_event('response_approval_requested', f"approval:{approval_id}", 'success', audit_detail, details=audit_payload)
    return jsonify(success=True, approval=_approval_row(approval_id), preview=preview)


@app.route('/api/response_approvals/<approval_id>', methods=['GET', 'POST'])
def api_response_approval_detail(approval_id):
    approval = _approval_row(approval_id)
    if not approval:
        return jsonify(error='approval not found'), 404
    if request.method == 'GET':
        return jsonify(_approval_diagnostics(approval))
    payload = request.json or {}
    command = payload.get('command')
    user = current_user()
    now = datetime.now().isoformat()
    if command in {'approve', 'reject', 'cancel'}:
        decision_reason = _clean_optional_text(payload.get('reason') or payload.get('decision_reason'))
        if not decision_reason:
            _approval_incident_event(approval, 'approval_decision_blocked', 'decision reason is required', actor=user['username'], result='denied')
            audit_event('response_approval_failed', f"approval:{approval_id}", 'failed', 'decision reason is required')
            return jsonify(error='decision reason is required'), 400
        contract = _approval_contract(approval['action'])
        if not contract:
            _approval_incident_event(approval, 'approval_decision_blocked', 'unsupported response action', actor=user['username'], result='failed')
            audit_event('response_approval_failed', f"approval:{approval_id}", 'failed', 'unsupported response action')
            return jsonify(error='unsupported response action'), 400
        if command in {'approve', 'reject'} and not _role_allows(user, contract['required_role']):
            _approval_incident_event(approval, 'approval_decision_blocked', f"{contract['required_role']} role required", actor=user['username'], result='denied')
            audit_event('access_denied', f"approval:{approval_id}", 'denied', f"{contract['required_role']} role required")
            return jsonify(error=f"{contract['required_role']} role required"), 403
        if command == 'approve' and approval['requested_by'] == user['username']:
            _approval_incident_event(approval, 'approval_decision_blocked', 'self approval is prohibited', actor=user['username'], result='denied')
            audit_event('response_approval_failed', f"approval:{approval_id}", 'denied', 'self approval is prohibited')
            return jsonify(error='requester cannot approve their own request'), 403
        if command == 'cancel' and approval['requested_by'] != user['username'] and user['role'] != 'admin':
            _approval_incident_event(approval, 'approval_decision_blocked', 'only requester or admin can cancel approval', actor=user['username'], result='denied')
            audit_event('access_denied', f"approval:{approval_id}", 'denied', 'only requester or admin can cancel approval')
            return jsonify(error='only requester or admin can cancel approval'), 403
        status = 'cancelled' if command == 'cancel' else ('approved' if command == 'approve' else 'rejected')
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM response_approvals WHERE id = ? AND organization_id = ?",
                (approval_id, user.get('organization_id'))
            ).fetchone()
            if not row:
                conn.rollback()
                return jsonify(error='approval not found'), 404
            current = _response_approval_from_row(row)
            if current['status'] != 'pending':
                conn.rollback()
                _approval_incident_event(current, 'approval_decision_blocked', 'approval already has a terminal decision', actor=user['username'], result='denied')
                audit_event('response_approval_failed', f"approval:{approval_id}", 'denied', 'approval already has a terminal decision')
                return jsonify(error='approval already has a terminal decision', approval=current), 409
            if _approval_expired(current, datetime.fromisoformat(now)):
                _mark_approval_expired(conn, current, now)
                conn.commit()
                expired_approval = _approval_row(approval_id)
                _approval_incident_event(expired_approval, 'approval_expired', f"{current['action']} target={current['target']}", actor=user['username'], result='denied')
                audit_event('response_approval_expired', f"approval:{approval_id}", 'denied', current['action'])
                return jsonify(error='approval request has expired', approval=expired_approval), 409
            updated = conn.execute(
                """
                UPDATE response_approvals
                SET status = ?, approved_by = ?, approver_role = ?, decision_reason = ?,
                    decided_at = ?, updated_at = ?, result = ?
                WHERE id = ? AND organization_id = ? AND status = ?
                """,
                (status, user['username'], user['role'], decision_reason, now, now, decision_reason,
                 approval_id, user.get('organization_id'), 'pending')
            )
            if updated.rowcount != 1:
                conn.rollback()
                return jsonify(error='approval already has a terminal decision', approval=_approval_row(approval_id)), 409
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        finally:
            conn.close()
        updated_approval = _approval_row(approval_id)
        _approval_incident_event(updated_approval, f"approval_{status}", f"{approval['action']} target={approval['target']}", actor=user['username'], reason=decision_reason, result='success')
        details = _approval_structured_details(updated_approval, reason=decision_reason, approver_role=user['role'])
        audit_event(f"response_action_{status}", f"approval:{approval_id}", 'success', approval['action'], details=details)
        audit_event(f"response_approval_{status}", f"approval:{approval_id}", 'success', approval['action'], details=details)
        return jsonify(success=True, approval=updated_approval)
    if command == 'execute':
        execution_payload = _approval_payload(
            payload.get('action', approval['action']),
            payload.get('target', approval['target']),
            payload.get('incident_id', approval.get('incident_id')),
            payload.get('anomaly_id', approval.get('anomaly_id')),
            payload.get('dry_run', bool(approval.get('dry_run'))),
        )
        auth = authorizeApprovedAction(approval_id, {**execution_payload, 'requester': approval['requested_by']}, actor=user, consume=True)
        if not auth['ok']:
            blocked_approval = auth.get('approval') or approval
            _approval_incident_event(blocked_approval, 'response_execution_blocked', auth['error'], actor=user['username'], result='denied')
            audit_event('response_action_started', f"approval:{approval_id}", 'denied', auth['error'], details=_approval_structured_details(blocked_approval, error=auth['error'], result='denied'))
            return jsonify(error=auth['error'], approval=auth.get('approval')), auth['status_code']
        try:
            audit_event('response_action_started', f"approval:{approval_id}", 'success', approval['action'], details=_approval_structured_details(auth['approval'], payload_digest=auth['payload_digest'], result='success'))
            result = _execute_response_action(approval['action'], approval['target'], dry_run=bool(approval['dry_run']))
            _db_exec("UPDATE response_approvals SET executed_at = ?, updated_at = ?, result = ? WHERE id = ?", (now, now, result['detail'], approval_id))
            executed_approval = _approval_row(approval_id)
            _approval_incident_event(executed_approval, 'response_executed', result['detail'], actor=user['username'], result='success', executed=result['executed'])
            result_details = _approval_structured_details(executed_approval, result='success', executed=result['executed'], execution_result=result)
            audit_event('response_action_succeeded', f"approval:{approval_id}", 'success', result['detail'], details=result_details)
            audit_event('response_action_executed', f"approval:{approval_id}", 'success', result['detail'], details=result_details)
            return jsonify(success=True, result=result, approval=executed_approval)
        except Exception as exc:
            failure_result = _json_loads(str(exc), None)
            if isinstance(failure_result, dict) and failure_result.get('detail'):
                failure_detail = failure_result['detail']
            else:
                failure_result = None
                failure_detail = 'response action execution failed'
                app.logger.error('response action execution failed correlation_id=%s exception_type=%s', uuid.uuid4().hex, type(exc).__name__)
            _db_exec(
                "UPDATE response_approvals SET executed_at = ?, updated_at = ?, result = ? WHERE id = ?",
                (now, now, failure_detail, approval_id)
            )
            failed_approval = _approval_row(approval_id)
            _approval_incident_event(failed_approval, 'response_failed', failure_detail, actor=user['username'], result='failed')
            failed_details = _approval_structured_details(failed_approval, error=failure_detail, result='failed', execution_result=failure_result)
            audit_event('response_action_failed', f"approval:{approval_id}", 'failed', failure_detail, details=failed_details)
            audit_event('response_action_executed', f"approval:{approval_id}", 'failed', failure_detail, details=failed_details)
            return jsonify(error=failure_detail, result=failure_result, approval=failed_approval), 400
    audit_event('response_approval_failed', f"approval:{approval_id}", 'failed', f"unsupported command={command}")
    return jsonify(error='unsupported command'), 400

def op_eval(value, operator, threshold):
    if operator == '>': return value > threshold
    if operator == '<': return value < threshold
    if operator == '>=': return value >= threshold
    if operator == '<=': return value <= threshold
    if operator in {'==', 'equals'}: return value == threshold
    return False

def apply_playbooks(anomalies):
    seen = {(r.get('playbook_id'), r.get('anomaly_id')) for r in _playbook_runs_from_db(limit=1000)}
    for anomaly in anomalies:
        for pb in persisted_playbook_matches(anomaly, organization_id=anomaly.get('organization_id')):
            _record_playbook_run(anomaly, pb, seen=seen)


def _workspace_playbooks(organization_id):
    return _playbooks_from_db(organization_id)


def _write_rejected_audit(payload, reason, actor=None, org_id=None):
    audit_event(
        'playbook.write_rejected',
        f"playbook:{payload.get('stable_key') or payload.get('id') or payload.get('name') or 'unknown'}",
        'failed',
        reason,
        actor=actor,
        organization_id=org_id,
        details={
            'request_digest': _request_digest(payload),
            'reason': reason,
            'stable_key': payload.get('stable_key'),
        },
    )


def _playbook_row_by_identifier(identifier, organization_id):
    if identifier is None:
        return None
    rows = _db_query(
        "SELECT * FROM playbooks WHERE (id = ? OR stable_key = ?) AND (organization_id IS NULL OR organization_id = ?) LIMIT 1",
        (identifier, str(identifier), organization_id)
    )
    return rows[0] if rows else None


def _persist_playbook_definition(definition, existing=None, organization_id=None):
    if existing:
        _db_exec(
            """
            UPDATE playbooks
            SET name = ?, description = ?, kind = ?, category = ?, metric = ?,
                operator = ?, threshold = ?, action = ?, target = ?, enabled = ?,
                auto = ?, yaml = ?, trigger_json = ?, recommended_action_key = ?,
                required_approval_role = ?, steps_yaml = ?, source = ?, version = ?,
                definition_digest = ?, updated_at = ?, updated_by = ?
            WHERE id = ?
            """,
            (
                definition['name'], definition['description'], definition['kind'], definition['category'],
                definition['metric'], definition['operator'], definition['threshold'], definition['action'],
                definition['target'], int(definition['enabled']), int(definition['auto']), definition['yaml'],
                definition['trigger_json'], definition['recommended_action_key'], definition['required_approval_role'],
                definition['steps_yaml'], definition['source'], definition['version'], definition['definition_digest'],
                definition['updated_at'], definition['updated_by'], existing['id'],
            )
        )
        return existing['id']
    cur = _db_exec(
        """
        INSERT INTO playbooks (
            organization_id, stable_key, name, description, kind, category, metric,
            operator, threshold, action, target, enabled, auto, yaml, trigger_json,
            recommended_action_key, required_approval_role, steps_yaml, source, version,
            definition_digest, created_at, created_by, updated_at, updated_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            organization_id, definition['stable_key'], definition['name'], definition['description'],
            definition['kind'], definition['category'], definition['metric'], definition['operator'],
            definition['threshold'], definition['action'], definition['target'], int(definition['enabled']),
            int(definition['auto']), definition['yaml'], definition['trigger_json'], definition['recommended_action_key'],
            definition['required_approval_role'], definition['steps_yaml'], definition['source'],
            definition['version'], definition['definition_digest'], definition['created_at'], definition['created_by'],
            definition['updated_at'], definition['updated_by'],
        )
    )
    return cur.lastrowid


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
    existing = None
    if payload.get('action') in {'update', 'enable', 'disable', 'toggle'} or payload.get('id') or payload.get('stable_key'):
        existing = _playbook_row_by_identifier(payload.get('id') or payload.get('stable_key'), org_id)
        if payload.get('action') in {'update', 'enable', 'disable', 'toggle'} and not existing:
            _write_rejected_audit(payload, 'playbook not found', actor=user['username'], org_id=org_id)
            return jsonify(error='playbook not found'), 404
    if payload.get('action') == 'enable':
        payload['enabled'] = True
    elif payload.get('action') == 'disable':
        payload['enabled'] = False
    elif payload.get('action') == 'toggle' and existing:
        payload['enabled'] = not bool(existing['enabled'])
    try:
        existing_model = _playbooks_from_db(org_id)
        existing_pb = next((pb for pb in existing_model if existing and pb['id'] == existing['id']), None)
        definition = _normalize_playbook_definition(payload, existing=existing_pb, actor=user['username'], source=(existing_pb or {}).get('source') or payload.get('source') or PLAYBOOK_SOURCE_CUSTOM)
    except Exception as exc:
        reason = _public_error_detail(exc, 'playbook validation failed')
        _write_rejected_audit(payload, reason, actor=user['username'], org_id=org_id)
        if reason == 'trigger threshold must be numeric':
            audit_event('playbook_create_failed', 'playbook:new', 'failed', 'threshold must be numeric')
        return jsonify(error=reason), 400
    if not existing and _db_query("SELECT id FROM playbooks WHERE stable_key = ?", (definition['stable_key'],)):
        _write_rejected_audit(payload, 'stable_key already exists', actor=user['username'], org_id=org_id)
        return jsonify(error='stable_key already exists'), 400
    playbook_id = _persist_playbook_definition(definition, existing=existing, organization_id=org_id)
    load_persistent_state()
    saved = next(pb for pb in _playbooks_from_db(org_id) if pb['id'] == playbook_id)
    event_type = 'playbook_updated' if existing else 'playbook_created'
    audit_event(event_type, f"playbook:{saved['stable_key']}", 'success', saved['name'], details={
        'stable_key': saved['stable_key'],
        'version': saved['version'],
        'definition_digest': saved['definition_digest'],
        'old_definition_digest': (existing_pb or {}).get('definition_digest') if existing else None,
        'changed': (existing_pb or {}).get('definition_digest') != saved['definition_digest'] if existing else True,
    })
    return jsonify(success=True, playbook=saved, playbooks=_workspace_playbooks(org_id))

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
        pb = next(iter(persisted_playbook_matches(anomaly, organization_id=org_id)), None)
    if not pb:
        audit_event('playbook_trigger_failed', f"playbook:{pb_id or 'auto'}", 'failed', f"anomaly={payload.get('anomaly_id') or 'manual'}")
        return jsonify(success=False, message='Playbook not found'), 404
    if anomaly:
        incident_rows = _db_query("SELECT * FROM incidents WHERE anomaly_id = ? AND organization_id = ? LIMIT 1", (anomaly['id'], org_id))
        if incident_rows:
            anomaly = dict(anomaly)
            anomaly['incident_id'] = incident_rows[0]['id']
        run_entry = _record_playbook_run(anomaly, pb)
        if run_entry is None:
            existing = _db_query("SELECT * FROM playbook_runs WHERE anomaly_id = ? AND playbook_id = ? LIMIT 1", (anomaly['id'], pb['id']))
            run_entry = _playbook_runs_from_db(org_id, [pb['id']], limit=1000)
            run_entry = next((run for run in run_entry if run['anomaly_id'] == anomaly['id']), None)
    else:
        manual_anomaly = {
            'id': None,
            'organization_id': org_id,
            'incident_id': None,
            'metric': payload.get('metric') or pb.get('metric') or 'manual',
            'value': float(payload.get('value') or 0),
            'created_by': current_user()['username'],
        }
        run_entry = {
        'organization_id': org_id,
        'playbook_id': pb['id'],
            'playbook_stable_key': pb.get('stable_key'),
            'playbook_name': pb['name'],
            'playbook_kind': pb.get('kind'),
            'playbook_version': pb.get('version'),
            'definition_digest': pb.get('definition_digest'),
        'name': pb['name'],
            'anomaly_id': None,
            'incident_id': None,
            'metric': manual_anomaly['metric'],
            'value': manual_anomaly['value'],
        'threshold': pb['threshold'],
            'action': pb.get('recommended_action_key') or pb['action'],
            'recommended_action_key': pb.get('recommended_action_key') or pb['action'],
            'required_approval_role': pb.get('required_approval_role') or 'none',
        'target': pb['target'],
        'timestamp': datetime.now().isoformat(),
            'created_at': datetime.now().isoformat(),
            'created_by': current_user()['username'],
        'auto': False,
        'status': 'open',
            'yaml': pb.get('steps_yaml') or pb.get('yaml', ''),
            'steps_yaml': pb.get('steps_yaml') or pb.get('yaml', ''),
    }
        cur = _db_exec(
            """
            INSERT INTO playbook_runs (organization_id, playbook_id, playbook_stable_key, playbook_name, playbook_kind, playbook_version, definition_digest, name, anomaly_id, incident_id, metric, value, threshold, action, recommended_action_key, required_approval_role, target, timestamp, created_at, created_by, auto, status, yaml, steps_yaml)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_entry['organization_id'], run_entry['playbook_id'], run_entry['playbook_stable_key'], run_entry['playbook_name'], run_entry['playbook_kind'], run_entry['playbook_version'], run_entry['definition_digest'], run_entry['name'], run_entry['anomaly_id'], run_entry['incident_id'], run_entry['metric'], run_entry['value'], run_entry['threshold'], run_entry['action'], run_entry['recommended_action_key'], run_entry['required_approval_role'], run_entry['target'], run_entry['timestamp'], run_entry['created_at'], run_entry['created_by'], int(run_entry['auto']), run_entry['status'], run_entry['yaml'], run_entry['steps_yaml'])
        )
        run_entry['id'] = cur.lastrowid
        playbook_runs.append(run_entry)
    audit_event('playbook_triggered', f"playbook:{pb['id']}", 'success', f"anomaly={payload.get('anomaly_id') or 'manual'}", details={'run_id': run_entry['id'], 'anomaly_id': payload.get('anomaly_id')})
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
            history=_automation_history_from_db()
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
    audit_event('automation_rule_created', f"automation_rule:{rule['id']}", 'success', rule['name'], details=rule)
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

    try:
        threshold = float(payload.get('threshold', 90))
    except (TypeError, ValueError):
        audit_event('anomaly_rule_create_failed', 'anomaly_rule:new', 'failed', 'threshold must be numeric')
        return jsonify(error='threshold must be numeric'), 400
    rule = {
        'id': next_rule_id,
        'metric': payload.get('metric', 'cpu_percent'),
        'operator': payload.get('operator', '>'),
        'threshold': threshold,
        'severity': normalize_severity(payload.get('severity', 'high'), default='info'),
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
    audit_event('anomaly_rule_created', f"anomaly_rule:{rule['id']}", 'success', f"{rule['metric']} {rule['operator']} {rule['threshold']}", details=rule)
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
        start=request.args.get('start') or request.args.get('start_time') or None,
        end=request.args.get('end') or request.args.get('end_time') or None,
        organization_id=user.get('organization_id') if user else None,
    ))

@app.route('/api/audit')
def api_audit():
    return api_audit_events()


@app.route('/api/vocabulary')
def api_vocabulary():
    return jsonify(vocabulary_payload())

@app.route('/api/audit_summary')
def api_audit_summary():
    user = current_user()
    rows = _audit_rows(limit=200, organization_id=user.get('organization_id') if user else None)
    medium_count = len([r for r in rows if r['severity'] == 'medium'])
    denied = len([r for r in rows if r['outcome'] == 'denied'])
    return jsonify(summary=f"{len(rows)} telemetry audit events, {medium_count} Medium severity, {denied} denied outcomes")

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
        severity = normalize_severity(anomaly.get('severity'), default='info')
        status = normalize_status('open' if anomaly['risk_score'] >= 75 else 'investigating')
        alerts.append({
            'id': anomaly['id'],
            'time': anomaly['timestamp'],
            'event': f"{anomaly['metric']} anomaly",
            'severity': severity,
            'severity_label': severity_label(severity),
            'severity_class': severity_class(severity),
            'source': anomaly.get('indicator', 'local telemetry'),
            'status': status,
            'status_label': status_label(status),
            'status_class': status_class(status),
            'title': f"{severity_label(severity)} {anomaly['metric']} anomaly",
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

def health_payload():
    return {
        'ok': sampler_is_healthy(),
        'service': 'saaoe',
        'version': SAAOE_VERSION,
    }


@app.route('/health')
@app.route('/healthz')
def health():
    payload = health_payload()
    return jsonify(payload), 200 if payload['ok'] else 503

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
    health = 'critical' if cpu > CPU_THRESHOLD or mem > MEMORY_THRESHOLD else ('medium' if cpu > (CPU_THRESHOLD * 0.8) or mem > (MEMORY_THRESHOLD * 0.8) else 'info')
    addrs = []
    for entries in psutil.net_if_addrs().values():
        for entry in entries:
            if getattr(entry, 'family', None) == socket.AF_INET and entry.address != '127.0.0.1':
                addrs.append(entry.address)
    local = {
        'name': socket.gethostname(),
        'ip': addrs[0] if addrs else '127.0.0.1',
        'health': health,
        'health_label': severity_label(health),
        'health_class': severity_class(health),
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

def create_app(config_overrides=None):
    if config_overrides:
        app.config.update(config_overrides)
    init_db()
    _seed_db()
    load_persistent_state()
    return app


if __name__ == '__main__':
    if CONFIG.terminal_ws_enabled:
        start_terminal_ws()
    for line in startup_summary(CONFIG):
        print(line)
    if not CONFIG.protected_bind:
        print('WARNING: SAAOE is not bound to a loopback address. Use authentication, TLS, and network controls before exposing it.')
    app.run(host=APP_HOST, port=APP_PORT, debug=SAAOE_DEBUG)
