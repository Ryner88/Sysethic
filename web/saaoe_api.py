import threading
import time
from collections import deque
from datetime import datetime
import queue
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
import select
import shlex
import socketserver
import struct
import subprocess

import psutil
from flask import Flask, jsonify, render_template, Response, stream_with_context, request
import pandas as pd

try:
    import GPUtil  # optional
except Exception:
    GPUtil = None

# --- Flask app ---
app = Flask(__name__, static_folder='static', template_folder='templates')

# Paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_PATH = os.path.join(BASE_DIR, "logs", "system_log.csv")

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
    {'id': 1, 'metric': 'cpu_percent', 'operator': '>', 'threshold': 90, 'severity': 'critical', 'enabled': True, 'alert_in_app': True, 'alert_email': False},
    {'id': 2, 'metric': 'memory_percent', 'operator': '>', 'threshold': 85, 'severity': 'high', 'enabled': True, 'alert_in_app': True, 'alert_email': False},
]
next_rule_id = 3

playbooks = [
    {'id': 1, 'name': 'Kill runaway CPU', 'category': 'system', 'metric': 'cpu_percent', 'operator': '>', 'threshold': 95, 'action': 'kill_process', 'target': 'cmdline', 'enabled': True, 'auto': True, 'yaml': 'name: Kill runaway CPU\ncategory: system\nsteps:\n  - action: snapshot_process\n    target: top_cpu\n  - action: isolate_process\n    target: "{{ process.pid }}"\n  - action: notify\n    target: security-ops\n'},
    {'id': 2, 'name': 'Isolate suspicious IP', 'category': 'network', 'metric': 'memory_percent', 'operator': '>', 'threshold': 90, 'action': 'block_ip', 'target': 'external', 'enabled': True, 'auto': False, 'yaml': 'name: Isolate suspicious IP\ncategory: network\nsteps:\n  - action: block_ip\n    target: "{{ anomaly.ip }}"\n  - action: collect_connections\n    target: host\n'},
]
next_playbook_id = 3
playbook_runs = []

automation_rules = [
    {'id': 1, 'name': 'Critical containment', 'field': 'severity', 'operator': 'equals', 'value': 'critical', 'action': 'Isolate Process', 'enabled': True},
    {'id': 2, 'name': 'High risk evidence capture', 'field': 'risk_score', 'operator': '>=', 'value': '75', 'action': 'Capture Forensics Bundle', 'enabled': True},
]
next_automation_rule_id = 3
automation_history = []

THREAT_INTEL_PATH = os.environ.get('THREAT_INTEL_PATH', os.path.join(BASE_DIR, 'config', 'threat_intel.json'))

DIAGNOSTIC_COMMANDS = {'netstat', 'ss', 'grep', 'rg', 'ps', 'uptime', 'whoami', 'hostname'}
TERMINAL_WS_STARTED = False

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


def _threat_lookup(indicator_type, indicator):
    feed = _load_threat_intel().get(f'{indicator_type}s', {})
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


def _load_anomalies(start=None, end=None, severity=None, apply_automation=True):
    if not os.path.exists(LOG_PATH):
        return []

    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    if df.empty:
        return []

    if start:
        df = df[df['timestamp'] >= pd.to_datetime(start)]
    if end:
        df = df[df['timestamp'] <= pd.to_datetime(end)]

    anomalies = []
    for col in ['cpu_percent', 'memory_percent']:
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

    decorated = [_decorate_threat_intel(a) for a in anomalies]
    sorted_list = sorted(decorated, key=lambda x: x['timestamp'], reverse=True)
    if apply_automation:
        apply_playbooks(sorted_list)
        apply_automation_rules(sorted_list)
    if severity:
        sorted_list = [a for a in sorted_list if a.get('severity') == severity]
    return sorted_list[:200]


def _audit_rows(limit=100):
    logs = []
    if os.path.exists(LOG_PATH):
        df = pd.read_csv(LOG_PATH, parse_dates=['timestamp']).tail(limit)
        for _, row in df.iterrows():
            sev = 'warning' if row.get('cpu_percent', 0) > 70 else 'info'
            outcome = 'flagged' if sev == 'warning' else 'allowed'
            logs.append({
                'timestamp': row['timestamp'].isoformat(),
                'action': 'metric_sample',
                'role': 'system',
                'severity': sev,
                'outcome': outcome,
                'resource': 'host.telemetry',
                'details': f"CPU {row.get('cpu_percent', 0):.1f}%, memory {row.get('memory_percent', 0):.1f}%"
            })
    return logs


def _report_summary():
    anomalies = _load_anomalies(apply_automation=False)
    audits = _audit_rows()
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
    seen = {(h.get('rule_id'), h.get('anomaly_id')) for h in automation_history}
    for anomaly in anomalies[:25]:
        for rule in automation_rules:
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
                automation_history.append(entry)
                notification_queue.put({'type': 'automation_action', 'rule': rule['name'], 'details': entry})


def _timeline_for_anomaly(anomaly_id):
    anomaly = next((a for a in _load_anomalies(apply_automation=False) if a['id'] == anomaly_id), None)
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
    base = os.path.basename(parts[0])
    if base not in DIAGNOSTIC_COMMANDS:
        return None, f"Command '{base}' is not enabled. Allowed: {', '.join(sorted(DIAGNOSTIC_COMMANDS))}"
    if any(token.startswith('/') or '..' in token for token in parts[1:]):
        return None, 'Absolute paths and parent directory traversal are blocked in browser diagnostics.'
    return parts, None


def _ws_send(sock, text):
    payload = text.encode('utf-8')
    if len(payload) < 126:
        header = struct.pack('!BB', 0x81, len(payload))
    elif len(payload) < 65536:
        header = struct.pack('!BBH', 0x81, 126, len(payload))
    else:
        header = struct.pack('!BBQ', 0x81, 127, len(payload))
    sock.sendall(header + payload)


def _ws_recv(sock):
    header = sock.recv(2)
    if len(header) < 2:
        return None
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if opcode == 0x8:
        return None
    if length == 126:
        length = struct.unpack('!H', sock.recv(2))[0]
    elif length == 127:
        length = struct.unpack('!Q', sock.recv(8))[0]
    mask = sock.recv(4)
    data = bytearray(sock.recv(length))
    for i in range(length):
        data[i] ^= mask[i % 4]
    return data.decode('utf-8', errors='replace')


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
        _ws_send(self.request, 'Connected to SAAOE diagnostic terminal. Allowed commands: ' + ', '.join(sorted(DIAGNOSTIC_COMMANDS)) + '\n')
        while True:
            command = _ws_recv(self.request)
            if command is None:
                break
            args, error = _validate_terminal_command(command)
            if error:
                _ws_send(self.request, f"blocked: {error}\n")
                continue
            try:
                proc = subprocess.Popen(args, cwd=BASE_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                start = time.time()
                while proc.poll() is None:
                    if time.time() - start > 12:
                        proc.kill()
                        _ws_send(self.request, '\ncommand timed out after 12 seconds\n')
                        break
                    ready, _, _ = select.select([proc.stdout], [], [], 0.2)
                    if ready:
                        line = proc.stdout.readline()
                        if line:
                            _ws_send(self.request, line)
                if proc.stdout:
                    for line in proc.stdout.readlines():
                        _ws_send(self.request, line)
                _ws_send(self.request, f"\nexit {proc.returncode if proc.returncode is not None else 'timeout'}\n")
            except FileNotFoundError:
                _ws_send(self.request, f"{args[0]} is not installed on this host\n")
            except Exception as exc:
                _ws_send(self.request, f"terminal error: {exc}\n")


def start_terminal_ws():
    global TERMINAL_WS_STARTED
    if TERMINAL_WS_STARTED:
        return
    TERMINAL_WS_STARTED = True
    try:
        server = socketserver.ThreadingTCPServer(('127.0.0.1', 8765), TerminalWebSocketHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except OSError:
        pass


start_terminal_ws()

# --- Routes ---
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
    return render_template('terminal.html')

@app.route('/reports')
def reports_page():
    return render_template('reports.html')

@app.route('/automation')
def automation_page():
    return render_template('automation.html')

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

    for i, timestamp in enumerate(timestamps):
        cpu = float(cpu_values[i]) if i < len(cpu_values) else 0.0
        memory = float(mem_values[i]) if i < len(mem_values) else 0.0
        rx = float(rx_values[i]) if i < len(rx_values) else 0.0
        tx = float(tx_values[i]) if i < len(tx_values) else 0.0

        anomaly_score = min(100.0, (cpu * 0.45) + (memory * 0.35) + ((rx + tx) * 8.0))

        points.append({
            'timestamp': timestamp,
            'cpu': round(cpu, 2),
            'memory': round(memory, 2),
            'network': round(rx + tx, 4),
            'anomaly_score': round(anomaly_score, 2),
            'risk_level': (
                'critical' if anomaly_score >= 85 else
                'high' if anomaly_score >= 65 else
                'medium' if anomaly_score >= 40 else
                'low'
            )
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
    return jsonify(host='127.0.0.1', port=8765, allowed=sorted(DIAGNOSTIC_COMMANDS))

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
    return jsonify(anomalies=_load_anomalies(
        start=request.args.get('start'),
        end=request.args.get('end'),
        severity=request.args.get('severity')
    ))

@app.route('/api/anomalies/heatmap')
def api_anomalies_heatmap():
    anomalies = _load_anomalies(apply_automation=False)
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
    if not anomaly:
        return jsonify(error='not found'), 404
    return jsonify(anomaly=anomaly, timeline=events)

def op_eval(value, operator, threshold):
    if operator == '>': return value > threshold
    if operator == '<': return value < threshold
    if operator == '>=': return value >= threshold
    if operator == '<=': return value <= threshold
    return False

def apply_playbooks(anomalies):
    seen = {(r.get('playbook_id'), r.get('anomaly_id')) for r in playbook_runs}
    for anomaly in anomalies:
        for pb in playbooks:
            if not pb.get('enabled', False):
                continue
            if anomaly.get('metric') != pb.get('metric'):
                continue
            if op_eval(anomaly.get('value', 0), pb.get('operator'), pb.get('threshold')):
                if (pb['id'], anomaly.get('id')) in seen:
                    continue
                run_entry = {
                    'id': len(playbook_runs)+1,
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
                playbook_runs.append(run_entry)
                seen.add((pb['id'], anomaly.get('id')))
                if pb.get('auto'):
                    notification_queue.put({
                        'type': 'playbook_trigger',
                        'playbook': pb['name'],
                        'details': run_entry
                    })

@app.route('/api/playbooks', methods=['GET', 'POST'])
def api_playbooks():
    global next_playbook_id
    if request.method == 'GET':
        return jsonify(playbooks=playbooks, runs=playbook_runs)
    payload = request.json or {}
    if payload.get('action') == 'delete':
        pid = int(payload.get('id', 0))
        playbooks[:] = [pb for pb in playbooks if pb['id'] != pid]
        return jsonify(success=True, playbooks=playbooks)
    new_pb = {
        'id': next_playbook_id,
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
    playbooks.append(new_pb)
    next_playbook_id += 1
    return jsonify(success=True, playbook=new_pb, playbooks=playbooks)

@app.route('/api/playbook_trigger', methods=['POST'])
def api_playbook_trigger():
    payload = request.json or {}
    pb_id = int(payload.get('id', 0) or 0)
    anomaly = None
    if payload.get('anomaly_id'):
        anomaly = next((a for a in _load_anomalies(apply_automation=False) if a['id'] == payload.get('anomaly_id')), None)
    pb = next((x for x in playbooks if x['id'] == pb_id), None)
    if not pb and anomaly:
        pb = next((x for x in playbooks if x.get('enabled') and x.get('category') == anomaly.get('category')), None)
    if not pb and anomaly:
        pb = next((x for x in playbooks if x.get('enabled') and x.get('metric') == anomaly.get('metric')), None)
    if not pb:
        return jsonify(success=False, message='Playbook not found'), 404
    run_entry = {
        'id': len(playbook_runs)+1,
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
    playbook_runs.append(run_entry)
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

@app.route('/api/reports/download.<fmt>')
def api_reports_download(fmt):
    summary = _report_summary()
    if fmt == 'csv':
        return _csv_response(summary)
    if fmt == 'pdf':
        return _pdf_response(summary)
    return jsonify(error='unsupported format'), 400

@app.route('/api/automation_rules', methods=['GET', 'POST'])
def api_automation_rules():
    global next_automation_rule_id
    if request.method == 'GET':
        return jsonify(rules=automation_rules, history=automation_history[-100:])
    payload = request.json or {}
    if payload.get('action') == 'delete':
        rid = int(payload.get('id', 0))
        automation_rules[:] = [r for r in automation_rules if r['id'] != rid]
        return jsonify(success=True, rules=automation_rules)
    rule = {
        'id': next_automation_rule_id,
        'name': payload.get('name', 'New automation rule'),
        'field': payload.get('field', 'severity'),
        'operator': payload.get('operator', 'equals'),
        'value': payload.get('value', 'critical'),
        'action': payload.get('run_action', 'Isolate Process'),
        'enabled': bool(payload.get('enabled', True)),
    }
    automation_rules.append(rule)
    next_automation_rule_id += 1
    return jsonify(success=True, rule=rule, rules=automation_rules)

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
        return jsonify(rules=anomaly_rules)

    payload = request.json or {}
    if 'action' in payload and payload['action'] == 'delete':
        rid = int(payload.get('id', 0))
        anomaly_rules[:] = [r for r in anomaly_rules if r['id'] != rid]
        return jsonify(success=True, rules=anomaly_rules)

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
    anomaly_rules.append(rule)
    next_rule_id += 1
    return jsonify(success=True, rule=rule, rules=anomaly_rules)

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
    return jsonify({'status': 'test anomaly sent'})

@app.route('/api/logs')
def api_logs():
    if not os.path.exists(LOG_PATH):
        return jsonify(logs=[])
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    logs = df.tail(20).to_dict(orient='records')
    return jsonify(logs=logs)

@app.route('/api/audit_summary')
def api_audit_summary():
    rows = _audit_rows(limit=200)
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
    return jsonify(access=sorted(files, key=lambda x: x['time'], reverse=True)[:200])

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
    health = 'critical' if cpu > 90 or mem > 90 else ('warning' if cpu > 70 or mem > 80 else 'good')
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
    app.run(host='0.0.0.0', port=5000, debug=True)
