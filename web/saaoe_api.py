import threading
import time
from collections import deque
from datetime import datetime
import queue
import statistics
import json
import socket
import random

import psutil
from flask import Flask, jsonify, render_template, Response, stream_with_context, request
import pandas as pd
import os

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
    {'id': 1, 'name': 'Kill runaway CPU', 'metric': 'cpu_percent', 'operator': '>', 'threshold': 95, 'action': 'kill_process', 'target': 'cmdline', 'enabled': True, 'auto': True},
    {'id': 2, 'name': 'Isolate suspicious IP', 'metric': 'memory_percent', 'operator': '>', 'threshold': 90, 'action': 'block_ip', 'target': 'external', 'enabled': True, 'auto': False},
]
next_playbook_id = 3
playbook_runs = []

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
    for p in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            info = p.info
            cpu = float(info.get('cpu_percent') or 0.0)
            rss = info.get('memory_info').rss if info.get('memory_info') else 0
            procs.append({
                'pid': int(info.get('pid')), 'name': (info.get('name') or 'proc')[:40],
                'cpu': cpu, 'mem_mb': float(rss) / (1024*1024)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    cpu_top = sorted(procs, key=lambda x: x['cpu'], reverse=True)[:n]
    mem_top = sorted(procs, key=lambda x: x['mem_mb'], reverse=True)[:n]
    data = {'cpu_top': cpu_top, 'mem_top': mem_top, 'ts': datetime.now().strftime('%H:%M:%S')}
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

@app.route('/api/usage')
def api_usage():
    return jsonify({'cpu': list(cpu_series), 'memory': list(mem_series), 'timestamps': list(usage_ts)})

@app.route('/api/disk')
def api_disk():
    return jsonify({'read': list(read_series), 'write': list(write_series), 'timestamps': list(disk_ts)})

@app.route('/api/net')
def api_net():
    return jsonify({'rx': list(rx_series), 'tx': list(tx_series), 'timestamps': list(net_ts)})

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
    return jsonify(rows=rows[:limit], updated=data['ts'])

@app.route('/api/temps')
def api_temps():
    return jsonify({'temps': _read_temps()})

@app.route('/api/gpu')
def api_gpu():
    return jsonify(_read_gpus())

@app.route('/anomalies')
def anomalies_page():
    return render_template('anomalies.html')

@app.route('/api/anomalies')
def api_anomalies():
    if not os.path.exists(LOG_PATH):
        return jsonify(anomalies=[])

    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    if df.empty:
        return jsonify(anomalies=[])

    # filter window support
    start = request.args.get('start')
    end = request.args.get('end')
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
            severity = 'critical' if z > 3 else 'high'
            anomalies.append({
                'timestamp': row['timestamp'].isoformat(),
                'metric': col,
                'value': float(row[col]),
                'threshold': float(thresh),
                'severity': severity,
                'category': 'system',
                'confidence': min(1.0, abs(z) / 5)
            })

    # apply custom rules (extends results)
    for rule in anomaly_rules:
        if not rule.get('enabled'):
            continue
        metric = rule['metric']
        if metric not in df.columns:
            continue
        rvalue = df[metric].iloc[-1] if not df.empty else None
        if rvalue is None:
            continue
        ops = {
            '>': rvalue > rule['threshold'],
            '<': rvalue < rule['threshold'],
            '>=': rvalue >= rule['threshold'],
            '<=': rvalue <= rule['threshold']
        }
        if ops.get(rule['operator'], False):
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

    # sort and limit
    sorted_list = sorted(anomalies, key=lambda x: x['timestamp'], reverse=True)

    # apply playbooks
    apply_playbooks(sorted_list)

    # filtering by severity
    severity = request.args.get('severity')
    if severity:
        sorted_list = [a for a in sorted_list if a.get('severity') == severity]

    return jsonify(anomalies=sorted_list[:200])

def op_eval(value, operator, threshold):
    if operator == '>': return value > threshold
    if operator == '<': return value < threshold
    if operator == '>=': return value >= threshold
    if operator == '<=': return value <= threshold
    return False

def apply_playbooks(anomalies):
    for anomaly in anomalies:
        for pb in playbooks:
            if not pb.get('enabled', False):
                continue
            if anomaly.get('metric') != pb.get('metric'):
                continue
            if op_eval(anomaly.get('value', 0), pb.get('operator'), pb.get('threshold')):
                run_entry = {
                    'id': len(playbook_runs)+1,
                    'playbook_id': pb['id'],
                    'name': pb['name'],
                    'metric': anomaly['metric'],
                    'value': anomaly['value'],
                    'threshold': pb['threshold'],
                    'action': pb['action'],
                    'target': pb['target'],
                    'timestamp': datetime.now().isoformat(),
                    'auto': pb.get('auto', False),
                    'status': 'executed' if pb.get('auto') else 'ready'
                }
                playbook_runs.append(run_entry)
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
        'metric': payload.get('metric', 'cpu_percent'),
        'operator': payload.get('operator', '>'),
        'threshold': float(payload.get('threshold', 90)),
        'action': payload.get('action_type', 'block_ip'),
        'target': payload.get('target', 'external'),
        'enabled': bool(payload.get('enabled', True)),
        'auto': bool(payload.get('auto', False))
    }
    playbooks.append(new_pb)
    next_playbook_id += 1
    return jsonify(success=True, playbook=new_pb, playbooks=playbooks)

@app.route('/api/playbook_trigger', methods=['POST'])
def api_playbook_trigger():
    payload = request.json or {}
    pb_id = int(payload.get('id', 0))
    pb = next((x for x in playbooks if x['id'] == pb_id), None)
    if not pb:
        return jsonify(success=False, message='Playbook not found'), 404
    run_entry = {
        'id': len(playbook_runs)+1,
        'playbook_id': pb['id'],
        'name': pb['name'],
        'metric': payload.get('metric', 'n/a'),
        'value': payload.get('value', 0),
        'threshold': pb['threshold'],
        'action': pb['action'],
        'target': pb['target'],
        'timestamp': datetime.now().isoformat(),
        'auto': False,
        'status': 'manual_triggered'
    }
    playbook_runs.append(run_entry)
    notification_queue.put({'type':'playbook_manual_trigger','playbook':pb['name'],'details':run_entry})
    return jsonify(success=True, run=run_entry)

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
    # Placeholder for audit summary
    return jsonify(summary="5 critical events in last hour, 23 warnings")

@app.route('/api/ai_alerts')
def api_ai_alerts():
    # Placeholder for AI alerts
    return jsonify(alerts="Model drift detected, retraining recommended")

@app.route('/api/security/alerts')
def api_security_alerts():
    # Mock security alerts
    return jsonify(alerts=[
        {'time': '14:32', 'event': 'Unauthorized access', 'severity': 'High', 'source': '192.168.1.100'},
        {'time': '14:28', 'event': 'Firewall triggered', 'severity': 'Medium', 'source': 'eth0'}
    ])

@app.route('/api/files/access')
def api_files_access():
    # Mock file access
    return jsonify(access=[
        {'time': '14:45', 'user': 'user1', 'file': '/home/user1/docs/private.txt', 'action': 'Read', 'classification': 'Private'}
    ])

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
    # mocked assets summary, in prod should be from CMDB / service inventory
    local = {'name': socket.gethostname(), 'ip': socket.gethostbyname(socket.gethostname()), 'health': 'good', 'active_processes': len(psutil.pids()), 'vuln_scan': '2026-03-19 (no findings)'}
    peers = []
    for i in range(3):
        peers.append({
            'name': f'host-{100+i}',
            'ip': f'10.0.1.{i+5}',
            'health': random.choice(['good', 'warning', 'critical']),
            'active_processes': random.randint(40, 150),
            'vuln_scan': f'2026-03-{15+i} ' + random.choice(['(no findings)', '(low findings)', '(needs patch)'])
        })
    return jsonify(assets=[local] + peers)

@app.route('/api/threat_trends')
def api_threat_trends():
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp']) if os.path.exists(LOG_PATH) else pd.DataFrame()
    if df.empty:
        return jsonify(trends=[])

    df['day'] = df['timestamp'].dt.floor('D')
    summary = df.groupby('day').agg(anomalies=('cpu_percent','count')).reset_index()
    # severity distribution mock
    data = []
    for _, row in summary.iterrows():
        data.append({'day': row['day'].strftime('%Y-%m-%d'), 'count': int(row['anomalies']), 'critical': random.randint(0, 4), 'high': random.randint(0, 8), 'medium': random.randint(0,10), 'low': random.randint(0,12)})
    return jsonify(trends=data)

@app.route('/api/net_graph')
def api_net_graph():
    # Adult minimal graph - process-to-external ip mapping using live pid connections
    connections = []
    try:
        # use psutil.net_connections to avoid deprecation warning (p.connections deprecated)
        proc_map = {p.pid: p.info['name'] for p in psutil.process_iter(attrs=['pid','name'])}
        for c in psutil.net_connections(kind='inet'):
            if c.raddr and getattr(c, 'status', None) == 'ESTABLISHED' and c.pid in proc_map:
                proc_name = proc_map.get(c.pid, f'pid-{c.pid}')
                connections.append((proc_name, c.raddr.ip))
    except Exception:
        pass

    nodes = []
    links = []
    seen_nodes = set()
    for proc, ip in connections[:20]:
        proc_id = f'proc-{proc}-{random.randint(1,9999)}'
        ext_id = f'ext-{ip}'
        if proc_id not in seen_nodes:
            nodes.append({'id': proc_id, 'label': proc, 'type': 'process'})
            seen_nodes.add(proc_id)
        if ext_id not in seen_nodes:
            nodes.append({'id': ext_id, 'label': ip, 'type': 'ip'})
            seen_nodes.add(ext_id)
        links.append({'source': proc_id, 'target': ext_id, 'score': random.uniform(0.2,1.0)})

    if not nodes:
        nodes = [{'id':'proc-dummy','label':'svc-example','type':'process'},{'id':'ext-8.8.8.8','label':'8.8.8.8','type':'ip'}]
        links = [{'source':'proc-dummy','target':'ext-8.8.8.8','score':0.8}]

    return jsonify(graph={'nodes':nodes,'links':links})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)