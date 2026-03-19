import threading
import time
from collections import deque
from datetime import datetime

import psutil
from flask import Flask, jsonify, render_template
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

@app.route('/api/anomalies')
def api_anomalies():
    if not os.path.exists(LOG_PATH):
        return jsonify(anomalies=[])
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    if df.empty:
        return jsonify(anomalies=[])
    anomalies = []
    for col in ['cpu_percent', 'memory_percent']:
        thresh = df[col].mean() + 2 * df[col].std()
        high = df[df[col] > thresh]
        for _, row in high.iterrows():
            anomalies.append({
                'timestamp': row['timestamp'],
                'metric': col,
                'value': row[col],
                'threshold': thresh
            })
    # Remove duplicates if same timestamp
    seen = set()
    unique = []
    for a in sorted(anomalies, key=lambda x: x['timestamp'], reverse=True):
        key = (a['timestamp'], a['metric'])
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return jsonify(anomalies=unique[:10])  # last 10

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)