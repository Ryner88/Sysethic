from flask import Flask, render_template, send_from_directory, jsonify, render_template_string
import pandas as pd
import os

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_PATH = os.path.join(BASE_DIR, "logs", "system_log.csv")
IMG_DIR  = os.path.join(BASE_DIR, "logs")

@app.route("/")
def index():
    df = pd.read_csv(LOG_PATH, parse_dates=["timestamp"])
    threshold = df["cpu_percent"].mean() + 2 * df["cpu_percent"].std()
    return render_template(
        "dashboard.html",
        threshold=round(threshold, 2)
    )

@app.route("/images/<path:filename>")
def images(filename):
    return send_from_directory(IMG_DIR, filename)

# Top Cards (unchanged)…
@app.route('/api/audit_summary')
def api_audit_summary():
    snippet = render_template_string(
        "<ul><li>5 critical events in last hour</li>"
        "<li>23 warnings</li></ul>"
    )
    return jsonify(html=snippet)

@app.route('/api/ai_alerts')
def api_ai_alerts():
    snippet = render_template_string(
        "<ul><li>Model drift detected at 14:03</li>"
        "<li>Retraining recommended</li></ul>"
    )
    return jsonify(html=snippet)

@app.route('/api/system_health')
def api_system_health():
    snippet = render_template_string(
        "<p>All systems nominal (no errors in past 10 min)</p>"
    )
    return jsonify(html=snippet)

# Real-time usage
@app.route('/api/usage')
def api_usage():
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp']).tail(30)
    times = df['timestamp'].dt.strftime('%H:%M:%S').tolist()
    return jsonify(timestamps=times,
                   cpu=df['cpu_percent'].tolist(),
                   memory=df['memory_percent'].tolist())

# CPU Anomalies & Logs (unchanged)…
@app.route('/api/anomalies')
def api_anomalies():
    df    = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    thresh = df['cpu_percent'].mean() + 2 * df['cpu_percent'].std()
    records = df[df['cpu_percent'] > thresh].to_dict(orient='records')
    return jsonify(anomalies=records)

@app.route('/api/logs')
def api_logs():
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp'])
    return jsonify(logs=df.tail(20).to_dict(orient='records'))

# New endpoints for Disk & Network
@app.route('/api/disk')
def api_disk():
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp']).tail(30)
    times = df['timestamp'].dt.strftime('%H:%M:%S').tolist()
    return jsonify(timestamps=times,
                   read=df['disk_read_bytes'].tolist(),
                   write=df['disk_write_bytes'].tolist())

@app.route('/api/network')
def api_network():
    df = pd.read_csv(LOG_PATH, parse_dates=['timestamp']).tail(30)
    times = df['timestamp'].dt.strftime('%H:%M:%S').tolist()
    return jsonify(timestamps=times,
                   sent=df['net_bytes_sent'].tolist(),
                   recv=df['net_bytes_recv'].tolist())

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
