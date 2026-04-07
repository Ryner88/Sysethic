#!/usr/bin/env python3
"""saaoe_cli.py

Simple command-line client for the SAAOE Flask API.
"""

import argparse
import json
import sys

try:
    import requests
except ImportError:
    sys.stderr.write("requests is required: pip install requests\n")
    sys.exit(1)


def request_json(url, params=None):
    resp = requests.get(url, params=params, timeout=10)
    resp.raise_for_status()
    return resp.json()


def pretty_print(obj):
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def main():
    parser = argparse.ArgumentParser(description='SAAOE CLI wrapper (HTTP API client)')
    parser.add_argument('--host', default='localhost', help='API host (default: localhost)')
    parser.add_argument('--port', default=5000, type=int, help='API port (default: 5000)')
    parser.add_argument('--raw', action='store_true', help='Print raw JSON instead of pretty output')
    parser.add_argument('--watch', action='store_true', help='Run in continuous/watch mode')
    parser.add_argument('--interval', type=float, default=5.0, help='Polling interval in seconds for watch mode (default 5.0)')

    subparsers = parser.add_subparsers(dest='cmd', required=True)

    parser_health = subparsers.add_parser('system_health', help='GET /api/system_health')
    parser_usage = subparsers.add_parser('usage', help='GET /api/usage')
    parser_disk = subparsers.add_parser('disk', help='GET /api/disk')
    parser_net = subparsers.add_parser('net', help='GET /api/net')
    parser_procs = subparsers.add_parser('procs', help='GET /api/procs')
    parser_procs.add_argument('--limit', type=int, default=12, help='Limit process rows (default 12)')

    parser_anomalies = subparsers.add_parser('anomalies', help='GET /api/anomalies')
    parser_anomalies.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'], help='Filter by severity')

    subparsers.add_parser('assets', help='GET /api/assets')
    subparsers.add_parser('threat_trends', help='GET /api/threat_trends')
    subparsers.add_parser('test_anomaly', help='GET /api/test_anomaly')

    args = parser.parse_args()
    base = f'http://{args.host}:{args.port}'

    routes = {
        'system_health': '/api/system_health',
        'usage': '/api/usage',
        'disk': '/api/disk',
        'net': '/api/net',
        'procs': '/api/procs',
        'anomalies': '/api/anomalies',
        'assets': '/api/assets',
        'threat_trends': '/api/threat_trends',
        'test_anomaly': '/api/test_anomaly',
    }

    if args.cmd not in routes:
        parser.error(f'Unknown command: {args.cmd}')

    url = base + routes[args.cmd]
    params = {}

    if args.cmd == 'procs':
        params['limit'] = args.limit
    if args.cmd == 'anomalies' and args.severity:
        params['severity'] = args.severity

    def fetch_once():
        try:
            out = request_json(url, params=params or None)
        except requests.exceptions.RequestException as e:
            sys.stderr.write(f'Error requesting {url}: {e}\n')
            return None

        if args.raw:
            print(json.dumps(out, separators=(',', ':'), ensure_ascii=False))
        else:
            pretty_print(out)
        return out

    if args.watch:
        import time
        print(f"Watching {args.cmd} @ {url} every {args.interval} seconds. Ctrl-C to stop.")
        try:
            while True:
                fetch_once()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print('\nWatcher stopped')
            return

    # single-shot mode
    result = fetch_once()
    if result is None:
        sys.exit(1)


if __name__ == '__main__':
    main()
