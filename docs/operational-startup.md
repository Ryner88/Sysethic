# Operational Startup

SAAOE is packaged for local operation through one Python operations interface:

```bash
venv/bin/python -m web.saaoe_cli <command>
```

Shell and PowerShell scripts are compatibility wrappers only. They forward to the shared CLI and must not contain lifecycle logic.

## Supported Platforms

- Python 3.10 or newer.
- Linux, macOS, and Windows with local filesystem access, SQLite, `venv`, and `pip`.
- Default operation is local-only on `127.0.0.1:5001`.

Public reverse-proxy deployment is intentionally outside the default quick-start path.

## Install

Linux/macOS:

```bash
python3 scripts/setup_saaoe.py
```

Windows PowerShell:

```powershell
py -3 scripts\setup_saaoe.py
```

The setup script is idempotent. It creates `venv/`, installs pinned dependencies, creates `.env` only if missing, generates a long secret without printing it, initializes or migrates SQLite, verifies the schema, and runs preflight checks. It does not overwrite configuration, replace secrets, reset the database, or duplicate administrators.

Safe production defaults written on first run:

```text
SAAOE_MODE=production
SAAOE_HOST=127.0.0.1
SAAOE_DEBUG=false
SAAOE_SESSION_COOKIE_SECURE=false
SAAOE_ENABLE_TERMINAL_WS=0
```

`SAAOE_SESSION_COOKIE_SECURE=false` is for local HTTP operation. If SAAOE is later placed behind HTTPS, revisit the cookie and proxy model as a separate deployment review.

## First Administrator

If no user exists, create the first administrator from an interactive terminal:

```bash
venv/bin/python -m web.saaoe_cli bootstrap-admin
```

The bootstrap command is allowed only while the user table is empty. It collects the password through `getpass`, uses the application password hashing implementation, creates no default credentials, records a sanitized `admin_bootstrap_created` audit event, and refuses all later bootstrap attempts.

Passwords, secret keys, and password hashes must never appear in console output, logs, or audit details.

## Lifecycle Commands

Linux/macOS:

```bash
venv/bin/python -m web.saaoe_cli start
venv/bin/python -m web.saaoe_cli status
venv/bin/python -m web.saaoe_cli health
venv/bin/python -m web.saaoe_cli stop
```

Windows PowerShell:

```powershell
venv\Scripts\python.exe -m web.saaoe_cli start
venv\Scripts\python.exe -m web.saaoe_cli status
venv\Scripts\python.exe -m web.saaoe_cli health
venv\Scripts\python.exe -m web.saaoe_cli stop
```

Compatibility wrappers:

```bash
scripts/start-saaoe.sh start
scripts/start-saaoe.sh health
```

```powershell
scripts\saaoe.ps1 start
scripts\saaoe.ps1 health
```

`start` runs preflight checks, launches the Waitress production WSGI server on loopback by default, stores runtime metadata under `instance/runtime/`, and polls `/healthz` until ready. If health does not become ready, startup stops the recorded process and returns nonzero.

`stop` terminates only the recorded SAAOE process. It validates PID, process creation time, and command identity before sending a graceful termination signal, then applies forced termination only after re-validating the process.

`status` distinguishes stopped, healthy, running but unhealthy, and stale runtime metadata.

System services must use foreground mode:

```bash
venv/bin/python -m web.saaoe_cli run --foreground
```

An example systemd unit is available at `packaging/systemd/saaoe.service.example`.

## Health

The public endpoint is:

```text
/healthz
```

It returns only a minimal service health payload and must not expose secrets, paths, usernames, environment values, telemetry details, or configuration values.

The CLI health command validates:

| Check | Pass condition |
| --- | --- |
| Configuration | Production-like mode, strong secret, debug disabled, loopback binding |
| Database | Connection succeeds and required schema tables exist |
| Telemetry sampler | In-process sampler buffer is populated |
| Protected page | Anonymous request redirects specifically to setup or login |
| Protected API | Anonymous request returns the defined authentication/setup error |
| Application | `/healthz` returns the expected SAAOE service/version payload |
| Live endpoint | Running service responds on loopback |

Use JSON output for automation:

```bash
venv/bin/python -m web.saaoe_cli health --json
```

Exit codes:

- `0`: healthy
- `1`: application reached but one or more checks failed
- `2`: command/configuration error or application unreachable

A `404`, unexpected `403`, or generic successful response is not proof that authentication works.

## Locations

- Configuration: `.env`
- SQLite database: `data/saaoe.db` by default
- Runtime metadata and lifecycle logs: `instance/runtime/`
- Telemetry CSV: `logs/system_log.csv` by default
- Quarantine directory: `quarantine/`

`data/*.db`, `.env`, virtual environments, and `instance/` are ignored by git.

## Backup

Stop SAAOE before copying the SQLite database:

```bash
venv/bin/python -m web.saaoe_cli stop
cp data/saaoe.db backups/saaoe-$(date +%Y%m%d).db
```

Back up `.env` separately and protect it as secret material. Do not paste or commit `SAAOE_SECRET_KEY`.

## Troubleshooting

- Linux/macOS: confirm `python3 --version`, `venv/bin/python -m pip --version`, filesystem write access to `data/`, `logs/`, and `instance/runtime/`, and that port `127.0.0.1:5001` is free.
- Windows: use `py -3`, confirm `venv\Scripts\python.exe` exists, and run PowerShell from the repository root if path resolution fails.
- If `status` reports stale runtime metadata, run `stop` once. It removes stale metadata without terminating unrelated processes.
- If `health` fails configuration checks, inspect `.env` for production mode, a strong secret, loopback binding, and debug disabled.

## Startup Services

- systemd: copy and adapt `packaging/systemd/saaoe.service.example`.
- launchd: use `venv/bin/python -m web.saaoe_cli run --foreground` as the program arguments.
- Windows scheduled start: run `venv\Scripts\python.exe -m web.saaoe_cli run --foreground`.

Service managers should own restart policy. They should not use `start`, because `start` is the background PID mechanism for operator shells.

## Upgrade

1. Stop SAAOE.
2. Back up `.env` and the SQLite database.
3. Pull or unpack the new code.
4. Run `python3 scripts/setup_saaoe.py` or `py -3 scripts\setup_saaoe.py`.
5. Run `venv/bin/python -m web.saaoe_cli health --json`.
6. Start SAAOE.

Setup applies additive SQLite migrations through `init_db()` and preserves existing configuration, secrets, users, approvals, audit records, incidents, playbooks, and validation records.

## Safety Boundaries

Phase 3-4 response-action contracts remain in force:

- `quarantine_file` and `block_ip` execution adapters remain unavailable and fail closed.
- Packaging must not enable host-impacting actions.
- Validation events may create evidence, anomalies, incidents, playbook runs, and audit events, but must not request, approve, consume, or execute response actions.
- `restart_service` remains the only bounded real host-impacting adapter and is restricted to the hard-coded `saaoe-dashboard` allowlist contract.

Phase 4 closeout remains valid: `venv/bin/python -m unittest discover` passed with 42 tests before Phase 5 packaging work.
