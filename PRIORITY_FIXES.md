# Priority Fixes

## P0 - Security Hardening

- Replace the development WebSocket terminal with an authenticated backend channel before production use.
- Keep the diagnostic command allowlist strict and reject shell metacharacters, pipes, redirection, absolute paths, and long-running commands.
- Add authorization checks to playbook execution, automation rule creation, report downloads, and anomaly response endpoints.
- Persist audit events for terminal commands, automation actions, playbook runs, and report exports.

## P1 - Reliability

- Move anomaly rules, automation rules, playbooks, and run history out of in-memory globals into durable storage.
- Add duplicate suppression for repeated automation and playbook executions across app restarts.
- Add server-side validation for YAML playbook definitions and reject malformed or unsupported remediation steps.
- Add tests for anomaly ID generation, risk scoring, framework mapping, report export, and playbook matching.

## P2 - Product Completeness

- Configure `THREAT_INTEL_PATH` with a maintained local JSON feed or wire it to an approved provider ingestion job.
- Add filters to reports for time range, severity, framework, and asset.
- Add search and status filters to automation history and playbook runs.
- Add visual loading and error states for the terminal, reports, timeline, heatmap, and response modal.

## Verification Checklist

- Run `venv/bin/python -m py_compile web/saaoe_api.py`.
- Smoke test `/anomalies`, `/reports`, `/automation`, `/playbooks`, and `/terminal`.
- Confirm report CSV and PDF downloads open correctly.
- Confirm a blocked terminal command returns a clear refusal.
- Confirm the Respond action triggers a matching YAML playbook run.
