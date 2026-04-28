# Priority Fixes

These are near-term items because they improve the current project and make demos smoother.

## 1. Add Demo Center Basics

Goal: Create a controlled way to trigger fake scenarios for testing and presentations.

Add:

- CPU Spike Demo
- Suspicious Network Demo
- Sensitive File Demo

Why priority: demos make the app easier to present and prove that alerts, playbooks, logs, and UI updates work.

## 2. Add Core Playbook List

Goal: Show available response workflows in the app.

Start with:

- Kill Runaway CPU Process
- Memory Leak Response
- Suspicious Network Connection
- Sensitive File Detected
- Human Approval Required
- Create Incident Report

Why priority: playbooks are central to SAAOE's identity.

## 3. Connect Demos to Playbooks

Goal: Running a demo should trigger a matching recommendation.

Example:

- CPU Spike Demo
- creates CPU anomaly
- recommends Kill Runaway CPU Process playbook

Why priority: this connects the app's pieces into one clear workflow.

## 4. Add Basic Incident Creation

Goal: When an important alert occurs, create an incident record.

Example:

- Incident: `SA-001`
- Type: CPU Spike
- Severity: High
- Status: Open
- Recommended Playbook: Kill Runaway CPU Process

Why priority: incidents make alerts feel more professional and easier to track.

## 5. Improve Audit Log Consistency

Goal: Every demo and playbook action should create an audit entry.

Log:

- Demo started
- Alert generated
- Playbook recommended
- User approved or rejected action
- Incident closed

Why priority: this supports grading, screenshots, and project explanation.

## 6. Add Manual Approval Before Risky Actions

Goal: Prevent destructive automation from running without user confirmation.

Risky actions:

- Kill process
- Block IP
- Delete or quarantine file
- Restart service

Why priority: safer design and better ethics/autonomy story.

## 7. Add Clearer Severity and Status Labels

Goal: Make alerts easier to understand at a glance.

Use these severities:

- Info
- Low
- Medium
- High
- Critical

Use these statuses:

- Open
- Investigating
- Resolved
- Dismissed

Why priority: improves UX and makes the dashboard more readable.
