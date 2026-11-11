# GHOST SIGNALS
### NIGHTSHIFT // Detection Engineering Lab

Ghost Signals is a home-lab detection-engineering project
focused on Windows telemetry, Sigma rules, and reproducible
security detection tests.

## Architecture

Windows 11 Pro
  -> Sysmon
  -> NXLog Community Edition
  -> TCP 5514
  -> Ubuntu rsyslog
  -> Python JSON normalizer
  -> Sigma SQLite detection engine
  -> JSON alerts and Markdown reports

## Lab Environment

- Linux Mint host with KVM/QEMU
- Windows 11 Pro endpoint
- Ubuntu Server log collector
- Isolated virtual network: 192.168.77.0/24
- Sysmon process-creation telemetry

## Current Detection

NIGHTSHIFT PowerShell Lab Marker

Detects a controlled test marker in Windows PowerShell
process-creation events.

MITRE ATT&CK: T1059.001 — PowerShell

This marker is a test artifact, not an indicator of compromise.

## Run the Detection

Install dependencies in a virtual environment:

    pip install "pysigma>=2.0.1,<3" \
      "pysigma-backend-sqlite>=2.1,<3" pyyaml

Place your private normalized JSONL telemetry in events/.

Run:

    python scripts/run_sigma.py \
      --rule rules/windows/powershell_lab_marker.yml \
      --events events/sysmon-normalized.jsonl \
      --output results/sigma-alerts.jsonl \
      --report results/detection-report.md

## Run Automated Tests

    python -m unittest discover \
      -s tests -p 'test_sigma_engine.py' -v

## Security

Real event logs, usernames, command-line arguments,
and generated alerts are excluded from version control.

Do not upload unsanitized telemetry.

## Roadmap

- Additional Sigma detections
- Sysmon processing pipelines
- Automated detection regression testing
- Alert deduplication
- Threat hunting exercises
- Detection coverage reporting
