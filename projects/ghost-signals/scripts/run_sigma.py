
#!/usr/bin/env python3
"""Ghost Signals: execute a Sigma rule against Sysmon JSONL."""

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqliteBackend


FIELDS = [
    "EventID", "Channel", "Hostname", "UtcTime",
    "Image", "CommandLine", "ParentImage",
    "User", "ProcessGuid", "ProcessId",
]


def load_events(path):
    events = []
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {number}: {exc}"
                ) from exc
            if not isinstance(event, dict):
                raise ValueError(f"Line {number} is not an object")
            events.append(event)
    return events


def create_database(events):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row

    # NOCASE makes Windows path and command matching
    # case-insensitive in SQLite.
    columns = ", ".join(
        f'"{field}" TEXT COLLATE NOCASE'
        for field in FIELDS
    )
    db.execute(f"CREATE TABLE logs ({columns})")

    placeholders = ",".join("?" for _ in FIELDS)
    db.executemany(
        f"INSERT INTO logs VALUES ({placeholders})",
        [
            tuple(
                None if event.get(field) is None
                else str(event[field])
                for field in FIELDS
            )
            for event in events
        ],
    )
    db.commit()
    return db


def execute(rule_path, events):
    rule_text = rule_path.read_text(encoding="utf-8")
    metadata = yaml.safe_load(rule_text)

    collection = SigmaCollection.from_yaml(rule_text)
    queries = sqliteBackend().convert(collection)

    if len(queries) != 1:
        raise ValueError(
            f"Expected one SQL query, got {len(queries)}"
        )

    query = queries[0].strip().rstrip(";")
    if not query.upper().startswith("SELECT "):
        raise ValueError("Backend did not produce a SELECT query")

    db = create_database(events)

    # This project currently targets Sysmon Event ID 1.
    # The Sigma logsource declares process_creation,
    # but without a processing pipeline we must apply
    # that logsource constraint explicitly.
    constrained_query = (
        "SELECT * FROM (" + query + ") AS matches "
        "WHERE EventID = '1' "
        "AND Channel = 'Microsoft-Windows-Sysmon/Operational'"
    )

    rows = db.execute(constrained_query).fetchall()
    alerts = [dict(row) for row in rows]

    db.close()
    return metadata, constrained_query, alerts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", required=True, type=Path)
    parser.add_argument("--events", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    events = load_events(args.events)
    metadata, query, alerts = execute(args.rule, events)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)

    with args.output.open("w", encoding="utf-8") as output:
        for alert in alerts:
            output.write(json.dumps(alert) + "\n")

    now = datetime.now(timezone.utc).isoformat()

    report = f"""# Ghost Signals — Detection Report

## Detection
- Rule: {metadata.get('title')}
- Rule ID: {metadata.get('id')}
- Severity: {metadata.get('level')}
- Status: {metadata.get('status')}
- Generated: {now}

## Execution Summary
- Events loaded: {len(events)}
- Matching events: {len(alerts)}
- Engine: pySigma SQLite backend
- Log source: Windows Sysmon Event ID 1

## Converted Query

```sql
{query}
```

## Results

The engine returned {len(alerts)} matching event(s).

## ATT&CK Mapping

{', '.join(metadata.get('tags', []))}

## Analyst Notes

This rule detects a controlled lab marker in
PowerShell process creation telemetry.

The marker is not inherently malicious.
Alerts demonstrate detection coverage, not compromise.

## Limitations

- Batch evaluation of an exported log snapshot
- No real-time alerting or automatic deduplication
- Only the configured process-creation rule is evaluated
- This report excludes raw command lines and user details
"""

    args.report.write_text(report, encoding="utf-8")

    print("GHOST SIGNALS // SIGMA ENGINE")
    print(f"Events loaded: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"SQL: {query}")
    print(f"Alerts: {args.output}")
    print(f"Report: {args.report}")


if __name__ == "__main__":
    main()
