
# NIGHTSHIFT // Ghost Signals
## Phase 9 — Behavioral Threat Hunting

### Objective

Evaluate three Windows process-creation detection rules
against synthetic test cases and real Sysmon telemetry.

### Lab Environment

- Endpoint: Windows 11 Pro
- Telemetry: Sysmon Event ID 1
- Forwarder: NXLog Community Edition
- Collector: Ubuntu Server / rsyslog
- Detection engine: pySigma SQLite backend

### GS-002 — Encoded PowerShell

Detection hypothesis:
PowerShell encoded-command arguments may indicate
attempts to obscure execution content.

ATT&CK: T1059.001

Test:
Execute a harmless Base64-encoded PowerShell command.

Analyst considerations:
- Decode the command safely without executing it.
- Inspect parent process and user context.
- Determine whether the execution is authorized.
- Correlate with network and file activity.

### GS-003 — Office Spawning PowerShell

Detection hypothesis:
An Office application launching PowerShell may indicate
document-based execution or unusual automation.

ATT&CK: T1059.001

Test:
Synthetic Sysmon process-creation event.

Analyst considerations:
- Inspect Office document origin.
- Review parent-child process relationships.
- Check command-line arguments.
- Investigate related email or attachment activity.

### GS-004 — PowerShell Web Retrieval

Detection hypothesis:
PowerShell web-retrieval functionality may indicate
remote content access or staged payload retrieval.

ATT&CK: T1059.001

Test:
Harmless loopback web request.

Analyst considerations:
- Identify the destination.
- Determine whether the request succeeded.
- Inspect subsequent processes and file writes.
- Compare against approved administrative activity.

### Validation

Record actual results after running the tests:

| Rule | Synthetic tests | Real telemetry | Notes |
|---|---|---|---|
| GS-002 | Pending | Pending | |
| GS-003 | Pending | Not yet tested | |
| GS-004 | Pending | Pending | |

### Limitations

- Process-creation telemetry alone does not prove compromise.
- Encoded commands can be legitimate.
- Office automation can be legitimate.
- Web retrieval is common in administrative scripts.
- The current engine processes snapshots, not live streams.
- Additional argument variations may evade these starter rules.

### Future Improvements

- Add false-positive baselines.
- Add more PowerShell argument variations.
- Correlate process and network events.
- Incorporate parent-process reputation and context.
- Introduce severity and confidence scoring.
```

Update the validation table with your actual results rather than assuming the tests passed.

## Step 8 — Commit Phase 9 to Git

Before committing, run the full regression suite again:

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

Review the files:

```bash
git status --short
```

Stage only the new rules, tests, and documentation:

```bash
git add \
  rules/windows/powershell_encoded_command.yml \
  rules/windows/office_spawns_powershell.yml \
  rules/windows/powershell_web_retrieval.yml \
  tests/test_phase9_detections.py \
  docs/detections/phase9-hunting-report.md
```

Inspect:

```bash
git diff --cached --stat
```

Then commit:

```bash
git commit -m "Add behavioral PowerShell and Office detection rules"
```

No real Windows event logs should be included in this commit.

---

## Phase 9 completion tracker

{@body const tasks=["Three behavioral Sigma rules created","Sigma rules parsed successfully","All automated regression tests passed","Windows encoded PowerShell test completed","Windows web-retrieval test completed","Ubuntu telemetry normalized and copied","GS-002 and GS-004 produced expected real detections","Threat-hunting report updated with actual results","Phase 9 changes committed"]}
{@body const [completed,setCompleted]=DIL.useState([])}
<box border radius="xl" padding={3} gap={3}>
  <row align="center" justify="between">
    **NIGHTSHIFT // PHASE 9**
    <text color="secondary" tabularNums>{completed.length} of {tasks.length}</text>
  </row>
  <box background="surface-tertiary" height="6px" radius="full" clip>
    <box background="surface-inverted" height="100%" width={`${100*completed.length/tasks.length}%`} radius="full"/>
  </box>
  {#each tasks as task,i}
    <checkbox key={i} checked={completed.includes(i)} onChange={v=>setCompleted(old=>v?[...old,i]:old.filter(x=>x!==i))}>{task}</checkbox>
  {/each}
  <button block disabled={completed.length!==tasks.length} onClick={()=>GenUI.issueNewTurn("Phase 9 is complete. Take me through Phase 10: expand Ghost Signals into a more capable threat-hunting platform with correlated Sysmon events, richer detection rules, and investigation workflows.")}>Continue to Phase 10 <icon name="arrow-right" inline/></button>
</box>

Phase 10 will be a bigger upgrade: instead of treating each Sysmon event independently, we'll begin correlating process creation, DNS queries, and network connections using `ProcessGuid` and timestamps. That moves Ghost Signals toward the kind of investigation workflow you'd use in a SOC.

For now, the most important results are the **14 automated tests and the real GS-002/GS-004 alert counts**. Those will tell us whether the detection engine handles these new behavioral rules as intended.
