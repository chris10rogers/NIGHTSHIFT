
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_sigma import execute

RULE = ROOT / "rules/windows/powershell_lab_marker.yml"

CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def event(image, command, event_id=1, channel=CHANNEL):
    return {
        "EventID": event_id,
        "Channel": channel,
        "Hostname": "NIGHTSHIFT-TEST",
        "UtcTime": "2026-11-11 16:00:00",
        "Image": image,
        "CommandLine": command,
        "ProcessGuid": "{SYNTHETIC-GUID}",
        "User": "LAB\\testuser",
    }


PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
MARKER = "NIGHTSHIFT-FORWARD-TEST"


class TestSigmaEngine(unittest.TestCase):

    def matches(self, sample):
        _, _, alerts = execute(RULE, [sample])
        return len(alerts)

    def test_positive_powershell(self):
        self.assertEqual(
            self.matches(event(PS, f"powershell.exe {MARKER}")), 1
        )

    def test_benign_powershell(self):
        self.assertEqual(
            self.matches(event(PS, "powershell.exe Get-Date")), 0
        )

    def test_wrong_executable(self):
        self.assertEqual(
            self.matches(event(CMD, f"cmd.exe /c echo {MARKER}")), 0
        )

    def test_wrong_event_id(self):
        self.assertEqual(
            self.matches(event(PS, MARKER, event_id=3)), 0
        )

    def test_wrong_channel(self):
        self.assertEqual(
            self.matches(event(
                PS, MARKER, channel="Security"
            )), 0
        )

    def test_case_insensitive_matching(self):
        self.assertEqual(
            self.matches(event(
                PS.upper(), MARKER.lower()
            )), 1
        )

    def test_multiple_events(self):
        samples = [
            event(PS, MARKER),
            event(PS, "Get-Date"),
            event(CMD, MARKER),
        ]
        _, _, alerts = execute(RULE, samples)
        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()
