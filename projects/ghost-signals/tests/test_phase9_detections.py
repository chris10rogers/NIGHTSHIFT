
"""Phase 9 behavioral detection regression tests."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_sigma import execute

RULES = ROOT / "rules/windows"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EXPLORER = r"C:\Windows\explorer.exe"


def make_event(image, command, parent=EXPLORER, event_id=1):
    return {
        "EventID": event_id,
        "Channel": CHANNEL,
        "Hostname": "NIGHTSHIFT-TEST",
        "UtcTime": "2026-11-11 16:00:00",
        "Image": image,
        "CommandLine": command,
        "ParentImage": parent,
        "User": r"LAB\testuser",
        "ProcessGuid": "{SYNTHETIC-GUID}",
        "ProcessId": 1234,
    }


class TestPhase9Detections(unittest.TestCase):

    def matches(self, rule, sample):
        path = RULES / rule
        _, _, alerts = execute(path, [sample])
        return len(alerts)

    def test_encoded_positive(self):
        self.assertEqual(
            self.matches(
                "powershell_encoded_command.yml",
                make_event(PS, "powershell.exe -enc VABFAFMAVA=="),
            ),
            1,
        )

    def test_encoded_negative(self):
        self.assertEqual(
            self.matches(
                "powershell_encoded_command.yml",
                make_event(PS, "powershell.exe -NoProfile Get-Date"),
            ),
            0,
        )

    def test_encoded_wrong_executable(self):
        self.assertEqual(
            self.matches(
                "powershell_encoded_command.yml",
                make_event(CMD, "cmd.exe -enc VABFAFMAVA=="),
            ),
            0,
        )

    def test_office_parent_positive(self):
        self.assertEqual(
            self.matches(
                "office_spawns_powershell.yml",
                make_event(PS, "powershell.exe Get-Date", WORD),
            ),
            1,
        )

    def test_office_parent_negative(self):
        self.assertEqual(
            self.matches(
                "office_spawns_powershell.yml",
                make_event(PS, "powershell.exe Get-Date"),
            ),
            0,
        )

    def test_web_retrieval_positive(self):
        self.assertEqual(
            self.matches(
                "powershell_web_retrieval.yml",
                make_event(
                    PS,
                    "powershell.exe -Command Invoke-WebRequest "
                    "http://127.0.0.1/test",
                ),
            ),
            1,
        )

    def test_web_retrieval_negative(self):
        self.assertEqual(
            self.matches(
                "powershell_web_retrieval.yml",
                make_event(PS, "powershell.exe Get-Date"),
            ),
            0,
        )


if __name__ == "__main__":
    unittest.main()
