import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OfflineTriageTest(unittest.TestCase):
    def test_offline_triage_generates_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "triage.json"
            command = [
                sys.executable,
                str(ROOT / "src" / "triage.py"),
                "--input",
                str(ROOT / "data" / "sample_incident.json"),
                "--offline",
                "--output",
                str(output),
            ]
            completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True)
            self.assertIn("Wrote triage report", completed.stdout)

            data = json.loads(output.read_text(encoding="utf-8"))
            for field in [
                "summary",
                "incident_type",
                "risk_level",
                "confidence",
                "iocs",
                "attack_patterns",
                "mitre_attack",
                "evidence",
                "recommended_actions",
                "limitations",
            ]:
                self.assertIn(field, data)
            self.assertEqual(data["risk_level"], "high")
            self.assertGreaterEqual(data["confidence"], 0.7)


if __name__ == "__main__":
    unittest.main()
