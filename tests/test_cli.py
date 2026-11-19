"""端到端 CLI 测试：python -m solution --input ... --output ..."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests.support import REPO_ROOT, TempWorkspace


class CliEndToEndTest(unittest.TestCase):
    def setUp(self):
        self.ws = TempWorkspace("aec-cli-")
        self.output = os.path.join(self.ws.path, "result.json")
        self.cases = os.path.join(REPO_ROOT, "cases.json")

    def tearDown(self):
        self.ws.cleanup()

    def test_cli_runs_and_writes_result(self):
        proc = subprocess.run(
            [
                sys.executable, "-m", "solution",
                "--input", self.cases,
                "--output", self.output,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=REPO_ROOT,
            timeout=180,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.isfile(self.output))
        with open(self.output, "r", encoding="utf-8") as fh:
            result = json.load(fh)

        self.assertTrue(result["overall_passed"])
        self.assertEqual(result["decision_table"]["total"], 36)
        self.assertEqual(result["decision_table"]["failed"], 0)
        self.assertEqual(result["crash_scenarios"]["total"], 2)
        self.assertEqual(result["crash_scenarios"]["passed"], 2)
        self.assertEqual(result["ordered_scenario_failures"], [])

        # 清单文件绝不能声明执行过程序
        for case in result["decision_table"]["cases"]:
            self.assertIn("expect", case)

    def test_cli_rejects_missing_input(self):
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", "no-such-cases.json",
             "--output", self.output],
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=REPO_ROOT,
        )
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
