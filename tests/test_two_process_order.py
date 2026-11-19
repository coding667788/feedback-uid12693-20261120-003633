"""两个独立进程以相反顺序固定 X/Y/Z 与两个崩溃点。

进程 A：X -> Y -> Z -> KILL_PRE_COMMIT -> KILL_POST_COMMIT
进程 B：Z -> Y -> X -> KILL_POST_COMMIT -> KILL_PRE_COMMIT

两进程使用各自独立工作区并发运行，最终断言：
  * 两种顺序下 X/Y/Z 的具体错误码与持久记录数完全相同；
  * 崩溃不变量（无部分准入、无重复行）在两种顺序下都成立；
  * 进程间数据库完全隔离、互不污染。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest

from tests.support import REPO_ROOT, TempWorkspace, load_document


class TwoProcessOppositeOrderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = load_document()
        cls.ws = TempWorkspace("aec-two-proc-")
        cls.cases_path = os.path.join(REPO_ROOT, "cases.json")

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def _spawn(self, order: str) -> dict:
        workspace = self.ws.sub(f"proc-{order.lower()}")
        report = os.path.join(workspace, "report.json")
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run(
            [
                sys.executable, "-m", "solution.flow_process",
                "--input", self.cases_path,
                "--order", order,
                "--workspace", workspace,
                "--out", report,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=REPO_ROOT,
            env=env,
            timeout=180,
        )
        self.assertEqual(
            proc.returncode, 0,
            msg=f"进程 {order} 失败:\nSTDOUT={proc.stdout}\nSTDERR={proc.stderr}",
        )
        with open(report, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def test_opposite_orders_in_two_real_processes(self):
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            fut_a = pool.submit(self._spawn, "XYZ")
            fut_b = pool.submit(self._spawn, "ZYX")
            report_a = fut_a.result(timeout=180)
            report_b = fut_b.result(timeout=180)

        self.assertTrue(report_a["passed"], report_a["failures"])
        self.assertTrue(report_b["passed"], report_b["failures"])

        def flow_summary(report, letter):
            return next(
                item["summary"] for item in report["items"]
                if item["kind"] == "scenario" and item["scenario"] == letter
            )

        def crash_summary(report, sid):
            return next(
                item["summary"] for item in report["items"]
                if item["kind"] == "crash" and item["scenario"] == sid
            )

        # ---- X：两种顺序下错误码完全一致 -----------------------------------
        for report in (report_a, report_b):
            x = flow_summary(report, "X")
            self.assertEqual(
                x["steps"][0]["commit_error_code"], "STALE_DEVICE_GENERATION"
            )
            self.assertEqual(x["steps"][0]["after_move_generation"], 2)
            self.assertEqual(
                x["steps"][1]["commit_error_code"], "NO_AUTHORIZATION"
            )
            self.assertEqual(x["records"], 0)

        # ---- Y：吊销主导错误码，记录数固定为 1 ------------------------------
        for report in (report_a, report_b):
            y = flow_summary(report, "Y")
            self.assertEqual(y["steps"][0]["decision"], "ALLOW")
            self.assertEqual(
                y["steps"][2]["error_code"], "ISSUER_KEY_REVOKED"
            )
            self.assertEqual(y["steps"][3]["error_code"], "NO_AUTHORIZATION")
            self.assertEqual(y["records"], 1)

        # ---- Z：回执固定 v1，新请求按 v2 重判 -------------------------------
        for report in (report_a, report_b):
            z = flow_summary(report, "Z")
            self.assertTrue(z["steps"][2]["same_receipt"])
            self.assertEqual(z["steps"][2]["policy_version"], 1)
            self.assertEqual(
                z["steps"][3]["error_code"], "NO_AUTHORIZATION"
            )
            self.assertEqual(z["steps"][3]["policy_version"], 2)
            self.assertEqual(z["records"], 1)

        # ---- 崩溃不变量在两种顺序下都成立 -----------------------------------
        for report in (report_a, report_b):
            pre = crash_summary(report, "KILL_PRE_COMMIT")
            post = crash_summary(report, "KILL_POST_COMMIT")
            self.assertEqual(pre["worker_returncode"], 42)
            self.assertEqual(pre["records_after_recovery"], 0)
            self.assertEqual(pre["manifests_after_recovery"], 0)
            self.assertEqual(post["worker_returncode"], 43)
            self.assertEqual(post["records_after_recovery"], 1)
            self.assertEqual(post["manifests_after_recovery"], 1)

        # ---- 进程间隔离：两套工作区各有独立数据库文件 ------------------------
        db_a = os.path.join(self.ws.path, "proc-xyz", "flow-x", "data", "aec.db")
        db_b = os.path.join(self.ws.path, "proc-zyx", "flow-z", "data", "aec.db")
        self.assertTrue(os.path.isfile(db_a))
        self.assertTrue(os.path.isfile(db_b))
        self.assertNotEqual(os.path.getsize(db_a), 0)


if __name__ == "__main__":
    unittest.main()
