"""真实杀进程崩溃恢复测试。

工人子进程在两个崩溃点 os._exit：
  * 清单已 fsync 写盘、SQLite 事务尚未提交；
  * 事务提交完成之后。
随后重开数据库，断言无部分准入、无重复行、孤儿清单被回收。
"""

from __future__ import annotations

import os
import unittest

from solution.clock import Clock
from solution.replay import run_crash_scenario
from solution.service import AdmissionService
from solution.store import Store
from tests.support import TempWorkspace, load_document


class CrashRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.document = load_document()
        self.ws = TempWorkspace("aec-crash-")

    def tearDown(self):
        self.ws.cleanup()

    def test_kill_after_manifest_before_commit_leaves_nothing(self):
        scenario = next(
            s for s in self.document["crash_scenarios"]
            if s["scenario_id"] == "KILL_PRE_COMMIT"
        )
        report = run_crash_scenario(scenario, self.ws.path, self.document)

        # 工人必须以专用退出码 42 真实终止
        self.assertEqual(report["worker_returncode"], 42)
        self.assertEqual(report["records_after_recovery"], 0)
        self.assertEqual(report["manifests_after_recovery"], 0)
        # 清单确实写过、恢复时作为孤儿被清除（崩溃点的文件系统证据；
        # 注意崩溃时写事务随进程死亡回滚，flow_events 里不会留下提交后事件）
        self.assertEqual(len(report["removed_orphan_manifests"]), 1)
        kinds = [e["kind"] for e in report["events"]]
        self.assertIn("prepare", kinds)
        self.assertNotIn("commit_allow", kinds)

        # 再次重开库：重复执行恢复必须幂等，仍无任何残留
        store = Store(os.path.join(
            self.ws.path, "crash", "kill_pre_commit", "db"
        ))
        svc = AdmissionService(store, Clock(self.document["time_axis"]["T_MID"]))
        self.assertEqual(svc.recover_orphan_manifests(), [])
        self.assertEqual(store.count_admissions(), 0)
        self.assertEqual(len(store.list_manifest_files()), 0)
        store.close()

    def test_kill_after_commit_persists_exactly_one_row(self):
        scenario = next(
            s for s in self.document["crash_scenarios"]
            if s["scenario_id"] == "KILL_POST_COMMIT"
        )
        report = run_crash_scenario(scenario, self.ws.path, self.document)

        self.assertEqual(report["worker_returncode"], 43)
        self.assertEqual(report["records_after_recovery"], 1)
        self.assertEqual(report["manifests_after_recovery"], 1)
        self.assertEqual(report["removed_orphan_manifests"], [])
        kinds = [e["kind"] for e in report["events"]]
        self.assertEqual(kinds, [
            "prepare", "commit_allow", "crash_after_commit",
        ])

        # 重开库：request_id 唯一、无重复行、清单与记录一一对应
        store = Store(os.path.join(
            self.ws.path, "crash", "kill_post_commit", "db"
        ))
        rows = store.list_admissions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["request_id"], "req-crash-post")
        self.assertEqual(rows[0]["decision"], "ALLOW")
        self.assertTrue(os.path.isfile(rows[0]["manifest_path"]))
        store.close()

    def test_replay_after_crash_does_not_duplicate(self):
        # 提交后崩溃 -> 重开库 -> 同 request_id 重放必须命中幂等分支
        scenario = next(
            s for s in self.document["crash_scenarios"]
            if s["scenario_id"] == "KILL_POST_COMMIT"
        )
        run_crash_scenario(scenario, self.ws.path, self.document)
        from solution.models import LaunchRequest

        db_ws = os.path.join(self.ws.path, "crash", "kill_post_commit", "db")
        store = Store(db_ws)
        svc = AdmissionService(
            store, Clock(self.document["time_axis"]["T_MID"])
        )
        req = LaunchRequest.from_dict(scenario["request"])
        prep = svc.prepare(req, "dup-check")
        out = svc.commit(req, prep["snapshot_id"], "dup-check")
        self.assertTrue(out["replayed"])
        self.assertEqual(store.count_admissions(), 1)
        store.close()


if __name__ == "__main__":
    unittest.main()
