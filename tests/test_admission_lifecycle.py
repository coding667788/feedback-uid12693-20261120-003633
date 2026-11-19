"""准入生命周期：幂等回执、政策版本固定、身份变化强制重判、依赖上限。"""

from __future__ import annotations

import json
import unittest

from solution.bootstrap import bootstrap, reset_workspace
from solution.clock import Clock
from solution.errors import E_TOO_MANY_DEPENDENCIES, AdmissionError
from solution.models import LaunchRequest
from solution.replay import run_scenario
from solution.service import AdmissionService
from solution.store import Store
from tests.support import TempWorkspace, load_document

T_MID = "2026-06-15T12:00:00Z"


class AdmissionLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.document = load_document()
        self.ws = TempWorkspace("aec-life-")
        self.store_ws = self.ws.sub("db")
        reset_workspace(self.store_ws)
        self.store = bootstrap(self.store_ws, self.document["decision_fixture"])
        self.svc = AdmissionService(self.store, Clock(T_MID))

    def tearDown(self):
        self.store.close()
        self.ws.cleanup()

    def _case_request(self, cid: str) -> LaunchRequest:
        case = next(c for c in self.document["decision_cases"] if c["case_id"] == cid)
        return LaunchRequest.from_dict(case["request"])

    def test_idempotent_replay_returns_same_receipt_and_no_duplicate_row(self):
        req = self._case_request("C01")
        prep1 = self.svc.prepare(req, "life")
        out1 = self.svc.commit(req, prep1["snapshot_id"], "life")
        self.assertEqual(out1["decision"], "ALLOW")
        rid = out1["receipt"]["receipt_id"]

        # 第二次完整 prepare+commit，同 request_id
        prep2 = self.svc.prepare(req, "life")
        out2 = self.svc.commit(req, prep2["snapshot_id"], "life")
        self.assertTrue(out2["replayed"])
        self.assertEqual(out2["receipt"]["receipt_id"], rid)
        self.assertEqual(self.store.count_admissions(), 1)

        # 数据库里 request_id 唯一、无重复行
        rows = self.store.list_admissions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["request_id"], req.request_id)

    def test_receipt_pins_policy_version_and_hit_rules(self):
        req = self._case_request("C07")  # issuer+path 联合允许
        prep = self.svc.prepare(req, "life")
        out = self.svc.commit(req, prep["snapshot_id"], "life")
        receipt = out["receipt"]
        self.assertEqual(receipt["policy_version"], 1)
        self.assertEqual(receipt["decision"], "ALLOW")
        hits = receipt["parts"][0]["hit_rules"]
        self.assertTrue(any(h["rule_id"] == "R06" for h in hits))

    def test_identity_changes_when_path_or_key_changes(self):
        # C26 与 C27 内容摘要相同但入口不同，身份摘要必须不同
        c26 = next(c for c in self.document["decision_cases"] if c["case_id"] == "C26")
        c27 = next(c for c in self.document["decision_cases"] if c["case_id"] == "C27")
        req26 = LaunchRequest.from_dict(c26["request"])
        req27 = LaunchRequest.from_dict(c27["request"])
        self.assertEqual(
            req26.parts[0].content_digest, req27.parts[0].content_digest
        )
        self.assertNotEqual(req26.identity_digest, req27.identity_digest)

    def test_dependency_limit_enforced_at_request_validation(self):
        case = next(c for c in self.document["decision_cases"] if c["case_id"] == "C33")
        doc = json.loads(json.dumps(case["request"]))
        extra = dict(doc["parts"][1])
        extra["slot"] = 26
        extra["role"] = "dependency"
        extra["name"] = "dep26"
        doc["parts"].append(extra)
        doc.pop("identity_digest", None)
        with self.assertRaises(AdmissionError) as ctx:
            LaunchRequest.from_dict(doc)
        self.assertEqual(ctx.exception.code, E_TOO_MANY_DEPENDENCIES)

    def test_z_scenario_receipt_stays_pinned_after_withdrawal(self):
        summary = run_scenario("Z", self.ws.sub("flow-z"), self.document)
        steps = summary["steps"]
        self.assertEqual(steps[0]["policy_version"], 1)
        self.assertEqual(steps[1]["new_policy_version"], 2)
        self.assertTrue(steps[2]["same_receipt"])
        self.assertEqual(steps[2]["policy_version"], 1)
        self.assertEqual(steps[3]["error_code"], "NO_AUTHORIZATION")
        self.assertEqual(steps[3]["policy_version"], 2)
        # 只有首次准入落一条记录
        self.assertEqual(summary["records"], 1)


if __name__ == "__main__":
    unittest.main()
