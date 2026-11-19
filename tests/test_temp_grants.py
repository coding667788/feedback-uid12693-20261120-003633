"""临时放宽管理规则：双审批、禁止放宽明确拒绝、窗口与跨组语义。"""

from __future__ import annotations

import unittest

from solution.bootstrap import bootstrap, reset_workspace
from solution.clock import Clock
from solution.errors import AdmissionError, E_TEMP_GRANT_INVALID
from solution.service import AdmissionService
from tests.support import TempWorkspace, load_document

T_MID = "2026-06-15T12:00:00Z"
T_LATE = "2026-09-01T08:00:00Z"
T_OLD = "2026-01-01T00:00:00Z"
T_EXPIRED = "2026-03-01T00:00:00Z"


class TempGrantManagementTest(unittest.TestCase):
    def setUp(self):
        self.document = load_document()
        self.ws = TempWorkspace("aec-grant-")
        self.store_ws = self.ws.sub("db")
        reset_workspace(self.store_ws)
        self.store = bootstrap(self.store_ws, self.document["decision_fixture"])
        self.svc = AdmissionService(self.store, Clock(T_MID))

    def tearDown(self):
        self.store.close()
        self.ws.cleanup()

    def _grant(self, **over):
        base = {
            "org_id": "org-acme",
            "group_id": "G3",
            "base_rule_id": "R11",
            "valid_from": T_OLD,
            "valid_to": T_LATE,
            "approver1": "alice",
            "approver2": "bob",
        }
        base.update(over)
        return base

    def test_two_distinct_approvers_required(self):
        with self.assertRaises(AdmissionError) as ctx:
            self.svc.create_temp_grant(
                self._grant(approver1="alice", approver2="alice")
            )
        self.assertEqual(ctx.exception.code, E_TEMP_GRANT_INVALID)

    def test_cannot_relax_explicit_deny_rule(self):
        # R03 是 deny_digest
        with self.assertRaises(AdmissionError) as ctx:
            self.svc.create_temp_grant(
                self._grant(base_rule_id="R03")
            )
        self.assertEqual(ctx.exception.code, E_TEMP_GRANT_INVALID)
        self.assertIn("拒绝", ctx.exception.message)

    def test_validity_window_must_be_ordered(self):
        with self.assertRaises(AdmissionError) as ctx:
            self.svc.create_temp_grant(
                self._grant(valid_from=T_LATE, valid_to=T_OLD)
            )
        self.assertEqual(ctx.exception.code, E_TEMP_GRANT_INVALID)

    def test_unknown_target_group_rejected(self):
        with self.assertRaises(AdmissionError) as ctx:
            self.svc.create_temp_grant(
                self._grant(group_id="G-DOES-NOT-EXIST")
            )
        self.assertEqual(ctx.exception.code, E_TEMP_GRANT_INVALID)

    def test_grant_persisted_and_visible_in_engine(self):
        grant = self.svc.create_temp_grant(self._grant())
        rows = self.store.active_temp_grants("org-acme", "G3")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["grant_id"], grant["grant_id"])
        self.assertNotEqual(rows[0]["approver1"], rows[0]["approver2"])

    def test_expired_grant_has_no_effect(self):
        # 到期授权写入后，引擎在 T_MID 判定时应视为过期
        self.svc.create_temp_grant(
            self._grant(valid_from=T_OLD, valid_to=T_EXPIRED)
        )
        from solution.models import LaunchRequest

        case = next(c for c in self.document["decision_cases"]
                    if c["case_id"] == "C16")
        req = LaunchRequest.from_dict(case["request"])
        prep = self.svc.prepare(req, "grant-exp")
        self.assertEqual(prep["preview"]["error_code"], "RULE_EXPIRED")


if __name__ == "__main__":
    unittest.main()
