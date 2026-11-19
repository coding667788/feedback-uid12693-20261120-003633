"""36 条合成策略独立决策表测试，逐条断言具体判定与错误码。"""

from __future__ import annotations

import unittest

from solution.replay import DecisionRunner
from tests.support import TempWorkspace, load_document


class DecisionTableTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = load_document()
        cls.ws = TempWorkspace("aec-decision-")
        cls.runner = DecisionRunner(cls.ws.path, cls.document["decision_fixture"])
        cls.results = {r["case_id"]: r for r in
                       [cls.runner.run_case(c) for c in cls.document["decision_cases"]]}

    @classmethod
    def tearDownClass(cls):
        cls.ws.cleanup()

    def test_at_least_30_policies_and_36_cases(self):
        rules = self.document["decision_fixture"]["rules"]
        self.assertGreaterEqual(len(rules), 30)
        self.assertEqual(len(self.document["decision_cases"]), 36)

    def _assert_case(self, cid, decision, code):
        r = self.results[cid]
        self.assertTrue(r["passed"], f"{cid} 未通过: {r}")
        self.assertEqual(r["actual_decision"], decision)
        self.assertEqual(r["actual_error_code"], code)

    def test_allow_baseline_and_group_rules(self):
        self._assert_case("C01", "ALLOW", "OK")
        self._assert_case("C02", "ALLOW", "OK")

    def test_group_rule_does_not_leak_across_groups(self):
        self._assert_case("C03", "DENY", "NO_AUTHORIZATION")
        self._assert_case("C36", "ALLOW", "OK")

    def test_explicit_deny_overrides_allow(self):
        self._assert_case("C04", "DENY", "DENY_EXPLICIT")
        self._assert_case("C08", "DENY", "DENY_EXPLICIT")
        self._assert_case("C12", "DENY", "DENY_EXPLICIT")
        self._assert_case("C29", "DENY", "DENY_EXPLICIT")
        self._assert_case("C32", "DENY", "DENY_EXPLICIT")
        self._assert_case("C34", "ALLOW", "OK")  # 对照：未拒绝的同设备

    def test_expired_rules_and_default_deny(self):
        self._assert_case("C05", "DENY", "RULE_EXPIRED")
        self._assert_case("C06", "DENY", "NO_AUTHORIZATION")
        self._assert_case("C35", "DENY", "RULE_EXPIRED")

    def test_issuer_path_joint_allow_and_same_named_segments(self):
        self._assert_case("C07", "ALLOW", "OK")
        self._assert_case("C09", "ALLOW", "OK")
        self._assert_case("C10", "ALLOW", "OK")
        self._assert_case("C11", "ALLOW", "OK")
        # 整段匹配：exact 不得命中 exactish
        self._assert_case("C13", "DENY", "NO_AUTHORIZATION")

    def test_temp_grants_two_approvers_and_expiry(self):
        self._assert_case("C14", "DENY", "NO_AUTHORIZATION")
        self._assert_case("C15", "ALLOW", "OK")
        self._assert_case("C16", "DENY", "RULE_EXPIRED")
        self._assert_case("C17", "DENY", "NO_AUTHORIZATION")
        # 临时授权确实把 grant_id 固定进命中规则
        c15 = self.results["C15"]
        grant_hits = [
            h for p in c15["receipt"]["parts"] for h in p["hit_rules"]
            if h.get("grant_id")
        ]
        self.assertEqual(len(grant_hits), 1)

    def test_remote_issuer_simulated_status_changes(self):
        self._assert_case("C18", "ALLOW", "OK")
        self._assert_case("C19", "DENY", "REMOTE_ISSUER_STATUS_BAD")
        self._assert_case("C20", "DENY", "REMOTE_ISSUER_STATUS_BAD")

    def test_chain_revocation_rotation_and_untrusted_root(self):
        self._assert_case("C21", "DENY", "ISSUER_KEY_REVOKED")
        self._assert_case("C22", "DENY", "ISSUER_KEY_REVOKED")
        self._assert_case("C23", "DENY", "ISSUER_UNTRUSTED")

    def test_attestation_and_integrity_failures(self):
        self._assert_case("C24", "DENY", "ISSUER_CHAIN_INVALID")
        self._assert_case("C25", "DENY", "ISSUER_CHAIN_INVALID")

    def test_moved_entry_and_re_evaluation(self):
        self._assert_case("C26", "ALLOW", "OK")
        self._assert_case("C27", "DENY", "NO_AUTHORIZATION")

    def test_multi_part_launch_all_or_nothing(self):
        self._assert_case("C28", "ALLOW", "OK")
        self._assert_case("C30", "DENY", "NO_AUTHORIZATION")
        self._assert_case("C31", "ALLOW", "OK")
        self._assert_case("C33", "ALLOW", "OK")  # 主程序 + 25 依赖上限

    def test_denied_laaves_no_persisted_record(self):
        for cid in ("C04", "C05", "C19", "C21", "C27"):
            self.assertEqual(self.results[cid]["persisted_records"], 0, cid)
            self.assertEqual(self.results[cid]["manifest_files"], 0, cid)
        for cid in ("C01", "C15", "C33"):
            self.assertEqual(self.results[cid]["persisted_records"], 1, cid)
            self.assertEqual(self.results[cid]["manifest_files"], 1, cid)

    def test_every_case_actually_passed(self):
        failed = [cid for cid, r in self.results.items() if not r["passed"]]
        self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
