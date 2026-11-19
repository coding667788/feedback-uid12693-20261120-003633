"""重放编排：决策表执行、X/Y/Z 顺序场景、崩溃场景（工人子进程）。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

from .bootstrap import bootstrap, reset_workspace
from .clock import Clock
from .errors import AdmissionError
from .models import LaunchRequest
from .service import AdmissionService
from .store import Store


# ---------------------------------------------------------------------------
# 决策表
# ---------------------------------------------------------------------------

class DecisionRunner:
    """每个决策用例使用独立工作区，互不污染。"""

    def __init__(self, root_workspace: str, fixture: dict):
        self.root_workspace = root_workspace
        self.fixture = fixture

    def _open(self, case_id: str, now: str):
        ws = os.path.join(self.root_workspace, "decision", case_id.lower())
        reset_workspace(ws)
        store = bootstrap(ws, self.fixture)
        svc = AdmissionService(store, Clock(now))
        return ws, store, svc

    def run_case(self, case: dict) -> dict:
        ws, store, svc = self._open(case["case_id"], case["now"])
        create_errors = []
        try:
            # 远端签发者模拟状态变化
            for change in case.get("remote_changes", []):
                svc.set_remote_status(change["issuer_id"], change["status"])
            # 证书吊销 / 轮换标记
            for st in case.get("cert_status", []):
                store.set_cert_status(st["kid"], st["status"])
            # 临时授权（非法授权记录创建错误，效果等同无授权）
            for grant in case.get("temp_grants", []):
                expect_create_error = grant.pop("expect_create_error", None)
                try:
                    svc.create_temp_grant(dict(grant))
                except AdmissionError as exc:
                    if expect_create_error is None or exc.code != expect_create_error:
                        raise
                    create_errors.append(exc.code)

            request = LaunchRequest.from_dict(case["request"])
            prepared = svc.prepare(request, flow_id=case["case_id"])
            committed = svc.commit(
                request, prepared["snapshot_id"], flow_id=case["case_id"]
            )
            actual_decision = committed["decision"]
            actual_code = committed["error_code"]
            persisted = store.count_admissions()
            manifest_files = len(store.list_manifest_files())
            receipt = committed["receipt"]
        finally:
            store.close()

        passed = (
            actual_decision == case["expect_decision"]
            and actual_code == case["expect_error_code"]
        )
        return {
            "case_id": case["case_id"],
            "note": case["note"],
            "expect_decision": case["expect_decision"],
            "expect_error_code": case["expect_error_code"],
            "actual_decision": actual_decision,
            "actual_error_code": actual_code,
            "passed": passed,
            "persisted_records": persisted,
            "manifest_files": manifest_files,
            "create_errors": create_errors,
            "receipt": receipt,
            "workspace": ws,
        }


def run_decision_suite(workspace: str, document: dict) -> dict:
    runner = DecisionRunner(workspace, document["decision_fixture"])
    results = [runner.run_case(c) for c in document["decision_cases"]]
    passed = sum(1 for r in results if r["passed"])
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "all_passed": passed == len(results),
        "cases": results,
    }


# ---------------------------------------------------------------------------
# X / Y / Z 顺序场景（同进程服务，模拟跨阶段状态变更）
# ---------------------------------------------------------------------------

def _rekeyed_dependency(doc: dict, new_kid: str) -> dict:
    """Y 场景：吊销后用新钥重新签发依赖部件。"""
    info = doc["flow_requests"]["Y"]
    from tools.make_cases import make_part

    part = make_part(
        info["dep_name"], info["issuer_id"], new_kid, info["dep_path"],
        slot=1, role="dependency",
    )
    return part


def run_scenario(letter: str, workspace: str, document: dict) -> dict:
    ws = os.path.join(workspace, f"flow-{letter.lower()}")
    reset_workspace(ws)
    store = bootstrap(ws, document["flow_fixture"])
    clock = Clock(document["time_axis"]["T_MID"])
    svc = AdmissionService(store, clock)
    info = doc_ref(document, letter)
    steps: list[dict] = []

    def admit(rid: str, req_dict: dict, gen: int):
        d = json.loads(json.dumps(req_dict))
        d["request_id"] = rid
        d["device_generation"] = gen
        d.pop("identity_digest", None)  # 改写后由模型重算身份
        request = LaunchRequest.from_dict(d)
        prepared = svc.prepare(request, flow_id=f"flow-{letter}")
        committed = svc.commit(
            request, prepared["snapshot_id"], flow_id=f"flow-{letter}"
        )
        return prepared, committed

    if letter == "X":
        # 旧策略预检 -> 设备转组（代数推进）-> 提交被拦 -> 新代重判仍拒绝
        req = info["request"]
        d = json.loads(json.dumps(req))
        d.pop("identity_digest", None)
        request = LaunchRequest.from_dict(d)
        prepared = svc.prepare(request, flow_id="flow-X")
        assert prepared["preview"]["decision"] == "ALLOW", "X 预检必须先允许"
        moved = svc.move_device_group(info["device"], info["target_group"])
        committed = svc.commit(
            request, prepared["snapshot_id"], flow_id="flow-X"
        )
        steps.append({
            "step": "prepare_then_move_then_commit",
            "preview": prepared["preview"]["error_code"],
            "after_move_generation": moved["generation"],
            "commit_decision": committed["decision"],
            "commit_error_code": committed["error_code"],
        })
        # 用新代数重放同一请求：FG2 无授权
        _, replay = admit("req-x-admit-gen2", req, moved["generation"])
        steps.append({
            "step": "replay_at_new_generation",
            "commit_decision": replay["decision"],
            "commit_error_code": replay["error_code"],
        })
        summary = {
            "scenario": "X",
            "title": "旧策略预检后设备转组",
            "expect_final_error": "STALE_DEVICE_GENERATION",
            "expect_replay_error": "NO_AUTHORIZATION",
            "steps": steps,
            "records": store.count_admissions(),
        }

    elif letter == "Y":
        req = info["request"]
        prepared, first = admit("req-y-admit", req, 1)
        assert first["decision"] == "ALLOW", "Y 首次准入必须允许"
        steps.append({
            "step": "initial_admit",
            "decision": first["decision"],
            "records": store.count_admissions(),
        })
        # 依赖签发者密钥吊销 -> 设备代数推进
        revoked = svc.revoke_issuer_key(
            info["revoke_kid"], [info["device"]], flow_id="flow-Y"
        )
        steps.append({
            "step": "revoke_dependency_key",
            "new_generation": revoked["device_generations"][info["device"]],
        })
        # 旧请求重提（仍带旧代数）：吊销 + 代数陈旧双重拦截
        _, stale = admit("req-y-admit-replay-oldgen", req, 1)
        steps.append({
            "step": "replay_old_generation_after_revoke",
            "decision": stale["decision"],
            "error_code": stale["error_code"],
        })
        # 轮换新钥并用新代数重提：签名链恢复但部件身份变化，重判
        rotated = svc.rotate_issuer_key(
            info["revoke_kid"], info["new_kid"], [info["device"]],
            flow_id="flow-Y",
        )
        new_gen = rotated["device_generations"][info["device"]]
        d2 = json.loads(json.dumps(req))
        d2["parts"][1] = _rekeyed_dependency(document, info["new_kid"])
        d2["request_id"] = "req-y-admit-newkey"
        d2["device_generation"] = new_gen
        d2.pop("identity_digest", None)
        request2 = LaunchRequest.from_dict(d2)
        prepared2 = svc.prepare(request2, flow_id="flow-Y")
        second = svc.commit(request2, prepared2["snapshot_id"], flow_id="flow-Y")
        steps.append({
            "step": "retry_with_rotated_key_new_generation",
            "decision": second["decision"],
            "error_code": second["error_code"],
            "note": "新钥恢复签发链，但新部件身份按同代策略重新判定",
        })
        summary = {
            "scenario": "Y",
            "title": "一项依赖许可被吊销",
            "expect_replay_error": "ISSUER_KEY_REVOKED",
            "expect_rekey_error": "NO_AUTHORIZATION",
            "steps": steps,
            "records": store.count_admissions(),
        }

    else:  # Z
        req = info["request"]
        _, first = admit("req-z-admit", req, 1)
        assert first["decision"] == "ALLOW", "Z 首次准入必须允许"
        receipt_v1 = first["receipt"]
        steps.append({
            "step": "initial_admit",
            "policy_version": receipt_v1["policy_version"],
            "receipt_id": receipt_v1["receipt_id"],
        })
        # 策略撤回：新版本移除允许规则（代数不变）
        new_version = svc.withdraw_rule(info["rule_id"], flow_id="flow-Z")
        steps.append({
            "step": "withdraw_rule",
            "new_policy_version": new_version,
        })
        # 同 request_id 幂等重放：返回固定 v1 回执，不产生重复行
        _, replay = admit("req-z-admit", req, 1)
        steps.append({
            "step": "idempotent_replay_same_request_id",
            "replayed": replay["replayed"],
            "policy_version": replay["receipt"]["policy_version"],
            "same_receipt": replay["receipt"]["receipt_id"]
            == receipt_v1["receipt_id"],
        })
        # 新 request_id（同身份内容）必须按 v2 重判 -> 无授权拒绝
        _, retried = admit("req-z-admit-after-withdraw", req, 1)
        steps.append({
            "step": "new_request_re_evaluated_under_v2",
            "decision": retried["decision"],
            "error_code": retried["error_code"],
            "policy_version": retried["receipt"]["policy_version"],
        })
        summary = {
            "scenario": "Z",
            "title": "先准入后策略撤回",
            "expect_retry_error": "NO_AUTHORIZATION",
            "steps": steps,
            "records": store.count_admissions(),
        }

    summary["admission_rows"] = [
        {
            "request_id": r["request_id"],
            "decision": r["decision"],
            "policy_version": r["policy_version"],
        }
        for r in store.list_admissions()
    ]
    store.close()
    return summary


def doc_ref(document: dict, letter: str) -> dict:
    return document["flow_requests"][letter]


# ---------------------------------------------------------------------------
# 崩溃场景：真实工人子进程 + 屏障 + 重开库对账
# ---------------------------------------------------------------------------

def _python_exe() -> str:
    return sys.executable or "python"


def run_worker_subprocess(job: dict, job_dir: str, timeout: float = 60.0) -> dict:
    os.makedirs(job_dir, exist_ok=True)
    job_path = os.path.join(job_dir, "job.json")
    with open(job_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(job, fh, ensure_ascii=False)
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # cwd=仓库根时，-m 会把 cwd 加入 sys.path，包可被找到；
    # 合成 cases.json 为自产输入，工人作业文件同样由本进程生成。
    proc = subprocess.run(
        [_python_exe(), "-m", "solution.worker", "--job", job_path],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=repo_root,
        env=env,
        timeout=timeout,
    )
    stdout = proc.stdout.strip().splitlines()
    parsed = json.loads(stdout[-1]) if stdout else {}
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "result": parsed,
    }


def run_crash_scenario(scenario: dict, workspace: str, document: dict) -> dict:
    ws = os.path.join(workspace, "crash", scenario["scenario_id"].lower())
    reset_workspace(ws)
    job_dir = os.path.join(ws, "job")
    barrier_dir = os.path.join(ws, "barriers")
    job = {
        "action": "admit",
        "workspace": os.path.join(ws, "db"),
        "fixture": document["crash_fixture"],
        "request": scenario["request"],
        "now": document["time_axis"]["T_MID"],
        "flow_id": scenario["scenario_id"],
        "crash_plan": {"phase": scenario["crash_phase"]},
        "barrier_dir": barrier_dir,
        "reset": True,
    }
    run = run_worker_subprocess(job, job_dir)

    # 重开数据库：恢复孤儿清单并对账（模拟服务重启）
    store = Store(os.path.join(ws, "db"))
    svc = AdmissionService(store, Clock(document["time_axis"]["T_MID"]))
    removed = svc.recover_orphan_manifests()
    records = store.count_admissions()
    manifests = len(store.list_manifest_files())
    events = [
        {"kind": e["kind"], "detail": e["detail"]}
        for e in store.list_events(scenario["scenario_id"])
    ]
    store.close()

    passed = (
        run["returncode"] == scenario["expect_exit_code"]
        and records == scenario["expect_records_after_recovery"]
        and manifests == scenario["expect_manifests_after_recovery"]
    )
    return {
        "scenario_id": scenario["scenario_id"],
        "crash_phase": scenario["crash_phase"],
        "worker_returncode": run["returncode"],
        "expect_returncode": scenario["expect_exit_code"],
        # 仅保留基名，避免临时目录随机后缀破坏重放确定性
        "removed_orphan_manifests": [os.path.basename(p) for p in removed],
        "records_after_recovery": records,
        "manifests_after_recovery": manifests,
        "events": events,
        "stderr_tail": run["stderr"][-300:],
        "passed": passed,
    }


def run_all_crash_scenarios(workspace: str, document: dict) -> dict:
    results = [
        run_crash_scenario(s, workspace, document)
        for s in document["crash_scenarios"]
    ]
    return {
        "total": len(results),
        "passed": sum(1 for r in results if r["passed"]),
        "all_passed": all(r["passed"] for r in results),
        "scenarios": results,
    }
