"""独立工人进程入口：python -m solution.worker --job job.json

两种运行方式：

* 普通作业：prepare/commit，输出 JSON 结果行；
* 崩溃作业：按 crash_plan 在“清单写入未提交”或“提交完成后”真实终止
  （os._exit），父测试进程凭退出码与屏障文件确认崩溃点确实发生。

屏障协议：作业可带 barrier_dir，工人在关键动作前后落 *.signal 文件并
flush，父进程轮询这些文件做精确同步，避免脆弱的 sleep。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .bootstrap import bootstrap
from .clock import Clock
from .errors import AdmissionError
from .models import LaunchRequest
from .service import AdmissionService
from .store import Store


def _signal(barrier_dir: str | None, name: str) -> None:
    if not barrier_dir:
        return
    os.makedirs(barrier_dir, exist_ok=True)
    path = os.path.join(barrier_dir, name + ".signal")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(name)
        fh.flush()
        os.fsync(fh.fileno())


def run_job(job: dict) -> dict:
    workspace = job["workspace"]
    fixture = job["fixture"]
    now = job.get("now")
    clock = Clock(now)

    if job.get("reset", True):
        from .bootstrap import reset_workspace

        reset_workspace(workspace)
    store = bootstrap(workspace, fixture)
    svc = AdmissionService(store, clock)
    barrier = job.get("barrier_dir")

    try:
        if job["action"] == "admit":
            request = LaunchRequest.from_dict(job["request"])
            _signal(barrier, "before_prepare")
            prepared = svc.prepare(request, flow_id=job.get("flow_id", "worker"))
            _signal(barrier, "after_prepare")
            crash_plan = job.get("crash_plan")
            committed = svc.commit(
                request, prepared["snapshot_id"],
                flow_id=job.get("flow_id", "worker"),
                crash_plan=crash_plan,
            )
            _signal(barrier, "after_commit_return")
            out = {
                "ok": True,
                "prepared": {
                    "snapshot_id": prepared["snapshot_id"],
                    "policy_version": prepared["policy_version"],
                    "device_generation": prepared["device_generation"],
                    "preview_decision": prepared["preview"]["decision"],
                    "preview_error_code": prepared["preview"]["error_code"],
                },
                "committed": committed,
            }
            if committed["decision"] == "ALLOW":
                out["manifest_path"] = store.manifest_path_for(
                    request.request_id
                )
            return out

        if job["action"] == "recover":
            removed = svc.recover_orphan_manifests()
            return {
                "ok": True,
                "removed_orphan_manifests": removed,
                "admission_count": store.count_admissions(),
                "manifest_count": len(store.list_manifest_files()),
            }

        raise AdmissionError("BAD_REQUEST", f"未知 action {job['action']}")
    finally:
        store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线准入工人进程")
    parser.add_argument("--job", required=True, help="作业 JSON 文件路径")
    args = parser.parse_args(argv)

    with open(args.job, "r", encoding="utf-8") as fh:
        job = json.load(fh)

    try:
        result = run_job(job)
    except AdmissionError as exc:
        result = {"ok": False, "error_code": exc.code, "message": exc.message}
        print(json.dumps(result, ensure_ascii=False))
        return 2
    except SystemExit:
        # 崩溃计划通过 os._exit 真实终止；若被拦截包装成 SystemExit，
        # 保留其退出码（42=清单写入未提交，43=提交完成后终止）
        raise
    except Exception as exc:
        result = {"ok": False, "error_code": "WORKER_CRASH", "message": repr(exc)}
        print(json.dumps(result, ensure_ascii=False))
        return 3

    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
