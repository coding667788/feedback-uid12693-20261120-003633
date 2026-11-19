"""命令行入口：python -m solution --input cases.json --output result.json"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import __version__
from .bootstrap import fixture_fingerprint, load_cases
from .replay import (
    run_all_crash_scenarios,
    run_decision_suite,
    run_scenario,
)

# 每个顺序流必须满足的具体断言（与 tests 中保持一致，CLI 也直接判失败）
FLOW_EXPECTATIONS = {
    "X": {
        "final_error": "STALE_DEVICE_GENERATION",
        "replay_error": "NO_AUTHORIZATION",
        "records": 0,
    },
    "Y": {
        "replay_error": "ISSUER_KEY_REVOKED",
        "records": 1,
    },
    "Z": {
        "retry_error": "NO_AUTHORIZATION",
        "records": 1,
    },
}


def _check_flow(letter: str, summary: dict) -> list[str]:
    failures: list[str] = []
    exp = FLOW_EXPECTATIONS[letter]
    if letter == "X":
        if summary["steps"][0]["commit_error_code"] != exp["final_error"]:
            failures.append("X 提交未按 STALE_DEVICE_GENERATION 拦截")
        if summary["steps"][1]["commit_error_code"] != exp["replay_error"]:
            failures.append("X 新代重判未返回 NO_AUTHORIZATION")
    if letter == "Y":
        if summary["steps"][2]["error_code"] != exp["replay_error"]:
            failures.append("Y 吊销后旧代重提未返回 ISSUER_KEY_REVOKED")
        if summary["steps"][3]["error_code"] != summary["expect_rekey_error"]:
            failures.append("Y 换钥新身份重判未返回 NO_AUTHORIZATION")
    if letter == "Z":
        if summary["steps"][2]["same_receipt"] is not True:
            failures.append("Z 幂等回执未固定原政策版本")
        if summary["steps"][3]["error_code"] != exp["retry_error"]:
            failures.append("Z 撤回后新请求未返回 NO_AUTHORIZATION")
    if summary["records"] != exp["records"]:
        failures.append(
            f"{letter} 持久记录数 {summary['records']} != {exp['records']}"
        )
    return failures


def run(input_path: str, output_path: str, workspace: str | None = None) -> dict:
    document = load_cases(input_path)
    own_workspace = workspace is None
    if own_workspace:
        workspace = tempfile.mkdtemp(prefix="aec-run-")
    os.makedirs(workspace, exist_ok=True)

    decision = run_decision_suite(workspace, document)

    flow_summaries = {}
    flow_failures: list[str] = []
    for letter in ("X", "Y", "Z"):
        summary = run_scenario(letter, workspace, document)
        flow_summaries[letter] = summary
        flow_failures.extend(f"{letter}: {f}" for f in _check_flow(letter, summary))

    crash = run_all_crash_scenarios(workspace, document)

    result = {
        "tool": "offline-application-execution-control",
        "version": __version__,
        "input_file": os.path.abspath(input_path),
        "cases_fingerprint": fixture_fingerprint(document),
        "decision_table": {
            "total": decision["total"],
            "passed": decision["passed"],
            "failed": decision["failed"],
            "all_passed": decision["all_passed"],
            "cases": [
                {
                    "case_id": c["case_id"],
                    "note": c["note"],
                    "expect": f"{c['expect_decision']}/{c['expect_error_code']}",
                    "actual": f"{c['actual_decision']}/{c['actual_error_code']}",
                    "passed": c["passed"],
                    "persisted_records": c["persisted_records"],
                }
                for c in decision["cases"]
            ],
        },
        "ordered_scenarios": flow_summaries,
        "ordered_scenario_failures": flow_failures,
        "crash_scenarios": crash,
        "overall_passed": (
            decision["all_passed"]
            and not flow_failures
            and crash["all_passed"]
        ),
    }
    with open(output_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2, sort_keys=True)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线应用执行控制服务重放器")
    parser.add_argument("--input", required=True, help="cases.json 路径")
    parser.add_argument("--output", required=True, help="result.json 输出路径")
    parser.add_argument("--workspace", default=None, help="可选：固定工作区目录")
    args = parser.parse_args(argv)

    result = run(args.input, args.output, args.workspace)
    dt = result["decision_table"]
    print(
        f"decision table: {dt['passed']}/{dt['total']} passed; "
        f"ordered flows: {'OK' if not result['ordered_scenario_failures'] else 'FAIL'}; "
        f"crash: {result['crash_scenarios']['passed']}/{result['crash_scenarios']['total']}"
    )
    print(f"overall_passed={result['overall_passed']}")
    print(f"result written to {os.path.abspath(args.output)}")
    return 0 if result["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
