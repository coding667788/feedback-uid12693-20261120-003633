"""独立进程顺序流入口：python -m solution.flow_process --input cases.json \
        --order XYZ --workspace <dir> --out <report.json>

每个进程在自己的工作区里按给定顺序完整执行 X/Y/Z 与两个崩溃场景，
用于验证两种相反顺序下断言完全一致、进程间互不干扰。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .__main__ import _check_flow
from .bootstrap import load_cases
from .replay import (
    run_all_crash_scenarios,
    run_scenario,
)

ORDER_MAP = {
    "XYZ": ["X", "Y", "Z", "KILL_PRE_COMMIT", "KILL_POST_COMMIT"],
    "ZYX": ["Z", "Y", "X", "KILL_POST_COMMIT", "KILL_PRE_COMMIT"],
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="独立进程顺序流")
    parser.add_argument("--input", required=True)
    parser.add_argument("--order", required=True, choices=sorted(ORDER_MAP))
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    document = load_cases(args.input)
    os.makedirs(args.workspace, exist_ok=True)
    report = {"order": args.order, "items": [], "failures": []}

    for item in ORDER_MAP[args.order]:
        if item in ("X", "Y", "Z"):
            summary = run_scenario(item, args.workspace, document)
            failures = [f"{item}: {f}" for f in _check_flow(item, summary)]
            report["items"].append({
                "kind": "scenario", "scenario": item, "summary": summary,
            })
            report["failures"].extend(failures)
        else:
            scenario_id = item
            scenario = next(
                s for s in document["crash_scenarios"]
                if s["scenario_id"] == scenario_id
            )
            from .replay import run_crash_scenario

            crash = run_crash_scenario(scenario, args.workspace, document)
            report["items"].append({
                "kind": "crash", "scenario": scenario_id, "summary": crash,
            })
            if not crash["passed"]:
                report["failures"].append(f"{scenario_id}: crash invariants failed")

    report["passed"] = not report["failures"]
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print(json.dumps({
        "order": args.order,
        "passed": report["passed"],
        "failures": report["failures"],
        "report": os.path.abspath(args.out),
    }, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
