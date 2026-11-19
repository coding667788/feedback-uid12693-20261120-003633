"""核心准入服务：两阶段提交、事务内重核、管理操作、清单原子写。

阶段一 prepare：读取一次状态快照（提示），纯内存评估，不写准入数据；
阶段二 commit：BEGIN IMMEDIATE 事务内重新加载全部受影响状态，重新核对
设备代数、策略版本、规则有效期与当前吊销/远端状态，再重跑引擎。

只有整单 ALLOW 才在同一事务里落一条 admission_records 并 fsync 清单。
任何异常都回滚，绝不留下部分准入。
"""

from __future__ import annotations

import json
import os
from typing import Any

from .bootstrap import EPOCH
from .clock import Clock
from .crypto import canonical, new_secret_hex, sha256_text
from .engine import ALLOW, DENY, evaluate_launch
from .errors import (
    AdmissionError,
    ALLOW_KINDS,
    CERT_ACTIVE,
    CERT_REVOKED,
    CERT_ROTATED,
    DENY_KINDS,
    E_BAD_REQUEST,
    E_OK,
    E_SNAPSHOT_STALE,
    E_STALE_DEVICE_GENERATION,
    E_STALE_POLICY_VERSION,
    E_TEMP_GRANT_INVALID,
    E_UNKNOWN_SNAPSHOT,
    REMOTE_GOOD,
)
from .models import LaunchRequest
from .store import Store


class AdmissionService:
    def __init__(self, store: Store, clock: Clock):
        self.store = store
        self.clock = clock

    # ---- 状态装载 -------------------------------------------------------------
    def _build_context(self, conn, request: LaunchRequest) -> dict:
        """从事务内的连接重新加载全部受影响状态。"""
        device = self.store.get_device(request.device_id)
        if device is None:
            raise AdmissionError(E_BAD_REQUEST, f"未知设备 {request.device_id}")
        org = self.store.get_org(request.org_id)
        if org is None:
            raise AdmissionError(E_BAD_REQUEST, f"未知组织 {request.org_id}")
        version = org["current_policy_version"]

        cert_rows = self.store.list_certs(request.org_id)
        certs = {row["kid"]: dict(row) for row in cert_rows}
        remote_rows = conn.execute(
            "SELECT * FROM remote_issuer_status WHERE org_id=?", (request.org_id,)
        ).fetchall()
        remote = {row["issuer_id"]: dict(row) for row in remote_rows}

        rules = [dict(r) for r in self.store.active_rules(request.org_id, version)]
        grants = [
            dict(g)
            for g in self.store.active_temp_grants(request.org_id, device["group_id"])
        ]
        return {
            "device": dict(device),
            "policy_version": version,
            "certs": certs,
            "remote": remote,
            "rules": rules,
            "temp_grants": grants,
            "device_group": device["group_id"],
            "now": self.clock.now(),
        }

    def _fingerprint(self, conn, org_id: str, device_id: str, version: int) -> str:
        """对“会影响判定的全部状态”取指纹，快照与提交两期必须一致才算新鲜。"""
        device = self.store.get_device(device_id)
        payload = {
            "device": {
                "group_id": device["group_id"],
                "generation": device["generation"],
            },
            "certs": [
                {
                    "kid": r["kid"],
                    "status": r["status"],
                    "not_before": r["not_before"],
                    "not_after": r["not_after"],
                }
                for r in self.store.list_certs(org_id)
            ],
            "remote": [
                {"issuer_id": r["issuer_id"], "status": r["status"]}
                for r in conn.execute(
                    "SELECT issuer_id, status FROM remote_issuer_status "
                    "WHERE org_id=? ORDER BY issuer_id",
                    (org_id,),
                ).fetchall()
            ],
            "rules": [
                {
                    "rule_id": r["rule_id"],
                    "version_removed": r["version_removed"],
                    "valid_from": r["valid_from"],
                    "valid_to": r["valid_to"],
                    "layer": r["layer"],
                    "group_id": r["group_id"],
                    "kind": r["kind"],
                    "match_digest": r["match_digest"],
                    "match_issuer_id": r["match_issuer_id"],
                    "match_path_segments": r["match_path_segments"],
                }
                for r in self.store.active_rules(org_id, version)
            ],
            "grants": [
                {
                    "grant_id": r["grant_id"],
                    "base_rule_id": r["base_rule_id"],
                    "valid_from": r["valid_from"],
                    "valid_to": r["valid_to"],
                    "approver1": r["approver1"],
                    "approver2": r["approver2"],
                }
                for r in conn.execute(
                    "SELECT * FROM temp_grants WHERE org_id=? ORDER BY grant_id",
                    (org_id,),
                ).fetchall()
            ],
            "policy_version": version,
        }
        return sha256_text(canonical(payload))

    # ---- 阶段一：快照 + 预检 ---------------------------------------------------
    def prepare(self, request: LaunchRequest, flow_id: str = "adhoc") -> dict:
        """读取一次快照作为提示，执行纯内存预检，不写准入数据。"""
        now = self.clock.now()
        with self.store.immediate() as conn:
            device = self.store.get_device(request.device_id)
            if device is None:
                raise AdmissionError(E_BAD_REQUEST, f"未知设备 {request.device_id}")
            org = self.store.get_org(request.org_id)
            if org is None:
                raise AdmissionError(E_BAD_REQUEST, f"未知组织 {request.org_id}")
            version = org["current_policy_version"]
            fingerprint = self._fingerprint(conn, request.org_id, request.device_id, version)
            # 固定时钟下同一请求会产生同指纹，加入库内快照序号避免碰撞
            seq_row = conn.execute(
                "SELECT COUNT(*) AS c FROM snapshots"
            ).fetchone()
            snapshot_id = "snap-" + sha256_text(
                canonical({
                    "rid": request.request_id,
                    "fp": fingerprint,
                    "ts": now,
                    "seq": seq_row["c"],
                })
            )[:16]
            self.store.insert_snapshot({
                "snapshot_id": snapshot_id,
                "org_id": request.org_id,
                "device_id": request.device_id,
                "fingerprint": fingerprint,
                "policy_version": version,
                "device_generation": device["generation"],
                "created_at": now,
            })
            ctx = self._build_context(conn, request)
            preview = evaluate_launch(request, ctx)
            self.store.log_event(flow_id, "prepare", request.request_id, now)
        return {
            "snapshot_id": snapshot_id,
            "policy_version": version,
            "device_generation": device["generation"],
            "preview": preview,
            "fingerprint": fingerprint,
            "prepared_at": now,
        }

    # ---- 阶段二：事务内重核 + 提交 --------------------------------------------
    def commit(
        self,
        request: LaunchRequest,
        snapshot_id: str,
        flow_id: str = "adhoc",
        crash_plan: dict | None = None,
    ) -> dict:
        """提交准入。

        crash_plan（仅测试工人使用）：
          {"phase": "after_manifest_before_commit"} -> 写完清单、未提交即退出；
          {"phase": "after_commit"} -> 提交完成后退出。
        """
        now = self.clock.now()
        with self.store.immediate() as conn:
            # 0) 幂等：同 request_id 已有持久记录则原样返回，绝不产生重复行
            existing = self.store.get_admission(request.request_id)
            if existing is not None:
                receipt = json.loads(existing["receipt"])
                self.store.log_event(
                    flow_id, "idempotent_replay", request.request_id, now
                )
                return {
                    "replayed": True,
                    "decision": existing["decision"],
                    "error_code": existing["error_code"],
                    "receipt": receipt,
                }

            # 1) 快照存在性
            snap = self.store.get_snapshot(snapshot_id)
            if snap is None:
                raise AdmissionError(E_UNKNOWN_SNAPSHOT, f"未知快照 {snapshot_id}")

            # 2) 事务内重新核对代数与策略版本（核心重核点）
            device = self.store.get_device(request.device_id)
            org = self.store.get_org(request.org_id)
            current_version = org["current_policy_version"]
            staleness = []
            if device["generation"] != request.device_generation:
                staleness.append(E_STALE_DEVICE_GENERATION)
            if snap["policy_version"] != current_version:
                staleness.append(E_STALE_POLICY_VERSION)
            current_fp = self._fingerprint(
                conn, request.org_id, request.device_id, current_version
            )
            if current_fp != snap["fingerprint"]:
                staleness.append(E_SNAPSHOT_STALE)

            # 3) 重新加载全部受影响状态并完整重跑引擎（有效期/吊销/远端状态）
            ctx = self._build_context(conn, request)
            result = evaluate_launch(request, ctx)

            # 4) 陈旧性与引擎判定的优先级（按失败原因精确度分级）：
            #    a) 签发链/吊销/远端状态类硬失败：以具体安全错误码为准，
            #       陈旧信号附带保留（Y 场景吊销必须报 ISSUER_KEY_REVOKED）；
            #    b) 设备代数陈旧（转组、轮换、吊销推进代数）：若引擎未发现
            #       硬失败，则以 STALE_DEVICE_GENERATION 接管（X 场景）；
            #    c) 策略版本陈旧（撤回）：以 STALE_POLICY_VERSION 接管，
            #       引擎原因附带；
            #    d) 快照指纹不一致：SNAPSHOT_STALE 兜底。
            hard_security = {
                "ISSUER_KEY_REVOKED",
                "ISSUER_CHAIN_INVALID",
                "ISSUER_UNTRUSTED",
                "REMOTE_ISSUER_STATUS_BAD",
                "DENY_EXPLICIT",
            }
            engine_code = result["error_code"]
            if engine_code in hard_security:
                if staleness:
                    result["staleness"] = staleness
            elif E_STALE_DEVICE_GENERATION in staleness:
                result = {
                    "decision": DENY,
                    "error_code": E_STALE_DEVICE_GENERATION,
                    "parts": result["parts"],
                    "staleness": staleness,
                    "engine_error_code": engine_code,
                }
            elif E_STALE_POLICY_VERSION in staleness:
                result = {
                    "decision": DENY,
                    "error_code": E_STALE_POLICY_VERSION,
                    "parts": result["parts"],
                    "staleness": staleness,
                    "engine_error_code": engine_code,
                }
            elif staleness:
                result = {
                    "decision": DENY,
                    "error_code": staleness[0],
                    "parts": result["parts"],
                    "staleness": staleness,
                    "engine_error_code": engine_code,
                }

            # 5) 固定当时使用的政策版本与命中规则，形成幂等回执
            receipt = self._build_receipt(request, result, current_version, ctx, now)

            if result["decision"] != ALLOW:
                self.store.log_event(
                    flow_id, "commit_deny",
                    f"{request.request_id}:{result['error_code']}", now,
                )
                # 拒绝不落持久准入记录；返回判定结果供调用方断言
                return {
                    "replayed": False,
                    "decision": DENY,
                    "error_code": result["error_code"],
                    "receipt": receipt,
                }

            # 6) 全部件允许：同一事务内落库 + 写合成启动清单
            manifest_path = self.store.manifest_path_for(request.request_id)
            manifest = self._build_manifest(request, receipt, manifest_path)
            self._atomic_write_manifest(manifest_path, manifest)
            if crash_plan and crash_plan.get("phase") == "after_manifest_before_commit":
                self.store.log_event(
                    flow_id, "crash_after_manifest_before_commit",
                    request.request_id, now,
                )
                # 清单已 fsync 落盘但事务尚未提交；真实退出后 SQLite
                # 自动回滚写事务，恢复阶段再清除孤儿清单。
                self._hard_exit(42)

            self.store.insert_admission(
                {
                    "request_id": request.request_id,
                    "identity_digest": request.identity_digest,
                    "org_id": request.org_id,
                    "device_id": request.device_id,
                    "device_generation": request.device_generation,
                    "policy_version": current_version,
                    "decision": ALLOW,
                    "error_code": E_OK,
                    "created_at": now,
                },
                receipt,
                manifest_path,
            )
            self.store.log_event(flow_id, "commit_allow", request.request_id, now)

            if crash_plan and crash_plan.get("phase") == "after_commit":
                # 提交已完成（with 退出前显式 commit），随后真实退出
                conn.commit()
                self.store.log_event(
                    flow_id, "crash_after_commit", request.request_id, now
                )
                conn.commit()
                self._hard_exit(43)

        return {
            "replayed": False,
            "decision": ALLOW,
            "error_code": E_OK,
            "receipt": receipt,
            "manifest_path": manifest_path,
        }

    def _hard_exit(self, code: int) -> None:
        """真实终止工人进程（os._exit 跳过缓冲与清理，模拟崩溃）。"""
        import sys

        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)

    # ---- 回执 / 清单 ----------------------------------------------------------
    def _build_receipt(self, request, result, version, ctx, now) -> dict:
        return {
            "receipt_id": "rcp-" + sha256_text(
                canonical({"rid": request.request_id, "id": request.identity_digest})
            )[:16],
            "request_id": request.request_id,
            "identity_digest": request.identity_digest,
            "org_id": request.org_id,
            "device_id": request.device_id,
            "device_generation": request.device_generation,
            "policy_version": version,
            "decision": result["decision"],
            "error_code": result["error_code"],
            "evaluated_at": now,
            "parts": [
                {
                    "slot": p["slot"],
                    "name": p["name"],
                    "decision": p["decision"],
                    "error_code": p["error_code"],
                    "hit_rules": p["hits"],
                }
                for p in result["parts"]
            ],
        }

    def _build_manifest(self, request, receipt, manifest_path) -> dict:
        """合成启动清单：只记录判定结果与受控部件清单，绝不包含可执行动作。"""
        return {
            "manifest_kind": "synthetic-admission-manifest",
            "manifest_version": 1,
            "request_id": request.request_id,
            "org_id": request.org_id,
            "device_id": request.device_id,
            "policy_version": receipt["policy_version"],
            "device_generation": receipt["device_generation"],
            "receipt_id": receipt["receipt_id"],
            "admitted": True,
            "execution_performed": False,
            "parts": [
                {
                    "slot": p.slot,
                    "role": p.role,
                    "name": p.name,
                    "content_digest": p.content_digest,
                    "issuer_id": p.issuer_id,
                    "leaf_kid": p.leaf_kid,
                    "entry_path": p.entry_path,
                }
                for p in request.parts
            ],
            "written_at": self.clock.now(),
        }

    def _atomic_write_manifest(self, path: str, manifest: dict) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    # ---- 恢复：清理未提交孤儿清单 ---------------------------------------------
    def recover_orphan_manifests(self) -> list[str]:
        """重开数据库后，删除没有对应 admission_records 的清单文件。

        崩溃在“清单已写、事务未提交”时，事务回滚而清单文件残留；
        恢复阶段按持久记录对账清除，保证不留部分准入痕迹。
        """
        admitted_ids = {
            row["request_id"] for row in self.store.list_admissions()
        }
        removed = []
        for path in self.store.list_manifest_files():
            rid = os.path.splitext(os.path.basename(path))[0]
            if rid not in admitted_ids:
                os.remove(path)
                removed.append(path)
        return removed

    # ---- 管理操作 --------------------------------------------------------------
    def rotate_issuer_key(
        self, old_kid: str, new_kid: str, devices: list[str], flow_id: str = "mgmt"
    ) -> dict:
        """签发者凭据轮换：旧钥置 ROTATED，同组织新钥 ACTIVE，相关设备代数+1。"""
        now = self.clock.now()
        with self.store.immediate():
            old = self.store.get_cert(old_kid)
            if old is None:
                raise AdmissionError(E_BAD_REQUEST, f"未知密钥 {old_kid}")
            if self.store.get_cert(new_kid) is not None:
                raise AdmissionError(E_BAD_REQUEST, f"新密钥已存在 {new_kid}")
            self.store.set_cert_status(old_kid, CERT_ROTATED)
            new_cert = {
                "kid": new_kid,
                "org_id": old["org_id"],
                "issuer_id": old["issuer_id"],
                "parent_kid": old["parent_kid"],
                "secret_hex": new_secret_hex(new_kid),
                "status": CERT_ACTIVE,
                "not_before": EPOCH,
                "not_after": old["not_after"],
            }
            from .crypto import sign_cert

            if new_cert["parent_kid"] is None:
                new_cert["signature"] = sign_cert(
                    new_cert, new_cert["secret_hex"]
                )
            else:
                new_cert["signature"] = sign_cert(
                    new_cert, new_secret_hex(new_cert["parent_kid"])
                )
            self.store.insert_cert(new_cert)
            gens = {}
            for dev_id in devices:
                gens[dev_id] = self.store.bump_device_generation(dev_id, now)
            self.store.log_event(flow_id, "rotate", f"{old_kid}->{new_kid}", now)
        return {"old_kid": old_kid, "new_kid": new_kid, "device_generations": gens}

    def revoke_issuer_key(
        self, kid: str, devices: list[str], flow_id: str = "mgmt"
    ) -> dict:
        """吊销叶子密钥：置 REVOKED 并推进受影响设备代数。"""
        now = self.clock.now()
        with self.store.immediate():
            cert = self.store.get_cert(kid)
            if cert is None:
                raise AdmissionError(E_BAD_REQUEST, f"未知密钥 {kid}")
            self.store.set_cert_status(kid, CERT_REVOKED)
            gens = {}
            for dev_id in devices:
                gens[dev_id] = self.store.bump_device_generation(dev_id, now)
            self.store.log_event(flow_id, "revoke", kid, now)
        return {"kid": kid, "device_generations": gens}

    def move_device_group(self, device_id: str, new_group: str, flow_id: str = "mgmt"):
        now = self.clock.now()
        with self.store.immediate():
            gen = self.store.move_device_group(device_id, new_group, now)
            self.store.log_event(
                flow_id, "move_group", f"{device_id}->{new_group}", now
            )
        return {"device_id": device_id, "group_id": new_group, "generation": gen}

    def set_remote_status(self, issuer_id: str, status: str, flow_id: str = "mgmt"):
        now = self.clock.now()
        with self.store.immediate():
            row = self.store.conn.execute(
                "SELECT org_id FROM remote_issuer_status WHERE issuer_id=?",
                (issuer_id,),
            ).fetchone()
            if row is None:
                raise AdmissionError(E_BAD_REQUEST, f"未知远端签发者 {issuer_id}")
            self.store.upsert_remote_status(issuer_id, row["org_id"], status, now)
            self.store.log_event(flow_id, "remote_status", f"{issuer_id}={status}", now)
        return {"issuer_id": issuer_id, "status": status}

    def new_policy_version(self, org_id: str, note: str, flow_id: str = "mgmt") -> int:
        now = self.clock.now()
        with self.store.immediate():
            org = self.store.get_org(org_id)
            nxt = org["current_policy_version"] + 1
            self.store.insert_policy_version(org_id, nxt, now, note)
            self.store.set_policy_version(org_id, nxt)
            self.store.log_event(flow_id, "new_policy_version", f"v{nxt}:{note}", now)
        return nxt

    def withdraw_rule(self, rule_id: str, flow_id: str = "mgmt") -> int:
        """策略撤回：在新版本中移除规则（不改代数，靠策略版本与指纹拦截）。"""
        now = self.clock.now()
        with self.store.immediate():
            rule = self.store.get_rule(rule_id)
            if rule is None:
                raise AdmissionError(E_BAD_REQUEST, f"未知规则 {rule_id}")
            org = self.store.get_org(rule["org_id"])
            nxt = org["current_policy_version"] + 1
            self.store.insert_policy_version(
                rule["org_id"], nxt, now, f"withdraw {rule_id}"
            )
            self.store.set_policy_version(rule["org_id"], nxt)
            self.store.withdraw_rule(rule_id, nxt)
            self.store.log_event(flow_id, "withdraw_rule", rule_id, now)
        return nxt

    def create_temp_grant(self, grant: dict, flow_id: str = "mgmt") -> dict:
        """设备组临时放宽：必须挂在允许规则上、两位不同审批者、不能放宽拒绝。"""
        now = self.clock.now()
        with self.store.immediate():
            if grant["approver1"] == grant["approver2"]:
                raise AdmissionError(
                    E_TEMP_GRANT_INVALID, "临时授权需要两位不同审批者"
                )
            base = self.store.get_rule(grant["base_rule_id"])
            if base is None:
                raise AdmissionError(
                    E_TEMP_GRANT_INVALID, f"基础规则不存在 {grant['base_rule_id']}"
                )
            if base["kind"] in DENY_KINDS:
                raise AdmissionError(
                    E_TEMP_GRANT_INVALID, "明确拒绝规则不允许被临时放宽"
                )
            if base["kind"] not in ALLOW_KINDS:
                raise AdmissionError(
                    E_TEMP_GRANT_INVALID, "临时授权只能挂在允许规则上"
                )
            # 允许跨组放宽（G1 的允许临时授予 G3）；设备组必须存在，
            # 实际作用域由引擎按 grant.group_id 与设备组匹配把关。
            group_row = self.store.conn.execute(
                "SELECT 1 FROM device_groups WHERE org_id=? AND group_id=?",
                (base["org_id"], grant["group_id"]),
            ).fetchone()
            if group_row is None:
                raise AdmissionError(
                    E_TEMP_GRANT_INVALID,
                    f"临时授权目标组不存在 {grant['group_id']}",
                )
            if not (grant["valid_from"] < grant["valid_to"]):
                raise AdmissionError(
                    E_TEMP_GRANT_INVALID, "临时授权有效期窗口非法"
                )
            org = self.store.get_org(base["org_id"])
            grant = dict(grant)
            grant.setdefault("org_id", base["org_id"])
            grant["version_added"] = org["current_policy_version"]
            grant["created_at"] = now
            grant.setdefault(
                "grant_id",
                "grant-" + sha256_text(canonical(grant))[:12],
            )
            self.store.insert_temp_grant(grant)
            self.store.log_event(flow_id, "temp_grant", grant["grant_id"], now)
        return grant
