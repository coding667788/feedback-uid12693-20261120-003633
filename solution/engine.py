"""策略评估引擎（纯函数式，给定上下文做判定）。

判定顺序（每个部件独立执行）：

1. 签发链验证：叶子 -> 根逐跳验 HMAC 签名、有效期、密钥状态、受信根；
2. 内容见证：用叶子密钥重算 chain_digest，绑定内容 SHA-256；
3. 远端签发者模拟状态必须 GOOD；
4. 明确拒绝（在有效期、层级适用）优先命中 => DENY_EXPLICIT；
5. 否则寻找允许（基线/组规则 + 双审批临时放宽）；
6. 只有过期候选 => RULE_EXPIRED；什么都没有 => NO_AUTHORIZATION。

拒绝覆盖一切允许；整单仅当全部部件 ALLOW 才 ALLOW。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .crypto import attest_content_digest, canonical, hmac_hex, sign_cert
from .errors import (
    CERT_ACTIVE,
    E_DENY_EXPLICIT,
    E_ISSUER_CHAIN_INVALID,
    E_ISSUER_KEY_REVOKED,
    E_ISSUER_UNTRUSTED,
    E_NO_AUTHORIZATION,
    E_OK,
    E_REMOTE_STATUS_BAD,
    E_RULE_EXPIRED,
    REMOTE_GOOD,
)
from .paths import has_segment_sequence

ALLOW = "ALLOW"
DENY = "DENY"


# ---- 签发链验证 ------------------------------------------------------------------

def verify_chain(part, certs: dict, remote: dict, now: str) -> tuple[bool, str, str]:
    """验证叶子密钥所在的整条合成签发链。

    certs: kid -> 证书 dict（含 secret_hex / status / signature / parent_kid）
    remote: issuer_id -> {"status": GOOD/SUSPENDED/REVOKED}
    返回 (ok, error_code, detail)。
    """
    leaf = certs.get(part.leaf_kid)
    if leaf is None:
        return False, E_ISSUER_UNTRUSTED, f"叶子密钥 {part.leaf_kid} 不在受信库"
    if leaf["issuer_id"] != part.issuer_id:
        return False, E_ISSUER_CHAIN_INVALID, "请求签发者与叶子证书签发者不一致"

    # 逐跳向上：每跳证书必须由父密钥正确签名且处于 ACTIVE、在有效期内
    kid = part.leaf_kid
    seen: set[str] = set()
    while True:
        if kid in seen:
            return False, E_ISSUER_CHAIN_INVALID, "签发链存在环"
        seen.add(kid)
        cert = certs.get(kid)
        if cert is None:
            return False, E_ISSUER_UNTRUSTED, f"链上证书缺失: {kid}"
        if cert["status"] != CERT_ACTIVE:
            if cert["kid"] == part.leaf_kid:
                return (
                    False,
                    E_ISSUER_KEY_REVOKED,
                    f"叶子密钥状态为 {cert['status']}（轮换/吊销后旧钥立即失效）",
                )
            return False, E_ISSUER_KEY_REVOKED, f"链上证书 {kid} 状态为 {cert['status']}"
        if not (cert["not_before"] <= now <= cert["not_after"]):
            return False, E_ISSUER_CHAIN_INVALID, f"证书 {kid} 不在有效期窗口"

        if cert["parent_kid"] is None:
            # 根证书：必须自签，且属于请求组织的受信根
            if cert["org_id"] != _org_of(certs, part):
                return False, E_ISSUER_UNTRUSTED, "受信根不属于请求组织"
            expect = sign_cert(cert, cert["secret_hex"])
            if not hmac_equal(expect, cert["signature"]):
                return False, E_ISSUER_CHAIN_INVALID, f"根证书 {kid} 自签无效"
            break

        parent = certs.get(cert["parent_kid"])
        if parent is None:
            return False, E_ISSUER_UNTRUSTED, f"父证书缺失: {cert['parent_kid']}"
        expect = sign_cert(cert, parent["secret_hex"])
        if not hmac_equal(expect, cert["signature"]):
            return False, E_ISSUER_CHAIN_INVALID, f"证书 {kid} 的父级签名无效"
        kid = cert["parent_kid"]

    # 叶子对内容摘要的签发链见证（防摘要被替换 / 移用）
    expect_attest = attest_content_digest(leaf["secret_hex"], part.content_digest)
    if not hmac_equal(expect_attest, part.chain_digest):
        return False, E_ISSUER_CHAIN_INVALID, "chain_digest 与内容摘要验签失败"

    status = remote.get(part.issuer_id)
    if status is not None and status["status"] != REMOTE_GOOD:
        return False, E_REMOTE_STATUS_BAD, (
            f"远端签发者模拟状态={status['status']}"
        )
    return True, E_OK, "签发链验证通过"


def _org_of(certs: dict, part) -> str:
    cert = certs.get(part.leaf_kid)
    return cert["org_id"] if cert else ""


def hmac_equal(a: str, b: str) -> bool:
    import hmac as _hmac

    return _hmac.compare_digest(a, b)


# ---- 规则匹配 --------------------------------------------------------------------

@dataclass
class Hit:
    rule_id: str
    layer: str
    kind: str
    group_id: str | None = None
    grant_id: str | None = None

    def to_dict(self) -> dict:
        d = {"rule_id": self.rule_id, "layer": self.layer, "kind": self.kind}
        if self.group_id:
            d["group_id"] = self.group_id
        if self.grant_id:
            d["grant_id"] = self.grant_id
        return d


@dataclass
class PartDecision:
    slot: int
    name: str
    decision: str
    error_code: str
    hits: list[Hit] = field(default_factory=list)
    expired_candidates: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "slot": self.slot,
            "name": self.name,
            "decision": self.decision,
            "error_code": self.error_code,
            "hits": [h.to_dict() for h in self.hits],
            "expired_candidates": list(self.expired_candidates),
            "detail": self.detail,
        }


def _rule_scope_applies(rule: dict, device_group: str) -> bool:
    if rule["layer"] == "baseline":
        return True
    return rule["group_id"] == device_group


def _rule_in_window(rule: dict, now: str) -> bool:
    return rule["valid_from"] <= now <= rule["valid_to"]


def _rule_matches_part(rule: dict, part) -> bool:
    kind = rule["kind"]
    if kind in ("digest_allow", "deny_digest"):
        return rule["match_digest"] == part.content_digest
    # issuer_path_allow / deny_issuer_path：签发者 + 连续路径段联合
    if rule["match_issuer_id"] != part.issuer_id:
        return False
    segments = json.loads(rule["match_path_segments"] or "[]")
    return has_segment_sequence(part.entry_path, segments)


def evaluate_part(part, ctx: dict) -> PartDecision:
    """ctx 键：certs / remote / now / rules / temp_grants / device_group。"""
    now = ctx["now"]
    ok, code, detail = verify_chain(part, ctx["certs"], ctx["remote"], now)
    if not ok:
        return PartDecision(
            slot=part.slot, name=part.name, decision=DENY,
            error_code=code, detail=detail,
        )

    denies: list[Hit] = []
    allows: list[Hit] = []
    expired: list[str] = []

    for rule in ctx["rules"]:
        if not _rule_scope_applies(rule, ctx["device_group"]):
            continue
        if not _rule_matches_part(rule, part):
            continue
        if not _rule_in_window(rule, now):
            expired.append(f"{rule['rule_id']}(window)")
            continue
        hit = Hit(rule["rule_id"], rule["layer"], rule["kind"], rule["group_id"])
        if rule["kind"] in ("deny_digest", "deny_issuer_path"):
            denies.append(hit)
        else:
            allows.append(hit)

    # 双审批临时放宽：挂在仍生效的允许规则上，按 grant 自身的组与窗口匹配，
    # 从而支持把某组的允许临时放宽给另一设备组。
    for grant in ctx["temp_grants"]:
        base = next(
            (r for r in ctx["rules"] if r["rule_id"] == grant["base_rule_id"]), None
        )
        if base is None:
            continue
        if grant["group_id"] != ctx["device_group"]:
            continue
        if not _rule_matches_part(base, part):
            continue
        if not (grant["valid_from"] <= now <= grant["valid_to"]):
            expired.append(f"{grant['grant_id']}(grant-window)")
            continue
        allows.append(
            Hit(
                base["rule_id"], base["layer"], base["kind"],
                grant["group_id"], grant["grant_id"],
            )
        )

    # 拒绝覆盖所有允许
    if denies:
        return PartDecision(
            slot=part.slot, name=part.name, decision=DENY,
            error_code=E_DENY_EXPLICIT, hits=denies,
            detail="命中明确拒绝规则，拒绝覆盖一切允许",
        )
    if allows:
        return PartDecision(
            slot=part.slot, name=part.name, decision=ALLOW, error_code=E_OK,
            hits=allows, detail="命中有效允许规则",
        )
    if expired:
        return PartDecision(
            slot=part.slot, name=part.name, decision=DENY,
            error_code=E_RULE_EXPIRED, expired_candidates=expired,
            detail="唯一匹配的授权已过有效期",
        )
    return PartDecision(
        slot=part.slot, name=part.name, decision=DENY,
        error_code=E_NO_AUTHORIZATION,
        detail="缺少有效授权，默认拒绝",
    )


def evaluate_launch(request, ctx: dict) -> dict:
    """对整单（主程序 + 依赖）逐部件判定并汇总。"""
    part_decisions = [evaluate_part(p, ctx) for p in request.parts]
    overall_allow = all(d.decision == ALLOW for d in part_decisions)
    # 整单错误码：全部 OK 才 OK；否则取第一个拒绝部件的码，保证可断言
    overall_code = E_OK
    if not overall_allow:
        overall_code = next(d.error_code for d in part_decisions if d.decision == DENY)
    return {
        "decision": ALLOW if overall_allow else DENY,
        "error_code": overall_code,
        "parts": [d.to_dict() for d in part_decisions],
    }
