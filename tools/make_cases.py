"""生成可重放的 cases.json（全部输入自行合成、确定性、离线）。

运行：python -m tools.make_cases            # 写入仓库根 cases.json
     python tools/make_cases.py --out <path>

cases.json 包含：
  decision_fixture / decision_cases : 36 条独立决策表；
  flow_fixture + scenarios          : X 转组 / Y 吊销 / Z 撤回三场景；
  crash_fixture + crash_scenarios   : 两类真实杀进程崩溃点；
  时间轴固定，任何机器重放结果一致。
"""

from __future__ import annotations

import argparse
import json
import os

from solution.crypto import (
    attest_content_digest,
    canonical,
    new_secret_hex,
    sha256_text,
)
from solution.models import compute_identity
from solution.paths import normalize_entry

T0 = "2026-06-01T08:00:00Z"
T_OLD = "2026-01-01T00:00:00Z"
T_EXPIRED = "2026-03-01T00:00:00Z"
T_FUTURE = "2099-12-31T23:59:59Z"
T_MID = "2026-06-15T12:00:00Z"
T_LATE = "2026-09-01T08:00:00Z"

ORG = "org-acme"


# ---------------------------------------------------------------------------
# 合成助手
# ---------------------------------------------------------------------------

def digest_of(name: str) -> str:
    return sha256_text("synthetic-content:" + name)


def root_cert(kid: str, org_id: str = ORG, issuer_id: str = "root-ca") -> dict:
    return {
        "kid": kid,
        "org_id": org_id,
        "issuer_id": issuer_id,
        "parent_kid": None,
        "not_before": T_OLD,
        "not_after": T_FUTURE,
    }


def leaf_cert(kid: str, issuer_id: str, root_kid: str, org_id: str = ORG) -> dict:
    return {
        "kid": kid,
        "org_id": org_id,
        "issuer_id": issuer_id,
        "parent_kid": root_kid,
        "not_before": T_OLD,
        "not_after": T_FUTURE,
    }


def make_part(
    name: str,
    issuer_id: str,
    leaf_kid: str,
    path: str,
    slot: int = 0,
    role: str = "main",
    digest: str | None = None,
    bad_attest: bool = False,
) -> dict:
    content = digest or digest_of(name)
    attest = attest_content_digest(new_secret_hex(leaf_kid), content)
    if bad_attest:
        attest = attest[:-4] + "dead"
    return {
        "slot": slot,
        "role": role,
        "name": name,
        "content_digest": content,
        "issuer_id": issuer_id,
        "leaf_kid": leaf_kid,
        "chain_digest": attest,
        "entry_path": normalize_entry(path),
    }


def make_request(rid: str, device: str, gen: int, parts: list[dict]) -> dict:
    from solution.models import Part

    tparts = tuple(Part.from_dict(p) for p in parts)
    return {
        "request_id": rid,
        "org_id": ORG,
        "device_id": device,
        "device_generation": gen,
        "parts": parts,
        "identity_digest": compute_identity(ORG, tparts),
        "client_ts": T0,
    }


def digest_rule(rid, kind, digest, layer="baseline", group=None,
                vfrom=T0, vto=T_FUTURE, desc=""):
    return {
        "rule_id": rid,
        "org_id": ORG,
        "version_added": 1,
        "layer": layer,
        "group_id": group,
        "kind": kind,
        "match_digest": digest,
        "match_issuer_id": None,
        "match_path_segments": None,
        "valid_from": vfrom,
        "valid_to": vto,
        "description": desc,
    }


def issuer_path_rule(rid, kind, issuer_id, segments, layer="baseline",
                     group=None, vfrom=T0, vto=T_FUTURE, desc=""):
    return {
        "rule_id": rid,
        "org_id": ORG,
        "version_added": 1,
        "layer": layer,
        "group_id": group,
        "kind": kind,
        "match_digest": None,
        "match_issuer_id": issuer_id,
        "match_path_segments": segments,
        "valid_from": vfrom,
        "valid_to": vto,
        "description": desc,
    }


# ---------------------------------------------------------------------------
# 决策表 fixture 与 36 条用例
# ---------------------------------------------------------------------------

def build_decision_suite() -> tuple[dict, list[dict]]:
    # 组：G1 研发组，G2 财务组，G3 外协组
    groups = [
        {"group_id": "G1", "org_id": ORG, "name": "engineering"},
        {"group_id": "G2", "org_id": ORG, "name": "finance"},
        {"group_id": "G3", "org_id": ORG, "name": "contractors"},
    ]
    devices = [
        {"device_id": f"dev-{g.lower()}-{i:02d}", "org_id": ORG,
         "group_id": g, "generation": 1}
        for g in ("G1", "G2", "G3") for i in range(1, 14)
    ]

    certs = [root_cert("root-1")]
    for iss in ("iss-acme", "iss-vendor", "iss-remote", "iss-evil", "iss-tmp"):
        certs.append(leaf_cert(f"leaf-{iss}", iss, "root-1"))
    # 独立根（不受信）
    certs.append(root_cert("root-foreign", org_id="org-other", issuer_id="root-ca"))
    certs.append(leaf_cert("leaf-foreign", "iss-foreign", "root-foreign",
                           org_id="org-other"))
    # 已轮换 / 已吊销的旧钥
    certs.append(leaf_cert("leaf-acme-old", "iss-acme", "root-1"))
    certs.append(leaf_cert("leaf-acme-new", "iss-acme", "root-1"))
    certs.append(leaf_cert("leaf-revoked", "iss-vendor", "root-1"))

    remote = [
        {"issuer_id": "iss-acme", "org_id": ORG, "status": "GOOD"},
        {"issuer_id": "iss-vendor", "org_id": ORG, "status": "GOOD"},
        {"issuer_id": "iss-remote", "org_id": ORG, "status": "GOOD"},
        {"issuer_id": "iss-tmp", "org_id": ORG, "status": "GOOD"},
    ]

    d = {n: digest_of(n) for n in (
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
        "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi",
        "rho", "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega",
        "lib-a", "lib-b", "lib-c", "lib-d", "lib-e", "suite-main",
        "suite-dep1", "suite-dep2", "big-main", "tampered", "replayed",
    )}

    P = "C:\\Program Files\\Acme\\{0}\\app.exe"
    rules = [
        digest_rule("R01", "digest_allow", d["alpha"], desc="基线摘要允许 alpha"),
        digest_rule("R02", "digest_allow", d["beta"], layer="group", group="G1",
                    desc="G1 组摘要允许 beta（G2/G3 无授权）"),
        digest_rule("R03", "deny_digest", d["gamma"], desc="基线明确拒绝 gamma"),
        digest_rule("R04", "digest_allow", d["gamma"], layer="group", group="G1",
                    desc="G1 试图允许 gamma，但拒绝覆盖"),
        digest_rule("R05", "digest_allow", d["delta"], vfrom=T_OLD, vto=T_EXPIRED,
                    desc="delta 的允许规则在 T_MID 前已过期"),
        issuer_path_rule("R06", "issuer_path_allow", "iss-vendor",
                         ["vendor", "tools"], desc="签发者+路径段联合允许"),
        issuer_path_rule("R07", "deny_issuer_path", "iss-vendor",
                         ["vendor", "tools", "secret"],
                         desc="联合拒绝：敏感子目录覆盖允许"),
        issuer_path_rule("R08", "issuer_path_allow", "iss-vendor",
                         ["vendor", "tools"], layer="group", group="G2",
                         desc="仅 G2 生效的联合允许"),
        issuer_path_rule("R09", "issuer_path_allow", "iss-acme",
                         ["acme", "signed"], desc="acme/signed 联合允许（同名段陷阱）"),
        issuer_path_rule("R10", "deny_issuer_path", "iss-acme",
                         ["acme", "signed", "untrusted"],
                         desc="同名 acme 段下的拒绝子树"),
        digest_rule("R11", "digest_allow", d["eta"], layer="group", group="G1",
                    desc="eta 的 G1 允许；G3 只能靠双审批临时放宽"),
        digest_rule("R12", "digest_allow", d["theta"], vfrom=T_OLD, vto=T_EXPIRED,
                    desc="theta 允许过期"),
        issuer_path_rule("R13", "issuer_path_allow", "iss-tmp",
                         ["temp"], vfrom=T_OLD, vto=T_EXPIRED,
                         desc="tmp 联合允许已过期"),
        digest_rule("R14", "digest_allow", d["iota"],
                    desc="iota 基线允许（远端状态变化用）"),
        digest_rule("R14B", "digest_allow", digest_of("iota-remote"),
                    desc="iota-remote 基线允许（iss-remote 远端状态用例）"),
        digest_rule("R15", "digest_allow", d["kappa"],
                    desc="kappa 基线允许（换钥用）"),
        digest_rule("R16", "deny_digest", d["lambda"],
                    desc="lambda 明确拒绝（临时放宽禁止对象）"),
        digest_rule("R17", "digest_allow", d["nu"], layer="group", group="G1",
                    desc="G1 允许 nu（跨组不生效）"),
        issuer_path_rule("R18", "issuer_path_allow", "iss-vendor",
                         ["vendor", "exact"], desc="整段匹配，不得子串误匹配"),
        digest_rule("R19", "digest_allow", d["pi"], desc="pi 基线允许"),
        digest_rule("R20", "deny_digest", d["rho"], desc="rho 拒绝（多依赖混入）"),
        digest_rule("R21", "digest_allow", d["sigma"], desc="sigma 允许"),
        digest_rule("R22", "digest_allow", d["tau"], desc="tau 允许"),
        digest_rule("R23", "digest_allow", d["lib-a"], desc="依赖允许 lib-a"),
        digest_rule("R24", "digest_allow", d["lib-b"], desc="依赖允许 lib-b"),
        digest_rule("R25", "digest_allow", d["lib-c"], desc="依赖允许 lib-c"),
        digest_rule("R26", "digest_allow", d["lib-d"], desc="依赖允许 lib-d"),
        digest_rule("R27", "digest_allow", d["lib-e"], desc="依赖允许 lib-e"),
        digest_rule("R28", "digest_allow", d["suite-main"], desc="套件主程序"),
        digest_rule("R29", "digest_allow", d["suite-dep1"], desc="套件依赖1"),
        digest_rule("R30", "digest_allow", d["suite-dep2"], desc="套件依赖2"),
        digest_rule("R31", "digest_allow", d["upsilon"], desc="upsilon 允许"),
        issuer_path_rule("R32", "issuer_path_allow", "iss-vendor",
                         ["vendor", "approved"],
                         desc="phi 的路径联合允许（移动入口即失配，强制重判）"),
        digest_rule("R33", "digest_allow", d["chi"], desc="chi 允许（同路径不同摘要）"),
        digest_rule("R34", "deny_digest", d["psi"], desc="psi 明确拒绝"),
        digest_rule("R35", "digest_allow", d["omega"], layer="group", group="G2",
                    desc="G2 允许 omega"),
        digest_rule("R36", "digest_allow", d["big-main"], desc="25 依赖主程序"),
    ]
    for i, name in enumerate(("dep01", "dep02", "dep03", "dep04", "dep05",
                              "dep06", "dep07", "dep08", "dep09", "dep10",
                              "dep11", "dep12", "dep13", "dep14", "dep15",
                              "dep16", "dep17", "dep18", "dep19", "dep20",
                              "dep21", "dep22", "dep23", "dep24", "dep25"), start=1):
        rules.append(digest_rule(
            f"R36D{i:02d}", "digest_allow", digest_of(name),
            desc=f"big suite dep {i}",
        ))

    fixture = {
        "boot_at": T0,
        "organizations": [{"org_id": ORG, "name": "Acme Corp", "policy_version": 1}],
        "device_groups": groups,
        "devices": devices,
        "issuer_certs": certs,
        "remote_issuer_status": remote,
        "rules": rules,
    }

    G1 = [x["device_id"] for x in devices if x["group_id"] == "G1"]
    G2 = [x["device_id"] for x in devices if x["group_id"] == "G2"]
    G3 = [x["device_id"] for x in devices if x["group_id"] == "G3"]

    cases: list[dict] = []

    def add(cid, dev, parts, expect_decision, expect_code, note,
            remote_changes=None, cert_status=None, gen=1, temp_grants=None,
            now=T_MID):
        cases.append({
            "case_id": cid,
            "now": now,
            "device_id": dev,
            "request": make_request(f"req-{cid}", dev, gen, parts),
            "expect_decision": expect_decision,
            "expect_error_code": expect_code,
            "remote_changes": remote_changes or [],
            "cert_status": cert_status or [],
            "temp_grants": temp_grants or [],
            "note": note,
        })

    # 1-4 基础允许/组规则/拒绝覆盖
    add("C01", G1[0], [make_part("alpha", "iss-acme", "leaf-iss-acme", P.format("alpha"))],
        "ALLOW", "OK", "基线摘要允许")
    add("C02", G1[1], [make_part("beta", "iss-acme", "leaf-iss-acme", P.format("beta"))],
        "ALLOW", "OK", "G1 组规则允许")
    add("C03", G2[0], [make_part("beta", "iss-acme", "leaf-iss-acme", P.format("beta"))],
        "DENY", "NO_AUTHORIZATION", "组规则跨组不生效，默认拒绝")
    add("C04", G1[2], [make_part("gamma", "iss-acme", "leaf-iss-acme", P.format("gamma"))],
        "DENY", "DENY_EXPLICIT", "明确拒绝覆盖组允许")

    # 5-7 过期 / 无授权 / 联合允许
    add("C05", G1[3], [make_part("delta", "iss-acme", "leaf-iss-acme", P.format("delta"))],
        "DENY", "RULE_EXPIRED", "允许规则已过期", now=T_MID)
    add("C06", G1[4], [make_part("epsilon", "iss-acme", "leaf-iss-acme",
                                 P.format("epsilon"))],
        "DENY", "NO_AUTHORIZATION", "无任何规则，默认拒绝")
    add("C07", G1[5], [make_part("zeta", "iss-vendor", "leaf-iss-vendor",
                                 "C:\\Program Files\\Vendor\\Tools\\zeta.exe")],
        "ALLOW", "OK", "签发者+路径段联合允许")

    # 8-10 联合拒绝 / 跨组联合 / 同名段
    add("C08", G1[6], [make_part("eta", "iss-vendor", "leaf-iss-vendor",
                                 "C:\\Program Files\\Vendor\\Tools\\Secret\\eta.exe")],
        "DENY", "DENY_EXPLICIT", "敏感子目录联合拒绝覆盖允许")
    add("C09", G1[7], [make_part("theta", "iss-vendor", "leaf-iss-vendor",
                                 "C:\\Program Files\\Vendor\\Tools\\theta.exe")],
        "ALLOW", "OK", "G1 基线联合允许 R06 命中")
    add("C10", G2[1], [make_part("iota", "iss-vendor", "leaf-iss-vendor",
                                 "C:\\Program Files\\Vendor\\Tools\\iota.exe")],
        "ALLOW", "OK", "G2 同时命中基线 R06 与组 R08")

    # 11-13 同名路径段 / 拒绝子树 / 整段匹配
    add("C11", G1[8], [make_part("kappa", "iss-acme", "leaf-iss-acme",
                                 "C:\\Program Files\\Acme\\Signed\\kappa.exe")],
        "ALLOW", "OK", "命中 acme/signed 同名段允许")
    add("C12", G1[9], [make_part("lambda", "iss-acme", "leaf-iss-acme",
                                 "C:\\Program Files\\Acme\\Signed\\Untrusted\\lambda.exe")],
        "DENY", "DENY_EXPLICIT", "同名段下拒绝子树优先")
    add("C13", G1[10], [make_part("mu", "iss-vendor", "leaf-iss-vendor",
                                  "C:\\Program Files\\Vendor\\Exactish\\mu.exe")],
        "DENY", "NO_AUTHORIZATION", "exact 段不得子串匹配 exactish")

    # 14-17 临时授权：双审批 / 同人 / 到期 / 禁止放宽拒绝
    add("C14", G3[0], [make_part("eta", "iss-acme", "leaf-iss-acme", P.format("eta"))],
        "DENY", "NO_AUTHORIZATION", "无临时授权时 G3 不许 eta")
    add("C15", G3[1], [make_part("eta", "iss-acme", "leaf-iss-acme", P.format("eta"))],
        "ALLOW", "OK", "双审批临时放宽生效",
        temp_grants=[{"base_rule_id": "R11", "group_id": "G3",
                      "valid_from": T0, "valid_to": T_LATE,
                      "approver1": "alice", "approver2": "bob"}])
    add("C16", G3[2], [make_part("eta", "iss-acme", "leaf-iss-acme", P.format("eta"))],
        "DENY", "RULE_EXPIRED", "临时授权到期",
        temp_grants=[{"base_rule_id": "R11", "group_id": "G3",
                      "valid_from": T_OLD, "valid_to": T_EXPIRED,
                      "approver1": "alice", "approver2": "bob"}],
        now=T_MID)
    add("C17", G3[3], [make_part("eta", "iss-acme", "leaf-iss-acme", P.format("eta"))],
        "DENY", "NO_AUTHORIZATION", "同审批人临时授权在装载时被拒，等同无授权",
        temp_grants=[{"base_rule_id": "R11", "group_id": "G3",
                      "valid_from": T0, "valid_to": T_LATE,
                      "approver1": "alice", "approver2": "alice",
                      "expect_create_error": "TEMP_GRANT_INVALID"}])

    # 18-20 远端签发者模拟状态
    add("C18", G1[11], [make_part("iota-remote", "iss-remote", "leaf-iss-remote",
                                  "C:\\Program Files\\Remote\\iota.exe")],
        "ALLOW", "OK", "远端状态 GOOD")
    add("C19", G2[2], [make_part("iota-remote", "iss-remote", "leaf-iss-remote",
                                 "C:\\Program Files\\Remote\\iota.exe")],
        "DENY", "REMOTE_ISSUER_STATUS_BAD", "远端 SUSPENDED",
        remote_changes=[{"issuer_id": "iss-remote", "status": "SUSPENDED"}])
    add("C20", G2[3], [make_part("iota-remote", "iss-remote", "leaf-iss-remote",
                                 "C:\\Program Files\\Remote\\iota.exe")],
        "DENY", "REMOTE_ISSUER_STATUS_BAD", "远端 REVOKED",
        remote_changes=[{"issuer_id": "iss-remote", "status": "REVOKED"}])

    # 21-24 签发链：吊销 / 轮换 / 外来根 / 摘要篡改
    add("C21", G2[4], [make_part("kappa", "iss-vendor", "leaf-revoked",
                                 P.format("kappa"))],
        "DENY", "ISSUER_KEY_REVOKED", "叶子密钥已吊销",
        cert_status=[{"kid": "leaf-revoked", "status": "REVOKED"}])
    add("C22", G2[5], [make_part("kappa", "iss-acme", "leaf-acme-old",
                                 P.format("kappa"))],
        "DENY", "ISSUER_KEY_REVOKED", "轮换后旧钥 ROTATED 立即失效",
        cert_status=[{"kid": "leaf-acme-old", "status": "ROTATED"}])
    add("C23", G2[6], [make_part("nu", "iss-foreign", "leaf-foreign",
                                 P.format("nu"))],
        "DENY", "ISSUER_UNTRUSTED", "外来组织根不受信")
    # 24 篡改：内容摘要被改写，chain_digest 是对原（未篡改）摘要的见证
    original_digest = digest_of("tampered")
    tampered = make_part("tampered", "iss-acme", "leaf-iss-acme",
                         P.format("tampered"),
                         digest=original_digest[:-4] + "0000")
    # 用原摘要重算一个合法见证，再把内容摘要改成伪造值 -> 验签必然失败
    tampered["chain_digest"] = attest_content_digest(
        new_secret_hex("leaf-iss-acme"), original_digest
    )
    add("C24", G2[7], [tampered],
        "DENY", "ISSUER_CHAIN_INVALID", "内容摘要与 chain_digest 不匹配")

    # 25-27 见证伪造 / 入口移动重判 / 同路径不同摘要
    add("C25", G2[8], [make_part("xi", "iss-acme", "leaf-iss-acme",
                                 P.format("xi"), bad_attest=True)],
        "DENY", "ISSUER_CHAIN_INVALID", "伪造的签发见证")
    # 26-27 入口移动重判（签发者+路径段联合授权，移动即失配）
    p32 = make_part("phi", "iss-vendor", "leaf-iss-vendor",
                    "C:\\Program Files\\Vendor\\Approved\\phi.exe")
    add("C26", G2[9], [p32],
        "ALLOW", "OK", "phi 在批准入口允许")
    add("C27", G2[10], [{**p32, "entry_path": normalize_entry(
            "C:\\Users\\Public\\Downloads\\phi.exe"), "slot": 0}],
        "DENY", "NO_AUTHORIZATION", "同一摘要移动入口，身份变化须重判且无授权")

    # 28-30 多依赖：全允许 / 一个被拒 / 一个无授权
    dep_libs = [
        make_part("lib-a", "iss-acme", "leaf-iss-acme",
                  "C:\\Program Files\\Acme\\lib\\lib-a.dll", 1, "dependency"),
        make_part("lib-b", "iss-acme", "leaf-iss-acme",
                  "C:\\Program Files\\Acme\\lib\\lib-b.dll", 2, "dependency"),
    ]
    add("C28", G2[11], [make_part("pi", "iss-acme", "leaf-iss-acme",
                                  P.format("pi"))] + dep_libs,
        "ALLOW", "OK", "主程序+2 依赖全部允许")
    add("C29", G3[4], [make_part("rho", "iss-acme", "leaf-iss-acme",
                                 P.format("rho"))] + dep_libs,
        "DENY", "DENY_EXPLICIT", "主程序被明确拒绝，整单拒绝")
    add("C30", G3[5], [make_part("pi", "iss-acme", "leaf-iss-acme", P.format("pi")),
                       make_part("omicro n", "iss-acme", "leaf-iss-acme",
                                 "C:\\Program Files\\Acme\\lib\\unknown.dll",
                                 1, "dependency", digest=digest_of("omicron"))],
        "DENY", "NO_AUTHORIZATION", "依赖无授权，整单拒绝")

    # 31-33 套件全允许 / 三依赖含拒绝 / 上限 25
    suite_parts = [
        make_part("suite-main", "iss-acme", "leaf-iss-acme", P.format("suite")),
        make_part("suite-dep1", "iss-acme", "leaf-iss-acme",
                  "C:\\Program Files\\Acme\\suite\\d1.dll", 1, "dependency"),
        make_part("suite-dep2", "iss-acme", "leaf-iss-acme",
                  "C:\\Program Files\\Acme\\suite\\d2.dll", 2, "dependency"),
    ]
    add("C31", G3[6], suite_parts, "ALLOW", "OK", "三件套全部允许")
    add("C32", G3[7], suite_parts[:2] + [
        make_part("psi", "iss-acme", "leaf-iss-acme",
                  "C:\\Program Files\\Acme\\suite\\d3.dll", 2, "dependency")
    ], "DENY", "DENY_EXPLICIT", "套件中混入明确拒绝部件")
    big_parts = [make_part("big-main", "iss-acme", "leaf-iss-acme",
                           P.format("big"))]
    for i in range(1, 26):
        nm = f"dep{i:02d}"
        big_parts.append(make_part(
            nm, "iss-acme", "leaf-iss-acme",
            f"C:\\Program Files\\Acme\\big\\{nm}.dll", i, "dependency",
            digest=digest_of(nm)))
    add("C33", G3[8], big_parts, "ALLOW", "OK", "主程序+25 依赖达到上限全部允许")

    # 34-36 换钥重判 / 过期联合规则 / 组允许在正确组生效
    p34 = make_part("upsilon", "iss-acme", "leaf-acme-new",
                    P.format("upsilon"))
    add("C34", G3[9], [p34], "ALLOW", "OK", "换钥后新钥请求作为新身份判定允许")
    add("C35", G3[10], [make_part("omega", "iss-tmp", "leaf-iss-tmp",
                                  "C:\\Program Files\\Temp\\omega.exe")],
        "DENY", "RULE_EXPIRED", "联合允许规则已过期", now=T_LATE)
    add("C36", G2[12], [make_part("omega", "iss-acme", "leaf-iss-acme",
                                  P.format("omega"))],
        "ALLOW", "OK", "G2 组允许 omega 在 G2 生效")

    assert len(cases) == 36, len(cases)
    return fixture, cases


# ---------------------------------------------------------------------------
# 顺序场景 fixture（X 转组 / Y 吊销 / Z 撤回）与崩溃场景
# ---------------------------------------------------------------------------

def build_flow_fixture() -> dict:
    certs = [root_cert("f-root")]
    for iss in ("f-iss-a", "f-iss-b"):
        certs.append(leaf_cert(f"f-leaf-{iss.split('-')[-1]}", iss, "f-root"))
    return {
        "boot_at": T0,
        "organizations": [{"org_id": ORG, "name": "Acme Corp", "policy_version": 1}],
        "device_groups": [
            {"group_id": "FG1", "org_id": ORG, "name": "flow-g1"},
            {"group_id": "FG2", "org_id": ORG, "name": "flow-g2"},
        ],
        "devices": [
            {"device_id": "fdev-x", "org_id": ORG, "group_id": "FG1",
             "generation": 1},
            {"device_id": "fdev-y", "org_id": ORG, "group_id": "FG1",
             "generation": 1},
            {"device_id": "fdev-z", "org_id": ORG, "group_id": "FG1",
             "generation": 1},
        ],
        "issuer_certs": certs,
        "remote_issuer_status": [
            {"issuer_id": "f-iss-a", "org_id": ORG, "status": "GOOD"},
            {"issuer_id": "f-iss-b", "org_id": ORG, "status": "GOOD"},
        ],
        "rules": [
            digest_rule("FR01", "digest_allow", digest_of("flow-x-main"),
                        layer="group", group="FG1", desc="X 主程序 G1 允许"),
            digest_rule("FR02", "digest_allow", digest_of("flow-x-dep"),
                        layer="group", group="FG1", desc="X 依赖 G1 允许"),
            digest_rule("FR03", "digest_allow", digest_of("flow-y-main"),
                        desc="Y 主程序基线允许"),
            digest_rule("FR04", "digest_allow", digest_of("flow-y-dep"),
                        desc="Y 依赖基线允许（吊销对象）"),
            digest_rule("FR05", "digest_allow", digest_of("flow-z-main"),
                        desc="Z 主程序允许（撤回对象）"),
        ],
    }


def build_flow_requests() -> dict:
    x_main = make_part("flow-x-main", "f-iss-a", "f-leaf-a",
                       "C:\\Program Files\\Flow\\X\\x.exe")
    x_dep = make_part("flow-x-dep", "f-iss-a", "f-leaf-a",
                      "C:\\Program Files\\Flow\\X\\xdep.dll", 1, "dependency")
    y_main = make_part("flow-y-main", "f-iss-a", "f-leaf-a",
                       "C:\\Program Files\\Flow\\Y\\y.exe")
    y_dep = make_part("flow-y-dep", "f-iss-b", "f-leaf-b",
                      "C:\\Program Files\\Flow\\Y\\ydep.dll", 1, "dependency")
    z_main = make_part("flow-z-main", "f-iss-a", "f-leaf-a",
                       "C:\\Program Files\\Flow\\Z\\z.exe")
    return {
        "X": {
            "request": make_request("req-x-admit", "fdev-x", 1, [x_main, x_dep]),
            "device": "fdev-x",
            "target_group": "FG2",
        },
        "Y": {
            "request": make_request("req-y-admit", "fdev-y", 1, [y_main, y_dep]),
            "device": "fdev-y",
            "revoke_kid": "f-leaf-b",
            "new_kid": "f-leaf-b2",
            "issuer_id": "f-iss-b",
            "dep_name": "flow-y-dep-rekeyed",
            "dep_path": "C:\\Program Files\\Flow\\Y\\ydep.dll",
        },
        "Z": {
            "request": make_request("req-z-admit", "fdev-z", 1, [z_main]),
            "device": "fdev-z",
            "rule_id": "FR05",
        },
    }


def build_crash_fixture() -> dict:
    return {
        "boot_at": T0,
        "organizations": [{"org_id": ORG, "name": "Acme Corp", "policy_version": 1}],
        "device_groups": [
            {"group_id": "CG1", "org_id": ORG, "name": "crash-g1"},
        ],
        "devices": [
            {"device_id": "cdev-1", "org_id": ORG, "group_id": "CG1",
             "generation": 1},
            {"device_id": "cdev-2", "org_id": ORG, "group_id": "CG1",
             "generation": 1},
        ],
        "issuer_certs": [
            root_cert("c-root"),
            leaf_cert("c-leaf", "c-iss", "c-root"),
        ],
        "remote_issuer_status": [
            {"issuer_id": "c-iss", "org_id": ORG, "status": "GOOD"},
        ],
        "rules": [
            digest_rule("CR01", "digest_allow", digest_of("crash-app"),
                        desc="崩溃场景允许规则"),
        ],
    }


def build_crash_scenarios() -> list[dict]:
    part = make_part("crash-app", "c-iss", "c-leaf",
                     "C:\\Program Files\\Crash\\app.exe")
    return [
        {
            "scenario_id": "KILL_PRE_COMMIT",
            "device_id": "cdev-1",
            "request": make_request("req-crash-pre", "cdev-1", 1, [part]),
            "crash_phase": "after_manifest_before_commit",
            "expect_exit_code": 42,
            "expect_records_after_recovery": 0,
            "expect_manifests_after_recovery": 0,
        },
        {
            "scenario_id": "KILL_POST_COMMIT",
            "device_id": "cdev-2",
            "request": make_request("req-crash-post", "cdev-2", 1, [part]),
            "crash_phase": "after_commit",
            "expect_exit_code": 43,
            "expect_records_after_recovery": 1,
            "expect_manifests_after_recovery": 1,
        },
    ]


def build_document() -> dict:
    decision_fixture, decision_cases = build_decision_suite()
    return {
        "document_version": "1.0",
        "generated_at": "2026-11-20T00:00:00Z",
        "time_axis": {"T0": T0, "T_MID": T_MID, "T_LATE": T_LATE,
                      "T_EXPIRED": T_EXPIRED},
        "decision_fixture": decision_fixture,
        "decision_cases": decision_cases,
        "flow_fixture": build_flow_fixture(),
        "flow_requests": build_flow_requests(),
        "scenario_order_xyz": ["X", "Y", "Z", "KILL_PRE_COMMIT", "KILL_POST_COMMIT"],
        "scenario_order_zyx": ["Z", "Y", "X", "KILL_POST_COMMIT", "KILL_PRE_COMMIT"],
        "crash_fixture": build_crash_fixture(),
        "crash_scenarios": build_crash_scenarios(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="生成合成 cases.json")
    default_out = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cases.json"
    )
    parser.add_argument("--out", default=default_out)
    args = parser.parse_args()
    doc = build_document()
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2, sort_keys=True)
    print(f"wrote {args.out}: {len(doc['decision_cases'])} decision cases, "
          f"3 ordered scenarios, 2 crash scenarios")


if __name__ == "__main__":
    main()
