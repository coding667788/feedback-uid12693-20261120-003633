"""工作区引导：把 cases.json 中的合成实体装载进全新的 SQLite 工作区。"""

from __future__ import annotations

import json
import os
import shutil

from .crypto import canonical, new_secret_hex, sha256_text, sign_cert
from .store import Store
from .errors import AdmissionError, E_BAD_REQUEST, CERT_ACTIVE, REMOTE_GOOD
EPOCH = "2026-01-01T00:00:00Z"
FAR_FUTURE = "2099-12-31T23:59:59Z"


def reset_workspace(workspace: str) -> None:
    """删除并重建工作区，保证每个流程在干净状态上重放。"""
    if os.path.isdir(workspace):
        shutil.rmtree(workspace)
    os.makedirs(workspace, exist_ok=True)


def _materialize_cert(raw: dict) -> dict:
    """补全合成证书的密钥与父子签名（fixture 里只需声明信任拓扑）。"""
    cert = dict(raw)
    cert.setdefault("secret_hex", new_secret_hex(cert["kid"]))
    cert.setdefault("status", CERT_ACTIVE)
    cert.setdefault("not_before", EPOCH)
    cert.setdefault("not_after", FAR_FUTURE)
    parent_kid = cert.get("parent_kid")
    if parent_kid is None:
        cert["signature"] = sign_cert(cert, cert["secret_hex"])  # 根自签
    else:
        # 父密钥由同样的确定性种子派生，离线可复算
        parent_secret = new_secret_hex(parent_kid)
        cert["signature"] = sign_cert(cert, parent_secret)
    return cert


def bootstrap(workspace: str, fixture: dict) -> Store:
    """在 workspace 下建库并装载组织/组/设备/证书/远端状态/策略/规则。"""
    if not os.path.isdir(workspace):
        os.makedirs(workspace, exist_ok=True)
    store = Store(workspace)
    now = fixture.get("boot_at", EPOCH)
    with store.immediate() as conn:
        store.meta_put("schema_version", "1")
        store.meta_put("boot_at", now)

        for org in fixture["organizations"]:
            store.upsert_org(org["org_id"], org["name"], org.get("policy_version", 1))
            store.insert_policy_version(
                org["org_id"], org.get("policy_version", 1), now, "bootstrap"
            )

        for grp in fixture.get("device_groups", []):
            store.upsert_group(grp["group_id"], grp["org_id"], grp["name"])

        for dev in fixture["devices"]:
            store.upsert_device(
                dev["device_id"], dev["org_id"], dev["group_id"],
                int(dev.get("generation", 1)), now,
            )

        for raw_cert in fixture.get("issuer_certs", []):
            store.insert_cert(_materialize_cert(raw_cert))

        for remote in fixture.get("remote_issuer_status", []):
            store.upsert_remote_status(
                remote["issuer_id"], remote["org_id"],
                remote.get("status", REMOTE_GOOD), now,
            )

        for rule in fixture.get("rules", []):
            if rule["rule_id"] in {r["rule_id"] for r in _existing_rules(store)}:
                raise AdmissionError(E_BAD_REQUEST, f"规则 id 重复: {rule['rule_id']}")
            store.insert_rule(rule)
    return store


def _existing_rules(store: Store):
    rows = store.conn.execute("SELECT rule_id FROM rules").fetchall()
    return [{"rule_id": r["rule_id"]} for r in rows]


def load_cases(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def fixture_fingerprint(fixture: dict) -> str:
    """fixture 自身指纹，写入结果文件便于人工核对重放一致性。"""
    return sha256_text(canonical(fixture))
