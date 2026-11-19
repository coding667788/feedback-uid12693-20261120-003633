"""SQLite 存储层。

工作区布局::

    <workspace>/
        aec.db                SQLite 主库（WAL 模式）
        manifests/<rid>.json  合成启动清单（仅判定结果，无程序执行）

所有写事务在服务层用 BEGIN IMMEDIATE 打开，配合 WAL 与 busy_timeout，
两个独立进程并发访问时由 SQLite 自己串行化。
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    org_id                 TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    current_policy_version INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS device_groups (
    group_id TEXT PRIMARY KEY,
    org_id   TEXT NOT NULL,
    name     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id  TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    group_id   TEXT NOT NULL,
    generation INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issuer_certs (
    kid        TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    issuer_id  TEXT NOT NULL,
    parent_kid TEXT,
    secret_hex TEXT NOT NULL,
    status     TEXT NOT NULL,            -- ACTIVE / ROTATED / REVOKED
    not_before TEXT NOT NULL,
    not_after  TEXT NOT NULL,
    signature  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remote_issuer_status (
    issuer_id  TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    status     TEXT NOT NULL,            -- GOOD / SUSPENDED / REVOKED
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_versions (
    org_id     TEXT NOT NULL,
    version    INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (org_id, version)
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id             TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    version_added       INTEGER NOT NULL,
    version_removed     INTEGER,          -- NULL 表示当前仍有效
    layer               TEXT NOT NULL,    -- baseline / group
    group_id            TEXT,             -- 组规则必填
    kind                TEXT NOT NULL,
    match_digest        TEXT,
    match_issuer_id     TEXT,
    match_path_segments TEXT,             -- JSON 数组
    valid_from          TEXT NOT NULL,
    valid_to            TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS temp_grants (
    grant_id     TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    group_id     TEXT NOT NULL,
    base_rule_id TEXT NOT NULL,
    valid_from   TEXT NOT NULL,
    valid_to     TEXT NOT NULL,
    approver1    TEXT NOT NULL,
    approver2    TEXT NOT NULL,
    version_added INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id       TEXT PRIMARY KEY,
    org_id            TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    policy_version    INTEGER NOT NULL,
    device_generation INTEGER NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admission_records (
    request_id        TEXT PRIMARY KEY,
    identity_digest   TEXT NOT NULL,
    org_id            TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    device_generation INTEGER NOT NULL,
    policy_version    INTEGER NOT NULL,
    decision          TEXT NOT NULL,       -- ALLOW / DENY
    error_code        TEXT,
    receipt           TEXT NOT NULL,       -- JSON 幂等回执
    manifest_path     TEXT,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS flow_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id  TEXT NOT NULL,
    kind     TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_org ON rules(org_id);
CREATE INDEX IF NOT EXISTS idx_adm_org ON admission_records(org_id);
CREATE INDEX IF NOT EXISTS idx_certs_issuer ON issuer_certs(org_id, issuer_id);
"""


class Store:
    def __init__(self, workspace: str):
        self.workspace = os.path.abspath(workspace)
        self.data_dir = os.path.join(self.workspace, "data")
        self.manifest_dir = os.path.join(self.data_dir, "manifests")
        self.db_path = os.path.join(self.data_dir, "aec.db")
        os.makedirs(self.manifest_dir, exist_ok=True)
        self.conn = sqlite3.connect(
            self.db_path, timeout=30.0, isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # ---- 事务 ----------------------------------------------------------------
    @contextmanager
    def immediate(self):
        """写事务：BEGIN IMMEDIATE 立即拿写锁，提交/回滚自动配对。"""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    # ---- meta ----------------------------------------------------------------
    def meta_get(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def meta_put(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- 组织 / 组 / 设备 -----------------------------------------------------
    def upsert_org(self, org_id: str, name: str, version: int) -> None:
        self.conn.execute(
            "INSERT INTO organizations(org_id, name, current_policy_version) "
            "VALUES(?,?,?) ON CONFLICT(org_id) DO UPDATE SET "
            "name=excluded.name, current_policy_version=excluded.current_policy_version",
            (org_id, name, version),
        )

    def get_org(self, org_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM organizations WHERE org_id=?", (org_id,)
        ).fetchone()

    def upsert_group(self, group_id: str, org_id: str, name: str) -> None:
        self.conn.execute(
            "INSERT INTO device_groups(group_id, org_id, name) VALUES(?,?,?) "
            "ON CONFLICT(group_id) DO UPDATE SET name=excluded.name",
            (group_id, org_id, name),
        )

    def list_groups(self, org_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM device_groups WHERE org_id=? ORDER BY group_id", (org_id,)
        ).fetchall()

    def upsert_device(
        self, device_id: str, org_id: str, group_id: str, generation: int, at: str
    ) -> None:
        self.conn.execute(
            "INSERT INTO devices(device_id, org_id, group_id, generation, updated_at) "
            "VALUES(?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
            "group_id=excluded.group_id, generation=excluded.generation, "
            "updated_at=excluded.updated_at",
            (device_id, org_id, group_id, generation, at),
        )

    def get_device(self, device_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()

    def bump_device_generation(self, device_id: str, at: str) -> int:
        self.conn.execute(
            "UPDATE devices SET generation=generation+1, updated_at=? WHERE device_id=?",
            (at, device_id),
        )
        return self.get_device(device_id)["generation"]

    def move_device_group(self, device_id: str, group_id: str, at: str) -> int:
        self.conn.execute(
            "UPDATE devices SET group_id=?, generation=generation+1, updated_at=? "
            "WHERE device_id=?",
            (group_id, at, device_id),
        )
        return self.get_device(device_id)["generation"]

    # ---- 证书链 ---------------------------------------------------------------
    def insert_cert(self, cert: dict) -> None:
        self.conn.execute(
            "INSERT INTO issuer_certs(kid, org_id, issuer_id, parent_kid, secret_hex, "
            "status, not_before, not_after, signature) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                cert["kid"], cert["org_id"], cert["issuer_id"], cert["parent_kid"],
                cert["secret_hex"], cert["status"], cert["not_before"],
                cert["not_after"], cert["signature"],
            ),
        )

    def get_cert(self, kid: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM issuer_certs WHERE kid=?", (kid,)
        ).fetchone()

    def set_cert_status(self, kid: str, status: str) -> None:
        self.conn.execute(
            "UPDATE issuer_certs SET status=? WHERE kid=?", (status, kid)
        )

    def list_certs(self, org_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM issuer_certs WHERE org_id=? ORDER BY kid", (org_id,)
        ).fetchall()

    # ---- 远端签发者模拟状态 ---------------------------------------------------
    def upsert_remote_status(self, issuer_id: str, org_id: str, status: str, at: str):
        self.conn.execute(
            "INSERT INTO remote_issuer_status(issuer_id, org_id, status, updated_at) "
            "VALUES(?,?,?,?) ON CONFLICT(issuer_id) DO UPDATE SET "
            "status=excluded.status, updated_at=excluded.updated_at",
            (issuer_id, org_id, status, at),
        )

    def get_remote_status(self, issuer_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM remote_issuer_status WHERE issuer_id=?", (issuer_id,)
        ).fetchone()

    # ---- 策略版本与规则 -------------------------------------------------------
    def insert_policy_version(self, org_id: str, version: int, at: str, note: str):
        self.conn.execute(
            "INSERT INTO policy_versions(org_id, version, created_at, note) "
            "VALUES(?,?,?,?) ON CONFLICT DO NOTHING",
            (org_id, version, at, note),
        )

    def set_policy_version(self, org_id: str, version: int) -> None:
        self.conn.execute(
            "UPDATE organizations SET current_policy_version=? WHERE org_id=?",
            (version, org_id),
        )

    def insert_rule(self, rule: dict) -> None:
        self.conn.execute(
            "INSERT INTO rules(rule_id, org_id, version_added, version_removed, layer, "
            "group_id, kind, match_digest, match_issuer_id, match_path_segments, "
            "valid_from, valid_to, description) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                rule["rule_id"], rule["org_id"], rule["version_added"],
                rule.get("version_removed"), rule["layer"], rule.get("group_id"),
                rule["kind"], rule.get("match_digest"), rule.get("match_issuer_id"),
                json.dumps(rule.get("match_path_segments") or []),
                rule["valid_from"], rule["valid_to"], rule.get("description", ""),
            ),
        )

    def withdraw_rule(self, rule_id: str, removed_version: int) -> None:
        self.conn.execute(
            "UPDATE rules SET version_removed=? WHERE rule_id=?",
            (removed_version, rule_id),
        )

    def get_rule(self, rule_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM rules WHERE rule_id=?", (rule_id,)
        ).fetchone()

    def active_rules(self, org_id: str, current_version: int) -> list[sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT * FROM rules WHERE org_id=? AND version_added<=? "
            "AND (version_removed IS NULL OR version_removed>?) ORDER BY rule_id",
            (org_id, current_version, current_version),
        ).fetchall()
        return rows

    # ---- 临时授权 -------------------------------------------------------------
    def insert_temp_grant(self, g: dict) -> None:
        self.conn.execute(
            "INSERT INTO temp_grants(grant_id, org_id, group_id, base_rule_id, "
            "valid_from, valid_to, approver1, approver2, version_added, created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                g["grant_id"], g["org_id"], g["group_id"], g["base_rule_id"],
                g["valid_from"], g["valid_to"], g["approver1"], g["approver2"],
                g["version_added"], g["created_at"],
            ),
        )

    def active_temp_grants(self, org_id: str, group_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM temp_grants WHERE org_id=? AND group_id=? ORDER BY grant_id",
            (org_id, group_id),
        ).fetchall()

    # ---- 快照 -----------------------------------------------------------------
    def insert_snapshot(self, snap: dict) -> None:
        self.conn.execute(
            "INSERT INTO snapshots(snapshot_id, org_id, device_id, fingerprint, "
            "policy_version, device_generation, created_at) VALUES(?,?,?,?,?,?,?)",
            (
                snap["snapshot_id"], snap["org_id"], snap["device_id"],
                snap["fingerprint"], snap["policy_version"],
                snap["device_generation"], snap["created_at"],
            ),
        )

    def get_snapshot(self, snapshot_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()

    # ---- 准入记录 -------------------------------------------------------------
    def insert_admission(self, rec: dict, receipt: dict, manifest_path: str | None):
        self.conn.execute(
            "INSERT INTO admission_records(request_id, identity_digest, org_id, "
            "device_id, device_generation, policy_version, decision, error_code, "
            "receipt, manifest_path, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                rec["request_id"], rec["identity_digest"], rec["org_id"],
                rec["device_id"], rec["device_generation"], rec["policy_version"],
                rec["decision"], rec["error_code"], json.dumps(receipt, ensure_ascii=False),
                manifest_path, rec["created_at"],
            ),
        )

    def get_admission(self, request_id: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM admission_records WHERE request_id=?", (request_id,)
        ).fetchone()

    def list_admissions(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM admission_records ORDER BY created_at, request_id"
        ).fetchall()

    def count_admissions(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS c FROM admission_records"
        ).fetchone()["c"]

    # ---- 流程事件（测试可观测性） ---------------------------------------------
    def log_event(self, flow_id: str, kind: str, detail: str, at: str) -> None:
        self.conn.execute(
            "INSERT INTO flow_events(flow_id, kind, detail, at) VALUES(?,?,?,?)",
            (flow_id, kind, detail, at),
        )

    def list_events(self, flow_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM flow_events WHERE flow_id=? ORDER BY event_id", (flow_id,)
        ).fetchall()

    # ---- 清单文件 -------------------------------------------------------------
    def manifest_path_for(self, request_id: str) -> str:
        safe = "".join(ch for ch in request_id if ch.isalnum() or ch in "-_")
        return os.path.join(self.manifest_dir, f"{safe}.json")

    def list_manifest_files(self) -> list[str]:
        if not os.path.isdir(self.manifest_dir):
            return []
        return sorted(
            os.path.join(self.manifest_dir, f)
            for f in os.listdir(self.manifest_dir)
            if f.endswith(".json")
        )
