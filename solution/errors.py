"""全部错误码集中定义。

决策级错误码出现在每个部件（part）与整单判定中；管理面错误码由
管理操作（建临时授权、轮换等）抛出。
"""

from __future__ import annotations


class AdmissionError(Exception):
    """管理面 / 请求校验错误，携带稳定错误码。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message}


# ---- 决策结果码（写入回执与清单） ------------------------------------------------
E_OK = "OK"
# 命中明确拒绝规则（拒绝覆盖一切允许）
E_DENY_EXPLICIT = "DENY_EXPLICIT"
# 没有任何有效授权，默认拒绝
E_NO_AUTHORIZATION = "NO_AUTHORIZATION"
# 请求携带的设备代数与当前代数不一致（转组 / 轮换 / 吊销导致）
E_STALE_DEVICE_GENERATION = "STALE_DEVICE_GENERATION"
# 快照记录的策略版本已不是当前版本
E_STALE_POLICY_VERSION = "STALE_POLICY_VERSION"
# 快照指纹在提交事务内重算不一致
E_SNAPSHOT_STALE = "SNAPSHOT_STALE"
# 签发链签名 / 摘要验签失败
E_ISSUER_CHAIN_INVALID = "ISSUER_CHAIN_INVALID"
# 叶子密钥已被轮换或吊销
E_ISSUER_KEY_REVOKED = "ISSUER_KEY_REVOKED"
# 签发者不属于本组织受信根链
E_ISSUER_UNTRUSTED = "ISSUER_UNTRUSTED"
# 远端签发者模拟状态（OCSP 替身）为 SUSPENDED / REVOKED
E_REMOTE_STATUS_BAD = "REMOTE_ISSUER_STATUS_BAD"
# 规则 / 临时授权不在有效期窗口内
E_RULE_EXPIRED = "RULE_EXPIRED"
# 临时授权不合法（审批人不足、试图放宽明确拒绝等）
E_TEMP_GRANT_INVALID = "TEMP_GRANT_INVALID"

# ---- 请求校验 / 管理面错误码 -----------------------------------------------------
E_BAD_REQUEST = "BAD_REQUEST"
E_TOO_MANY_DEPENDENCIES = "TOO_MANY_DEPENDENCIES"
E_BAD_REQUEST_ID = "BAD_REQUEST_ID"
E_UNKNOWN_SNAPSHOT = "UNKNOWN_SNAPSHOT"
E_INTEGRITY = "CONTENT_INTEGRITY_FAILED"

MAX_DEPENDENCIES = 25

# 证书状态
CERT_ACTIVE = "ACTIVE"
CERT_ROTATED = "ROTATED"
CERT_REVOKED = "REVOKED"

# 远端签发者模拟状态
REMOTE_GOOD = "GOOD"
REMOTE_SUSPENDED = "SUSPENDED"
REMOTE_REVOKED = "REVOKED"

# 规则层级与种类
LAYER_BASELINE = "baseline"
LAYER_GROUP = "group"

KIND_DIGEST_ALLOW = "digest_allow"
KIND_ISSUER_PATH_ALLOW = "issuer_path_allow"
KIND_DENY_DIGEST = "deny_digest"
KIND_DENY_ISSUER_PATH = "deny_issuer_path"
DENY_KINDS = frozenset({KIND_DENY_DIGEST, KIND_DENY_ISSUER_PATH})
ALLOW_KINDS = frozenset({KIND_DIGEST_ALLOW, KIND_ISSUER_PATH_ALLOW})
