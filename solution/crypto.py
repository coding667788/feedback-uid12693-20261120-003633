"""合成密码学原语（全部标准库）。

真实企业场景使用 X.509 证书链与非对称签名；离线环境下用 HMAC-SHA256
模拟整条签发链的信任关系，语义保持一致：

* 每张证书由父级密钥对其规范化字段签名，根证书自签；
* 叶子密钥对应用内容 SHA-256 再做一次 HMAC，形成“经过当前签发链
  验证的摘要”（chain_digest）；
* 轮换 / 吊销通过证书状态表表达，旧密钥立即失效。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(obj) -> str:
    """稳定序列化：排序键、无空白，作为签名 / 指纹的规范报文。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hmac_hex(key_hex: str, message: str) -> str:
    return hmac.new(
        bytes.fromhex(key_hex), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def new_secret_hex(seed: str) -> str:
    """由种子确定性派生合成密钥（离线、可重放）。"""
    return hashlib.sha256(("synthetic-secret:" + seed).encode("utf-8")).hexdigest()


def random_id(prefix: str, seed: str) -> str:
    return f"{prefix}-{hashlib.sha1(seed.encode('utf-8')).hexdigest()[:12]}"


def cert_canonical_fields(cert: dict) -> dict:
    return {
        "kid": cert["kid"],
        "org_id": cert["org_id"],
        "issuer_id": cert["issuer_id"],
        "parent_kid": cert["parent_kid"],
        "not_before": cert["not_before"],
        "not_after": cert["not_after"],
    }


def sign_cert(cert: dict, parent_secret_hex: str) -> str:
    return hmac_hex(parent_secret_hex, canonical(cert_canonical_fields(cert)))


def attest_content_digest(leaf_secret_hex: str, content_digest: str) -> str:
    """叶子密钥对内容摘要的签发链见证。"""
    return hmac_hex(leaf_secret_hex, "attest:" + content_digest)
