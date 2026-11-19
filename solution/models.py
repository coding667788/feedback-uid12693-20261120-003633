"""准入请求的数据模型与校验。

一个请求（LaunchRequest）描述一次软件启动尝试，包含：

* 组织、设备、设备代数；
* 主程序与至多 25 个合成依赖；
* 每个部件绑定：内容 SHA-256、签发者叶子密钥、签发链见证摘要
  （chain_digest）、完整入口路径。

请求身份（identity_digest）对全部判定相关字段取哈希：同一摘要移动
到不同入口、或签发者换钥，都会得到不同身份，从而强制重判。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import canonical, sha256_text
from .errors import (
    AdmissionError,
    E_BAD_REQUEST,
    E_INTEGRITY,
    E_TOO_MANY_DEPENDENCIES,
    MAX_DEPENDENCIES,
)
from .paths import normalize_entry

PART_MAIN = "main"
PART_DEP = "dependency"


@dataclass(frozen=True)
class Part:
    slot: int                 # 0=主程序，1..25=依赖
    role: str                 # main / dependency
    name: str
    content_digest: str       # 应用内容 SHA-256
    issuer_id: str            # 签发者标识
    leaf_kid: str             # 叶子密钥 id（换钥即变）
    chain_digest: str         # 叶子密钥对 content_digest 的见证
    entry_path: str            # 完整入口路径

    def to_dict(self) -> dict:
        return {
            "slot": self.slot,
            "role": self.role,
            "name": self.name,
            "content_digest": self.content_digest,
            "issuer_id": self.issuer_id,
            "leaf_kid": self.leaf_kid,
            "chain_digest": self.chain_digest,
            "entry_path": self.entry_path,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Part":
        try:
            return cls(
                slot=int(d["slot"]),
                role=d["role"],
                name=d["name"],
                content_digest=d["content_digest"].lower(),
                issuer_id=d["issuer_id"],
                leaf_kid=d["leaf_kid"],
                chain_digest=d["chain_digest"],
                entry_path=normalize_entry(d["entry_path"]),
            )
        except KeyError as exc:
            raise AdmissionError(E_BAD_REQUEST, f"部件缺少字段: {exc}") from exc


@dataclass(frozen=True)
class LaunchRequest:
    request_id: str
    org_id: str
    device_id: str
    device_generation: int
    parts: tuple[Part, ...]
    identity_digest: str
    client_ts: str

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "org_id": self.org_id,
            "device_id": self.device_id,
            "device_generation": self.device_generation,
            "parts": [p.to_dict() for p in self.parts],
            "identity_digest": self.identity_digest,
            "client_ts": self.client_ts,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LaunchRequest":
        required = ("request_id", "org_id", "device_id", "device_generation", "parts")
        for key in required:
            if key not in d:
                raise AdmissionError(E_BAD_REQUEST, f"请求缺少字段: {key}")
        parts = tuple(Part.from_dict(p) for p in d["parts"])
        validate_parts(parts)
        recomputed = compute_identity(d["org_id"], parts)
        identity = d.get("identity_digest")
        if identity is None:
            identity = recomputed  # 重放器改写部件后由模型重算身份
        elif identity != recomputed:
            raise AdmissionError(E_INTEGRITY, "请求身份摘要与内容不一致")
        return cls(
            request_id=str(d["request_id"]),
            org_id=d["org_id"],
            device_id=d["device_id"],
            device_generation=int(d["device_generation"]),
            parts=parts,
            identity_digest=identity,
            client_ts=d.get("client_ts", ""),
        )


def validate_parts(parts: tuple[Part, ...]) -> None:
    if not parts:
        raise AdmissionError(E_BAD_REQUEST, "启动请求至少包含一个主程序")
    if parts[0].role != PART_MAIN or parts[0].slot != 0:
        raise AdmissionError(E_BAD_REQUEST, "slot 0 必须是主程序")
    deps = [p for p in parts if p.role == PART_DEP]
    if len(deps) > MAX_DEPENDENCIES:
        raise AdmissionError(
            E_TOO_MANY_DEPENDENCIES,
            f"依赖数量 {len(deps)} 超过上限 {MAX_DEPENDENCIES}",
        )
    if len(parts) != len({p.slot for p in parts}):
        raise AdmissionError(E_BAD_REQUEST, "部件 slot 重复")
    for p in parts:
        if len(p.content_digest) != 64:
            raise AdmissionError(E_BAD_REQUEST, f"内容摘要不是 SHA-256: {p.name}")


def compute_identity(org_id: str, parts: tuple[Part, ...]) -> str:
    """请求身份：组织 + 每个部件的全部判定相关字段。

    入口路径变化、叶子密钥换钥都会改变身份，强制新请求重判。
    """
    payload = {
        "org_id": org_id,
        "parts": [
            {
                "content_digest": p.content_digest,
                "issuer_id": p.issuer_id,
                "leaf_kid": p.leaf_kid,
                "chain_digest": p.chain_digest,
                "entry_path": p.entry_path,
            }
            for p in parts
        ],
    }
    return sha256_text(canonical(payload))
