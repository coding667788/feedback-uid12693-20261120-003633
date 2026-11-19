"""Windows 入口路径处理与路径段匹配。"""

from __future__ import annotations

from .errors import AdmissionError, E_BAD_REQUEST

DRIVE_SEP = ":\\"


def normalize_entry(path: str) -> str:
    """规范化完整入口路径：反斜杠统一、小写（Windows 不区分大小写）。

    正斜杠也接受（合成输入），统一转为反斜杠。
    """
    if not isinstance(path, str) or not path.strip():
        raise AdmissionError(E_BAD_REQUEST, "入口路径为空")
    p = path.strip().replace("/", "\\")
    if "\\" not in p:
        raise AdmissionError(E_BAD_REQUEST, f"入口路径缺少完整目录结构: {path}")
    # 形如 C:\... 或 \\server\share\...
    if not (len(p) >= 3 and p[1:3] == DRIVE_SEP) and not p.startswith("\\\\"):
        raise AdmissionError(E_BAD_REQUEST, f"入口路径必须是完整 Windows 路径: {path}")
    return p.lower()


def split_segments(path: str) -> list[str]:
    """拆成路径段，丢弃盘符与空段。

    例如 C:\\Program Files\\Acme\\app.exe -> ["program files", "acme", "app.exe"]
    """
    norm = normalize_entry(path)
    parts = [seg for seg in norm.split("\\") if seg]
    if parts and len(parts[0]) == 2 and parts[0].endswith(":"):
        parts = parts[1:]
    return parts


def has_segment_sequence(entry_path: str, segments: list[str]) -> bool:
    """规则声明的路径段序列必须在入口路径中作为连续整段出现。

    按整段比较（避免 "acme" 误匹配 "acme2" 这种同名子串）。
    """
    if not segments:
        return False
    wanted = [s.lower() for s in segments]
    actual = split_segments(entry_path)
    n = len(wanted)
    for i in range(0, len(actual) - n + 1):
        if actual[i : i + n] == wanted:
            return True
    return False


def has_named_segment(entry_path: str, segment: str) -> bool:
    return segment.lower() in split_segments(entry_path)
