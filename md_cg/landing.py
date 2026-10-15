# -*- coding: utf-8 -*-
"""md_cg · 台账/日志落盘咽喉（安全重构 P3）

# 功能名：派生内容落盘密级闸（台账面）
# 生效条件：任一模块向明文台账/日志（`_consistency.jsonl`、`_forgetting.jsonl`、
#           `_writelimit.json` 签名面）追加可能携带正文/原文片段的记录时
# 子功能：①来源密级合成（取最高档，未知=最高档）②写入入口的声明密级解析（None=缺省档）
#         ③是否超出台账上限判定 ④超限即只写脱敏骨架 ⑤单点追加
# 执行：调用方构造完整记录 → append_ledger(path, rec, level=…, scrub=…)
# 验证方式：python -X utf8 -m md_cg.test_landing_gate（含结构守卫与定点变异）
# 不适用条件：节点正文落盘（归 mdcg._write_node / _check_sensitivity_landing）；
#             不判读权限、不判降密级合并（security.merge_downgrades 单点）

病象（证据：#148 #164 #186 #214 #243 #258 #294 #297 #298 #313 #315 #345 #359 #360）：
派生写把 private / restricted 正文落成 internal 明文。节点落盘有
`_check_sensitivity_landing` 单点，但台账、日志、聚合行不走 `_write_node`，
各自（或没有）判密级——#298 在 consistency 里补了一份 `ledger_level` + `scrub_record`，
#313 在 writelimit 里补了「加密级不落签名」，forgetting 的 DROP 留痕只挡加密级；
三处口径各异，restricted（不加密但限扩散）在后两处直接以明文落账。

裁定（使用者 2026-10-15）：台账/日志超密级时**只写脱敏骨架**（不拒写——台账是审计面，
拒写会把审计一起打断）。

台账上限 LEDGER_CEILING = internal：这些台账是明文文件、无逐条读过滤，按 internal
可见性对待；restricted / private / secret 来源一律去原文。
"""
from __future__ import annotations

import hashlib

from .security import SENSITIVITY_ORDER

#: 明文台账/日志的可见上限：高于此档的来源只落脱敏骨架。
LEDGER_CEILING = "internal"


# 生效条件：level 为 SENSITIVITY_ORDER 成员（经 crypto.normalize_sensitivity 归一）时返回下标；
# None / 空串 / 非法值一律返回最高档下标（fail-closed：判不了按最高档）。
def _rank(level) -> int:
    from .crypto import normalize_sensitivity
    s = normalize_sensitivity(level)
    if s in SENSITIVITY_ORDER:
        return SENSITIVITY_ORDER.index(s)
    return len(SENSITIVITY_ORDER) - 1


# 生效条件：返回 levels 中最高档的规范名；任一为 None/空串/非法即按最高档（未知 = 最高档）；
# 未给任何 level 时同样返回最高档（没有来源信息 ≠ 可以公开）。
def source_level(*levels) -> str:
    """派生内容的来源密级 = 所有来源的最高档；未知按最高档（fail-closed）。"""
    if not levels:
        return SENSITIVITY_ORDER[-1]
    return SENSITIVITY_ORDER[max(_rank(x) for x in levels)]


# 生效条件：declared 为**写入入口**的调用方声明密级（即将以该档落盘的内容）；假值时返回
# DEFAULT_SENSITIVITY（未声明的写入按缺省档落盘、读面按缺省档可见——这是事实，不是猜测）；
# 非假值经归一后原样返回（非法值保留原文，交 source_level/exceeds 按最高档处理）。
def declared_level(declared) -> str:
    """写入入口的声明密级解析——**只**用于「本条内容即将按此档落盘」的场合。

    与 source_level 的分工（最易混用处）：
      · 内容来自调用方本次写入、且未声明 ⇒ 它会按缺省档落盘 ⇒ declared_level 给缺省档；
      · 内容派生自其它节点/记录、来源密级没传下来 ⇒ 未知 ⇒ source_level 给最高档。
    """
    # 解析口径不另立：归一后交 security.declared_write_sensitivity（P2 立的写入入口单点）。
    from .crypto import normalize_sensitivity
    from .security import declared_write_sensitivity
    return declared_write_sensitivity(normalize_sensitivity(declared))


# 生效条件：level 的档位（未知=最高档）严格高于 ceiling 的档位时返回 True。
def exceeds(level, ceiling: str = LEDGER_CEILING) -> bool:
    """来源密级是否超出落点上限。"""
    return _rank(level) > SENSITIVITY_ORDER.index(ceiling)


# 生效条件：text 为任意值；返回 {"sha1": 前12位, "chars": 折叠空白后的长度}（空/None 时 sha1 为 ""）。
def skeleton(text) -> dict:
    """脱敏骨架：只留可对账的摘要与长度，不留任何原文片段。"""
    flat = " ".join(str(text or "").split())
    return {"sha1": hashlib.sha1(flat.encode("utf-8")).hexdigest()[:12] if flat else "",
            "chars": len(flat)}


# 生效条件：rec 为 dict；exceeds(level, ceiling) 为真时返回 scrub(dict(rec)) 的结果，否则返回 dict(rec)；
# 原 rec 一律不被修改。scrub 为 None 时超限记录按「无可脱敏字段」处理（原样）——调用方须自证无原文。
def land_record(rec: dict, *, level, scrub=None, ceiling: str = LEDGER_CEILING) -> dict:
    """按来源密级决定落盘形态：不超限原样，超限过 scrub 得脱敏副本。"""
    out = dict(rec or {})
    if scrub is not None and exceeds(level, ceiling):
        out = scrub(out)
    return out


# 生效条件：经 land_record 得到落盘形态后，以 fsutil.append_jsonl 追加到 path（补断行、0o600）；
# OSError 原样抛出（是否吞错由调用方按其既有语义决定）；返回实际落盘的记录。
def append_ledger(path: str, rec: dict, *, level, scrub=None,
                  ceiling: str = LEDGER_CEILING) -> dict:
    """台账/日志追加的唯一咽喉。"""
    from .fsutil import append_jsonl
    out = land_record(rec, level=level, scrub=scrub, ceiling=ceiling)
    append_jsonl(path, out)
    return out
