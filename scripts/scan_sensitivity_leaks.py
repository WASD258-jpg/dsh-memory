# -*- coding: utf-8 -*-
"""scan_sensitivity_leaks.py · 历史落盘降密级泄漏扫描（安全重构 P4，**只读**）

# 功能名：存量明文泄漏体检
# 生效条件：P1–P3 合入后对在役库跑一次；或怀疑旧版本留下 internal 明文时
# 子功能：
#   T1 _writelimit.json：签名 sk 记账密级 sens 超出 internal（#313 修前遗留的正文骨架）
#   T2 _writelimit.json：sens 为 null 的签名（#313 修前生产调用方从不传密级——**来源不可判**）
#   T3 _forgetting.jsonl：dropped_content 非空，且记录密级超限、或 duplicate_with 目标节点超限
#   T4 _consistency.jsonl：未脱敏（redacted≠True）且条件原文非空，而落账密级/被比对节点超限
#   T5 节点：加密档密级但正文不是密文（_check_sensitivity_landing 修前遗留）
#   T6 节点：internal/public 节点正文含聚合/整理摘录行，引用了密级更高的成员 id（#315 #360 形态）
# 执行：python -X utf8 scripts/scan_sensitivity_leaks.py <库根> [--json 报告路径]
# 验证方式：stdout 每类命中数；--json 写完整清单（只含 id/文件/行号/sha1，**不含原文**）
# 不适用条件：**不修改任何文件**——重加密/清除需按来源回溯逐条裁决（使用者裁定后另行执行）；
#             不解密密文（不需要密钥）；T2/T3 中「来源不可判」项只报不判。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from md_cg import crypto, landing          # noqa: E402

_RE_MEMBER = re.compile(r"^- (\S+) ", re.M)


def _sha(s):
    flat = " ".join(str(s or "").split())
    return hashlib.sha1(flat.encode("utf-8")).hexdigest()[:12] if flat else ""


def _read_jsonl(path):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if isinstance(rec, dict):
                yield i, rec


def _index(root):
    p = os.path.join(root, "_index.json")
    try:
        with open(p, encoding="utf-8") as f:
            return (json.load(f) or {}).get("nodes") or {}
    except (OSError, ValueError):
        return {}


def _node_level(nodes, nid):
    e = nodes.get(nid)
    if e is None:
        return None                      # 不在索引：来源不可判
    return e.get("sensitivity") or "internal"


def scan(root):
    nodes = _index(root)
    out = {k: [] for k in ("T1", "T2", "T3", "T4", "T5", "T6")}
    # T1/T2
    try:
        with open(os.path.join(root, "_writelimit.json"), encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    for sig, rec in ((st or {}).get("sigs") or {}).items():
        if not isinstance(rec, dict):
            continue
        sens = rec.get("sens")
        item = {"sig_sha1": _sha(sig), "nid": rec.get("nid"), "sens": sens}
        if sens is None:
            lv = _node_level(nodes, rec.get("nid"))
            item["target_level"] = lv
            out["T2"].append(item)
            if lv is not None and landing.exceeds(lv):
                out["T1"].append(dict(item, why="sens 缺失但签名指向的节点超限"))
        elif landing.exceeds(sens):
            out["T1"].append(item)
    # T3
    for ln, rec in _read_jsonl(os.path.join(root, "_forgetting.jsonl")):
        if not rec.get("dropped_content"):
            continue
        lv_rec = rec.get("sensitivity")
        lv_tgt = _node_level(nodes, rec.get("duplicate_with")) if rec.get("duplicate_with") else None
        if (lv_rec is not None and landing.exceeds(lv_rec)) or \
                (lv_tgt is not None and landing.exceeds(lv_tgt)):
            out["T3"].append({"line": ln, "trace_id": rec.get("trace_id"),
                              "content_sha1": rec.get("content_sha1") or _sha(rec["dropped_content"]),
                              "record_level": lv_rec, "target_level": lv_tgt})
    # T4
    for ln, rec in _read_jsonl(os.path.join(root, "_consistency.jsonl")):
        if rec.get("redacted") is True:
            continue
        has_text = bool(rec.get("pos") or rec.get("neg")) or any(
            isinstance(c, dict) and (c.get("pos_side") or c.get("neg_side") or c.get("slot"))
            for c in (rec.get("conflicts") or []))
        if not has_text:
            continue
        lvs = [rec.get("sensitivity")] if rec.get("sensitivity") else []
        lvs += [_node_level(nodes, c.get("with")) for c in (rec.get("conflicts") or [])
                if isinstance(c, dict) and c.get("with") and c.get("with") in nodes]
        if any(landing.exceeds(x) for x in lvs):
            out["T4"].append({"line": ln, "levels": sorted(set(map(str, lvs)))})
    # T5/T6
    for nid, e in nodes.items():
        path = e.get("path") or e.get("file")
        if not path:
            continue
        fp = path if os.path.isabs(path) else os.path.join(root, path)
        try:
            with open(fp, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        body = text.split("\n---", 2)[-1] if text.startswith("---") else text
        lv = e.get("sensitivity") or "internal"
        if crypto.is_encrypted_level(lv) and not crypto.is_encrypted(body.strip()):
            out["T5"].append({"node_id": nid, "level": lv, "file": path})
        if not landing.exceeds(lv) and ("【聚合" in body or "整理聚合" in body):
            higher = [m for m in _RE_MEMBER.findall(body)
                      if m in nodes and landing._rank(_node_level(nodes, m)) > landing._rank(lv)]
            if higher:
                out["T6"].append({"node_id": nid, "level": lv, "file": path,
                                  "higher_members": higher[:20]})
    return out


def main(argv):
    if not argv or argv[0].startswith("-"):
        print(__doc__)
        return 2
    root = argv[0]
    res = scan(root)
    names = {"T1": "写限台账·超限签名骨架", "T2": "写限台账·密级缺失（来源不可判）",
             "T3": "遗忘留痕·超限正文", "T4": "一致性台账·超限条件原文",
             "T5": "节点·加密档却明文", "T6": "节点·低档节点含高档成员摘录"}
    for k in sorted(res):
        print("%s %-28s %d" % (k, names[k], len(res[k])))
    if "--json" in argv:
        p = argv[argv.index("--json") + 1]
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"root": os.path.basename(os.path.abspath(root)), "findings": res},
                      f, ensure_ascii=False, indent=2)
        print("报告：" + p)
    hard = sum(len(res[k]) for k in ("T1", "T3", "T4", "T5", "T6"))
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
