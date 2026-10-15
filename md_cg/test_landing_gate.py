# -*- coding: utf-8 -*-
"""test_landing_gate · 台账/日志落盘咽喉守卫（安全重构 P3）

# 功能名：派生内容落盘密级闸（台账面）
# 生效条件：改动 md_cg/landing.py，或 consistency.log / forgetting.log / forgetting.record_drop /
#           writelimit 签名面的落盘方式之后必跑
# 子功能：L 咽喉语义（来源取最高档、未知=最高档、写入入口未声明=缺省档、超限判据）
#         B 落点行为（_forgetting.jsonl 的 DROP 正文、_consistency.jsonl 的条件原文、_writelimit 签名）
#           ——参数化覆盖 public/internal/restricted/private/secret/None/非法值
#         S 结构（台账模块不得绕过咽喉直写）
#         M 定点变异（进程内）：超限判据恒假 / 未知回到 internal ⇒ B 组必须转红
# 执行：python -X utf8 -m md_cg.test_landing_gate [--mutate]
# 验证方式：末行「通过 N / 失败 M」；--mutate 末行「定点变异自证：PASS」
# 不适用条件：节点正文落盘（_check_sensitivity_landing 的守卫负责）；沙箱一律 tempfile
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from md_cg import consistency, forgetting, landing, writelimit   # noqa: E402

_RESULTS = []
SECRET_TEXT = "敏感正文 ZETA-7781 不应出现在明文台账"


def check(name, ok, detail=""):
    _RESULTS.append((bool(ok), name))
    print(("PASS " if ok else "FAIL ") + name + (("  ——" + str(detail)) if (detail and not ok) else ""))


class _CG:
    def __init__(self, root):
        self.root = root
        self.actor = "tester"


def _lines(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


# (声明密级, 是否应保留原文)——写入入口语义：None = 缺省档 internal
_DROP_CASES = (("public", True), ("internal", True), (None, True),
               ("restricted", False), ("private", False), ("secret", False),
               ("bogus", False), (" Restricted ", False))


def l_group():
    print("== L 咽喉语义")
    check("L1 source_level 取最高档", landing.source_level("public", "restricted", "internal") == "restricted")
    check("L2 source_level 未知=最高档", landing.source_level("public", None) == "secret"
          and landing.source_level("internal", "bogus") == "secret" and landing.source_level() == "secret")
    check("L3 declared_level 未声明=缺省档、有值归一", landing.declared_level(None) == "internal"
          and landing.declared_level("") == "internal" and landing.declared_level(" Private") == "private")
    check("L4 exceeds：internal 及以下不超、restricted 起超、未知超",
          not landing.exceeds("public") and not landing.exceeds("internal")
          and landing.exceeds("restricted") and landing.exceeds(None) and landing.exceeds("bogus"))
    check("L5 land_record 不改原记录", (lambda r: (landing.land_record(
        r, level="secret", scrub=lambda x: {}) == {} and r == {"a": 1}))({"a": 1}))


def b_group():
    print("== B 落点行为（参数化）")
    d = tempfile.mkdtemp(prefix="p3gate_")
    try:
        for sens, keep in _DROP_CASES:
            root = os.path.join(d, "drop_%s" % str(sens).strip())
            os.makedirs(root, exist_ok=True)
            sink = forgetting.record_drop(_CG(root), SECRET_TEXT, node_id="n1", target="t1",
                                          verdict={"reason": "dup"}, layer="contextual",
                                          sensitivity=sens)
            recs = _lines(os.path.join(root, forgetting.LOG_FILE))
            raw = open(os.path.join(root, forgetting.LOG_FILE), encoding="utf-8").read()
            ok = (("ZETA-7781" in raw) is keep and bool((sink or {}).get("content_kept")) is keep
                  and recs and recs[-1].get("content_sha1"))
            check("B1[%r] _forgetting.jsonl DROP 正文%s" % (sens, "保留" if keep else "只留骨架"), ok,
                  {"in_file": "ZETA-7781" in raw, "sink": sink})
        # consistency：记录自带密级；未带密级按最高档
        for sens, keep in (("internal", True), ("restricted", False), ("private", False), (None, False)):
            root = os.path.join(d, "cons_%s" % sens)
            os.makedirs(root, exist_ok=True)
            rec = {"verdict": "REJECT", "pos": [SECRET_TEXT], "neg": [],
                   "conflicts": [{"with": "x", "pos_side": [SECRET_TEXT], "slot": SECRET_TEXT}]}
            if sens is not None:
                rec["sensitivity"] = sens
            consistency.log(_CG(root), rec)
            raw = open(os.path.join(root, consistency.LOG_FILE), encoding="utf-8").read()
            check("B2[%r] _consistency.jsonl 条件原文%s" % (sens, "保留" if keep else "去除"),
                  ("ZETA-7781" in raw) is keep and rec["pos"] == [SECRET_TEXT],
                  {"in_file": "ZETA-7781" in raw})
        # writelimit 签名面
        for sens, forbid in (("public", False), ("internal", False), (None, False),
                             ("restricted", True), ("private", True), ("secret", True), ("bogus", True)):
            check("B3[%r] _writelimit 模板签名%s" % (sens, "禁落" if forbid else "可落"),
                  writelimit._sig_forbidden(sens) is forbid)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def s_group():
    print("== S 结构：台账模块不绕过咽喉")
    bad = {}
    for name, allowed_append_targets in (("consistency.py", ()), ("forgetting.py", ("MAINTAIN_LOG",))):
        tree = ast.parse(open(os.path.join(_HERE, name), encoding="utf-8").read())
        hits = []
        for fdef in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            called = {getattr(c.func, "attr", getattr(c.func, "id", ""))
                      for c in ast.walk(fdef) if isinstance(c, ast.Call)}
            via_gate = bool(called & {"land_record", "append_ledger"})
            for n in ast.walk(fdef):
                if not isinstance(n, ast.Call):
                    continue
                fn = n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", "")
                if fn == "open" and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) \
                        and "a" in str(n.args[1].value) and not via_gate:
                    hits.append(n.lineno)
                if fn == "append_jsonl":
                    names = {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}
                    if not (names & set(allowed_append_targets)):
                        hits.append(n.lineno)
        if hits:
            bad[name] = sorted(set(hits))
    check("S1 consistency/forgetting 台账追加必经咽喉（land_record/append_ledger）", not bad, bad)
    src = open(os.path.join(_HERE, "consistency.py"), encoding="utf-8").read()
    check("S2 consistency 不另立密级序", '("public", "internal", "restricted", "private", "secret")' not in src)


def _mutate():
    print("!! 定点变异自证（进程内）")
    bad = []
    orig_exceeds, orig_rank = landing.exceeds, landing._rank

    def rank_unknown_internal(level):
        from md_cg.crypto import normalize_sensitivity
        s = normalize_sensitivity(level)
        return landing.SENSITIVITY_ORDER.index(s) if s in landing.SENSITIVITY_ORDER else 1
    muts = (("超限判据恒假", "exceeds", lambda *a, **k: False, ("B1['restricted']", "B2['restricted']", "B3['restricted']")),
            ("未知回到 internal", "_rank", rank_unknown_internal, ("B1['bogus']", "B2[None]", "B3['bogus']")))
    for desc, attr, fn, expect in muts:
        _RESULTS.clear()
        setattr(landing, attr, fn)
        try:
            b_group()
        finally:
            landing.exceeds, landing._rank = orig_exceeds, orig_rank
        reds = [n for ok, n in _RESULTS if not ok]
        hit = [e for e in expect if any(r.startswith(e) for r in reds)]
        ok = len(hit) == len(expect)
        print(("  OK   " if ok else "  MISMATCH ") + "%s 指定命中 %d/%d" % (desc, len(hit), len(expect)))
        if not ok:
            bad.append(desc)
    print("定点变异自证：%s" % ("PASS" if not bad else "FAIL"))
    return 0 if not bad else 1


def main():
    if "--mutate" in sys.argv:
        return _mutate()
    l_group()
    b_group()
    s_group()
    bad = [n for ok, n in _RESULTS if not ok]
    print("\nP3 落盘咽喉：通过 %d / 失败 %d" % (len(_RESULTS) - len(bad), len(bad)))
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
