# -*- coding: utf-8 -*-
"""test_scan_sensitivity_leaks.py · 存量泄漏体检脚本守卫（安全重构 P4）

# 功能名：scan_sensitivity_leaks 可鉴别 + 只读 + 报告不含原文
# 生效条件：改动 scripts/scan_sensitivity_leaks.py 之后必跑
# 子功能：①六类泄漏夹具各命中 1 条 ②干净夹具 0 命中、退出码 0 ③扫描前后库内文件逐字节不变
#         ④JSON 报告不含任何原文片段 ⑤定点变异：把超限判据换成恒假 ⇒ ①必须转红
# 执行：python -X utf8 scripts/test_scan_sensitivity_leaks.py
# 验证方式：末行「通过 N / 失败 M」，退出码 0/1
# 不适用条件：不测在役库；夹具一律 tempfile
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
for p in (_REPO, _HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

import scan_sensitivity_leaks as S          # noqa: E402
from md_cg import landing                   # noqa: E402

_R = []
SECRET = "私有原文 OMEGA-4411"


def check(name, ok, detail=""):
    _R.append((bool(ok), name))
    print(("PASS " if ok else "FAIL ") + name + (("  ——" + str(detail)) if detail and not ok else ""))


def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _fixture(d, leaky=True):
    nodes = {"p1": {"sensitivity": "private", "path": "knowledge/p1.md"},
             "i1": {"sensitivity": "internal", "path": "knowledge/i1.md"}}
    p1_body = SECRET if leaky else "<!-- mdcg-enc:v1:AAAA -->"
    _w(os.path.join(d, "knowledge/p1.md"), "---\nsensitivity: private\n---\n" + p1_body)
    i1_body = "X\n\n# 整理聚合（tidy）：同模板成员 1 条\n- p1 " + SECRET + "\n" if leaky else "X\n"
    _w(os.path.join(d, "knowledge/i1.md"), "---\nsensitivity: internal\n---\n" + i1_body)
    _w(os.path.join(d, "_index.json"), json.dumps({"nodes": nodes}))
    sigs = {"批次收官": {"nid": "p1", "sens": "private" if leaky else "internal"},
            "t:x": {"nid": "i1", "sens": None if leaky else "internal"}}
    _w(os.path.join(d, "_writelimit.json"), json.dumps({"sigs": sigs, "rate": {}}, ensure_ascii=False))
    drop = {"verdict": "DROP", "dropped_content": SECRET if leaky else None,
            "duplicate_with": "p1", "trace_id": "t1"}
    _w(os.path.join(d, "_forgetting.jsonl"), json.dumps(drop, ensure_ascii=False) + "\n")
    cons = {"pos": [SECRET] if leaky else [], "conflicts": [{"with": "p1"}], "sensitivity": "internal",
            "redacted": not leaky}
    _w(os.path.join(d, "_consistency.jsonl"), json.dumps(cons, ensure_ascii=False) + "\n")


def _digest(d):
    h = {}
    for root, _dd, ff in os.walk(d):
        for f in ff:
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                h[os.path.relpath(p, d)] = hashlib.sha1(fh.read()).hexdigest()
    return h


def run():
    d = tempfile.mkdtemp(prefix="scanleak_")
    try:
        leak, clean = os.path.join(d, "leak"), os.path.join(d, "clean")
        _fixture(leak, True)
        _fixture(clean, False)
        before = _digest(leak)
        res = S.scan(leak)
        for k in ("T1", "T2", "T3", "T4", "T5", "T6"):
            check("C1[%s] 泄漏夹具命中" % k, len(res[k]) >= 1, res[k])
        check("C2 扫描只读（库内文件逐字节不变）", _digest(leak) == before)
        rep = os.path.join(d, "r.json")
        rc = S.main([leak, "--json", rep])
        raw = open(rep, encoding="utf-8").read()
        check("C3 报告不含原文", "OMEGA-4411" not in raw and "私有原文" not in raw)
        check("C4 有硬命中 ⇒ 退出码 1", rc == 1)
        res2 = S.scan(clean)
        hard = {k: v for k, v in res2.items() if v}
        check("C5 干净夹具 0 命中", not hard, hard)
        check("C6 干净夹具退出码 0", S.main([clean]) == 0)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    run()
    # 定点变异：超限判据恒假 ⇒ C1 的 T1/T3/T4 必须转红
    good = list(_R)
    _R.clear()
    print("!! 定点变异轮（本轮的 FAIL 行为预期，判据见末条 M1）")
    orig = landing.exceeds
    landing.exceeds = lambda *a, **k: False
    try:
        run()
    finally:
        landing.exceeds = orig
    reds = [n for ok, n in _R if not ok]
    want = ("C1[T1]", "C1[T3]", "C1[T4]")
    hit = all(any(r.startswith(w) for r in reds) for w in want)
    _R[:] = good
    check("M1 定点变异：超限判据恒假 ⇒ T1/T3/T4 转红（守卫可鉴别）", hit, reds)
    bad = [n for ok, n in _R if not ok]
    print("\nP4 体检脚本守卫：通过 %d / 失败 %d" % (len(_R) - len(bad), len(bad)))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
