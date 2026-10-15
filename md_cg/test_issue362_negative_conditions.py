# -*- coding: utf-8 -*-
# 功能名：负条件归一/否定/边界判据（issue #362）
# 生效条件：python -X utf8 -m md_cg.test_issue362_negative_conditions [--mutate]；独立临时库，失败退出 1。
# 子功能：A 组=10 项否定/归一/边界判据；K 组=8 项肯定/自主题/边界定义对照。
# 执行：--mutate 在镜像目录逐项单行变异、清 __pycache__，每条校验指定断言转红。
# 验证方式：原镜像全绿，5/5 条变异均按指定判据转红；CRLF 用 universal newline 读取。
# 不适用条件：完整性能/平台覆盖与剩余边界见对应 PR 正文；本守卫不替代全量回归。
"""issue #362 守卫：A 组缺陷面 / K 组非恒真对照 / --mutate 镜像定点变异。
用法：python -X utf8 -m md_cg.test_issue362_negative_conditions [--mutate]
"""
MODULE = "md_cg.test_issue362_negative_conditions"

import os, sys, shutil, subprocess, tempfile, json, time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
FAILS = []

def _check(name, cond, detail=""):
    if not cond:
        FAILS.append(name)
    print(("  PASS " if cond else "  FAIL ") + name + (" " + str(detail)[:220] if not cond else ""), flush=True)

def _mirror_build():
    tree = Path(tempfile.mkdtemp(prefix="issue_mut_"))
    for name in ("md_cg", "scripts", "data", "rust"):
        shutil.copytree(_REPO/name, tree/name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "target", ".tmp"))
    for p in _REPO.iterdir():
        if p.is_file() and (p.suffix == ".py" or p.name in ("README.md", "package.json")):
            shutil.copy2(p, tree/p.name)
    return tree

def _run_in(tree):
    env = dict(os.environ, PYTHONPATH=str(tree), PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-X", "utf8", "-m", MODULE], cwd=tree, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    out = r.stdout + r.stderr
    reds = [ln.split("FAIL ", 1)[1].strip() for ln in out.splitlines() if "FAIL " in ln]
    return r.returncode, reds, out

def _mutate():
    tree = _mirror_build()
    good = 0
    try:
        rc, reds, out = _run_in(tree)
        _check("M0 未变异镜像全绿", rc == 0 and not reds, out[-900:])
        if rc or reds:
            return
        for desc, rel, old, new, expected in _MUTATIONS:
            assert "\n" not in old and "\r" not in old, "变异只允许单行锚点"
            p = tree/rel
            t = p.read_text(encoding="utf-8")  # universal newline：Windows CRLF 同口径
            if t.count(old) != 1:
                _check("M " + desc, False, "ANCHOR-MISS count=" + str(t.count(old)))
                continue
            try:
                p.write_text(t.replace(old, new, 1), encoding="utf-8")
                for cache in tree.rglob("__pycache__"):
                    shutil.rmtree(cache, ignore_errors=True)
                rc, reds, out = _run_in(tree)
                hit = all(any(r.startswith(e + " ") for r in reds) for e in expected)
                ok = rc != 0 and hit
                _check("M " + desc, ok, (rc, reds, out[-700:]))
                good += int(ok)
                print("    指定转红：" + ",".join(expected), flush=True)
            finally:
                p.write_text(t, encoding="utf-8")
        print("变异 %d/%d 全红" % (good, len(_MUTATIONS)), flush=True)
    finally:
        shutil.rmtree(tree, ignore_errors=True)

def _environment(root):
    os.environ.update(MDCG_ROOT=str(root/"brain"), MDCG_STATE_ROOT=str(root/"state"),
                      MDCG_AUX_ROOT=str(root/"auxstore"), MDCG_DATA_ROOT=str(root/"datastore"),
                      MDCG_EXPORT_ROOT=str(root), MDCG_SUSTAIN="0", MDCG_SLEEP="0", MDCG_WRITELIMIT="0")

def _cg(root):
    _environment(root)
    from md_cg.mdcos import MdCGSecure
    from md_cg.security import Principal
    return MdCGSecure(str(root/"brain"), principal=Principal(role="designer",clearance="secret",can_write=True,can_admin=True),autoflush=1)

def _ccg(value):
    return "\n".join(["# 功能名："+value,"# 生效条件：测试服务启动时","# 子功能：记录","# 执行："+value,"# 验证方式：测试","# 不适用条件：火星环境"])

def _node(neg):
    return {"frontmatter":{"non_applicable_conditions":[neg],"verification_basis":"test"},
            "content":_ccg("室内设备维护")}

def run():
    from md_cg.mdcg import neg_condition_hits as hits, MdCG
    print("== A 组：缺陷面 ==")
    for i, q in enumerate(["现在不是梅雨季节，多久浇水", "并非梅雨季节", "不在梅雨季节", "没有梅雨季节"]):
        _check("A1 否定作用域 " + str(i), not hits(["梅雨季节"],q), q)
    for i,(neg,q) in enumerate([("4G单模终端","４Ｇ单模终端能用吗"),("４Ｇ单模终端","4g单模终端"),("PDF扫描件","pdf扫描件"),("pdf扫描件","ＰＤＦ扫描件")]):
        _check("A2 字符归一 " + str(i), hits([neg],q)==[neg], (neg,q))
    q="无霜风冷冰箱适用这个手动除霜方法吗，还是不适用"
    node=_node("无霜风冷冰箱")
    qual=MdCG.judge_with_boundary(node,q)
    _check("A3 具体边界情境保留 REJECT", qual["qualification"]["state"]=="REJECT" and not qual["qualification"]["boundary_suppressed"],qual)
    _check("A4 边界标记与拒绝分别计数",qual["counts"]["reject"]==1 and qual["counts"]["boundary_hit"]==1,qual)
    print("== K 组：非恒真对照 ==")
    _check("K1 肯定出现仍拒绝",hits(["梅雨季节"],"现在是梅雨季节")==["梅雨季节"])
    _check("K2 否定不跨分句，后续肯定出现仍拒绝",hits(["梅雨季节"],"不是梅雨季节，后来进入梅雨季节")==["梅雨季节"])
    _check("K3 自主题豁免在归一后保持",not hits(["PDF扫描件"],"ＰＤＦ扫描件","pdf扫描件"))
    _check("K4 无关/空值/单字不拒绝",not hits(["梅雨季节","雨", ""],"晴天"))
    _check("K5 条件自身的无字不是否定前缀",hits(["无霜风冷冰箱"],"无霜风冷冰箱能用吗")==["无霜风冷冰箱"])
    generic=MdCG.judge_with_boundary(node,"什么条件下不适用？无霜风冷冰箱")
    _check("K6 询问拒绝域定义仍可展示",generic["qualification"]["state"]!="REJECT" and generic["qualification"]["boundary_suppressed"],generic)
    _check("K7 多词条件仍须全词命中",hits(["4G 终端"],"４ｇ终端")==["4G 终端"] and not hits(["4G 终端"],"4g基站"))
    _check("K8 非边界 query 与基础资格同态",MdCG.judge_with_boundary(node,"无霜风冷冰箱")["qualification"]["state"]==MdCG.judge_qualification(node,"无霜风冷冰箱")["state"])

_MUTATIONS=(
 ("撤销 NFKC", "md_cg/mdcg.py", '    return unicodedata.normalize("NFKC", str(text or "")).casefold()', '    return str(text or "").casefold()', ("A2",)),
 ("撤销 casefold", "md_cg/mdcg.py", '    return unicodedata.normalize("NFKC", str(text or "")).casefold()', '    return unicodedata.normalize("NFKC", str(text or ""))', ("A2",)),
 ("撤销否定作用域", "md_cg/mdcg.py", '            if not (own and item in own) and _neg_asserted(scene_norm, item):', '            if not (own and item in own):', ("A1",)),
 ("边界无差别抑制", "md_cg/mdcg.py", '        if bh["hit"] and bq and boundary_definition:', '        if bh["hit"] and bq:', ("A3","A4")),
 ("过度取消边界定义展示", "md_cg/mdcg.py", '        if bh["hit"] and bq and boundary_definition:', '        if False:', ("K6",)),
)
if __name__=="__main__":
    run()
    if "--mutate" in sys.argv: _mutate()
    sys.exit(bool(FAILS))
