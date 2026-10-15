# -*- coding: utf-8 -*-
# 功能名：缺省 lexical 的 IDF 与 Python/Rust parity（issue #363）
# 生效条件：python -X utf8 -m md_cg.test_issue363_lexical_idf [--mutate]；独立临时库，失败退出 1。
# 子功能：A 组=4 项稀有词/分数/双侧 parity 判据；K 组=5 项公共词/空查询/分数/jaccard/低层对照。
# 执行：--mutate 在镜像目录逐项单行变异、清 __pycache__，每条校验指定断言转红。
# 验证方式：原镜像全绿，2/2 条变异均按指定判据转红；CRLF 用 universal newline 读取。
# 不适用条件：完整性能/平台覆盖与剩余边界见对应 PR 正文；本守卫不替代全量回归。
"""issue #363 守卫：A 组缺陷面 / K 组非恒真对照 / --mutate 镜像定点变异。
用法：python -X utf8 -m md_cg.test_issue363_lexical_idf [--mutate]
"""
MODULE = "md_cg.test_issue363_lexical_idf"

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

def _rust(root,queries):
    exe=_REPO/"rust/target/release/mdcg-eval.exe"
    if os.name!="nt": exe=exe.with_suffix("")
    build=subprocess.run(["cargo","build","--release","--manifest-path",str(_REPO/"rust/Cargo.toml")],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=180)
    if build.returncode: raise RuntimeError(build.stderr[-1000:])
    from scripts import rank_parity as parity
    proc,mode=parity.rust_open(str(exe),str(root/"brain"),"legacy")
    try: return parity.rust_topk(proc,queries)
    finally: parity._close_proc(proc)

def run():
    from md_cg.mdcos import MdCGOS
    from md_cg import mdcg
    root=Path(tempfile.mkdtemp(prefix="iss363_"))
    _environment(root)
    # 固定关闭时间乘子：此守卫只判 IDF，时间效应由 test_p4_freshness 判。
    os.environ["MDCG_FRESHNESS"]="0"
    os.environ["MDCG_UNIFY_QUERY"]="0"
    mdcg.SCORE_MODE="legacy"
    try:
        cg=MdCGOS(str(root/"brain"),autoflush=1)
        cg.add("a_generic","这是什么",verification_basis="test")
        cg.add("z_rare","珍稀矿石",verification_basis="test")
        for i in range(8): cg.add("background_%d"%i,"这是什么，普通记录",verification_basis="test")
        cg.flush()
        q="这是什么珍稀矿石"
        queries=[q,"这是什么","珍稀矿石","完全无关"]
        def top(query):
            rows,_=cg.search_rrf(query,k=5,paths=("lexical",),judge=False,record=False)
            return [(r["id"],s) for r,s,*_ in rows]
        py={query:top(query) for query in queries}
        print("== A 组：稀有词证据须胜过自然问句公共词 ==")
        _check("A1 Python 缺省 lexical 稀有词居首",py[q] and py[q][0][0]=="z_rare",py[q])
        # 改 id 字典序也不应把同一公共词证据排在前面。
        qb=mdcg.bigrams(mdcg.normalize_en(q))
        docs=cg._lexical(q,cg._candidates(),{"scanned":0})
        scores={d["id"]:s for d,s in docs}
        _check("A2 IDF 打破实际分数并列",scores["z_rare"]>scores["a_generic"],scores)
        rs=_rust(root,queries)
        _check("A3 Py/Rust legacy 逐位 parity",all(py[x]==rs[x] for x in queries),(py,rs))
        _check("A4 Rust 同样把稀有词排首",rs[q] and rs[q][0][0]=="z_rare",rs[q])
        print("== K 组：非恒真对照 ==")
        _check("K1 公共词独立查询仍有召回",py["这是什么"] and py["这是什么"][0][0]=="a_generic",py["这是什么"])
        _check("K2 缺省分数仍有界",all(0<=s<=1 for s in scores.values()),scores)
        _check("K3 空查询不召回",not top(""))
        _check("K4 显式 jaccard 不使用 IDF",mdcg.lexical_sim({"a","b"},{"a"},"jaccard",idf={"a":10,"b":1})==.5)
        _check("K5 无 IDF 的低层公式保留",mdcg.lexical_sim({"a","b"},{"a"},"legacy")==.5)
        cg.close()
    finally: shutil.rmtree(root,ignore_errors=True)

_MUTATIONS=(
 ("Python IDF 接线脱焊", "md_cg/mdcos.py", '        scored = self._score(hits, query, qb, idf=idf)', '        scored = self._score(hits, query, qb)', ("A1","A2","A3")),
 ("Rust 回到无 IDF 覆盖率", "rust/src/retrieval.rs", '            if idf_total > 0.0 { matched / idf_total } else { 0.0 }', '            cap_hit as f64 / qbl', ("A3","A4")),
)
if __name__=="__main__":
    try: run()
    except Exception as e: _check("A3 Rust 必须实编实跑",False,repr(e))
    if "--mutate" in sys.argv: _mutate()
    sys.exit(bool(FAILS))
