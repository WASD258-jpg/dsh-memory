# -*- coding: utf-8 -*-
# 功能名：一致性降级正文入队与明确回执（issue #361）
# 生效条件：python -X utf8 -m md_cg.test_issue361_blindspot_queue [--mutate]；独立临时库，失败退出 1。
# 子功能：A 组=7 项裁决/入队/回执判据；K 组=3 项放行/元数据/低层契约对照。
# 执行：--mutate 在镜像目录逐项单行变异、清 __pycache__，每条校验指定断言转红。
# 验证方式：原镜像全绿，3/3 条变异均按指定判据转红；CRLF 用 universal newline 读取。
# 不适用条件：完整性能/平台覆盖与剩余边界见对应 PR 正文；本守卫不替代全量回归。
"""issue #361 守卫：A 组缺陷面 / K 组非恒真对照 / --mutate 镜像定点变异。
用法：python -X utf8 -m md_cg.test_issue361_blindspot_queue [--mutate]
"""
MODULE = "md_cg.test_issue361_blindspot_queue"

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

def run():
    from md_cg import mcp_server as ms, consistency
    from unittest.mock import patch
    root=Path(tempfile.mkdtemp(prefix="iss361_"))
    try:
        cg=_cg(root)
        print("== A 组：真实 BLINDSPOT 不得无去向 ==")
        content=_ccg("独立六要素正文 361")
        args={"node_id":"first","content":content,"gated":True,"verification_basis":"test","tags":["保留标签"]}
        r=ms._dispatch(cg,"mdcg_remember",args)
        _check("A1 真实空库一致性降级可见",r.get("verdict")=="DEFER" and r.get("conflict",{}).get("verdict")=="BLINDSPOT",r)
        _check("A2 正文进入既有队列且给出句柄",bool(r.get("proposed")) and content in cg.inbox_log.read_text(encoding="utf-8") if isinstance(cg.inbox_log,Path) else bool(r.get("proposed")) and content in "".join(x.get("content","") for x in __import__("md_cg.fsutil",fromlist=["read_jsonl"]).read_jsonl(cg.inbox_log)),r)
        _check("A3 明确未提交和去向",r.get("ok") is False and r.get("committed") is False and r.get("moved_to")=="review_queue" and r.get("status")=="pending_review",r)
        _check("A4 原因和操作指引",bool(r.get("reason")) and bool(r.get("hint")) and "既有节点均未声明条件" in r.get("reason",""),r)
        _check("A5 一致性裁决不因入队而放行",cg.get("first") is None,r)
        from md_cg.fsutil import read_jsonl
        rows=list(read_jsonl(cg.inbox_log))
        rec=next(x for x in rows if x.get("content")==content)
        _check("A6 入队保留调用声明",rec.get("tags")==["保留标签"] and (rec.get("extra") or {}).get("verification_basis")=="test",rec)
        again=ms._dispatch(cg,"mdcg_remember",args)
        _check("A7 重试幂等，不增加正文副本",again.get("proposed")==r.get("proposed") and len(list(read_jsonl(cg.inbox_log)))==len(rows),again)
        print("== K 组：非恒真对照 ==")
        bypass=ms._dispatch(cg,"mdcg_remember",dict(args,node_id="bypass",content=_ccg("不同内容 361"),consistency=False))
        _check("K1 consistency=False 正常落盘",bypass.get("verdict")=="ACCEPT" and bool(bypass.get("written")) and not bypass.get("proposed"),bypass)
        _check("K2 内部裁决槽不得污染 frontmatter","_consistency_result" not in (cg.get("bypass") or {}).get("frontmatter",{}))
        direct=cg.add("low_level",_ccg("低层对照"),consistency=True,on_conflict="defer")
        # 低层有显式条件时 verdict 可不同，固定 BLINDSPOT 检查历史 None 契约。
        vd={"verdict":"BLINDSPOT","reason":"对照缺可比条件","conflicts":[],"conflict_strength":0}
        with patch.object(consistency,"check",return_value=vd):
            low=cg.add("none_contract",content,consistency=True,on_conflict="defer")
        _check("K3 低层 defer 仍返回 None",low is None and cg.get("none_contract") is None)
        cg.close()
    finally:
        shutil.rmtree(root,ignore_errors=True)

_MUTATIONS=(
 ("裁决回传断线", "md_cg/mdcg.py", '                _consistency_result.update(vd)', '                pass', ("A1","A4")),
 ("队列写入断线", "md_cg/mdcos.py", '                    out["proposed"] = self.propose(node_id, content, layer=layer, **kw,', '                    out["proposed"] = (lambda *a, **k: None)(node_id, content, layer=layer, **kw,', ("A2",)),
 ("错误返回 ok", "md_cg/mdcos.py", '                    out.update(ok=False, committed=False, status="pending_review",', '                    out.update(ok=True, committed=True, status="pending_review",', ("A3",)),
)
if __name__=="__main__":
    try: run()
    except Exception as e:
        _check("A2 队列可回读",False,repr(e))
    if "--mutate" in sys.argv: _mutate()
    sys.exit(bool(FAILS))
