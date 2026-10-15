# -*- coding: utf-8 -*-
# 功能名：跨进程同 id 写事务（issue #322）
# 生效条件：python -X utf8 -m md_cg.test_issue322_node_write_lock [--mutate]；独立临时库，失败退出 1。
# 子功能：A 组=5 项竞态/超时判据；K 组=5 项顺序写/锁键/重入对照。
# 执行：--mutate 在镜像目录逐项单行变异、清 __pycache__，每条校验指定断言转红。
# 验证方式：原镜像全绿，4/4 条变异均按指定判据转红；CRLF 用 universal newline 读取。
# 不适用条件：完整性能/平台覆盖与剩余边界见对应 PR 正文；本守卫不替代全量回归。
"""issue #322 守卫：A 组缺陷面 / K 组非恒真对照 / --mutate 镜像定点变异。
用法：python -X utf8 -m md_cg.test_issue322_node_write_lock [--mutate]
"""
MODULE = "md_cg.test_issue322_node_write_lock"

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

def _worker(root,nid,layer,hold,entry):
    from md_cg import mcp_server as ms, writepipe
    cg=_cg(root)
    slot="holder" if hold else "contender"
    (root/(slot+"_ready")).touch()
    until=time.monotonic()+20
    while not (root/(slot+"_go")).exists():
        if time.monotonic()>until: raise TimeoutError("worker go")
        time.sleep(.01)
    if hold:
        original=writepipe._executor
        def pause(ctx):
            (root/"inside").touch()
            until=time.monotonic()+20
            while not (root/"release").exists():
                if time.monotonic()>until: raise TimeoutError("worker release")
                time.sleep(.01)
            return original(ctx)
        writepipe._executor=pause
        if entry=="gated":
            original_write=cg._write_node
            def pause_write(*args,**kw):
                (root/"inside").touch()
                until=time.monotonic()+20
                while not (root/"release").exists():
                    if time.monotonic()>until: raise TimeoutError("gated release")
                    time.sleep(.01)
                return original_write(*args,**kw)
            cg._write_node=pause_write
    try:
        args={"op":"write","node_id":nid,"content":_ccg("holder" if hold else "contender"),"content_kind":"text","layer":layer,"verification_basis":"test"}
        if entry=="gated":
            args.update(gated=True,consistency=False)
            r=ms._dispatch(cg,"mdcg_remember",args)
            r["committed"]=r.get("verdict")=="ACCEPT"
        else:
            r=ms._dispatch(cg,"cg",args)
    except Exception as e:
        r={"error":type(e).__name__+":"+str(e)}
    print(json.dumps(r,ensure_ascii=False),flush=True)
    cg.close()

def _wait(path):
    until=time.monotonic()+20
    while not path.exists():
        if time.monotonic()>until: raise TimeoutError(str(path))
        time.sleep(.01)

def _race(layer="knowledge",case=False,entry="write"):
    root=Path(tempfile.mkdtemp(prefix="iss322_"))
    processes=[]
    try:
        ids=("SameId","sameid") if case else ("same","same")
        # 两个 worker 在第一笔写入前都完成初始化，避免启动重扫替我们刷新陈旧索引。
        for i,nid in enumerate(ids):
            p=subprocess.Popen([sys.executable,"-X","utf8","-m",MODULE,"--worker",str(root),nid,layer if i==0 else "knowledge",str(i==0),entry],cwd=_REPO,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8",env=dict(os.environ,PYTHONPATH=str(_REPO)))
            processes.append(p)
            _wait(root/(("holder" if i==0 else "contender")+"_ready"))
        (root/"holder_go").touch()
        _wait(root/"inside")
        (root/"contender_go").touch()
        time.sleep(.3)
        blocked=processes[1].poll() is None
        (root/"release").touch()
        result=[]
        for p in processes:
            out,err=p.communicate(timeout=25)
            result.append(json.loads(out.splitlines()[-1]) if p.returncode==0 else {"worker_error":err[-300:]})
        return blocked,result
    finally:
        for p in processes:
            if p.poll() is None: p.kill();p.wait()
        shutil.rmtree(root,ignore_errors=True)

def run():
    print("== A 组：定序跨进程竞态 ==")
    blocked,r=_race()
    _check("A1 存在性判定到落盘串行，后写进审核",blocked and r[0].get("committed") is True and r[1].get("committed") is False and r[1].get("moved_to")=="review_queue",r)
    blocked,r=_race("anchor")
    _check("A2 anchor 先写，跨层后写必须拒绝",blocked and r[0].get("committed") is True and "ProtectionError" in str(r[1]),r)
    blocked,r=_race("anchor",True)
    _check("A3 casefold 同锁，大小写别名拒绝",blocked and r[0].get("committed") is True and "ValueError" in str(r[1]),r)
    blocked,r=_race(entry="gated")
    _check("A5 gated 入口的判既有与落盘也共锁",blocked and r[0].get("committed") is True and r[1].get("committed") is False and r[1].get("moved_to")=="review_queue",r)
    from md_cg import nodewrite
    from md_cg.fsutil import FileLock
    from unittest.mock import patch
    root=Path(tempfile.mkdtemp(prefix="iss322_control_"))
    try:
        cg=_cg(root)
        path=nodewrite.lock_path(cg,"Strict")
        real=FileLock
        def quick(p,**kw): return real(p,timeout=.03,poll=.005,**kw)
        caught=False
        with real(path,strict=True):
            with patch.object(nodewrite,"FileLock",quick):
                try:
                    with nodewrite.transaction(cg,"strict"): pass
                except TimeoutError: caught=True
        _check("A4 锁超时必须 fail-closed",caught)
        from md_cg import mcp_server as ms
        a={"op":"write","node_id":"serial","content":_ccg("初稿"),"content_kind":"text","verification_basis":"test","layer":"knowledge"}
        first=ms._dispatch(cg,"cg",a)
        second=ms._dispatch(cg,"cg",dict(a,content=_ccg("后稿")))
        print("== K 组：非恒真对照 ==")
        _check("K1 单进程顺序写仍新增+待审",first.get("committed") is True and second.get("committed") is False and second.get("moved_to")=="review_queue",(first,second))
        _check("K2 待审不覆盖原正文","初稿" in cg.get("serial")["content"])
        _check("K3 不同 id 不共锁",nodewrite.lock_path(cg,"a")!=nodewrite.lock_path(cg,"b"))
        _check("K4 同 casefold id 共锁",nodewrite.lock_path(cg,"User_ID")==nodewrite.lock_path(cg,"user_id"))
        with nodewrite.transaction(cg,"nested"):
            with nodewrite.transaction(cg,"NESTED"):
                nested=True
        _check("K5 同线程嵌套不自锁",nested)
        cg.close()
    finally: shutil.rmtree(root,ignore_errors=True)

_MUTATIONS=(
 ("gated 事务脱焊", "md_cg/mdcos.py", '    @nodewrite.gated_transaction', '    # gated 事务脱焊', ("A5",)),
 ("写链临界区脱焊", "md_cg/writepipe.py", '        with transaction(cg, _nid):', '        if True:', ("A1","A2")),
 ("锁 key 不 casefold", "md_cg/nodewrite.py", '    key = hashlib.sha256(node_id.casefold().encode("utf-8")).hexdigest()', '    key = hashlib.sha256(node_id.encode("utf-8")).hexdigest()', ("A3","K4")),
 ("锁超时放行", "md_cg/nodewrite.py", '    with FileLock(path, strict=True):', '    with FileLock(path, strict=False):', ("A4",)),
)
if __name__=="__main__":
    if "--worker" in sys.argv:
        _worker(Path(sys.argv[2]),sys.argv[3],sys.argv[4],sys.argv[5]=="True",sys.argv[6])
    else:
        try: run()
        except Exception as e: _check("A1 进程竞态正常完成",False,repr(e))
        if "--mutate" in sys.argv: _mutate()
        sys.exit(bool(FAILS))
