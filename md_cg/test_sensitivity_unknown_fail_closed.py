# -*- coding: utf-8 -*-
"""test_sensitivity_unknown_fail_closed · 漏传密级 fail-closed 守卫（安全重构 P2）

# 功能名：merge_downgrades 未知 incoming 密级按最高档
# 生效条件：改动 security.merge_downgrades，或任一合并落盘点（writelimit.converge_into /
#           forgetting.reinforce / writelimit 整理聚合）的密级取值方式之后必跑
# 子功能：①单点语义（incoming 未知=最高档；target 未知=缺省档）②CONVERGE 漏传密级 ⇒ 拒且不落盘
#         ③MERGE 漏传密级 ⇒ 拒且不落盘 ④secret 目标不误伤 ⑤已落盘节点缺字段按缺省档（不误伤整理）
#         ⑥定点变异：判据回到「None 按 internal」⇒ ②③必须转红
# 执行：python -X utf8 -m md_cg.test_sensitivity_unknown_fail_closed
# 验证方式：末行「通过 N / 失败 M」
# 不适用条件：不测调用方是否**正确**传密级（各 issue 守卫负责）；只测「漏传时不放行」这一兜底

## 病象
#313 #315 #345：调用方漏传 sensitivity ⇒ merge_downgrades(target, None) 把 None 按 internal 算
⇒ 判据放行 ⇒ private 明文并入 internal 节点。每次都只在出事的那条路径补传。
修法（使用者 2026-10-15 裁定）：判据层兜底——incoming 未知一律按最高档。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from md_cg import forgetting, security, writelimit          # noqa: E402
from md_cg.mdcos import MdCGSecure                          # noqa: E402
from md_cg.security import Principal, merge_downgrades      # noqa: E402

FAILS = []
PASSES = []
A = "# 功能名：批次1收官记忆\n\n内部内容 AAAA"
B = "# 功能名：批次2收官记忆\n\n来源密级未声明 UNKNOWN-BBBB"


def check(name, cond, detail=""):
    (PASSES if cond else FAILS).append(name)
    print("  [%s] %s%s" % ("PASS" if cond else "FAIL", name,
                           ("  · " + str(detail)) if (detail and not cond) else ""))


class _Box:
    def __init__(self, tag):
        self.tag = tag

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="p2fc_%s_" % self.tag)
        self._env = {k: os.environ.get(k) for k in ("MDCG_ROOT", "MDCG_AUX_ROOT", "MDCG_MASTER_KEY")}
        os.environ["MDCG_ROOT"] = os.path.join(self.dir, "cgroot")
        os.environ["MDCG_AUX_ROOT"] = os.path.join(self.dir, "auxstore")
        os.environ.setdefault("MDCG_MASTER_KEY", "00" * 32)
        os.makedirs(os.environ["MDCG_AUX_ROOT"], exist_ok=True)
        return os.environ["MDCG_ROOT"]

    def __exit__(self, *exc):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def _owner(root):
    return MdCGSecure(root, principal=Principal(
        actor="owner", clearance="secret", can_write=True, can_admin=True,
        role="designer", session="s1"))


def _run(path, target_sens, monkey=None):
    """在一次性沙箱里把 B 以**未传密级**的方式并入 target_sens 档节点，返回读数。"""
    saved = security.merge_downgrades
    if monkey is not None:
        security.merge_downgrades = monkey
    try:
        with _Box(path) as root:
            cg = _owner(root)
            cg.add("n1", A, layer="contextual", sensitivity=target_sens)
            if path == "converge":
                res = writelimit.converge_into(cg, "n1", B, actor="owner")
            else:
                res = forgetting.reinforce(cg, "n1", actor="owner", content=B)
            node = cg.get("n1") or {}
            out = {"ok": (res or {}).get("ok"), "error": (res or {}).get("error"),
                   "written": "UNKNOWN-BBBB" in (node.get("content") or "")}
            cg.close()
            return out
    finally:
        security.merge_downgrades = saved


def _old_semantics(t, i):
    """变异：回到 P2 之前的「None 按 internal」。"""
    try:
        return security._rank(i or security.DEFAULT_SENSITIVITY) \
            > security._rank(t or security.DEFAULT_SENSITIVITY)
    except security.AccessDenied:
        return True


def main():
    print("=== 安全重构 P2：漏传密级 fail-closed ===")
    print("\n[1] 单点语义")
    check("U1 incoming None/空串 ⇒ 按最高档",
          merge_downgrades("internal", None) is True and merge_downgrades("restricted", "") is True
          and merge_downgrades("private", None) is True and merge_downgrades("secret", None) is False)
    check("U2 target None ⇒ 按缺省档（internal）",
          merge_downgrades(None, "internal") is False and merge_downgrades(None, "restricted") is True)
    check("U3 node_effective_sensitivity：缺字段=缺省档，有值原样",
          security.node_effective_sensitivity({}) == security.DEFAULT_SENSITIVITY
          and security.node_effective_sensitivity(None) == security.DEFAULT_SENSITIVITY
          and security.node_effective_sensitivity({"sensitivity": "private"}) == "private")

    check("U4 写入入口未声明=缺省档，且并入 public 目标仍被拒（显式化不放宽）",
          security.declared_write_sensitivity(None) == security.DEFAULT_SENSITIVITY
          and security.declared_write_sensitivity("private") == "private"
          and merge_downgrades("public", security.declared_write_sensitivity(None)) is True)

    print("\n[2] 落盘点：漏传密级并入 internal 节点 ⇒ 拒且不落盘")
    for path in ("converge", "reinforce"):
        r = _run(path, "internal")
        check("F-%s 漏传密级 ⇒ merge_downgrade_refused 且未落盘" % path,
              r["error"] == "merge_downgrade_refused" and r["written"] is False, r)

    print("\n[3] 不误伤：secret 目标接收未知来源照旧放行")
    for path in ("converge", "reinforce"):
        r = _run(path, "secret")
        check("N-%s secret 目标不拒" % path, r["error"] != "merge_downgrade_refused", r)

    print("\n[4] 定点变异：判据回到「None 按 internal」⇒ 泄漏复现（守卫可鉴别）")
    for path in ("converge", "reinforce"):
        r = _run(path, "internal", monkey=_old_semantics)
        check("M-%s 旧语义下漏传密级被放行并落盘（证明 [2] 可鉴别）" % path,
              r["error"] != "merge_downgrade_refused" and r["written"] is True, r)

    print("\n通过 %d / 失败 %d" % (len(PASSES), len(FAILS)))
    if FAILS:
        print("失败项：" + "、".join(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
