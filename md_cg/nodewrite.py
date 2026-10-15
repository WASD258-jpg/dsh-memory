# -*- coding: utf-8 -*-
"""同 id 写事务：资格判定、正文与索引发布共用跨进程临界区（#322）。"""
import hashlib
import os
import threading
from contextlib import contextmanager
from functools import wraps

from .fsutil import FileLock

_ACTIVE = threading.local()


# 生效条件：node_id 为字符串时返回与 #350 相同 casefold 口径的固定长锁路径；非法类型交既有入参闸处理。
def lock_path(cg, node_id):
    key = hashlib.sha256(node_id.casefold().encode("utf-8")).hexdigest()
    return os.path.join(cg.root, "_node_write_locks", key)


# 生效条件：同线程同 root/id 的嵌套事务复用外层锁；否则 strict 获锁后刷新索引，执行事务，成功后 flush 再解锁；异常原样外抛。
@contextmanager
def transaction(cg, node_id):
    if not isinstance(node_id, str):
        yield
        return
    path = os.path.normcase(os.path.realpath(lock_path(cg, node_id)))
    held = getattr(_ACTIVE, "held", None)
    if held is None:
        held = _ACTIVE.held = set()
    if path in held:
        yield
        return
    with FileLock(path, strict=True):
        held.add(path)
        try:
            cg._maybe_reload_index()
            yield
            cg.flush()
        finally:
            held.remove(path)


# 生效条件：被装饰的高层 gated 写入入口须显式接收 node_id/content；所有裁决与落盘均在同 id 事务中执行。
def gated_transaction(fn):
    @wraps(fn)
    def locked(self, node_id, content, *args, **kw):
        with transaction(self, node_id):
            return fn(self, node_id, content, *args, **kw)
    return locked
