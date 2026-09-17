"""一次性验证脚本：SM4 标准 100 万次迭代向量（GB/T 32907-2016 附录 A.2）。

运行::

    PYTHONPATH=src .venv/bin/python scripts/check_sm4_1m.py

预计耗时约 25 秒（纯 Python）。结果写入 stdout，用于 README 与 self-test --full。
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from smcrypto.sm4 import SM4  # noqa: E402

EXPECTED = "595298c7c6fd271f0402f804c33d3f66"


def main() -> int:
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    c = SM4(key)
    blk = key
    t0 = time.time()
    for _ in range(1_000_000):
        blk = c.encrypt_block(blk)
    dt = time.time() - t0
    print("SM4 1M-iteration result:", blk.hex())
    print("expected (GB/T 32907-2016 附录 A.2):", EXPECTED)
    print("耗时: %.1f s" % dt)
    ok = blk.hex() == EXPECTED
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
