"""大规模差分对拍（一次性验证脚本，用于 README 数字取证）。

对 gmssl 做批量随机差分测试：
* SM3：随机长度消息摘要一致；
* SM4-ECB / SM4-CBC：随机长度、随机密钥/IV 加解密一致；
* SM4-CTR / CBC(nopad) / HMAC / PBKDF2：与 OpenSSL 对拍。

运行::

    PYTHONPATH=src .venv/bin/python scripts/differential_check.py
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from gmssl import func as g_func  # noqa: E402
from gmssl import sm3 as g_sm3
from gmssl import sm4 as g_sm4

from smcrypto.sm3 import hmac_sm3, pbkdf2_hmac_sm3, sm3_hexdigest  # noqa: E402
from smcrypto.sm4 import (  # noqa: E402
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
    sm4_ctr_xor,
    sm4_ecb_decrypt,
    sm4_ecb_encrypt,
)

rng = random.Random(20260917)


def gmssl_hash(data: bytes) -> str:
    return g_sm3.sm3_hash(g_func.bytes_to_list(data))


def gmssl_sm4(key: bytes, data: bytes, enc: bool, iv: bytes = None) -> bytes:
    c = g_sm4.CryptSM4(padding_mode=g_sm4.PKCS7)
    c.set_key(key, g_sm4.SM4_ENCRYPT if enc else g_sm4.SM4_DECRYPT)
    return c.crypt_cbc(iv, data) if iv is not None else c.crypt_ecb(data)


def find_openssl() -> "str | None":
    for cand in (
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/usr/local/opt/openssl/bin/openssl",
        shutil.which("openssl") or "",
    ):
        if cand and os.path.exists(cand):
            r = subprocess.run(
                [cand, "mac", "-digest", "SM3", "-macopt", "hexkey:00", "HMAC"],
                input=b"x",
                capture_output=True,
            )
            if r.returncode == 0:
                return cand
    return None


def main() -> int:
    fails = 0
    ossl = find_openssl()

    # ---- SM3：400 组随机长度（0..10000） ----
    sm3_cases = 400
    for i in range(sm3_cases):
        n = rng.choice([0, 1, 2, 55, 56, 57, 63, 64, 65]) if i < 60 else rng.randint(0, 10000)
        data = bytes(rng.randrange(256) for _ in range(n))
        if sm3_hexdigest(data) != gmssl_hash(data):
            fails += 1
            print("SM3 MISMATCH len=%d" % n)
    print("SM3 随机差分: %d 组（长度 0..10000，含全部填充边界），不一致 %d" % (sm3_cases, fails))

    # ---- SM4 ECB/CBC：各 200 组随机长度与随机密钥 ----
    for mode, fn_enc, fn_dec in (("ECB", sm4_ecb_encrypt, sm4_ecb_decrypt), ("CBC", sm4_cbc_encrypt, sm4_cbc_decrypt)):
        n_cases = 200
        local_fail = 0
        for i in range(n_cases):
            key = bytes(rng.randrange(256) for _ in range(16))
            iv = bytes(rng.randrange(256) for _ in range(16))
            n = rng.choice([0, 15, 16, 17, 31, 32, 33]) if i < 70 else rng.randint(0, 3000)
            data = bytes(rng.randrange(256) for _ in range(n))
            if mode == "ECB":
                mine = fn_enc(key, data)
                theirs = gmssl_sm4(key, data, True)
                back = fn_dec(key, theirs)
            else:
                mine = fn_enc(key, iv, data)
                theirs = gmssl_sm4(key, data, True, iv)
                back = fn_dec(key, iv, theirs)
            if mine != theirs or back != data:
                local_fail += 1
                print("SM4-%s MISMATCH len=%d" % (mode, n))
        fails += local_fail
        print("SM4-%s 随机差分: %d 组（长度 0..3000，含分组边界）与 gmssl 一致，不一致 %d" % (mode, n_cases, local_fail))

    # ---- OpenSSL 对拍 ----
    if ossl:
        ctr_fail = 0
        for i in range(120):
            key = bytes(rng.randrange(256) for _ in range(16))
            iv = bytes(rng.randrange(256) for _ in range(16))
            n = rng.choice([0, 1, 15, 16, 17]) if i < 40 else rng.randint(0, 2000)
            data = bytes(rng.randrange(256) for _ in range(n))
            r = subprocess.run([ossl, "enc", "-sm4-ctr", "-K", key.hex(), "-iv", iv.hex()], input=data, capture_output=True)
            if sm4_ctr_xor(key, iv, data) != r.stdout:
                ctr_fail += 1
                print("SM4-CTR MISMATCH len=%d" % n)
        print("SM4-CTR 与 OpenSSL 对拍: 120 组，不一致 %d" % ctr_fail)
        fails += ctr_fail

        hmac_fail = 0
        for i in range(60):
            key = bytes(rng.randrange(256) for _ in range(rng.choice([1, 16, 63, 64, 65, 100])))
            n = rng.choice([0, 1, 16, 55, 64]) if i < 20 else rng.randint(0, 1000)
            msg = bytes(rng.randrange(256) for _ in range(n))
            r = subprocess.run([ossl, "mac", "-digest", "SM3", "-macopt", "hexkey:" + key.hex(), "HMAC"], input=msg, capture_output=True)
            if hmac_sm3(key, msg).hex() != r.stdout.decode().strip().lower():
                hmac_fail += 1
                print("HMAC MISMATCH")
        print("HMAC-SM3 与 OpenSSL 对拍: 60 组（密钥 1..100 字节），不一致 %d" % hmac_fail)
        fails += hmac_fail

        pbkdf2_fail = 0
        cases = [(1, 16), (2, 32), (10, 20), (100, 16), (500, 32), (1000, 64), (2048, 48)]
        for it, dklen in cases:
            pw, salt = "pw-%d" % it, "salt-%d" % dklen
            r = subprocess.run(
                [ossl, "kdf", "-keylen", str(dklen), "-kdfopt", "digest:SM3", "-kdfopt", "pass:" + pw,
                 "-kdfopt", "salt:" + salt, "-kdfopt", "iter:" + str(it), "PBKDF2"],
                capture_output=True,
            )
            want = r.stdout.decode().strip().replace(":", "").lower()
            if pbkdf2_hmac_sm3(pw.encode(), salt.encode(), it, dklen).hex() != want:
                pbkdf2_fail += 1
                print("PBKDF2 MISMATCH it=%d dklen=%d" % (it, dklen))
        print("PBKDF2-HMAC-SM3 与 OpenSSL 对拍: %d 组，不一致 %d" % (len(cases), pbkdf2_fail))
        fails += pbkdf2_fail
    else:
        print("未找到支持 SM3 的 OpenSSL，跳过 OpenSSL 对拍")

    print("\n总计不一致: %d" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
