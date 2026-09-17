"""与 gmssl（duanhongyi 纯 Python 实现）的**在线**交叉验证测试。

* 未安装 gmssl 时整体 skip（不影响零依赖测试流程）；
* 安装方式：``uv pip install --python .venv/bin/python gmssl``（或 ``pip install gmssl``）；
* 运行方式（默认 discover 的 pattern 为 test*.py，本文件需显式指定）::

      python -m unittest discover -s tests -p "interop_gmssl.py" -v

覆盖范围：

* SM3 摘要一致（多种长度，含填充边界）；
* SM4 ECB / CBC 密文一致（双方加解密互通）；
* SM2：我方签名可被 gmssl 验签、gmssl 签名可被我方验签（含 DER）；
* SM2：我方加密 ↔ gmssl 解密、gmssl 加密 ↔ 我方解密（C1C3C2 / C1C2C3 两种排列）；
* 附加：若本机存在支持 SM3 的 OpenSSL（如 Homebrew openssl@3），
  再对 SM4-CTR / HMAC-SM3 / PBKDF2-HMAC-SM3 做一次独立对拍。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from smcrypto.sm2 import (  # noqa: E402
    compute_za,
    generate_keypair,
    sm2_decrypt,
    sm2_encrypt,
    sm2_sign,
    sm2_sign_der,
    sm2_verify,
    sm2_verify_der,
)
from smcrypto.sm3 import hmac_sm3, pbkdf2_hmac_sm3, sm3_hexdigest, sm3_kdf  # noqa: E402
from smcrypto.sm4 import (  # noqa: E402
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
    sm4_ctr_xor,
    sm4_ecb_decrypt,
    sm4_ecb_encrypt,
)

try:
    import gmssl  # noqa: F401
    from gmssl import func as g_func
    from gmssl import sm2 as g_sm2
    from gmssl import sm3 as g_sm3
    from gmssl import sm4 as g_sm4

    HAVE_GMSSL = True
except ImportError:  # pragma: no cover - 取决于运行环境
    HAVE_GMSSL = False

IDA_DEFAULT = b"1234567812345678"


def _gmssl_hash(data: bytes) -> str:
    return g_sm3.sm3_hash(g_func.bytes_to_list(data))


def _gmssl_sm4_ecb(key: bytes, data: bytes, encrypt: bool) -> bytes:
    c = g_sm4.CryptSM4(padding_mode=g_sm4.PKCS7)
    c.set_key(key, g_sm4.SM4_ENCRYPT if encrypt else g_sm4.SM4_DECRYPT)
    return c.crypt_ecb(data)


def _gmssl_sm4_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    c = g_sm4.CryptSM4(padding_mode=g_sm4.PKCS7)
    c.set_key(key, g_sm4.SM4_ENCRYPT if encrypt else g_sm4.SM4_DECRYPT)
    return c.crypt_cbc(iv, data)


def _gmssl_crypt2(priv_hex: str, pub_hex: str, mode: int, asn1: bool = False):
    return g_sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=mode, asn1=asn1)


@unittest.skipUnless(HAVE_GMSSL, "需要 gmssl：uv pip install --python .venv/bin/python gmssl")
class GmsslInteropBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.d, cls.pub = generate_keypair()
        cls.priv_hex = "%064x" % cls.d
        cls.pub_xy = "%064x%064x" % (cls.pub.x, cls.pub.y)


class TestSm3Interop(GmsslInteropBase):
    def test_digests_match(self) -> None:
        sizes = [0, 1, 55, 56, 57, 63, 64, 65, 100, 511, 512, 513, 4096]
        for size in sizes:
            data = bytes((i * 13 + size) % 256 for i in range(size))
            with self.subTest(size=size):
                self.assertEqual(sm3_hexdigest(data), _gmssl_hash(data))

    def test_kdf_match(self) -> None:
        z = bytes(range(32))
        for klen_bytes in (16, 32, 48):
            with self.subTest(klen=klen_bytes):
                t_mine = sm3_kdf(z, klen_bytes)
                # gmssl 的 KDF 接口以 hex 字符串为输入、以字节为长度
                t_gmssl = bytes.fromhex(g_sm3.sm3_kdf(z.hex().encode("utf8"), klen_bytes))
                self.assertEqual(t_mine, t_gmssl)


class TestSm4Interop(GmsslInteropBase):
    def test_ecb_encrypt_matches(self) -> None:
        key = bytes(range(16))
        for size in (0, 1, 15, 16, 17, 31, 32, 100):
            data = bytes((i * 7 + 1) % 256 for i in range(size))
            with self.subTest(size=size):
                self.assertEqual(sm4_ecb_encrypt(key, data), _gmssl_sm4_ecb(key, data, True))

    def test_ecb_decrypt_matches(self) -> None:
        key = bytes(range(16, 32))
        for size in (16, 17, 64):
            ct = _gmssl_sm4_ecb(key, bytes(size), True)
            with self.subTest(size=size):
                self.assertEqual(sm4_ecb_decrypt(key, ct), bytes(size))
                self.assertEqual(bytes(size), _gmssl_sm4_ecb(key, sm4_ecb_encrypt(key, bytes(size)), False))

    def test_cbc_mutual(self) -> None:
        key, iv = bytes(range(16)), bytes(range(16, 32))
        for size in (0, 1, 16, 17, 64, 257):
            data = bytes((i * 11 + 3) % 256 for i in range(size))
            with self.subTest(size=size):
                self.assertEqual(sm4_cbc_encrypt(key, iv, data), _gmssl_sm4_cbc(key, iv, data, True))
                self.assertEqual(sm4_cbc_decrypt(key, iv, _gmssl_sm4_cbc(key, iv, data, True)), data)
                self.assertEqual(_gmssl_sm4_cbc(key, iv, sm4_cbc_encrypt(key, iv, data), False), data)


class TestSm2Interop(GmsslInteropBase):
    def test_za_and_digest_e_match_gmssl(self) -> None:
        # 1) Z_A：按 GM/T 0003.2 定义用 gmssl 的 SM3 逐段拼接计算，与本实现一致
        za_gmssl = g_sm3.sm3_hash(
            g_func.bytes_to_list(
                bytes.fromhex(
                    "0080"
                    + "31323334353637383132333435363738"  # ID_A = '1234567812345678'
                    + g_sm2.default_ecc_table["a"]
                    + g_sm2.default_ecc_table["b"]
                    + g_sm2.default_ecc_table["g"]
                    + self.pub_xy
                )
            )
        )
        self.assertEqual(compute_za(self.pub, IDA_DEFAULT).hex(), za_gmssl)
        # 2) 待签名杂凑 e = SM3(Z_A || M)：gmssl 的 _sm3_z(M) 即其 hex 值
        g = _gmssl_crypt2(self.priv_hex, self.pub_xy, mode=1)
        for msg in (b"", b"probe", bytes(range(64))):
            with self.subTest(msg_len=len(msg)):
                e_mine = sm3_hexdigest(compute_za(self.pub, IDA_DEFAULT) + msg)
                self.assertEqual(e_mine, g._sm3_z(msg))

    def test_my_signature_verified_by_gmssl(self) -> None:
        g = _gmssl_crypt2(self.priv_hex, self.pub_xy, mode=1)
        for msg in (b"", b"hello gmssl", b"x" * 200):
            r, s = sm2_sign(self.d, msg)
            sig_hex = "%064x%064x" % (r, s)
            with self.subTest(msg_len=len(msg)):
                self.assertTrue(g.verify_with_sm3(sig_hex, msg), "gmssl 应接受本实现的签名")

    def test_gmssl_signature_verified_by_me(self) -> None:
        g = _gmssl_crypt2(self.priv_hex, self.pub_xy, mode=1)
        for msg in (b"", b"hello toolbox", b"y" * 300):
            sig = g.sign_with_sm3(msg)
            r, s = int(sig[:64], 16), int(sig[64:], 16)
            with self.subTest(msg_len=len(msg)):
                self.assertTrue(sm2_verify(self.pub, msg, r, s), "本实现应接受 gmssl 的签名")

    def test_der_signatures_mutual(self) -> None:
        g_der = _gmssl_crypt2(self.priv_hex, self.pub_xy, mode=1, asn1=True)
        msg = b"der interop"
        # 我方 DER -> gmssl 验签
        my_der = sm2_sign_der(self.d, msg)
        self.assertTrue(g_der.verify_with_sm3(my_der.hex(), msg))
        # gmssl DER -> 我方验签
        gm_der = bytes.fromhex(g_der.sign_with_sm3(msg))
        self.assertTrue(sm2_verify_der(self.pub, msg, gm_der))

    def test_encrypt_decrypt_mutual_both_modes(self) -> None:
        msg = b"SM2 interop message with some length!"
        for mode, gmode in (("C1C3C2", 1), ("C1C2C3", 0)):
            g = _gmssl_crypt2(self.priv_hex, self.pub_xy, mode=gmode)
            with self.subTest(mode=mode):
                # 我方加密（带 04 前缀）→ 去掉前缀后 gmssl 解密
                ct_mine = sm2_encrypt(self.pub, msg, mode=mode)
                self.assertEqual(g.decrypt(ct_mine[1:]), msg)
                # gmssl 加密（无前缀）→ 我方解密
                ct_gmssl = g.encrypt(msg)
                self.assertEqual(sm2_decrypt(self.d, ct_gmssl, mode=mode), msg)

    def test_encrypt_short_message_mutual(self) -> None:
        # 1 字节消息（C2 仅 1 字节）是最短的密文形态
        msg = b"\x42"
        g = _gmssl_crypt2(self.priv_hex, self.pub_xy, mode=1)
        self.assertEqual(sm2_decrypt(self.d, g.encrypt(msg), mode="C1C3C2"), msg)
        self.assertEqual(g.decrypt(sm2_encrypt(self.pub, msg)[1:]), msg)


def _find_openssl() -> "str | None":
    for cand in (
        os.environ.get("SMCT_OPENSSL", ""),
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/usr/local/opt/openssl/bin/openssl",
        shutil.which("openssl") or "",
    ):
        if cand and os.path.exists(cand):
            try:
                r = subprocess.run(
                    [cand, "mac", "-digest", "SM3", "-macopt", "hexkey:00", "HMAC"],
                    input=b"x",
                    capture_output=True,
                    timeout=10,
                )
                if r.returncode == 0:
                    return cand
            except Exception:  # noqa: BLE001
                continue
    return None


_OPENSSL = _find_openssl()


@unittest.skipUnless(_OPENSSL, "需要支持 SM3/SM4 的 OpenSSL（如 Homebrew openssl@3）")
class TestOpensslInterop(unittest.TestCase):
    """与 OpenSSL 3.x 的附加对拍（SM4-CTR / HMAC-SM3 / PBKDF2-HMAC-SM3）。"""

    def test_sm4_ctr_matches_openssl(self) -> None:
        key, iv = bytes(range(16)), bytes(range(16, 32))
        for size in (0, 1, 16, 17, 77, 256):
            data = bytes((i * 5 + 2) % 256 for i in range(size))
            r = subprocess.run(
                [_OPENSSL, "enc", "-sm4-ctr", "-K", key.hex(), "-iv", iv.hex()],
                input=data,
                capture_output=True,
                check=True,
            )
            with self.subTest(size=size):
                self.assertEqual(sm4_ctr_xor(key, iv, data), r.stdout)

    def test_sm4_cbc_nopad_matches_openssl(self) -> None:
        key, iv = bytes(range(16)), bytes(range(16, 32))
        for size in (16, 32, 64):
            data = bytes((i * 3 + 9) % 256 for i in range(size))
            r = subprocess.run(
                [_OPENSSL, "enc", "-sm4-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nopad"],
                input=data,
                capture_output=True,
                check=True,
            )
            with self.subTest(size=size):
                self.assertEqual(sm4_cbc_encrypt(key, iv, data, pad=False), r.stdout)

    def test_hmac_matches_openssl(self) -> None:
        for key, msg in ((b"key", b"message"), (bytes(range(20)), b"payload"), (b"k" * 100, b"m" * 70)):
            r = subprocess.run(
                [_OPENSSL, "mac", "-digest", "SM3", "-macopt", "hexkey:" + key.hex(), "HMAC"],
                input=msg,
                capture_output=True,
                check=True,
            )
            with self.subTest(key=key[:6]):
                self.assertEqual(hmac_sm3(key, msg).hex(), r.stdout.decode().strip().lower())

    def test_pbkdf2_matches_openssl(self) -> None:
        cases = [("password", "salt", 1, 32), ("password", "salt", 1000, 16), ("pw", "naCl", 1500, 64)]
        for pw, salt, it, dklen in cases:
            r = subprocess.run(
                [
                    _OPENSSL,
                    "kdf",
                    "-keylen",
                    str(dklen),
                    "-kdfopt",
                    "digest:SM3",
                    "-kdfopt",
                    "pass:" + pw,
                    "-kdfopt",
                    "salt:" + salt,
                    "-kdfopt",
                    "iter:" + str(it),
                    "PBKDF2",
                ],
                capture_output=True,
                check=True,
            )
            want = r.stdout.decode().strip().replace(":", "").lower()
            with self.subTest(iterations=it, dklen=dklen):
                self.assertEqual(pbkdf2_hmac_sm3(pw.encode(), salt.encode(), it, dklen).hex(), want)


if __name__ == "__main__":
    unittest.main(verbosity=2)
