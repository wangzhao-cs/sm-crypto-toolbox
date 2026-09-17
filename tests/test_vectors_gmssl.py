"""静态交叉验证向量测试（gmssl / OpenSSL 生成，见 tests/vectors_gmssl.py）。

本文件**不依赖** gmssl —— 向量已冻结在仓库内，任何环境都能运行。

零安装运行（仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import vectors_gmssl as V  # noqa: E402

from smcrypto.sm2 import (  # noqa: E402
    decode_point,
    decode_signature_der,
    public_key_from_private,
    sm2_decrypt,
    sm2_sign,
    sm2_verify,
    sm2_verify_der,
)
from smcrypto.sm3 import hmac_sm3, pbkdf2_hmac_sm3, sm3_hexdigest  # noqa: E402
from smcrypto.sm4 import (  # noqa: E402
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
    sm4_ctr_xor,
    sm4_ecb_decrypt,
    sm4_ecb_encrypt,
)


class TestStaticSm3Vectors(unittest.TestCase):
    def test_sm3(self) -> None:
        for name, (msg_hex, want) in V.SM3_VECTORS.items():
            with self.subTest(case=name):
                self.assertEqual(sm3_hexdigest(bytes.fromhex(msg_hex)), want)


class TestStaticSm4Vectors(unittest.TestCase):
    def test_ecb(self) -> None:
        v = V.SM4_ECB_VECTORS
        key = bytes.fromhex(v["key"])
        self.assertEqual(
            sm4_ecb_encrypt(key, bytes.fromhex(v["single_plaintext"])).hex(),
            v["single_padded_ciphertext"],
        )
        self.assertEqual(
            sm4_ecb_decrypt(key, bytes.fromhex(v["padded_ciphertext"])),
            bytes.fromhex(v["padded_plaintext"]),
        )
        self.assertEqual(
            sm4_ecb_encrypt(key, bytes.fromhex(v["boundary16_plaintext"])).hex(),
            v["boundary16_ciphertext"],
        )

    def test_cbc(self) -> None:
        v = V.SM4_CBC_VECTORS
        key, iv = bytes.fromhex(v["key"]), bytes.fromhex(v["iv"])
        self.assertEqual(sm4_cbc_encrypt(key, iv, bytes.fromhex(v["plaintext"])).hex(), v["ciphertext"])
        self.assertEqual(sm4_cbc_decrypt(key, iv, bytes.fromhex(v["ciphertext"])).hex(), v["plaintext"])

    def test_ctr(self) -> None:
        v = V.SM4_CTR_VECTORS
        key, iv = bytes.fromhex(v["key"]), bytes.fromhex(v["iv"])
        self.assertEqual(sm4_ctr_xor(key, iv, bytes.fromhex(v["plaintext"])).hex(), v["ciphertext"])


class TestStaticHmacPbkdf2Vectors(unittest.TestCase):
    """HMAC-SM3 / PBKDF2-HMAC-SM3 向量由 OpenSSL 3.x 生成（见生成脚本）。"""

    def test_hmac_sm3(self) -> None:
        self.assertTrue(V.HMAC_SM3_VECTORS, "无 OpenSSL 生成的 HMAC 向量")
        for (key_hex, msg_hex), want in V.HMAC_SM3_VECTORS.items():
            with self.subTest(key=key_hex[:8]):
                self.assertEqual(hmac_sm3(bytes.fromhex(key_hex), bytes.fromhex(msg_hex)).hex(), want)

    def test_pbkdf2_hmac_sm3(self) -> None:
        self.assertTrue(V.PBKDF2_SM3_VECTORS, "无 OpenSSL 生成的 PBKDF2 向量")
        for (pw, salt, it, dklen), want in V.PBKDF2_SM3_VECTORS.items():
            with self.subTest(iterations=it, dklen=dklen):
                got = pbkdf2_hmac_sm3(pw.encode("utf-8"), salt.encode("utf-8"), it, dklen)
                self.assertEqual(got.hex(), want)


class TestStaticSm2Vectors(unittest.TestCase):
    def setUp(self) -> None:
        self.d = int(V.SM2_VECTORS["private_key"], 16)
        self.pub = public_key_from_private(self.d)
        self.msg = bytes.fromhex(V.SM2_VECTORS["message_hex"])
        self.ida = V.SM2_VECTORS["ida"].encode("utf-8")

    def test_public_key_matches(self) -> None:
        self.assertEqual("%064x%064x" % (self.pub.x, self.pub.y), V.SM2_VECTORS["public_key_xy"])
        self.assertEqual(decode_point(bytes.fromhex(V.SM2_VECTORS["public_key_xy"])), self.pub)

    def test_signatures_verify(self) -> None:
        for key in ("sig_fixed_rs_hex", "sig_random_rs_hex"):
            sig = V.SM2_VECTORS[key]
            r, s = int(sig[:64], 16), int(sig[64:], 16)
            with self.subTest(case=key):
                self.assertTrue(sm2_verify(self.pub, self.msg, r, s))

    def test_reproduce_fixed_k_signature(self) -> None:
        r, s = sm2_sign(self.d, self.msg, k=int(V.SM2_VECTORS["k_fixed"], 16))
        self.assertEqual("%064x%064x" % (r, s), V.SM2_VECTORS["sig_fixed_rs_hex"])

    def test_der_signature(self) -> None:
        der = bytes.fromhex(V.SM2_VECTORS["sig_der_hex"])
        self.assertTrue(sm2_verify_der(self.pub, self.msg, der))
        self.assertEqual(decode_signature_der(der),
                         (int(V.SM2_VECTORS["sig_fixed_rs_hex"][:64], 16),
                          int(V.SM2_VECTORS["sig_fixed_rs_hex"][64:], 16)))

    def test_decrypt_gmssl_ciphertexts(self) -> None:
        want = bytes.fromhex(V.SM2_VECTORS["encrypt_plaintext_hex"])
        self.assertEqual(
            sm2_decrypt(self.d, bytes.fromhex(V.SM2_VECTORS["encrypt_c1c3c2_hex"]), mode="C1C3C2"), want
        )
        self.assertEqual(
            sm2_decrypt(self.d, bytes.fromhex(V.SM2_VECTORS["encrypt_c1c2c3_hex"]), mode="C1C2C3"), want
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
