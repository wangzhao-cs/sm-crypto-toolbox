"""SMCT v1 文件容器格式测试：头部字段、随机性、篡改与错误处理。

零安装运行（仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from smcrypto.filecrypt import (  # noqa: E402
    DEFAULT_ITERATIONS,
    HEADER_SIZE,
    MAGIC,
    VERSION,
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
    parse_header,
)
from smcrypto.sm3 import pbkdf2_hmac_sm3  # noqa: E402

FAST_ITER = 400  # 测试用低迭代次数（PBKDF2 纯 Python 实现较慢）


class TestHeader(unittest.TestCase):
    def test_header_layout(self) -> None:
        ct = encrypt_bytes(b"payload", cipher="sm4-cbc", password="pw", iterations=1234)
        self.assertEqual(ct[:4], MAGIC)
        self.assertEqual(ct[4], VERSION)
        self.assertEqual(ct[5], 1)  # sm4-cbc
        self.assertEqual(ct[6], 1)  # 口令模式
        self.assertEqual(int.from_bytes(ct[8:12], "big"), 1234)
        h = parse_header(ct)
        self.assertEqual(h.cipher, "sm4-cbc")
        self.assertTrue(h.is_password_mode)
        self.assertEqual(h.iterations, 1234)
        self.assertEqual(len(h.salt), 16)
        self.assertEqual(len(h.iv), 16)

    def test_cipher_ids(self) -> None:
        for name, cid in (("sm4-cbc", 1), ("sm4-ctr", 2), ("sm4-ecb", 3)):
            with self.subTest(cipher=name):
                ct = encrypt_bytes(b"x", cipher=name, key=b"\x00" * 16)
                self.assertEqual(ct[5], cid)
                self.assertEqual(ct[6], 0)  # 原始密钥模式
                # ECB 无 IV（全零），其余算法 IV 随机
                if name == "sm4-ecb":
                    self.assertEqual(ct[28:44], bytes(16))
                else:
                    self.assertNotEqual(ct[28:44], bytes(16))

    def test_salt_iv_randomness_across_calls(self) -> None:
        a = encrypt_bytes(b"same", password="pw", iterations=FAST_ITER)
        b = encrypt_bytes(b"same", password="pw", iterations=FAST_ITER)
        self.assertNotEqual(a, b, "每次加密应使用新的 salt/IV")
        self.assertNotEqual(a[12:28], b[12:28])
        self.assertNotEqual(a[28:44], b[28:44])

    def test_parse_header_errors(self) -> None:
        good = encrypt_bytes(b"x", key=b"\x00" * 16)
        bad_cases = [
            b"",
            b"SM",  # 过短
            b"XXXX" + good[4:],  # 魔数错误
            good[:4] + b"\x09" + good[5:],  # 版本错误
            good[:5] + b"\x09" + good[6:],  # 算法编号错误
            good[:6] + b"\x09" + good[7:],  # 密钥来源错误
        ]
        for bad in bad_cases:
            with self.subTest(prefix=bad[:6]):
                with self.assertRaises(ValueError):
                    parse_header(bad)


class TestRoundtripAndErrors(unittest.TestCase):
    def test_roundtrip_with_fixed_salt_iv(self) -> None:
        salt = bytes(range(16))
        iv = bytes(range(16, 32))
        pt = b"deterministic container"
        ct = encrypt_bytes(pt, cipher="sm4-cbc", password="pw", iterations=FAST_ITER, salt=salt, iv=iv)
        self.assertEqual(ct[12:28], salt)
        self.assertEqual(ct[28:44], iv)
        self.assertEqual(decrypt_bytes(ct, password="pw"), pt)

    def test_derive_key_matches_pbkdf2(self) -> None:
        salt = b"0123456789abcdef"
        key = derive_key("password", salt, 777)
        self.assertEqual(len(key), 16)
        self.assertEqual(key, pbkdf2_hmac_sm3(b"password", salt, 777, 16))

    def test_derive_key_rejects_bad_iterations(self) -> None:
        with self.assertRaises(ValueError):
            derive_key("pw", b"salt", 0)

    def test_wrong_credentials_and_corruption(self) -> None:
        pt = os.urandom(64)
        ct = encrypt_bytes(pt, cipher="sm4-cbc", password="pw", iterations=FAST_ITER)
        # 错误口令：CBC 填充校验应拒绝（概率性，但此处固定 salt/IV 下确定）
        try:
            got = decrypt_bytes(ct, password="not-pw")
        except ValueError:
            got = None
        self.assertNotEqual(got, pt)
        # 篡改密文末字节 → 填充校验失败
        bad = bytearray(ct)
        bad[-1] ^= 0x01
        with self.assertRaises(ValueError):
            decrypt_bytes(bytes(bad), password="pw")
        # 口令模式容器不能用 --key 解
        with self.assertRaises(ValueError):
            decrypt_bytes(ct, key=b"\x00" * 16)
        # 参数互斥校验
        with self.assertRaises(ValueError):
            decrypt_bytes(ct)
        with self.assertRaises(ValueError):
            decrypt_bytes(ct, password="pw", key=b"\x00" * 16)

    def test_raw_key_validation(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", key="zz" * 16)  # 非法 hex
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", key=b"\x00" * 15)  # 长度错误
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", key=b"\x00" * 16, password="pw")  # 同时给出
        with self.assertRaises(ValueError):
            encrypt_bytes(b"x", cipher="aes-cbc", key=b"\x00" * 16)  # 不支持的算法

    def test_empty_and_large_payload(self) -> None:
        for size in (0, 1, 15, 16, 17, 4096):
            pt = os.urandom(size)
            with self.subTest(size=size):
                ct = encrypt_bytes(pt, cipher="sm4-ctr", password="pw", iterations=FAST_ITER)
                self.assertEqual(len(ct), HEADER_SIZE + size, "CTR 密文长度 = 头 + 明文")
                self.assertEqual(decrypt_bytes(ct, password="pw"), pt)

    def test_default_iterations_constant(self) -> None:
        ct = encrypt_bytes(b"x", password="pw")  # 使用默认迭代次数
        self.assertEqual(parse_header(ct).iterations, DEFAULT_ITERATIONS)
        self.assertGreaterEqual(DEFAULT_ITERATIONS, 10_000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
