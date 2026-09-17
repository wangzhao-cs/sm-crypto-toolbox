"""SM3 单元测试：标准向量、填充边界、增量接口、HMAC、PBKDF2、KDF。

零安装运行（仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hmac as _stdlib_hmac
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import vectors_gmssl  # noqa: E402  （由 gmssl / OpenSSL 交叉验证生成的静态向量）

from smcrypto.sm3 import (  # noqa: E402
    SM3,
    hmac_sm3,
    pbkdf2_hmac_sm3,
    sm3_digest,
    sm3_hexdigest,
    sm3_kdf,
)

# GB/T 32905-2016 附录 A 标准示例
STANDARD_KAT = {
    b"": "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
    b"abc": "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    b"abcd" * 16: "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
}


class _SM3Hasher:
    """hashlib 风格的 SM3 适配器 —— 让 CPython 标准库 ``hmac`` 参与对照。"""

    block_size = 64
    digest_size = 32
    name = "sm3"

    def __init__(self, data: bytes = b"") -> None:
        self._h = SM3(data)

    def copy(self) -> "_SM3Hasher":
        other = _SM3Hasher()
        other._h = self._h.copy()
        return other

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()

    def hexdigest(self) -> str:
        return self._h.hexdigest()


def _ref_pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """独立的内联 RFC 8018 参考实现（基于标准库 hmac + SM3 适配器）。"""

    def prf(key: bytes, msg: bytes) -> bytes:
        return _stdlib_hmac.new(key, msg, _SM3Hasher).digest()

    out = b""
    for i in range(1, (dklen + 31) // 32 + 1):
        u = prf(password, salt + i.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = prf(password, u)
            for j in range(len(t)):
                t[j] ^= u[j]
        out += bytes(t)
    return out[:dklen]


class TestSM3Vectors(unittest.TestCase):
    def test_standard_kat(self) -> None:
        """GB/T 32905-2016 标准示例。"""
        for msg, want in STANDARD_KAT.items():
            with self.subTest(msg=msg):
                self.assertEqual(sm3_hexdigest(msg), want)

    def test_static_vectors_generated_by_gmssl(self) -> None:
        """由 gmssl 交叉验证生成的静态向量（含 55/56/57/63/64/65 填充边界）。"""
        self.assertGreaterEqual(len(vectors_gmssl.SM3_VECTORS), 10)
        for name, (msg_hex, want) in vectors_gmssl.SM3_VECTORS.items():
            with self.subTest(case=name):
                self.assertEqual(sm3_hexdigest(bytes.fromhex(msg_hex)), want)

    def test_incremental_equals_oneshot(self) -> None:
        data = bytes((i * 31 + 7) % 256 for i in range(1000))
        for step in (1, 7, 13, 64, 999):
            with self.subTest(step=step):
                h = SM3()
                for i in range(0, len(data), step):
                    h.update(data[i : i + step])
                self.assertEqual(h.hexdigest(), sm3_hexdigest(data))

    def test_copy_repeated_digest_and_len(self) -> None:
        h = SM3(b"prefix")
        h2 = h.copy()
        h.update(b"-one")
        h2.update(b"-two")
        self.assertNotEqual(h.hexdigest(), h2.hexdigest())
        self.assertEqual(h.hexdigest(), h.hexdigest())  # digest 可重复调用
        self.assertEqual(len(sm3_digest(b"x")), 32)

    def test_digest_size_and_hex_length(self) -> None:
        d = sm3_digest(b"length check")
        self.assertEqual(len(d), 32)
        self.assertEqual(len(sm3_hexdigest(b"length check")), 64)
        self.assertEqual(d.hex(), sm3_hexdigest(b"length check"))

    def test_input_types(self) -> None:
        self.assertEqual(SM3(bytearray(b"abc")).hexdigest(), sm3_hexdigest(b"abc"))
        self.assertEqual(SM3(memoryview(b"abc")).hexdigest(), sm3_hexdigest(b"abc"))
        with self.assertRaises(TypeError):
            SM3("字符串不是字节串")  # type: ignore[arg-type]


class TestHMACSM3(unittest.TestCase):
    def test_matches_stdlib_hmac_reference(self) -> None:
        cases = [
            (b"key", b"The quick brown fox jumps over the lazy dog"),
            (b"", b"empty key"),
            (b"k" * 63, b"just under block size"),
            (b"k" * 64, b"exactly block size"),
            (b"k" * 65, b"just over block size"),
            (b"key", b""),
            (b"key", b"x" * 200),
        ]
        for key, msg in cases:
            with self.subTest(key=key, msg_len=len(msg)):
                want = _stdlib_hmac.new(key, msg, _SM3Hasher).hexdigest()
                self.assertEqual(hmac_sm3(key, msg).hex(), want)

    def test_static_vectors_generated_by_openssl(self) -> None:
        self.assertTrue(vectors_gmssl.HMAC_SM3_VECTORS, "缺少 OpenSSL 生成的 HMAC 向量")
        for (key_hex, msg_hex), want in vectors_gmssl.HMAC_SM3_VECTORS.items():
            with self.subTest(key=key_hex[:8]):
                self.assertEqual(hmac_sm3(bytes.fromhex(key_hex), bytes.fromhex(msg_hex)).hex(), want)

    def test_output_length(self) -> None:
        self.assertEqual(len(hmac_sm3(b"k", b"m")), 32)


class TestPBKDF2SM3(unittest.TestCase):
    def test_matches_reference_implementation(self) -> None:
        cases = [(b"password", b"salt", 1, 32), (b"password", b"salt", 100, 32), (b"p", b"s", 64, 16)]
        for pw, salt, it, dklen in cases:
            with self.subTest(iterations=it, dklen=dklen):
                self.assertEqual(
                    pbkdf2_hmac_sm3(pw, salt, it, dklen), _ref_pbkdf2(pw, salt, it, dklen)
                )

    def test_static_vectors_generated_by_openssl(self) -> None:
        self.assertTrue(vectors_gmssl.PBKDF2_SM3_VECTORS, "缺少 OpenSSL 生成的 PBKDF2 向量")
        for (pw, salt, it, dklen), want in vectors_gmssl.PBKDF2_SM3_VECTORS.items():
            with self.subTest(pw=pw, iterations=it, dklen=dklen):
                got = pbkdf2_hmac_sm3(pw.encode("utf-8"), salt.encode("utf-8"), it, dklen)
                self.assertEqual(got.hex(), want)

    def test_arguments_validation(self) -> None:
        with self.assertRaises(ValueError):
            pbkdf2_hmac_sm3(b"p", b"s", 0, 16)
        with self.assertRaises(ValueError):
            pbkdf2_hmac_sm3(b"p", b"s", 10, 0)

    def test_longer_output_extends_prefix(self) -> None:
        a = pbkdf2_hmac_sm3(b"pw", b"salt", 10, 16)
        b = pbkdf2_hmac_sm3(b"pw", b"salt", 10, 32)
        self.assertEqual(len(a), 16)
        self.assertEqual(len(b), 32)
        self.assertEqual(b[:16], a, "更长输出的前缀应保持一致（多分块拼接语义）")


class TestSM3KDF(unittest.TestCase):
    def test_kdf_manual_construction(self) -> None:
        z = bytes(range(32))
        for klen in (1, 16, 31, 32, 33, 64, 100):
            with self.subTest(klen=klen):
                want = b""
                ct = 1
                while len(want) < klen:
                    want += sm3_digest(z + ct.to_bytes(4, "big"))
                    ct += 1
                self.assertEqual(sm3_kdf(z, klen), want[:klen])

    def test_kdf_prefix_property(self) -> None:
        z = b"shared secret"
        self.assertEqual(sm3_kdf(z, 16), sm3_kdf(z, 64)[:16])

    def test_kdf_validation(self) -> None:
        with self.assertRaises(ValueError):
            sm3_kdf(b"z", -1)
        with self.assertRaises(ValueError):
            sm3_kdf(b"z", 2**40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
