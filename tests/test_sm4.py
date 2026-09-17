"""SM4 单元测试：标准向量、分组长度边界、ECB/CBC/CTR 往返、PKCS#7 填充。

零安装运行（仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import vectors_gmssl  # noqa: E402

from smcrypto.sm4 import (  # noqa: E402
    SM4,
    pkcs7_pad,
    pkcs7_unpad,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
    sm4_ctr_xor,
    sm4_ecb_decrypt,
    sm4_ecb_encrypt,
)

KAT_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
KAT_PT = bytes.fromhex("0123456789abcdeffedcba9876543210")
KAT_CT = "681edf34d206965e86b3e94f536e4246"  # GB/T 32907-2016 附录 A.1


class TestSM4Block(unittest.TestCase):
    def test_standard_block_kat(self) -> None:
        c = SM4(KAT_KEY)
        self.assertEqual(c.encrypt_block(KAT_PT).hex(), KAT_CT)
        self.assertEqual(c.decrypt_block(bytes.fromhex(KAT_CT)), KAT_PT)

    def test_key_length_validation(self) -> None:
        for bad in (b"", b"\x00" * 15, b"\x00" * 17):
            with self.subTest(key_len=len(bad)):
                with self.assertRaises(ValueError):
                    SM4(bad)

    def test_block_length_validation(self) -> None:
        c = SM4(KAT_KEY)
        for bad in (b"", b"\x00" * 15, b"\x00" * 17):
            with self.assertRaises(ValueError):
                c.encrypt_block(bad)
            with self.assertRaises(ValueError):
                c.decrypt_block(bad)

    def test_decrypt_uses_reversed_round_keys(self) -> None:
        # 解密不是"再加密一次"（非对合），且解密后须还原
        c = SM4(KAT_KEY)
        ct = c.encrypt_block(KAT_PT)
        self.assertNotEqual(c.encrypt_block(ct), KAT_PT)
        self.assertEqual(c.decrypt_block(ct), KAT_PT)


class TestSM4Modes(unittest.TestCase):
    def setUp(self) -> None:
        self.key = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.iv = bytes.fromhex("ffeeddccbbaa99887766554433221100")

    def test_ecb_roundtrip_all_lengths(self) -> None:
        for size in (0, 1, 15, 16, 17, 31, 32, 33, 100, 257):
            with self.subTest(size=size):
                pt = os.urandom(size)
                self.assertEqual(sm4_ecb_decrypt(self.key, sm4_ecb_encrypt(self.key, pt)), pt)

    def test_ecb_static_vectors(self) -> None:
        v = vectors_gmssl.SM4_ECB_VECTORS
        key = bytes.fromhex(v["key"])
        # 单分组（无填充语义）+ PKCS#7：前 16 字节应等于标准分组向量，总长 32
        single_pt = bytes.fromhex(v["single_plaintext"])
        padded_ct = sm4_ecb_encrypt(key, single_pt)
        self.assertEqual(len(padded_ct), 32)
        self.assertEqual(padded_ct[:16].hex(), v["single_ciphertext"])
        self.assertEqual(padded_ct.hex(), v["single_padded_ciphertext"])
        # 37 字节 → PKCS#7 填充到 48 字节
        self.assertEqual(
            sm4_ecb_encrypt(key, bytes.fromhex(v["padded_plaintext"])),
            bytes.fromhex(v["padded_ciphertext"]),
        )
        self.assertEqual(len(bytes.fromhex(v["padded_ciphertext"])), 48)
        # 16 字节恰好一个分组：填充应追加密文到 32 字节
        boundary_ct = bytes.fromhex(v["boundary16_ciphertext"])
        self.assertEqual(len(boundary_ct), 32)
        self.assertEqual(
            sm4_ecb_encrypt(key, bytes.fromhex(v["boundary16_plaintext"])), boundary_ct
        )
        self.assertEqual(sm4_ecb_decrypt(key, boundary_ct), bytes.fromhex(v["boundary16_plaintext"]))

    def test_cbc_roundtrip_and_iv_sensitivity(self) -> None:
        for size in (0, 1, 16, 17, 64, 100):
            with self.subTest(size=size):
                pt = os.urandom(size)
                ct = sm4_cbc_encrypt(self.key, self.iv, pt)
                self.assertEqual(sm4_cbc_decrypt(self.key, self.iv, ct), pt)
                # 换 IV 后密文不同，但用原 IV 仍能解密（说明 IV 参与且确定）
                other_iv = bytes(16)
                ct2 = sm4_cbc_encrypt(self.key, other_iv, pt)
                self.assertNotEqual(ct, ct2)
                self.assertEqual(sm4_cbc_decrypt(self.key, other_iv, ct2), pt)

    def test_cbc_static_vector_generated_by_gmssl(self) -> None:
        v = vectors_gmssl.SM4_CBC_VECTORS
        key, iv = bytes.fromhex(v["key"]), bytes.fromhex(v["iv"])
        pt, ct = bytes.fromhex(v["plaintext"]), bytes.fromhex(v["ciphertext"])
        self.assertEqual(sm4_cbc_encrypt(key, iv, pt), ct)
        self.assertEqual(sm4_cbc_decrypt(key, iv, ct), pt)

    def test_cbc_chaining_effect(self) -> None:
        pt = bytes(32)
        ct_a = sm4_cbc_encrypt(self.key, self.iv, pt)
        ct_b = sm4_cbc_encrypt(self.key, bytes(16), pt)
        # 首块不同（IV 不同），后续块受链式影响也不同
        self.assertNotEqual(ct_a[16:32], ct_b[16:32])

    def test_ctr_roundtrip_and_length_preserving(self) -> None:
        for size in (0, 1, 15, 16, 17, 100, 257):
            with self.subTest(size=size):
                pt = os.urandom(size)
                ct = sm4_ctr_xor(self.key, self.iv, pt)
                self.assertEqual(len(ct), size, "CTR 密文应与明文等长（无填充）")
                self.assertEqual(sm4_ctr_xor(self.key, self.iv, ct), pt)

    def test_ctr_static_vector(self) -> None:
        v = vectors_gmssl.SM4_CTR_VECTORS
        key, iv = bytes.fromhex(v["key"]), bytes.fromhex(v["iv"])
        pt, ct = bytes.fromhex(v["plaintext"]), bytes.fromhex(v["ciphertext"])
        self.assertEqual(sm4_ctr_xor(key, iv, pt), ct)
        self.assertEqual(sm4_ctr_xor(key, iv, ct), pt)

    def test_ctr_keystream_reuse(self) -> None:
        # 相同 key/iv 下，前 n 字节密文只依赖前 n 字节明文（流密码特性）
        pt = os.urandom(48)
        ks = sm4_ctr_xor(self.key, self.iv, bytes(48))
        self.assertEqual(sm4_ctr_xor(self.key, self.iv, pt), bytes(a ^ b for a, b in zip(pt, ks)))
        # 计数器自增：两块密钥流不相同
        self.assertNotEqual(ks[:16], ks[16:32])

    def test_mode_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            sm4_cbc_encrypt(self.key, b"\x00" * 15, b"data")
        with self.assertRaises(ValueError):
            sm4_ecb_decrypt(self.key, b"not multiple")  # 13 字节
        with self.assertRaises(ValueError):
            sm4_cbc_decrypt(self.key, self.iv, b"")


class TestPKCS7(unittest.TestCase):
    def test_pad_unpad_all_boundaries(self) -> None:
        for size in range(0, 65):
            with self.subTest(size=size):
                data = os.urandom(size)
                padded = pkcs7_pad(data)
                self.assertEqual(len(padded) % 16, 0)
                self.assertGreater(len(padded), size)
                self.assertEqual(pkcs7_unpad(padded), data)

    def test_full_block_padding_added(self) -> None:
        self.assertEqual(pkcs7_pad(bytes(16)), bytes(16) + bytes([16]) * 16)
        self.assertEqual(pkcs7_pad(b""), bytes([16]) * 16)

    def test_invalid_padding_rejected(self) -> None:
        bad_inputs = [
            b"",
            b"\x00" * 16,
            b"\x00" * 15 + b"\x00",
            b"A" * 14 + b"\x03\x03",
            b"A" * 15 + b"\x11",
            b"A" * 20,
            b"A" * 15 + b"\xff",
        ]
        for bad in bad_inputs:
            with self.subTest(pad=bad[-2:].hex()):
                with self.assertRaises(ValueError):
                    pkcs7_unpad(bad)


if __name__ == "__main__":
    unittest.main(verbosity=2)
