"""SM2 单元测试：曲线健全性、点运算、密钥、签名验签、DER、公钥加解密。

零安装运行（仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import vectors_gmssl  # noqa: E402

from smcrypto.sm2 import (  # noqa: E402
    GX,
    GY,
    INFINITY,
    A,
    B,
    G,
    N,
    P,
    _scalar_mul_raw,
    compute_za,
    decode_point,
    decode_signature_der,
    encode_point,
    encode_signature_der,
    generate_keypair,
    point_add,
    point_double,
    point_is_on_curve,
    public_key_from_private,
    scalar_mul,
    sign_digest,
    sm2_decrypt,
    sm2_encrypt,
    sm2_sign,
    sm2_sign_der,
    sm2_verify,
    sm2_verify_der,
    verify_digest,
)

STD = vectors_gmssl.SM2_VECTORS


class TestCurve(unittest.TestCase):
    def test_curve_parameters(self) -> None:
        self.assertEqual(A, P - 3, "sm2p256v1 的 a 应等于 p-3")
        self.assertEqual(P.bit_length(), 256)
        self.assertEqual(N.bit_length(), 256)
        self.assertTrue(0 < B < P)
        self.assertTrue(point_is_on_curve(G), "基点 G 必须在曲线上")
        self.assertEqual((G.x, G.y), (GX, GY))

    def test_order_n_times_g_is_infinity(self) -> None:
        """[n]G = O —— 用不做模 n 归约的原始标量乘真实计算（约 35ms）。"""
        self.assertTrue(_scalar_mul_raw(N, G).is_infinity)
        self.assertTrue(_scalar_mul_raw(1, G) == G)
        self.assertTrue(_scalar_mul_raw(0, G).is_infinity)

    def test_point_arithmetic_consistency(self) -> None:
        g2 = point_double(G)
        self.assertEqual(point_add(G, G), g2)
        self.assertEqual(scalar_mul(2), g2, "标量乘 [2]G 应等于倍点")
        g3 = point_add(g2, G)
        self.assertEqual(scalar_mul(3), g3)
        # 结合律 / 分配律抽样验证
        for k, m in ((5, 7), (12345, 67890), (N - 1, 1)):
            lhs = point_add(scalar_mul(k), scalar_mul(m))
            rhs = scalar_mul(k + m)
            self.assertEqual(lhs, rhs, "kG + mG != (k+m)G")
        # 无穷远点与逆元
        self.assertTrue(point_add(G, scalar_mul(N - 1)).is_infinity, "G + [n-1]G 应为 O")
        self.assertTrue(point_double(INFINITY).is_infinity)
        self.assertEqual(point_add(INFINITY, G), G)

    def test_public_key_on_curve_for_random_keys(self) -> None:
        for _ in range(5):
            d, pub = generate_keypair()
            self.assertTrue(point_is_on_curve(pub))
            self.assertEqual(scalar_mul(d), pub)


class TestKeys(unittest.TestCase):
    def test_keygen_range_and_uniqueness(self) -> None:
        seen = set()
        for _ in range(8):
            d, pub = generate_keypair()
            self.assertTrue(1 <= d <= N - 2, "私钥必须在 [1, n-2]")
            self.assertFalse(pub.is_infinity)
            seen.add(d)
        self.assertEqual(len(seen), 8, "连续生成的私钥不应重复")

    def test_public_key_from_private_validation(self) -> None:
        d, pub = generate_keypair()
        self.assertEqual(public_key_from_private(d), pub)
        for bad in (0, N - 1, N, -3):
            with self.assertRaises(ValueError):
                public_key_from_private(bad)

    def test_point_encoding_roundtrip(self) -> None:
        _, pub = generate_keypair()
        for prefix in (True, False):
            enc = encode_point(pub, prefix=prefix)
            self.assertEqual(len(enc), 65 if prefix else 64)
            self.assertEqual(decode_point(enc), pub)
        # 04 前缀与裸编码都可解析
        self.assertEqual(decode_point(encode_point(pub)[1:]), pub)

    def test_point_decoding_rejects_invalid(self) -> None:
        _, pub = generate_keypair()
        bad_inputs = [
            b"",
            b"\x04" + b"\x00" * 64,  # 不在曲线上
            encode_point(pub)[:60],  # 长度不足
            encode_point(pub) + b"\x00",  # 长度过长
            b"\x02" + encode_point(pub)[1:],  # 压缩前缀不受支持
        ]
        for bad in bad_inputs:
            with self.subTest(n=len(bad)):
                with self.assertRaises(ValueError):
                    decode_point(bad)


class TestSignature(unittest.TestCase):
    def test_za_matches_gmssl_generated_vector(self) -> None:
        d = int(STD["private_key"], 16)
        pub = public_key_from_private(d)
        za = compute_za(pub, STD["ida"].encode("utf-8"))
        self.assertEqual(za.hex(), STD["za"])

    def test_standard_example_signature_reproduced(self) -> None:
        """GB/T 32918.2 附录 A：固定 k 下签名应为标准示例值。"""
        d = int(STD["private_key"], 16)
        pub = public_key_from_private(d)
        msg = bytes.fromhex(STD["message_hex"])
        r, s = sm2_sign(d, msg, ida=STD["ida"].encode("utf-8"), k=int(STD["k_fixed"], 16))
        self.assertEqual("%064x%064x" % (r, s), STD["sig_fixed_rs_hex"])
        self.assertTrue(sm2_verify(pub, msg, r, s, ida=STD["ida"].encode("utf-8")))

    def test_verify_accepts_gmssl_signatures(self) -> None:
        """gmssl 生成的签名（固定 k 与随机 k）都必须能通过本实现验签。"""
        d = int(STD["private_key"], 16)
        pub = public_key_from_private(d)
        msg = bytes.fromhex(STD["message_hex"])
        for key in ("sig_fixed_rs_hex", "sig_random_rs_hex"):
            sig = STD[key]
            r, s = int(sig[:64], 16), int(sig[64:], 16)
            with self.subTest(case=key):
                self.assertTrue(sm2_verify(pub, msg, r, s), "gmssl 签名未被接受")

    def test_sign_verify_roundtrip_and_randomness(self) -> None:
        d, pub = generate_keypair()
        msg = b"roundtrip message"
        r1, s1 = sm2_sign(d, msg)
        r2, s2 = sm2_sign(d, msg)
        self.assertNotEqual((r1, s1), (r2, s2), "两次签名应因随机 k 而不同")
        self.assertTrue(sm2_verify(pub, msg, r1, s1))
        self.assertTrue(sm2_verify(pub, msg, r2, s2))
        # 自定义 ID 时签名与验签一致、且与默认 ID 的签名互不通过
        ida = b"alice@example.com"
        r3, s3 = sm2_sign(d, msg, ida=ida)
        self.assertTrue(sm2_verify(pub, msg, r3, s3, ida=ida))
        self.assertFalse(sm2_verify(pub, msg, r3, s3))

    def test_signature_tamper_rejected(self) -> None:
        d, pub = generate_keypair()
        msg = b"tamper check"
        r, s = sm2_sign(d, msg)
        _, other_pub = generate_keypair()
        cases = [
            (pub, msg + b"!", r, s),  # 消息被改
            (pub, msg, (r + 1) % N, s),  # r 被改
            (pub, msg, r, (s + 1) % N),  # s 被改
            (other_pub, msg, r, s),  # 换公钥
        ]
        for p, m, rr, ss in cases:
            with self.subTest(r=rr % 1000, s=ss % 1000):
                self.assertFalse(sm2_verify(p, m, rr, ss))

    def test_signature_range_checks(self) -> None:
        d, pub = generate_keypair()
        msg = b"range check"
        r, s = sm2_sign(d, msg)
        # 越界/非法的 (r, s) 必须被拒绝（返回 False 或抛 ValueError）
        for rr, ss in ((0, s), (r, 0), (N, s), (r, N), (-1, s), (r + N, s)):
            with self.subTest(r=rr, s=ss):
                try:
                    ok = sm2_verify(pub, msg, rr, ss)
                except ValueError:
                    ok = False
                self.assertFalse(ok)

    def test_sign_input_validation(self) -> None:
        with self.assertRaises(ValueError):
            sm2_sign(0, b"m")
        with self.assertRaises(ValueError):
            sm2_sign(N - 1, b"m")

    def test_digest_level_api(self) -> None:
        """sign_digest / verify_digest 与消息级 API 等价。"""
        d, pub = generate_keypair()
        e = int.from_bytes(os.urandom(32), "big")
        r, s = sign_digest(d, e)
        self.assertTrue(verify_digest(pub, e, r, s))
        self.assertFalse(verify_digest(pub, e ^ 1, r, s))


class TestDER(unittest.TestCase):
    def test_der_roundtrip(self) -> None:
        d, pub = generate_keypair()
        msg = b"der roundtrip"
        r, s = sm2_sign(d, msg)
        der = encode_signature_der(r, s)
        self.assertEqual(der[0], 0x30)
        self.assertEqual(decode_signature_der(der), (r, s))
        self.assertTrue(sm2_verify_der(pub, msg, der))

    def test_der_parses_gmssl_signature(self) -> None:
        der = bytes.fromhex(STD["sig_der_hex"])
        r, s = decode_signature_der(der)
        self.assertEqual("%064x%064x" % (r, s), STD["sig_fixed_rs_hex"])
        pub = public_key_from_private(int(STD["private_key"], 16))
        self.assertTrue(sm2_verify_der(pub, bytes.fromhex(STD["message_hex"]), der))
        # 我方生成的 DER 也应能被 gmssl（经静态向量比对）风格解析：长度结构一致
        self.assertEqual(
            sm2_sign_der(int(STD["private_key"], 16), bytes.fromhex(STD["message_hex"]),
                         ida=STD["ida"].encode(), k=int(STD["k_fixed"], 16)),
            der,
        )

    def test_der_rejects_invalid(self) -> None:
        bad_inputs = [
            b"",
            b"\x30\x00",
            b"\x31\x06\x02\x01\x01\x02\x01\x01",  # 错误标签
            b"\x30\x06\x02\x01\x01\x02\x01",  # 截断
            encode_signature_der(1, 1) + b"\x00",  # 尾随字节
            b"\x30\x08\x02\x02\x00\x81\x02\x02\x00\x82"[:6],
        ]
        for bad in bad_inputs:
            with self.subTest(data=bad.hex()):
                with self.assertRaises(ValueError):
                    decode_signature_der(bad)

    def test_der_signature_with_high_bit_integer(self) -> None:
        # r/s 最高位为 1 时 DER 需补 0x00；构造往返验证
        r = (1 << 255) | 0x1234
        s = (1 << 256) - 1  # 全 F：DER 需前置 0x00
        der = encode_signature_der(r, s)
        self.assertEqual(decode_signature_der(der), (r, s))


class TestEncrypt(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip_both_modes(self) -> None:
        d, pub = generate_keypair()
        for size in (1, 16, 32, 100):
            msg = os.urandom(size)
            for mode in ("C1C3C2", "C1C2C3"):
                with self.subTest(size=size, mode=mode):
                    ct = sm2_encrypt(pub, msg, mode=mode)
                    self.assertEqual(sm2_decrypt(d, ct, mode=mode), msg)
                    # 密文总长 = 1 + 64 + 32 + len(msg)
                    self.assertEqual(len(ct), 1 + 64 + 32 + size)

    def test_decrypts_gmssl_ciphertexts(self) -> None:
        """gmssl 生成的两种排列密文（随机 k 已冻结）必须能解出原文。"""
        d = int(STD["private_key"], 16)
        want = bytes.fromhex(STD["encrypt_plaintext_hex"])
        for key, mode in (("encrypt_c1c3c2_hex", "C1C3C2"), ("encrypt_c1c2c3_hex", "C1C2C3")):
            with self.subTest(mode=mode):
                self.assertEqual(sm2_decrypt(d, bytes.fromhex(STD[key]), mode=mode), want)

    def test_prefix_handling(self) -> None:
        d, pub = generate_keypair()
        msg = b"prefix behavior"
        ct = sm2_encrypt(pub, msg)
        self.assertEqual(ct[0], 0x04)
        self.assertEqual(sm2_decrypt(d, ct), msg)
        self.assertEqual(sm2_decrypt(d, ct[1:]), msg, "无 04 前缀也应可解（兼容 gmssl）")
        ct_np = sm2_encrypt(pub, msg, prefix=False)
        self.assertEqual(len(ct_np), len(ct) - 1)
        self.assertEqual(sm2_decrypt(d, ct_np), msg)

    def test_encrypt_options_validation(self) -> None:
        d, pub = generate_keypair()
        with self.assertRaises(ValueError):
            sm2_encrypt(pub, b"")  # 空明文不支持
        with self.assertRaises(ValueError):
            sm2_encrypt(pub, b"x", mode="C1C2C3C3")
        with self.assertRaises(ValueError):
            sm2_decrypt(d, b"\x04" + b"\x00" * 10)
        with self.assertRaises(ValueError):
            sm2_decrypt(0, b"\x04" + b"\x00" * 96)

    def test_decrypt_rejects_tampering(self) -> None:
        d, pub = generate_keypair()
        msg = b"tamper me please, tamper me"
        for mode in ("C1C3C2", "C1C2C3"):
            ct = bytearray(sm2_encrypt(pub, msg, mode=mode))
            for pos in (5, 70, len(ct) - 1):  # C1 内部 / C2 或 C3 区域
                bad = bytearray(ct)
                bad[pos] ^= 0x01
                with self.subTest(mode=mode, pos=pos):
                    with self.assertRaises(ValueError):
                        sm2_decrypt(d, bytes(bad), mode=mode)

    def test_wrong_key_cannot_decrypt(self) -> None:
        d, pub = generate_keypair()
        other_d, _ = generate_keypair()
        ct = sm2_encrypt(pub, b"secret data of some length")
        with self.assertRaises(ValueError):
            sm2_decrypt(other_d, ct)


if __name__ == "__main__":
    unittest.main(verbosity=2)
