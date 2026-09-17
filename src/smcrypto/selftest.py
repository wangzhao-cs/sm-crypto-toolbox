"""国密算法工具箱内置自检（``smctl self-test``）。

自检项覆盖：

* 标准已知答案向量（SM3 / SM4，来自 GB/T 标准附录）；
* 结构性参考实现交叉检查（HMAC-SM3 ↔ CPython ``hmac`` 模块；
  PBKDF2-HMAC-SM3 ↔ 内联 RFC 8018 参考实现）；
* 曲线健全性（G 在曲线上、``[n]G = O``）；
* SM2 标准示例复现与签名 / 加解密往返；
* SMCT 文件容器往返与错误检测。

说明：这里的内联参考实现只用于**对照**，生产路径始终走 ``smcrypto`` 主实现。
"""

from __future__ import annotations

import hmac as _stdlib_hmac
import os
import sys
import time
from typing import Callable, List, NamedTuple, Tuple

from . import _kat
from .filecrypt import decrypt_bytes, encrypt_bytes, parse_header
from .sm2 import (
    G,
    N,
    _scalar_mul_raw,
    compute_za,
    decode_signature_der,
    encode_signature_der,
    generate_keypair,
    point_is_on_curve,
    public_key_from_private,
    sm2_decrypt,
    sm2_encrypt,
    sm2_sign,
    sm2_verify,
    sm2_verify_der,
)
from .sm3 import SM3, hmac_sm3, pbkdf2_hmac_sm3, sm3_hexdigest
from .sm4 import (
    SM4,
    pkcs7_pad,
    pkcs7_unpad,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
    sm4_ctr_xor,
    sm4_ecb_decrypt,
    sm4_ecb_encrypt,
)

__all__ = ["run_self_test"]


class SelfTestResult(NamedTuple):
    """单项自检结果。"""

    name: str
    ok: bool
    detail: str
    elapsed_ms: float


# ---------------------------------------------------------------------------
# 参考实现（仅用于对照检查）
# ---------------------------------------------------------------------------


class _SM3Hasher:
    """hashlib 风格适配器，让 CPython 标准库 ``hmac`` 模块能使用 SM3 做对照。"""

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
    """内联 RFC 8018 参考实现（基于 CPython ``hmac`` 模块 + SM3 适配器）。"""

    def prf(key: bytes, msg: bytes) -> bytes:
        return _stdlib_hmac.new(key, msg, _SM3Hasher).digest()

    blocks = (dklen + 31) // 32
    out = b""
    for i in range(1, blocks + 1):
        u = prf(password, salt + i.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = prf(password, u)
            for j in range(len(t)):
                t[j] ^= u[j]
        out += bytes(t)
    return out[:dklen]


# ---------------------------------------------------------------------------
# 自检项
# ---------------------------------------------------------------------------


def _check_sm3_kat() -> str:
    for name, msg, want in _kat.SM3_VECTORS:
        got = sm3_hexdigest(msg)
        assert got == want, "SM3(%r) = %s，期望 %s" % (name, got, want)
    return "%d 个标准向量（empty/abc/abcd×16）一致" % len(_kat.SM3_VECTORS)


def _check_sm3_incremental() -> str:
    data = bytes(range(256)) * 3
    one_shot = SM3(data).hexdigest()
    h = SM3()
    for i in range(0, len(data), 37):
        h.update(data[i : i + 37])
    assert h.hexdigest() == one_shot, "增量式结果与一次性不一致"
    assert h.digest() == SM3(data).digest(), "digest() 重复调用结果不一致"
    return "768 字节分 21 次 update 与一次性结果一致"


def _check_hmac() -> str:
    cases = [
        (b"key", b"The quick brown fox jumps over the lazy dog"),
        (b"k" * 64, b"exactly block size key"),
        (b"k" * 100, b"long key gets hashed first"),
        (b"", b"empty key"),
        (b"key", b""),
    ]
    for key, msg in cases:
        want = _stdlib_hmac.new(key, msg, _SM3Hasher).hexdigest()
        got = hmac_sm3(key, msg).hex()
        assert got == want, "HMAC-SM3(%r, %r) 与标准库对照不一致" % (key, msg)
    return "%d 组用例与 CPython hmac 模块（RFC 2104 结构）一致" % len(cases)


def _check_pbkdf2() -> str:
    cases = [(b"password", b"salt", 1, 32), (b"password", b"salt", 500, 32), (b"p", b"s", 64, 16)]
    for pw, salt, it, dklen in cases:
        want = _ref_pbkdf2(pw, salt, it, dklen).hex()
        got = pbkdf2_hmac_sm3(pw, salt, it, dklen).hex()
        assert got == want, "PBKDF2-HMAC-SM3(iter=%d) 与 RFC 8018 参考实现不一致" % it
    return "%d 组用例（c=1/500/64）与内联 RFC 8018 参考实现一致" % len(cases)


def _check_sm4_block_kat() -> str:
    k = _kat.SM4_BLOCK_KAT
    c = SM4(bytes.fromhex(k["key"]))
    got = c.encrypt_block(bytes.fromhex(k["plaintext"])).hex()
    assert got == k["ciphertext"], "SM4 单分组向量不一致：%s" % got
    back = c.decrypt_block(bytes.fromhex(k["ciphertext"])).hex()
    assert back == k["plaintext"], "SM4 解密标准密文失败"
    return "GB/T 32907-2016 A.1 示例加解密一致"


def _check_sm4_modes() -> str:
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    for size in (0, 1, 15, 16, 17, 31, 32, 33, 100, 257):
        pt = os.urandom(size)
        assert sm4_ecb_decrypt(key, sm4_ecb_encrypt(key, pt)) == pt, "ECB 往返失败（%d 字节）" % size
        assert sm4_cbc_decrypt(key, iv, sm4_cbc_encrypt(key, iv, pt)) == pt, "CBC 往返失败（%d 字节）" % size
        assert sm4_ctr_xor(key, iv, sm4_ctr_xor(key, iv, pt)) == pt, "CTR 往返失败（%d 字节）" % size
    # CBC 标准向量
    k = _kat.SM4_CBC_KAT
    ct = sm4_cbc_encrypt(bytes.fromhex(k["key"]), bytes.fromhex(k["iv"]), bytes.fromhex(k["plaintext"]))
    assert ct.hex() == k["ciphertext"], "SM4-CBC 冻结向量不一致"
    return "ECB/CBC/CTR 各 10 种长度往返 + CBC 冻结向量一致"


def _check_pkcs7() -> str:
    for size in range(0, 33):
        data = os.urandom(size)
        padded = pkcs7_pad(data)
        assert len(padded) == (size // 16 + 1) * 16, "填充后长度错误（%d）" % size
        assert pkcs7_unpad(padded) == data, "填充往返失败（%d）" % size
    bad_pads = [
        b"",
        b"\x00" * 16,
        b"A" * 14 + b"\x03\x03",  # 最后两个字节不一致
        b"A" * 15 + b"\x11",  # 填充值 17 越界
        b"A" * 15 + b"\x00",  # 填充值 0 非法
        b"A" * 20,  # 非分组倍数
    ]
    for bad in bad_pads:
        try:
            pkcs7_unpad(bad)
        except ValueError:
            continue
        raise AssertionError("非法填充未被拒绝：%r" % bad)
    return "0..32 字节往返 + 6 类非法填充全部被拒绝"


def _check_curve() -> str:
    # 1) G 在曲线上
    assert point_is_on_curve(G), "基点 G 不在曲线上"
    # 2) [n]G = O（不做模 n 归约的原始标量乘，真实执行 256 轮倍点/点加）
    t0 = time.perf_counter()
    ninf = _scalar_mul_raw(N, G)
    dt = time.perf_counter() - t0
    assert ninf.is_infinity, "[n]G 不是无穷远点"
    # 3) 曲线参数位长
    assert N.bit_length() == 256 and G.x is not None and G.x.bit_length() <= 256
    return "[n]G = O（原始标量乘实算，%.0f ms）；G 满足曲线方程" % (dt * 1000)


def _check_sm2_std() -> str:
    ex = _kat.SM2_STD_EXAMPLE
    d = int(ex.d, 16)
    pub = public_key_from_private(d)
    assert pub.x == int(ex.pub_x, 16) and pub.y == int(ex.pub_y, 16), "标准示例公钥不一致"
    za = compute_za(pub, ex.ida)
    assert za.hex().upper() == ex.za, "标准示例 Z_A 不一致"
    r, s = sm2_sign(d, ex.msg, ida=ex.ida, k=int(ex.k, 16))
    assert "%064X" % r == ex.r and "%064X" % s == ex.s, "标准示例签名 (r, s) 不一致"
    assert sm2_verify(pub, ex.msg, r, s, ida=ex.ida), "标准示例签名验签失败"
    return "GB/T 32918.2 附录 A 示例 Z_A 与 (r, s) 完整复现"


def _check_sm2_sign() -> str:
    d, pub = generate_keypair()
    msg = b"sm-crypto-toolbox self-test"
    r1, s1 = sm2_sign(d, msg)
    r2, s2 = sm2_sign(d, msg)
    assert (r1, s1) != (r2, s2), "两次签名不应完全相同（随机 k 失效）"
    assert sm2_verify(pub, msg, r1, s1) and sm2_verify(pub, msg, r2, s2), "签名验签失败"
    tampered = [
        (pub, b"sm-crypto-toolbox self-tesT", r1, s1),
        (pub, msg, r1, (s1 + 1) % N),
        (pub, msg, (r1 + 1) % N, s1),
    ]
    d2, other = generate_keypair()
    tampered.append((other, msg, r1, s1))
    for p, m, rr, ss in tampered:
        assert not sm2_verify(p, m, rr, ss), "篡改数据竟然验签通过"
    return "随机性正常；4 类篡改（消息/r/s/公钥）全部拒绝"


def _check_sm2_encrypt() -> str:
    d, pub = generate_keypair()
    for size in (1, 16, 31, 32, 100):
        msg = os.urandom(size)
        for mode in ("C1C3C2", "C1C2C3"):
            ct = sm2_encrypt(pub, msg, mode=mode)
            assert sm2_decrypt(d, ct, mode=mode) == msg, "SM2 加解密往返失败"
            # 无 04 前缀（gmssl 风格）也须可解
            assert sm2_decrypt(d, ct[1:], mode=mode) == msg, "无 04 前缀密文解密失败"
    ct = sm2_encrypt(pub, b"tamper me")
    bad = bytearray(ct)
    bad[40] ^= 0x01  # 破坏 C1 内部字节
    try:
        sm2_decrypt(d, bytes(bad))
    except ValueError:
        pass
    else:
        raise AssertionError("被篡改的密文竟然解密成功")
    return "5 种长度 × 2 种排列往返；04 前缀兼容；篡改密文被拒"


def _check_sm2_der() -> str:
    d, pub = generate_keypair()
    msg = b"der roundtrip"
    r, s = sm2_sign(d, msg)
    der = encode_signature_der(r, s)
    assert decode_signature_der(der) == (r, s), "DER 编解码往返失败"
    assert der[0] == 0x30, "DER 首字节应为 SEQUENCE"

    assert sm2_verify_der(pub, msg, der), "DER 签名验签失败"
    junk = [b"", b"\x30\x00", b"\x31\x06\x02\x01\x01\x02\x01\x01", der + b"\x00"]
    for bad in junk:
        try:
            decode_signature_der(bad)
        except ValueError:
            continue
        raise AssertionError("非法 DER 未被拒绝：%r" % bad)
    return "编解码往返一致；4 类非法 DER 被拒绝"


def _check_filecrypt() -> str:
    wrong_rejected = 0
    wrong_total = 0
    for cipher in ("sm4-cbc", "sm4-ctr", "sm4-ecb"):
        for size in (0, 1, 15, 16, 17, 200):
            pt = os.urandom(size)
            container = encrypt_bytes(pt, cipher=cipher, password="口令口令", iterations=300)
            header = parse_header(container)
            assert header.cipher == cipher and header.is_password_mode, "文件头字段错误"
            assert header.iterations == 300, "迭代次数未写入文件头"
            assert decrypt_bytes(container, password="口令口令") == pt, "容器往返失败"
            # 容器不含认证标签：错误口令在 CBC/ECB 下通常由填充校验拒绝，
            # 在 CTR 下只能得到乱码——两种情况都要求绝不返回正确明文。
            # （空文件 + CTR 是退化情形：XOR 空数据必然得到空串，跳过该断言。）
            if size == 0 and cipher == "sm4-ctr":
                continue
            wrong_total += 1
            try:
                got = decrypt_bytes(container, password="wrong")
            except ValueError:
                wrong_rejected += 1
            else:
                assert got != pt, "错误口令竟然得到了正确明文"
    key = os.urandom(16)
    ct = encrypt_bytes(b"raw key mode", cipher="sm4-cbc", key=key)
    assert decrypt_bytes(ct, key=key) == b"raw key mode", "原始密钥模式往返失败"
    return "3 算法 × 6 长度往返；错误口令 %d/%d 被填充校验拒绝（余为乱码，容器无认证）" % (
        wrong_rejected,
        wrong_total,
    )


def _check_sm4_1m(full: bool) -> str:
    k = _kat.SM4_1M_KAT
    c = SM4(bytes.fromhex(k["key"]))
    blk = bytes.fromhex(k["key"])
    for _ in range(k["iterations"]):
        blk = c.encrypt_block(blk)
    assert blk.hex() == k["ciphertext"], "100 万次迭代结果与标准向量不一致"
    return "GB/T 32907-2016 A.2：%d 次迭代结果一致" % k["iterations"]


# ---------------------------------------------------------------------------
# 运行器
# ---------------------------------------------------------------------------

_FAST_CHECKS: List[Tuple[str, Callable[[], str]]] = [
    ("SM3 标准向量（GB/T 32905-2016 示例）", _check_sm3_kat),
    ("SM3 增量式接口 == 一次性接口", _check_sm3_incremental),
    ("HMAC-SM3 ↔ CPython hmac（RFC 2104）", _check_hmac),
    ("PBKDF2-HMAC-SM3 ↔ RFC 8018 参考实现", _check_pbkdf2),
    ("SM4 分组标准向量（GB/T 32907-2016 示例）", _check_sm4_block_kat),
    ("SM4 ECB/CBC/CTR 往返与冻结向量", _check_sm4_modes),
    ("PKCS#7 填充边界与非法填充拒绝", _check_pkcs7),
    ("SM2 曲线健全性（G 在曲线上、[n]G = O）", _check_curve),
    ("SM2 标准签名示例复现（Z_A/e/r/s）", _check_sm2_std),
    ("SM2 签名随机性与篡改拒绝", _check_sm2_sign),
    ("SM2 公钥加解密往返（C1C3C2/C1C2C3）", _check_sm2_encrypt),
    ("SM2 签名 DER 编解码往返", _check_sm2_der),
    ("SMCT 文件容器往返（口令/原始密钥）", _check_filecrypt),
]


def run_self_test(full: bool = False, stream=None) -> bool:
    """运行全部自检项，打印结果表，返回整体是否通过。

    :param full: 额外运行 SM4 100 万次迭代标准向量（约 25 秒）
    :param stream: 输出流（默认 stderr 之外的 stdout；测试可传入 io.StringIO）
    """
    stream = stream or sys.stdout
    checks = list(_FAST_CHECKS)
    if full:
        checks.append(
            ("SM4 100 万次迭代标准向量（GB/T 32907-2016 A.2，约 25s）", lambda: _check_sm4_1m(True))
        )

    results: List[SelfTestResult] = []
    t_all = time.perf_counter()
    for name, fn in checks:
        t0 = time.perf_counter()
        try:
            detail = fn()
            ok = True
        except Exception as exc:  # noqa: BLE001 - 自检需要兜住全部失败
            detail = "%s: %s" % (type(exc).__name__, exc)
            ok = False
        elapsed = (time.perf_counter() - t0) * 1000.0
        results.append(SelfTestResult(name, ok, detail, elapsed))

    total_ms = (time.perf_counter() - t_all) * 1000.0
    n_ok = sum(1 for r in results if r.ok)
    width = max(len(r.name) for r in results)
    for r in results:
        mark = "PASS" if r.ok else "FAIL"
        print("[%s] %-*s  %6.1f ms  %s" % (mark, width, r.name, r.elapsed_ms, r.detail), file=stream)
    print("-" * 72, file=stream)
    print(
        "自检结果: %d/%d 通过，总耗时 %.2f s%s"
        % (n_ok, len(results), total_ms / 1000.0, "（含 100 万次迭代慢速项）" if full else ""),
        file=stream,
    )
    return n_ok == len(results)
