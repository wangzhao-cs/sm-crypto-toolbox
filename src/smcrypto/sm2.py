"""SM2 椭圆曲线公钥密码算法（GM/T 0003 / GB/T 32918）——纯 Python 从零实现。

本模块基于推荐的 256 位素域椭圆曲线 **sm2p256v1**，提供：

* 仿射坐标点运算（点加 / 倍点 / 标量乘，双倍-加法算法）；
* 密钥对生成、公钥编解码（非压缩 / 裸 X||Y）；
* 数字签名与验签（SM2-with-SM3，含 Z_A 杂凑值，ID 默认 ``'1234567812345678'``）；
* 公钥加密与解密（支持 C1C2C3 与 C1C3C2 两种密文排列）；
* 签名值的 DER 编码与解析。

实现仅依赖 Python 标准库（``secrets`` 用于安全随机数），无第三方依赖。

参考标准：
* GM/T 0003.1~0003.4-2012《SM2 椭圆曲线公钥密码算法》
* GB/T 32918.1~32918.4-2016 同名标准

示例::

    >>> from smcrypto.sm2 import generate_keypair, sm2_sign, sm2_verify
    >>> d, pub = generate_keypair()
    >>> r, s = sm2_sign(d, b"hello sm2")
    >>> sm2_verify(pub, b"hello sm2", r, s)
    True

"""

from __future__ import annotations

import secrets
from typing import List, NamedTuple, Optional, Tuple

from .sm3 import sm3_digest, sm3_kdf

__all__ = [
    "P",
    "A",
    "B",
    "N",
    "GX",
    "GY",
    "G",
    "INFINITY",
    "IDA_DEFAULT",
    "Point",
    "point_add",
    "point_double",
    "scalar_mul",
    "point_is_on_curve",
    "encode_point",
    "decode_point",
    "generate_keypair",
    "public_key_from_private",
    "compute_za",
    "sm2_sign",
    "sm2_verify",
    "sm2_sign_der",
    "sm2_verify_der",
    "encode_signature_der",
    "decode_signature_der",
    "sm2_encrypt",
    "sm2_decrypt",
]

# ---------------------------------------------------------------------------
# sm2p256v1 曲线参数（GM/T 0003.5-2012 推荐曲线），已与 gmssl 源码核对一致
# ---------------------------------------------------------------------------

#: 素域特征 p
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
#: 曲线方程 y² = x³ + ax + b 中的 a
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
#: 曲线方程中的 b
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
#: 基点 G 的阶 n
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
#: 基点 G 的 x 坐标
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
#: 基点 G 的 y 坐标
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

#: 默认签名者标识 ID_A（GM/T 0003.2-2012 附录示例值）
IDA_DEFAULT = b"1234567812345678"


class Point(NamedTuple):
    """仿射坐标椭圆曲线点。``x``/``y`` 为 ``None`` 时表示无穷远点 O。"""

    x: Optional[int] = None
    y: Optional[int] = None

    @property
    def is_infinity(self) -> bool:
        """是否为无穷远点。"""
        return self.x is None

    def __str__(self) -> str:  # pragma: no cover - 便于调试
        if self.is_infinity:
            return "Point(∞)"
        return "Point(%064x, %064x)" % (self.x, self.y)


#: 无穷远点
INFINITY = Point(None, None)
#: 基点 G
G = Point(GX, GY)


def _inv_mod(x: int, m: int = P) -> int:
    """模逆元（m 为素数时可用费马小定理）。"""
    x %= m
    if x == 0:
        raise ZeroDivisionError("模逆元不存在：0 不可逆")
    return pow(x, m - 2, m)


def point_is_on_curve(pt: Point) -> bool:
    """校验点是否落在 sm2p256v1 曲线上（无穷远点视为合法）。"""
    if pt.is_infinity:
        return True
    if pt.x is None or pt.y is None:
        return False
    if not (0 <= pt.x < P and 0 <= pt.y < P):
        return False
    return (pt.y * pt.y - (pt.x * pt.x * pt.x + A * pt.x + B)) % P == 0


def point_double(pt: Point) -> Point:
    """倍点 2P（仿射坐标）。"""
    if pt.is_infinity:
        return INFINITY
    x1, y1 = pt.x, pt.y
    if y1 == 0:
        return INFINITY
    lam = (3 * x1 * x1 + A) * _inv_mod(2 * y1) % P
    x3 = (lam * lam - 2 * x1) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return Point(x3, y3)


def point_add(p1: Point, p2: Point) -> Point:
    """点加 P1 + P2（仿射坐标）。"""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    x1, y1 = p1.x, p1.y
    x2, y2 = p2.x, p2.y
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return INFINITY
        return point_double(p1)
    lam = (y2 - y1) * _inv_mod(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return Point(x3, y3)


def _scalar_mul_raw(k: int, pt: Point) -> Point:
    """不做模 n 归约的标量乘（双倍-加法 / 从高位到低位）。

    内部函数：公开 API 会先归约 ``k``，而曲线阶的健全性自检需要按原值计算
    ``[n]G`` 是否等于无穷远点，故保留此"原始"版本。
    """
    if pt.is_infinity or k == 0:
        return INFINITY
    result = INFINITY
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result


def scalar_mul(k: int, pt: Point = G) -> Point:
    """标量乘 [k]P（双倍-加法，从高位到低位扫描）。

    :param k: 非负整数标量（模曲线阶 n 归约后计算）
    :param pt: 曲线上的点，默认基点 G
    """
    if pt.is_infinity:
        return INFINITY
    return _scalar_mul_raw(k % N, pt)


# ---------------------------------------------------------------------------
# 公钥编解码
# ---------------------------------------------------------------------------


def encode_point(pt: Point, prefix: bool = True) -> bytes:
    """编码曲线点：非压缩格式 ``04 || X || Y``（``prefix=False`` 时为裸 ``X || Y``）。

    与 gmssl 等实现互操作时注意：gmssl 默认使用**不带** 04 前缀的裸格式。
    """
    if pt.is_infinity:
        raise ValueError("无法编码无穷远点")
    body = pt.x.to_bytes(32, "big") + pt.y.to_bytes(32, "big")
    return (b"\x04" + body) if prefix else body


def decode_point(data: bytes) -> Point:
    """解析曲线点，接受 ``04||X||Y``（65 字节）或裸 ``X||Y``（64 字节）。

    解析后校验点确实在曲线上，否则抛出 :class:`ValueError`。
    """
    data = bytes(data)
    if len(data) == 65 and data[0] == 0x04:
        data = data[1:]
    if len(data) != 64:
        raise ValueError("公钥/曲线点编码长度非法：期望 64 或 65 字节，实际 %d" % len(data))
    pt = Point(int.from_bytes(data[:32], "big"), int.from_bytes(data[32:], "big"))
    if not point_is_on_curve(pt):
        raise ValueError("公钥/曲线点不在 sm2p256v1 曲线上")
    if pt.is_infinity:
        raise ValueError("公钥不能为无穷远点")
    return pt


# ---------------------------------------------------------------------------
# 密钥对
# ---------------------------------------------------------------------------


def generate_keypair() -> Tuple[int, Point]:
    """生成 SM2 密钥对，返回 ``(私钥 d, 公钥点 P)``，其中 d ∈ [1, n-2]。"""
    d = secrets.randbelow(N - 2) + 1
    return d, scalar_mul(d, G)


def public_key_from_private(d: int) -> Point:
    """由私钥计算公钥 P = [d]G。"""
    if not 1 <= d <= N - 2:
        raise ValueError("私钥 d 必须满足 1 <= d <= n-2")
    return scalar_mul(d, G)


# ---------------------------------------------------------------------------
# Z_A 与签名 / 验签（SM2-with-SM3）
# ---------------------------------------------------------------------------


def compute_za(pub: Point, ida: bytes = IDA_DEFAULT) -> bytes:
    """计算签名者标识杂凑值 Z_A（GM/T 0003.2-2012 5.5 节）。

    Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)

    :param pub: 签名者公钥点 P_A
    :param ida: 标识 ID_A（默认 ``'1234567812345678'``）
    :returns: 32 字节 Z_A
    """
    if pub.is_infinity:
        raise ValueError("公钥不能为无穷远点")
    ida_b = bytes(ida)
    if len(ida_b) * 8 > 0xFFFF:
        raise ValueError("ID_A 过长")
    entl = (len(ida_b) * 8).to_bytes(2, "big")
    msg = (
        entl
        + ida_b
        + A.to_bytes(32, "big")
        + B.to_bytes(32, "big")
        + GX.to_bytes(32, "big")
        + GY.to_bytes(32, "big")
        + pub.x.to_bytes(32, "big")
        + pub.y.to_bytes(32, "big")
    )
    return sm3_digest(msg)


def _hash_msg(pub: Point, msg: bytes, ida: bytes) -> int:
    """计算待签名杂凑值 e = SM3(Z_A || M)，返回整数。"""
    za = compute_za(pub, ida)
    return int.from_bytes(sm3_digest(za + bytes(msg)), "big")


def sign_digest(d: int, e: int, k: Optional[int] = None) -> Tuple[int, int]:
    """对杂凑值 e 直接进行 SM2 签名，返回 ``(r, s)``（均为整数）。

    :param d: 私钥（1 <= d <= n-2）
    :param e: 被签名杂凑值（整数，内部按 mod n 参与运算）
    :param k: 可选的一次性随机数；传入固定值可复现签名（测试 / 向量用），
              不满足签名条件时抛出 :class:`ValueError`
    """
    if not 1 <= d <= N - 2:
        raise ValueError("私钥 d 必须满足 1 <= d <= n-2")
    const_k = k is not None
    attempts = 0
    while True:
        attempts += 1
        if const_k and attempts > 1:
            # 固定 k 且条件不满足：不可能通过重试改变结果
            raise ValueError("给定随机数 k 不满足签名条件，请更换 k")
        kk = k if const_k else secrets.randbelow(N - 1) + 1
        x1 = scalar_mul(kk, G)
        if x1.is_infinity:
            continue
        r = (e + x1.x) % N
        if r == 0 or (r + kk) % N == 0:
            continue
        s = _inv_mod(1 + d, N) * (kk - r * d) % N
        if s == 0:
            continue
        return r, s


def verify_digest(pub: Point, e: int, r: int, s: int) -> bool:
    """对杂凑值 e 用公钥验签（GM/T 0003.2-2012 6.2 节）。"""
    if pub.is_infinity or not point_is_on_curve(pub):
        raise ValueError("公钥非法")
    if not (1 <= r <= N - 1 and 1 <= s <= N - 1):
        return False
    t = (r + s) % N
    if t == 0:
        return False
    pt = point_add(scalar_mul(s, G), scalar_mul(t, pub))
    if pt.is_infinity:
        return False
    return (e + pt.x) % N == r


def sm2_sign(
    priv: int,
    msg: bytes,
    ida: bytes = IDA_DEFAULT,
    k: Optional[int] = None,
) -> Tuple[int, int]:
    """SM2-with-SM3 签名：先算 e = SM3(Z_A||M) 再签名，返回 ``(r, s)``。"""
    pub = public_key_from_private(priv)
    return sign_digest(priv, _hash_msg(pub, msg, ida), k)


def sm2_verify(
    pub: Point,
    msg: bytes,
    r: int,
    s: int,
    ida: bytes = IDA_DEFAULT,
) -> bool:
    """SM2-with-SM3 验签：先算 e = SM3(Z_A||M) 再校验 ``(r, s)``。"""
    return verify_digest(pub, _hash_msg(pub, msg, ida), r, s)


# ---------------------------------------------------------------------------
# 签名值的 DER 编码 / 解析
# ---------------------------------------------------------------------------


def encode_signature_der(r: int, s: int) -> bytes:
    """把签名 ``(r, s)`` 编码为 DER（``SEQUENCE { INTEGER r, INTEGER s }``）。"""

    def _int_der(v: int) -> bytes:
        if v < 0:
            raise ValueError("DER 整数不能为负")
        body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
        if body[0] & 0x80:  # 最高位为 1 时补 0x00，保证按无符号正整数解析
            body = b"\x00" + body
        return b"\x02" + bytes([len(body)]) + body

    payload = _int_der(r) + _int_der(s)
    if len(payload) >= 0x80:
        raise ValueError("签名 DER 长度超出单字节表示范围")
    return b"\x30" + bytes([len(payload)]) + payload


def decode_signature_der(data: bytes) -> Tuple[int, int]:
    """解析 DER 编码的签名，返回 ``(r, s)``；格式非法时抛出 :class:`ValueError`。"""
    data = bytes(data)

    def _read_tlv(buf: bytes, pos: int, expect_tag: int) -> Tuple[bytes, int]:
        """读取一个 TLV（支持单字节与长形式长度），返回 (内容, 新位置)。"""
        if pos + 2 > len(buf) or buf[pos] != expect_tag:
            raise ValueError("DER 解析失败：期望标签 0x%02x" % expect_tag)
        length = buf[pos + 1]
        pos += 2
        if length & 0x80:
            n_len = length & 0x7F
            if n_len == 0 or pos + n_len > len(buf):
                raise ValueError("DER 解析失败：长度字段非法")
            length = int.from_bytes(buf[pos : pos + n_len], "big")
            pos += n_len
        if pos + length > len(buf):
            raise ValueError("DER 解析失败：长度超出数据范围")
        return buf[pos : pos + length], pos + length

    def _to_int(body: bytes) -> int:
        if len(body) == 0:
            raise ValueError("DER 解析失败：空 INTEGER")
        if body[0] & 0x80:
            raise ValueError("DER 解析失败：负整数不受支持")
        return int.from_bytes(body, "big")

    seq, end = _read_tlv(data, 0, 0x30)
    if end != len(data):
        raise ValueError("DER 解析失败：SEQUENCE 之后存在多余字节")
    r_body, pos = _read_tlv(seq, 0, 0x02)
    s_body, pos = _read_tlv(seq, pos, 0x02)
    if pos != len(seq):
        raise ValueError("DER 解析失败：INTEGER 之后存在多余字节")
    return _to_int(r_body), _to_int(s_body)


def sm2_sign_der(
    priv: int,
    msg: bytes,
    ida: bytes = IDA_DEFAULT,
    k: Optional[int] = None,
) -> bytes:
    """SM2-with-SM3 签名，返回 DER 字节串。"""
    r, s = sm2_sign(priv, msg, ida, k)
    return encode_signature_der(r, s)


def sm2_verify_der(
    pub: Point,
    msg: bytes,
    der_sig: bytes,
    ida: bytes = IDA_DEFAULT,
) -> bool:
    """校验 DER 编码的 SM2 签名。"""
    r, s = decode_signature_der(der_sig)
    return sm2_verify(pub, msg, r, s, ida)


# ---------------------------------------------------------------------------
# 公钥加密 / 解密（GM/T 0003.4-2012）
# ---------------------------------------------------------------------------

_VALID_MODES = ("C1C3C2", "C1C2C3")


def _check_mode(mode: str) -> str:
    if mode not in _VALID_MODES:
        raise ValueError("密文排列必须是 %s 之一" % " 或 ".join(_VALID_MODES))
    return mode


def sm2_encrypt(
    pub: Point,
    msg: bytes,
    mode: str = "C1C3C2",
    k: Optional[int] = None,
    prefix: bool = True,
) -> bytes:
    """SM2 公钥加密（GM/T 0003.4-2012 第 6 章）。

    :param pub: 接收方公钥点
    :param msg: 明文（非空字节串）
    :param mode: 密文排列，``"C1C3C2"``（默认，现行常用）或 ``"C1C2C3"``（GM/T 0003.4-2012 原始顺序）
    :param k: 可选固定随机数（测试 / 向量用），正常留 ``None``
    :param prefix: C1 是否带 ``04`` 非压缩点前缀（默认 True；gmssl 用 False）
    :returns: 密文 ``C1 || C3 || C2`` 或 ``C1 || C2 || C3``

    密文各段含义：C1 = [k]G（曲线点）；C2 = M ⊕ KDF(x2||y2)；C3 = SM3(x2||M||y2)。
    若 KDF 输出为全 0 比特串，按标准更换 k 重试。
    """
    mode = _check_mode(mode)
    msg = bytes(msg)
    if len(msg) == 0:
        raise ValueError("SM2 加密不支持空明文")
    if pub.is_infinity or not point_is_on_curve(pub):
        raise ValueError("公钥非法")
    while True:
        kk = k if k is not None else secrets.randbelow(N - 1) + 1
        c1 = scalar_mul(kk, G)
        if c1.is_infinity:
            if k is not None:
                raise ValueError("随机数 k 非法")
            continue
        shared = scalar_mul(kk, pub)
        if shared.is_infinity:
            if k is not None:
                raise ValueError("随机数 k 非法")
            continue
        x2 = shared.x.to_bytes(32, "big")
        y2 = shared.y.to_bytes(32, "big")
        t = sm3_kdf(x2 + y2, len(msg))
        if t != bytes(len(t)):  # 非全零
            break
        if k is not None:
            raise ValueError("给定随机数 k 导致 KDF 输出全零，请更换 k")
    c2 = bytes(a ^ b for a, b in zip(msg, t))
    c3 = sm3_digest(x2 + msg + y2)
    c1_enc = encode_point(c1, prefix=prefix)
    body = (c1_enc + c3 + c2) if mode == "C1C3C2" else (c1_enc + c2 + c3)
    return body


def _split_cipher(cipher: bytes, mode: str) -> Tuple[bytes, bytes, bytes]:
    """按排列模式切分（不含 04 前缀的）密文为 (C1, C2, C3)。"""
    # 最短合法长度：C1(64) + C3(32) + C2(>=1)
    if len(cipher) < 96 + 1:
        raise ValueError("SM2 密文长度过短")
    c1, rest = cipher[:64], cipher[64:]
    if mode == "C1C3C2":
        c3, c2 = rest[:32], rest[32:]
    else:
        c2, c3 = rest[:-32], rest[-32:]
    if len(c2) == 0 or len(c3) != 32:
        raise ValueError("SM2 密文长度非法")
    return c1, c2, c3


def _decrypt_body(priv: int, body: bytes, mode: str) -> bytes:
    c1_b, c2, c3 = _split_cipher(body, mode)
    c1 = decode_point(c1_b)  # 含在曲线校验
    shared = scalar_mul(priv, c1)
    if shared.is_infinity:
        raise ValueError("SM2 解密失败：派生点为无穷远点")
    x2 = shared.x.to_bytes(32, "big")
    y2 = shared.y.to_bytes(32, "big")
    t = sm3_kdf(x2 + y2, len(c2))
    if t == bytes(len(t)):
        raise ValueError("SM2 解密失败：KDF 输出为全零比特串")
    msg = bytes(a ^ b for a, b in zip(c2, t))
    if sm3_digest(x2 + msg + y2) != c3:
        raise ValueError("SM2 解密失败：C3 校验值不匹配（密文被篡改或密钥错误）")
    return msg


def sm2_decrypt(priv: int, cipher: bytes, mode: str = "C1C3C2") -> bytes:
    """SM2 公钥解密，成功时校验 C3 并返回明文。

    自动兼容 C1 带 / 不带 ``04`` 前缀两种编码（依次尝试并校验 C3），
    校验失败时抛出 :class:`ValueError`。
    """
    mode = _check_mode(mode)
    if not 1 <= priv <= N - 2:
        raise ValueError("私钥 d 必须满足 1 <= d <= n-2")
    cipher = bytes(cipher)
    candidates: List[bytes] = []
    # C1 带 04 前缀时总长为 1+64+32+len(C2) ≥ 98
    if len(cipher) >= 98 and cipher[0] == 0x04:
        candidates.append(cipher[1:])
    candidates.append(cipher)
    last_err: Optional[Exception] = None
    for body in candidates:
        try:
            return _decrypt_body(priv, body, mode)
        except ValueError as exc:
            last_err = exc
    raise ValueError("SM2 解密失败：%s" % last_err)
