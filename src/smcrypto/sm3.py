"""SM3 密码杂凑算法（GB/T 32905-2016）——纯 Python 从零实现。

本模块提供：

* :func:`sm3_digest` / :func:`sm3_hexdigest` —— 一次性杂凑接口；
* :class:`SM3` —— 增量式杂凑对象（``update`` / ``digest`` / ``copy``）；
* :func:`hmac_sm3` —— HMAC-SM3（RFC 2104 结构，散列函数为 SM3）；
* :func:`pbkdf2_hmac_sm3` —— PBKDF2-HMAC-SM3 口令派生（RFC 8018）；
* :func:`sm3_kdf` —— SM2 密钥派生函数 KDF（GM/T 0003.4-2012）。

实现仅依赖 Python 标准库，无任何第三方依赖。

参考标准：GB/T 32905-2016《信息安全技术 SM3 密码杂凑算法》。

示例::

    >>> from smcrypto.sm3 import sm3_hexdigest
    >>> sm3_hexdigest(b"abc")
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'

"""

from __future__ import annotations

from typing import List, Optional, Union

__all__ = [
    "SM3_BLOCK_SIZE",
    "SM3_DIGEST_SIZE",
    "SM3",
    "new",
    "sm3_digest",
    "sm3_hexdigest",
    "hmac_sm3",
    "pbkdf2_hmac_sm3",
    "sm3_kdf",
]

#: 分组长度（字节）
SM3_BLOCK_SIZE = 64
#: 摘要长度（字节）
SM3_DIGEST_SIZE = 32

_MASK32 = 0xFFFFFFFF

# 初始值 IV（GB/T 32905-2016 4.1 节）
_IV = (
    0x7380166F,
    0x4914B2B9,
    0x172442D7,
    0xDA8A0600,
    0xA96F30BC,
    0x163138AA,
    0xE38DEE4D,
    0xB0FB0E4E,
)

# 常量 T_j：第 0~15 轮取 0x79CC4519，第 16~63 轮取 0x7A879D8A
_T = (0x79CC4519,) * 16 + (0x7A879D8A,) * 48

_Data = Union[bytes, bytearray, memoryview]


def _rotl32(x: int, n: int) -> int:
    """32 位循环左移（n 按 mod 32 处理）。"""
    n &= 31
    if n == 0:
        return x & _MASK32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _make_t_rotl():
    """预计算 rotl(T_j, j)（j = 0..63），压缩函数内直接查表，减少热路径开销。"""
    return tuple(_rotl32(_T[j], j) for j in range(64))


_T_ROTL = _make_t_rotl()


def _p0(x: int) -> int:
    """置换函数 P0(X) = X ^ (X <<< 9) ^ (X <<< 17)。"""
    return x ^ _rotl32(x, 9) ^ _rotl32(x, 17)


def _p1(x: int) -> int:
    """置换函数 P1(X) = X ^ (X <<< 15) ^ (X <<< 23)。"""
    return x ^ _rotl32(x, 15) ^ _rotl32(x, 23)


def _ff(j: int, x: int, y: int, z: int) -> int:
    """布尔函数 FF_j：j∈[0,15] 为 X^Y^Z；j∈[16,63] 为 (X&Y)|(X&Z)|(Y&Z)。"""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(j: int, x: int, y: int, z: int) -> int:
    """布尔函数 GG_j：j∈[0,15] 为 X^Y^Z；j∈[16,63] 为 (X&Y)|(~X&Z)。"""
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & _MASK32) & z)


def _compress(v: List[int], block: bytes) -> List[int]:
    """压缩函数 CF（GB/T 32905-2016 5.3.2 节）。

    :param v: 256 比特链变量，8 个 32 位字
    :param block: 恰好 64 字节的分组
    :returns: 新的链变量（8 个 32 位字）

    说明：为保证纯 Python 下可用的速度，热路径中把 32 位循环左移写成内联
    表达式、T 的循环移位预计算为 ``_T_ROTL`` 查表（与逐轮调用 :func:`_rotl32`
    在数学上完全等价，交叉验证测试覆盖了两者的一致性）。
    """
    mask = _MASK32
    t_rotl = _T_ROTL

    # ① 消息扩展：W_0..W_67
    w = [int.from_bytes(block[i : i + 4], "big") for i in range(0, 64, 4)]
    for j in range(16, 68):
        x = w[j - 16] ^ w[j - 9] ^ (((w[j - 3] << 15) | (w[j - 3] >> 17)) & mask)
        # P1(X) = X ^ (X <<< 15) ^ (X <<< 23)
        p1 = (x ^ ((x << 15) | (x >> 17)) ^ ((x << 23) | (x >> 9))) & mask
        w.append((p1 ^ ((w[j - 13] << 7) | (w[j - 13] >> 25)) ^ w[j - 6]) & mask)

    # ② 迭代压缩
    a, b, c, d, e, f, g, h = v
    for j in range(16):
        a12 = ((a << 12) | (a >> 20)) & mask
        ss1 = ((a12 + e + t_rotl[j]) & mask)
        ss1 = ((ss1 << 7) | (ss1 >> 25)) & mask
        ss2 = ss1 ^ a12
        tt1 = (a ^ b ^ c) + d + ss2 + (w[j] ^ w[j + 4])
        tt2 = (e ^ f ^ g) + h + ss1 + w[j]
        d = c
        c = ((b << 9) | (b >> 23)) & mask
        b = a
        a = tt1 & mask
        h = g
        g = ((f << 19) | (f >> 13)) & mask
        f = e
        z = tt2 & mask
        e = (z ^ ((z << 9) | (z >> 23)) ^ ((z << 17) | (z >> 15))) & mask
    for j in range(16, 64):
        a12 = ((a << 12) | (a >> 20)) & mask
        ss1 = ((a12 + e + t_rotl[j]) & mask)
        ss1 = ((ss1 << 7) | (ss1 >> 25)) & mask
        ss2 = ss1 ^ a12
        tt1 = ((a & b) | (a & c) | (b & c)) + d + ss2 + (w[j] ^ w[j + 4])
        tt2 = ((e & f) | ((~e & mask) & g)) + h + ss1 + w[j]
        d = c
        c = ((b << 9) | (b >> 23)) & mask
        b = a
        a = tt1 & mask
        h = g
        g = ((f << 19) | (f >> 13)) & mask
        f = e
        z = tt2 & mask
        e = (z ^ ((z << 9) | (z >> 23)) ^ ((z << 17) | (z >> 15))) & mask

    return [
        v[0] ^ a,
        v[1] ^ b,
        v[2] ^ c,
        v[3] ^ d,
        v[4] ^ e,
        v[5] ^ f,
        v[6] ^ g,
        v[7] ^ h,
    ]


def _pad(data: bytes, total_len: int) -> bytes:
    """对消息尾部做填充：0x80 || 0x00... || 64 比特长度。

    :param data: 尚未压缩的尾部数据
    :param total_len: 整个消息的总字节数（用于写入比特长度）
    """
    msg = data + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += (total_len * 8).to_bytes(8, "big")
    return msg


class SM3:
    """增量式 SM3 杂凑对象。

    用法::

        h = SM3()
        h.update(b"abc")
        h.hexdigest()

    ``new()`` 等价于 ``SM3()``。对象可被 ``copy()``，``digest()`` 可重复调用。
    """

    __slots__ = ("_buffer", "_total", "_state")

    def __init__(self, data: Optional[_Data] = None) -> None:
        self._state: List[int] = list(_IV)
        self._buffer = b""
        self._total = 0
        if data is not None:
            self.update(data)

    def update(self, data: _Data) -> "SM3":
        """追加数据（bytes / bytearray / memoryview）。"""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("SM3.update 仅接受 bytes/bytearray/memoryview")
        chunk = bytes(data)
        self._total += len(chunk)
        if self._buffer:
            chunk = self._buffer + chunk
            self._buffer = b""
        # 处理整分组
        n_blocks = len(chunk) // SM3_BLOCK_SIZE
        state = self._state
        for i in range(n_blocks):
            state = _compress(state, chunk[i * SM3_BLOCK_SIZE : (i + 1) * SM3_BLOCK_SIZE])
        self._state = state
        # 余下的不足一组的数据留待下次
        self._buffer = chunk[n_blocks * SM3_BLOCK_SIZE :]
        return self

    def digest(self) -> bytes:
        """返回 32 字节摘要（可重复调用，不改变内部状态）。"""
        tail = _pad(self._buffer, self._total)
        state = list(self._state)
        for i in range(len(tail) // SM3_BLOCK_SIZE):
            state = _compress(state, tail[i * SM3_BLOCK_SIZE : (i + 1) * SM3_BLOCK_SIZE])
        return b"".join(x.to_bytes(4, "big") for x in state)

    def hexdigest(self) -> str:
        """返回 64 个十六进制字符的摘要。"""
        return self.digest().hex()

    def copy(self) -> "SM3":
        """复制当前状态（用于 HMAC / PBKDF2 等场景）。"""
        other = SM3()
        other._state = list(self._state)
        other._buffer = self._buffer
        other._total = self._total
        return other


def new(data: Optional[_Data] = None) -> SM3:
    """创建增量式 SM3 对象（等价于 :class:`SM3`）。"""
    return SM3(data)


def sm3_digest(data: _Data) -> bytes:
    """一次性计算 SM3 摘要，返回 32 字节。"""
    return SM3(data).digest()


def sm3_hexdigest(data: _Data) -> str:
    """一次性计算 SM3 摘要，返回 64 位十六进制字符串。"""
    return SM3(data).hexdigest()


# ---------------------------------------------------------------------------
# HMAC-SM3（RFC 2104）
# ---------------------------------------------------------------------------


def hmac_sm3(key: _Data, msg: _Data) -> bytes:
    """HMAC-SM3：以 SM3 为散列函数的 HMAC，返回 32 字节。

    HMAC(K, M) = SM3((K' ^ opad) || SM3((K' ^ ipad) || M))，
    其中 K' 为密钥填充/散列到分组长度 64 字节。

    （RFC 2104 已将 SM3 收录为合法散列函数，国密体系中亦以 HMAC-SM3
    作为标准 KDF / 密钥交换的原语。）
    """
    key_b = bytes(key)
    if len(key_b) > SM3_BLOCK_SIZE:
        key_b = sm3_digest(key_b)
    key_b = key_b + b"\x00" * (SM3_BLOCK_SIZE - len(key_b))
    ipad = bytes(b ^ 0x36 for b in key_b)
    opad = bytes(b ^ 0x5C for b in key_b)
    inner = SM3(ipad + bytes(msg)).digest()
    return SM3(opad + inner).digest()


def _hmac_pads(key: bytes) -> "tuple[bytes, bytes]":
    """把密钥规整为 (ipad, opad) 两个 64 字节分组（供批量 HMAC 复用状态）。"""
    if len(key) > SM3_BLOCK_SIZE:
        key = sm3_digest(key)
    key = key + b"\x00" * (SM3_BLOCK_SIZE - len(key))
    return bytes(b ^ 0x36 for b in key), bytes(b ^ 0x5C for b in key)


# ---------------------------------------------------------------------------
# PBKDF2-HMAC-SM3（RFC 8018 / PKCS#5 v2.1）
# ---------------------------------------------------------------------------


def pbkdf2_hmac_sm3(
    password: _Data,
    salt: _Data,
    iterations: int,
    dklen: int = 32,
) -> bytes:
    """PBKDF2-HMAC-SM3 口令派生函数。

    :param password: 口令字节串
    :param salt: 盐值字节串
    :param iterations: 迭代次数 c（>= 1）
    :param dklen: 期望输出长度（字节）
    :returns: dklen 字节的派生密钥

    算法（RFC 8018 5.2 节）::

        DK = T_1 || T_2 || ... || T_l
        T_i = F(P, S, c, i)，F = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
        U_1 = PRF(P, S || INT_32_BE(i))，U_j = PRF(P, U_{j-1})
        PRF 即 HMAC-SM3。

    性能说明：迭代中复用 ipad/opad 的中间杂凑状态（与完全重新计算 HMAC
    数学等价），使纯 Python 实现可用。
    """
    if iterations < 1:
        raise ValueError("PBKDF2 迭代次数必须 >= 1")
    if dklen < 1:
        raise ValueError("PBKDF2 输出长度必须 >= 1")
    ipad, opad = _hmac_pads(bytes(password))
    ipad_state = SM3(ipad)
    opad_state = SM3(opad)

    def _prf(data: bytes) -> bytes:
        inner = ipad_state.copy()
        inner.update(data)
        outer = opad_state.copy()
        outer.update(inner.digest())
        return outer.digest()

    s = bytes(salt)
    blocks = (dklen + SM3_DIGEST_SIZE - 1) // SM3_DIGEST_SIZE
    dk = bytearray()
    for i in range(1, blocks + 1):
        u = _prf(s + i.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = _prf(u)
            for k in range(len(t)):
                t[k] ^= u[k]
        dk += t
    return bytes(dk[:dklen])


# ---------------------------------------------------------------------------
# SM2 密钥派生函数 KDF（GM/T 0003.4-2012 5.4.3 节，基于 SM3）
# ---------------------------------------------------------------------------


def sm3_kdf(z: _Data, klen: int) -> bytes:
    """SM2 的密钥派生函数 KDF(Z, klen)（基于 SM3）。

    :param z: 共享秘密比特串（本实现取字节串）
    :param klen: 期望输出长度（**字节**，内部按比特处理）
    :returns: klen 字节的派生密钥流

    若 ``klen`` 对应的输出恰好为全 0 比特串（概率极低），调用者应按
    GM/T 0003.4 的要求更换随机数重试——本函数返回原值，由调用者检查。
    """
    if klen < 0:
        raise ValueError("klen 不能为负")
    if klen > 0xFFFFFFFF * 32:
        raise ValueError("klen 超出 KDF 允许的最大长度")
    z_b = bytes(z)
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3_digest(z_b + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])
