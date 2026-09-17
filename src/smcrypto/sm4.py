"""SM4 分组密码算法（GB/T 32907-2016）——纯 Python 从零实现。

本模块提供：

* :class:`SM4` —— 密钥扩展 + 单分组加解密（32 轮非平衡 Feistel）；
* ECB / CBC / CTR 三种工作模式（:func:`sm4_ecb_encrypt` 等）；
* PKCS#7 填充与严格校验去填充（:func:`pkcs7_pad` / :func:`pkcs7_unpad`）。

实现仅依赖 Python 标准库，无任何第三方依赖。

参考标准：GB/T 32907-2016《信息安全技术 SM4 分组密码算法》。

示例::

    >>> from smcrypto.sm4 import sm4_ecb_encrypt
    >>> sm4_ecb_encrypt(bytes.fromhex("0123456789abcdeffedcba9876543210"),
    ...                 bytes.fromhex("0123456789abcdeffedcba9876543210"),
    ...                 pad=False).hex()
    '681edf34d206965e86b3e94f536e4246'

"""

from __future__ import annotations

from typing import List, Sequence, Union

__all__ = [
    "SM4_BLOCK_SIZE",
    "SM4_KEY_SIZE",
    "SM4",
    "pkcs7_pad",
    "pkcs7_unpad",
    "sm4_ecb_encrypt",
    "sm4_ecb_decrypt",
    "sm4_cbc_encrypt",
    "sm4_cbc_decrypt",
    "sm4_ctr_xor",
]

#: 分组长度（字节）
SM4_BLOCK_SIZE = 16
#: 密钥长度（字节）
SM4_KEY_SIZE = 16

_MASK32 = 0xFFFFFFFF

# S 盒（GB/T 32907-2016 附录 A）：与 gmssl 的 SM4_BOXES_TABLE 逐项比对一致
SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05"
    "2b679a762abe04c3aa44132649860699"
    "9c4250f491ef987a33540b43edcfac62"
    "e4b31ca9c908e89580df94fa758f3fa6"
    "4707a7fcf37317ba83593c19e6854fa8"
    "686b81b27164da8bf8eb0f4b70569d35"
    "1e240e5e6358d1a225227c3b01217887"
    "d40046579fd327524c3602e7a0c4c89e"
    "eabf8ad240c738b5a3f7f2cef96115a1"
    "e0ae5da49b341a55ad933230f58cb1e3"
    "1df6e22e8266ca60c02923ab0d534e6f"
    "d5db3745defd8e2f03ff6a726d6c5b51"
    "8d1baf92bbddbc7f11d95c411f105ad8"
    "0ac13188a5cd7bbd2d74d012b8e5b4b0"
    "8969974a0c96777e65b9f109c56ec684"
    "18f07dec3adc4d2079ee5f3ed7cb3948"
)

# 系统参数 FK（GB/T 32907-2016 4.2 节）
_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)


def _make_ck() -> List[int]:
    """固定参数 CK：CK_i = ck_{i,0}||ck_{i,1}||ck_{i,2}||ck_{i,3}，
    其中 ck_{i,j} = (4i+j)×7 mod 256（GB/T 32907-2016 4.2 节）。"""
    ck = []
    for i in range(32):
        ck.append(int.from_bytes(bytes(((4 * i + j) * 7 % 256) for j in range(4)), "big"))
    return ck


_CK = _make_ck()


def _rotl32(x: int, n: int) -> int:
    """32 位循环左移。"""
    n &= 31
    if n == 0:
        return x & _MASK32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _tau(a: int) -> int:
    """非线性变换 τ：对 4 个字节分别查 S 盒后拼接。"""
    return (
        (SBOX[(a >> 24) & 0xFF] << 24)
        | (SBOX[(a >> 16) & 0xFF] << 16)
        | (SBOX[(a >> 8) & 0xFF] << 8)
        | SBOX[a & 0xFF]
    )


def _t(a: int) -> int:
    """轮函数合成置换 T = L(τ(a))，L(B) = B ^ (B<<<2) ^ (B<<<10) ^ (B<<<18) ^ (B<<<24)。"""
    b = _tau(a)
    return b ^ _rotl32(b, 2) ^ _rotl32(b, 10) ^ _rotl32(b, 18) ^ _rotl32(b, 24)


def _t_prime(a: int) -> int:
    """密钥扩展合成置换 T' = L'(τ(a))，L'(B) = B ^ (B<<<13) ^ (B<<<23)。"""
    b = _tau(a)
    return b ^ _rotl32(b, 13) ^ _rotl32(b, 23)


class SM4:
    """SM4 分组密码。

    :param key: 16 字节密钥

    用法::

        c = SM4(key)
        ct = c.encrypt_block(pt)   # 单分组（16 字节）
        pt = c.decrypt_block(ct)
    """

    __slots__ = ("_rk",)

    def __init__(self, key: Union[bytes, bytearray, memoryview]) -> None:
        self._rk = self._expand_key(bytes(key))

    @staticmethod
    def _expand_key(key: bytes) -> List[int]:
        """密钥扩展：由 128 比特密钥生成 32 个轮密钥 rk_0..rk_31。"""
        if len(key) != SM4_KEY_SIZE:
            raise ValueError("SM4 密钥必须为 %d 字节，实际 %d 字节" % (SM4_KEY_SIZE, len(key)))
        mk = [int.from_bytes(key[i * 4 : i * 4 + 4], "big") for i in range(4)]
        k = [mk[i] ^ _FK[i] for i in range(4)]
        rk: List[int] = []
        for i in range(32):
            t = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _CK[i]
            k.append(k[i] ^ _t_prime(t))
            rk.append(k[i + 4])
        return rk

    @staticmethod
    def _crypt_block(rk: Sequence[int], block: bytes) -> bytes:
        """通用轮迭代：加密传正序轮密钥，解密传逆序轮密钥。"""
        x = [int.from_bytes(block[i * 4 : i * 4 + 4], "big") for i in range(4)]
        for i in range(32):
            x.append(x[i] ^ _t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
        # 反序变换 R
        return b"".join(v.to_bytes(4, "big") for v in (x[35], x[34], x[33], x[32]))

    def encrypt_block(self, block: Union[bytes, bytearray, memoryview]) -> bytes:
        """加密单个 16 字节分组。"""
        block = bytes(block)
        if len(block) != SM4_BLOCK_SIZE:
            raise ValueError("SM4 分组必须为 %d 字节" % SM4_BLOCK_SIZE)
        return self._crypt_block(self._rk, block)

    def decrypt_block(self, block: Union[bytes, bytearray, memoryview]) -> bytes:
        """解密单个 16 字节分组（轮密钥逆序）。"""
        block = bytes(block)
        if len(block) != SM4_BLOCK_SIZE:
            raise ValueError("SM4 分组必须为 %d 字节" % SM4_BLOCK_SIZE)
        return self._crypt_block(self._rk[::-1], block)


# ---------------------------------------------------------------------------
# PKCS#7 填充
# ---------------------------------------------------------------------------


def pkcs7_pad(data: Union[bytes, bytearray, memoryview], block_size: int = SM4_BLOCK_SIZE) -> bytes:
    """PKCS#7 填充：填充长度 n（1..block_size），每个填充字节值均为 n。

    若数据长度已是分组倍数，则追加一个完整填充分组（RFC 5652 约定）。
    """
    data = bytes(data)
    if block_size < 1 or block_size > 255:
        raise ValueError("block_size 必须在 1..255 之间")
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: Union[bytes, bytearray, memoryview], block_size: int = SM4_BLOCK_SIZE) -> bytes:
    """校验并移除 PKCS#7 填充；填充非法时抛出 :class:`ValueError`。"""
    data = bytes(data)
    if not data or len(data) % block_size != 0:
        raise ValueError("待去填充数据长度非法（必须为正的分组倍数）")
    n = data[-1]
    if n < 1 or n > block_size:
        raise ValueError("PKCS#7 填充无效：填充字节值 %d 越界" % n)
    if data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS#7 填充无效：填充字节不一致")
    return data[:-n]


# ---------------------------------------------------------------------------
# 工作模式：ECB / CBC / CTR
# ---------------------------------------------------------------------------


def _check_iv(iv: Union[bytes, bytearray, memoryview], name: str = "IV") -> bytes:
    iv = bytes(iv)
    if len(iv) != SM4_BLOCK_SIZE:
        raise ValueError("%s 必须为 %d 字节" % (name, SM4_BLOCK_SIZE))
    return iv


def sm4_ecb_encrypt(
    key: Union[bytes, bytearray, memoryview],
    data: Union[bytes, bytearray, memoryview],
    pad: bool = True,
) -> bytes:
    """SM4-ECB 加密。``pad=True`` 时先做 PKCS#7 填充。"""
    c = SM4(bytes(key))
    buf = pkcs7_pad(data) if pad else bytes(data)
    if len(buf) % SM4_BLOCK_SIZE != 0:
        raise ValueError("ECB 模式数据长度必须为分组倍数（pad=False 时）")
    return b"".join(
        c.encrypt_block(buf[i : i + SM4_BLOCK_SIZE]) for i in range(0, len(buf), SM4_BLOCK_SIZE)
    )


def sm4_ecb_decrypt(
    key: Union[bytes, bytearray, memoryview],
    data: Union[bytes, bytearray, memoryview],
    pad: bool = True,
) -> bytes:
    """SM4-ECB 解密。``pad=True`` 时去填充并校验。"""
    c = SM4(bytes(key))
    buf = bytes(data)
    if len(buf) == 0 or len(buf) % SM4_BLOCK_SIZE != 0:
        raise ValueError("ECB 模式密文长度必须为正的分组倍数")
    out = b"".join(
        c.decrypt_block(buf[i : i + SM4_BLOCK_SIZE]) for i in range(0, len(buf), SM4_BLOCK_SIZE)
    )
    return pkcs7_unpad(out) if pad else out


def sm4_cbc_encrypt(
    key: Union[bytes, bytearray, memoryview],
    iv: Union[bytes, bytearray, memoryview],
    data: Union[bytes, bytearray, memoryview],
    pad: bool = True,
) -> bytes:
    """SM4-CBC 加密：C_i = E(P_i ^ C_{i-1})，C_0 以 IV 代替。"""
    c = SM4(bytes(key))
    prev = _check_iv(iv)
    buf = pkcs7_pad(data) if pad else bytes(data)
    if len(buf) % SM4_BLOCK_SIZE != 0:
        raise ValueError("CBC 模式数据长度必须为分组倍数（pad=False 时）")
    out = bytearray()
    for i in range(0, len(buf), SM4_BLOCK_SIZE):
        blk = bytes(x ^ y for x, y in zip(buf[i : i + SM4_BLOCK_SIZE], prev))
        prev = c.encrypt_block(blk)
        out += prev
    return bytes(out)


def sm4_cbc_decrypt(
    key: Union[bytes, bytearray, memoryview],
    iv: Union[bytes, bytearray, memoryview],
    data: Union[bytes, bytearray, memoryview],
    pad: bool = True,
) -> bytes:
    """SM4-CBC 解密：P_i = D(C_i) ^ C_{i-1}。"""
    c = SM4(bytes(key))
    prev = _check_iv(iv)
    buf = bytes(data)
    if len(buf) == 0 or len(buf) % SM4_BLOCK_SIZE != 0:
        raise ValueError("CBC 模式密文长度必须为正的分组倍数")
    out = bytearray()
    for i in range(0, len(buf), SM4_BLOCK_SIZE):
        blk = buf[i : i + SM4_BLOCK_SIZE]
        dec = c.decrypt_block(blk)
        out += bytes(x ^ y for x, y in zip(dec, prev))
        prev = blk
    return pkcs7_unpad(bytes(out)) if pad else bytes(out)


def sm4_ctr_xor(
    key: Union[bytes, bytearray, memoryview],
    iv: Union[bytes, bytearray, memoryview],
    data: Union[bytes, bytearray, memoryview],
) -> bytes:
    """SM4-CTR 加解密（对称操作）：O_j = P_j ^ E(counter_j)。

    计数器为 128 比特大端整数，初值为 IV，每生成一个密钥流分组自增 1
    （与 OpenSSL ``sm4-ctr`` 行为一致）。无需填充，输出长度等于输入长度。
    """
    c = SM4(bytes(key))
    counter = int.from_bytes(_check_iv(iv), "big")
    buf = bytes(data)
    out = bytearray()
    for i in range(0, len(buf), SM4_BLOCK_SIZE):
        ks = c.encrypt_block(counter.to_bytes(16, "big"))
        chunk = buf[i : i + SM4_BLOCK_SIZE]
        out += bytes(x ^ y for x, y in zip(chunk, ks))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)
