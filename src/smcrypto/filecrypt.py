"""SM4 文件加密容器格式（SMCT v1）与文件加解密接口。

.. _smct-format:

容器格式（SMCT v1）
===================

所有多字节整数均为 **大端序**。文件头 44 字节固定长度::

    偏移  长度  字段
    ----  ----  ------------------------------------------------------------
    0     4     魔数 magic = b"SMCT"（SM Crypto Toolbox）
    4     1     版本号 version = 1
    5     1     算法编号 cipher：1=SM4-CBC，2=SM4-CTR，3=SM4-ECB
    6     1     密钥来源 key_mode：0=原始密钥（--key 直接给出 16 字节），
                       1=口令（PBKDF2-HMAC-SM3 派生）
    7     1     保留字段（恒为 0）
    8     4     PBKDF2 迭代次数（uint32，大端；原始密钥模式恒为 0）
    12    16    KDF 盐值 salt（16 字节随机数；原始密钥模式恒为全 0）
    28    16    IV / CTR 初始计数器（16 字节随机数；ECB 模式恒为全 0）
    44    N     密文主体（CBC/ECB 为 PKCS#7 填充后的密文；CTR 为异或结果）

设计要点：

* 口令模式：SM4 密钥 = PBKDF2-HMAC-SM3(口令, salt, iterations, dklen=16)，
  每次加密使用新的随机 salt 与 IV；
* CBC/ECB 采用 PKCS#7 填充，解密时严格校验（填充错误即报错，避免静默截断）；
* CTR 为流模式，密文与明文等长；
* 仅加密，不提供完整性认证（如需认证请叠加 HMAC-SM3——见 ``hmac`` 子命令）；
* 本格式面向教学与工具用途，正式生产请使用经审计的实现与标准容器（如 PKCS#7/CMS）。
"""

from __future__ import annotations

import secrets
from typing import NamedTuple, Optional, Union

from .sm3 import pbkdf2_hmac_sm3
from .sm4 import (
    SM4_KEY_SIZE,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
    sm4_ctr_xor,
    sm4_ecb_decrypt,
    sm4_ecb_encrypt,
)

__all__ = [
    "MAGIC",
    "VERSION",
    "HEADER_SIZE",
    "DEFAULT_ITERATIONS",
    "CIPHERS",
    "Header",
    "derive_key",
    "encrypt_bytes",
    "decrypt_bytes",
    "parse_header",
]

#: 文件魔数
MAGIC = b"SMCT"
#: 容器版本
VERSION = 1
#: 固定头长度（字节）
HEADER_SIZE = 44
#: 口令模式默认 PBKDF2 迭代次数（可调；纯 Python 实现所限，取值偏保守）
DEFAULT_ITERATIONS = 10_000
#: 盐值与 IV 长度
SALT_SIZE = 16
IV_SIZE = 16

#: 算法名 -> 编号
CIPHERS = {"sm4-cbc": 1, "sm4-ctr": 2, "sm4-ecb": 3}
_CIPHER_BY_ID = {v: k for k, v in CIPHERS.items()}

#: 密钥来源编号
_KEY_MODE_RAW = 0
_KEY_MODE_PASSWORD = 1

_Data = Union[bytes, bytearray, memoryview]


class Header(NamedTuple):
    """SMCT v1 容器文件头。"""

    version: int
    cipher: str
    key_mode: int
    iterations: int
    salt: bytes
    iv: bytes

    @property
    def is_password_mode(self) -> bool:
        return self.key_mode == _KEY_MODE_PASSWORD


def derive_key(password: Union[bytes, str], salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """由口令派生 16 字节 SM4 密钥：PBKDF2-HMAC-SM3。"""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if iterations < 1:
        raise ValueError("迭代次数必须 >= 1")
    return pbkdf2_hmac_sm3(password, salt, iterations, dklen=SM4_KEY_SIZE)


def _parse_key(key: Union[bytes, str, bytearray, memoryview]) -> bytes:
    """把 --key 参数（16 字节或 32 位十六进制字符串）规整为 16 字节密钥。"""
    if isinstance(key, str):
        text = key.strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        try:
            key = bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError("密钥 hex 解析失败：%s" % exc) from exc
    key = bytes(key)
    if len(key) != SM4_KEY_SIZE:
        raise ValueError("SM4 原始密钥必须为 %d 字节（%d 位十六进制）" % (SM4_KEY_SIZE, SM4_KEY_SIZE * 2))
    return key


def build_header(
    cipher: str,
    *,
    password: Optional[Union[bytes, str]] = None,
    key: Optional[Union[bytes, str]] = None,
    salt: Optional[bytes] = None,
    iv: Optional[bytes] = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> Header:
    """构造文件头（内部使用；也便于测试逐字段校验）。"""
    if cipher not in CIPHERS:
        raise ValueError("不支持的算法：%s（可选 %s）" % (cipher, "/".join(CIPHERS)))
    if (password is None) == (key is None):
        raise ValueError("必须且只能提供 password 或 key 之一")
    if password is not None:
        salt_b = secrets.token_bytes(SALT_SIZE) if salt is None else bytes(salt)
        if len(salt_b) != SALT_SIZE:
            raise ValueError("salt 必须为 %d 字节" % SALT_SIZE)
        iter_b = iterations
        key_mode = _KEY_MODE_PASSWORD
    else:
        salt_b = b"\x00" * SALT_SIZE
        iter_b = 0
        key_mode = _KEY_MODE_RAW
    if cipher == "sm4-ecb":
        iv_b = b"\x00" * IV_SIZE
    else:
        iv_b = secrets.token_bytes(IV_SIZE) if iv is None else bytes(iv)
        if len(iv_b) != IV_SIZE:
            raise ValueError("IV 必须为 %d 字节" % IV_SIZE)
    return Header(VERSION, cipher, key_mode, iter_b, salt_b, iv_b)


def pack_header(header: Header) -> bytes:
    """把 :class:`Header` 序列化为 44 字节。"""
    return (
        MAGIC
        + bytes([header.version, CIPHERS[header.cipher], header.key_mode, 0])
        + header.iterations.to_bytes(4, "big")
        + header.salt
        + header.iv
    )


def parse_header(data: _Data) -> Header:
    """解析并校验 44 字节文件头；格式非法时抛出 :class:`ValueError`。"""
    data = bytes(data)
    if len(data) < HEADER_SIZE:
        raise ValueError("文件过短，不是有效的 SMCT 容器")
    if data[:4] != MAGIC:
        raise ValueError("魔数不匹配：不是 SMCT 容器（got %r）" % data[:4])
    version = data[4]
    if version != VERSION:
        raise ValueError("不支持的容器版本：%d" % version)
    cipher_id = data[5]
    if cipher_id not in _CIPHER_BY_ID:
        raise ValueError("未知算法编号：%d" % cipher_id)
    key_mode = data[6]
    if key_mode not in (_KEY_MODE_RAW, _KEY_MODE_PASSWORD):
        raise ValueError("未知密钥来源编号：%d" % key_mode)
    iterations = int.from_bytes(data[8:12], "big")
    return Header(version, _CIPHER_BY_ID[cipher_id], key_mode, iterations, data[12:28], data[28:44])


def _body_encrypt(key: bytes, header: Header, plaintext: bytes) -> bytes:
    if header.cipher == "sm4-cbc":
        return sm4_cbc_encrypt(key, header.iv, plaintext)
    if header.cipher == "sm4-ctr":
        return sm4_ctr_xor(key, header.iv, plaintext)
    return sm4_ecb_encrypt(key, plaintext)


def _body_decrypt(key: bytes, header: Header, body: bytes) -> bytes:
    if header.cipher == "sm4-cbc":
        return sm4_cbc_decrypt(key, header.iv, body)
    if header.cipher == "sm4-ctr":
        return sm4_ctr_xor(key, header.iv, body)
    return sm4_ecb_decrypt(key, body)


def encrypt_bytes(
    plaintext: _Data,
    *,
    cipher: str = "sm4-cbc",
    password: Optional[Union[bytes, str]] = None,
    key: Optional[Union[bytes, str]] = None,
    iterations: int = DEFAULT_ITERATIONS,
    salt: Optional[bytes] = None,
    iv: Optional[bytes] = None,
) -> bytes:
    """把明文打包为 SMCT 容器（含文件头）。

    :param cipher: ``"sm4-cbc"``（默认）/ ``"sm4-ctr"`` / ``"sm4-ecb"``
    :param password: 口令（str 按 UTF-8 编码）；与 ``key`` 二选一
    :param key: 16 字节原始密钥（bytes 或十六进制字符串）；与 ``password`` 二选一
    :param iterations: PBKDF2 迭代次数（仅口令模式）
    :param salt: 覆盖随机盐值（测试用），仅口令模式
    :param iv: 覆盖随机 IV（测试用）
    """
    header = build_header(
        cipher, password=password, key=key, salt=salt, iv=iv, iterations=iterations
    )
    if password is not None:
        key_b = derive_key(password, header.salt, header.iterations)
    else:
        key_b = _parse_key(key)  # type: ignore[arg-type]
    body = _body_encrypt(key_b, header, bytes(plaintext))
    return pack_header(header) + body


def decrypt_bytes(
    container: _Data,
    *,
    password: Optional[Union[bytes, str]] = None,
    key: Optional[Union[bytes, str]] = None,
) -> bytes:
    """解密 SMCT 容器，返回明文；口令/密钥错误或数据损坏时抛出 :class:`ValueError`。"""
    container = bytes(container)
    header = parse_header(container)
    if (password is None) == (key is None):
        raise ValueError("必须且只能提供 password 或 key 之一")
    if header.is_password_mode:
        if password is None:
            raise ValueError("该容器为口令模式，请提供 --password")
        key_b = derive_key(password, header.salt, header.iterations)
    else:
        if key is None:
            raise ValueError("该容器为原始密钥模式，请提供 --key")
        key_b = _parse_key(key)
    return _body_decrypt(key_b, header, container[HEADER_SIZE:])
