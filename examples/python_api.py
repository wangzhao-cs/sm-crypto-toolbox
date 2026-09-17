"""库 API 示例：直接在 Python 中使用 smcrypto（无需命令行）。

运行::

    PYTHONPATH=src python examples/python_api.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from smcrypto import (  # noqa: E402
    decode_point,
    decode_signature_der,
    encode_point,
    encode_signature_der,
    generate_keypair,
    hmac_sm3,
    pbkdf2_hmac_sm3,
    public_key_from_private,
    sm2_decrypt,
    sm2_encrypt,
    sm2_sign,
    sm2_verify,
    sm3_hexdigest,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)


def section(title: str) -> None:
    print("\n== %s ==" % title)


section("SM3 杂凑")
print("SM3('abc')     =", sm3_hexdigest(b"abc"))
print("SM3(空串)      =", sm3_hexdigest(b""))
print("HMAC-SM3       =", hmac_sm3(b"secret", b"message").hex())
print("PBKDF2(1000)   =", pbkdf2_hmac_sm3(b"password", b"salt", 1000, 16).hex())

section("SM4-CBC 加解密")
key, iv = os.urandom(16), os.urandom(16)
plaintext = "国密算法工具箱 · SM4 演示".encode()
ciphertext = sm4_cbc_encrypt(key, iv, plaintext)
recovered = sm4_cbc_decrypt(key, iv, ciphertext)
print("明文长度       =", len(plaintext))
print("密文长度       =", len(ciphertext), "（PKCS#7 填充到分组倍数）")
print("密文(hex)      =", ciphertext.hex()[:48], "...")
print("解密还原成功   =", recovered == plaintext)

section("SM2 签名 / 验签")
d, pub = generate_keypair()
message = "要签名的消息".encode()
tampered = "要签名的消息!".encode()
print("私钥(hex)      =", "%064x" % d)
print("公钥(非压缩)   =", encode_point(pub).hex())
sig_r, sig_s = sm2_sign(d, message)
print("签名 (r, s)    = (%064x, %064x)" % (sig_r, sig_s))
print("验签           =", sm2_verify(pub, message, sig_r, sig_s))
print("篡改后验签     =", sm2_verify(pub, tampered, sig_r, sig_s))

der = encode_signature_der(sig_r, sig_s)
print("DER 签名(hex)  =", der.hex())
print("DER 解析往返   =", decode_signature_der(der) == (sig_r, sig_s))

section("SM2 公钥加密 / 私钥解密")
ct = sm2_encrypt(pub, "机密消息：SM2 公钥加密演示".encode())
print("密文长度       =", len(ct), "（C1C3C2，C1 带 04 前缀）")
print("解密           =", sm2_decrypt(d, ct).decode("utf-8"))

section("其他便捷接口")
# 从私钥反推公钥；公钥编解码往返
pub2 = public_key_from_private(d)
print("公钥一致性     =", pub2 == pub)
print("公钥解码往返   =", decode_point(encode_point(pub)) == pub)
print("DER 风格签名   =", encode_signature_der(*sm2_sign(d, b"x")).hex()[:32], "...")

print("\n完成：以上结果均由本仓库纯 Python 实现实时计算。")
