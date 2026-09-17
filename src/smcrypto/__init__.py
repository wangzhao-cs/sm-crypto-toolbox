"""国密算法工具箱（sm-crypto-toolbox）。

纯 Python 从零实现的国密算法教学与工具库：

* **SM3**（GB/T 32905-2016）—— 杂凑 / HMAC / PBKDF2 / KDF
* **SM4**（GB/T 32907-2016）—— ECB / CBC / CTR / PKCS#7
* **SM2**（GM/T 0003 / GB/T 32918）—— 签名验签 / 公钥加解密 / DER

零第三方依赖（仅标准库，Python >= 3.9）。

顶层示例::

    from smcrypto import sm3_hexdigest, sm4_cbc_encrypt, sm2_sign, sm2_verify

::

    命令行入口：``smctl``（或 ``python -m smcrypto``），见 ``smctl --help``。
"""

from .filecrypt import (
    DEFAULT_ITERATIONS,
    Header,
    decrypt_bytes,
    derive_key,
    encrypt_bytes,
    parse_header,
)
from .sm2 import (
    IDA_DEFAULT,
    INFINITY,
    Point,
    compute_za,
    decode_point,
    decode_signature_der,
    encode_point,
    encode_signature_der,
    generate_keypair,
    public_key_from_private,
    sm2_decrypt,
    sm2_encrypt,
    sm2_sign,
    sm2_sign_der,
    sm2_verify,
    sm2_verify_der,
)
from .sm3 import (
    SM3,
    hmac_sm3,
    pbkdf2_hmac_sm3,
    sm3_digest,
    sm3_hexdigest,
    sm3_kdf,
)
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

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # sm3
    "SM3",
    "sm3_digest",
    "sm3_hexdigest",
    "hmac_sm3",
    "pbkdf2_hmac_sm3",
    "sm3_kdf",
    # sm4
    "SM4",
    "pkcs7_pad",
    "pkcs7_unpad",
    "sm4_ecb_encrypt",
    "sm4_ecb_decrypt",
    "sm4_cbc_encrypt",
    "sm4_cbc_decrypt",
    "sm4_ctr_xor",
    # sm2
    "Point",
    "INFINITY",
    "IDA_DEFAULT",
    "generate_keypair",
    "public_key_from_private",
    "encode_point",
    "decode_point",
    "compute_za",
    "sm2_sign",
    "sm2_verify",
    "sm2_sign_der",
    "sm2_verify_der",
    "encode_signature_der",
    "decode_signature_der",
    "sm2_encrypt",
    "sm2_decrypt",
    # filecrypt
    "Header",
    "encrypt_bytes",
    "decrypt_bytes",
    "derive_key",
    "parse_header",
    "DEFAULT_ITERATIONS",
]
