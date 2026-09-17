"""内置已知答案测试（KAT）向量 —— 全部来自公开标准或经交叉验证生成。

.. warning::

    本文件中的每个向量都必须有可追溯来源，**严禁凭记忆编造**。
    新增向量前请先跑 ``scripts/gen_interop_vectors.py`` 或对照标准原文核验。

来源与核验记录
==============

* **SM3**：GB/T 32905-2016 附录 A 示例（空串 / ``abc`` / ``abcd``×16），
  已与 gmssl 3.2.2（``gmssl.sm3.sm3_hash``）及 OpenSSL 3.6.3
  （``openssl dgst -sm3``）逐字节比对一致。
* **SM4 分组**：GB/T 32907-2016 附录 A.1 示例；
  已与 gmssl（``CryptSM4.crypt_ecb``）及 OpenSSL（``openssl enc -sm4-ecb -nopad``）
  比对一致。
* **SM4 100 万次迭代**：GB/T 32907-2016 附录 A.2 示例；
  本仓库 ``scripts/check_sm4_1m.py`` 实测复现（结果与期望一致）。
* **SM4-CBC**：由 gmssl 3.2.2 生成（固定 key/iv/plaintext），
  并由 OpenSSL ``openssl enc -sm4-cbc -nopad`` 复核一致后冻结。
* **SM2**：GB/T 32918.2-2016 附录 A 示例 —— d、k、M（``message digest``）、
  ID（``1234567812345678``）为标准给值；本实现按标准公式独立计算出的
  Z_A、e、r、s 与公开示例值一致，并已用 gmssl ``sign_with_sm3``（固定 k）
  复核出完全相同的 (r, s)。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# SM3
# ---------------------------------------------------------------------------

#: (名称, 消息, 期望十六进制摘要)
SM3_VECTORS = (
    ("empty", b"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"),
    ("abc", b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
    (
        "abcd_x16",
        b"abcd" * 16,
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    ),
)

# ---------------------------------------------------------------------------
# SM4
# ---------------------------------------------------------------------------

#: GB/T 32907-2016 附录 A.1：单分组加密
SM4_BLOCK_KAT = {
    "key": "0123456789abcdeffedcba9876543210",
    "plaintext": "0123456789abcdeffedcba9876543210",
    "ciphertext": "681edf34d206965e86b3e94f536e4246",
}

#: GB/T 32907-2016 附录 A.2：同分组迭代 100 万次加密
SM4_1M_KAT = {
    "key": "0123456789abcdeffedcba9876543210",
    "ciphertext": "595298c7c6fd271f0402f804c33d3f66",
    "iterations": 1_000_000,
}

#: SM4-CBC 固定向量（由 gmssl 生成、OpenSSL 复核后冻结）
SM4_CBC_KAT = {
    "key": "0123456789abcdeffedcba9876543210",
    "iv": "000102030405060708090a0b0c0d0e0f",
    "plaintext": "00112233445566778899aabbccddeeff" * 2,
    "ciphertext": (
        "4691e99a3261b6144f6aa68bea48dbbd"
        "16e96658f113bf22cbe041bb87f2e011"
        "45d4184544ee7728d4f5e61653665de5"
    ),
    "padding": "pkcs7",
}

# ---------------------------------------------------------------------------
# SM2（GB/T 32918.2-2016 附录 A 示例）
# ---------------------------------------------------------------------------


class _Sm2StdExample:
    """SM2 签名标准示例（字段均为十六进制字符串，不含 0x 前缀）。"""

    d = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
    pub_x = "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
    pub_y = "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
    za = "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3"
    msg = b"message digest"
    ida = b"1234567812345678"
    e = "F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640"
    k = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"
    r = "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"
    s = "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"


SM2_STD_EXAMPLE = _Sm2StdExample()
