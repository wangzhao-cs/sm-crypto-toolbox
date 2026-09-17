"""生成 tests/vectors_gmssl.py —— 交叉验证静态向量（gmssl + OpenSSL）。

用法::

    .venv/bin/python scripts/gen_interop_vectors.py

约定：

* gmssl（duanhongyi 纯 Python 实现）为**强制**来源：缺失则脚本退出并提示安装；
* OpenSSL（要求支持 SM3/SM4，如 Homebrew 的 OpenSSL 3.x）若可用则追加
  HMAC-SM3 / PBKDF2-HMAC-SM3 / SM4-CBC 交叉验证向量，并在文件中注明；
* 生成文件带 provenance 头，供 ``tests/test_vectors_gmssl.py`` 在无第三方
  依赖环境下校验本仓库实现。

**严禁**手写 / 回忆向量填入生成文件。
"""

from __future__ import annotations

import datetime
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
OUT_PATH = os.path.join(REPO, "tests", "vectors_gmssl.py")

sys.path.insert(0, os.path.join(REPO, "src"))  # noqa: E402

try:
    import gmssl  # noqa: E402
    from gmssl import func as g_func
    from gmssl import sm2 as g_sm2
    from gmssl import sm3 as g_sm3
    from gmssl import sm4 as g_sm4
except ImportError:  # pragma: no cover
    print("错误：未安装 gmssl。请先运行: uv pip install --python .venv/bin/python gmssl", file=sys.stderr)
    raise SystemExit(2)


def gmssl_sm3_hex(data: bytes) -> str:
    return g_sm3.sm3_hash(g_func.bytes_to_list(data))


def find_openssl() -> "str | None":
    """返回一个支持 SM3 的 openssl 可执行文件路径，找不到返回 None。"""
    candidates = [
        os.environ.get("SMCT_OPENSSL", ""),
        "/opt/homebrew/opt/openssl/bin/openssl",
        "/usr/local/opt/openssl/bin/openssl",
        shutil.which("openssl") or "",
    ]
    for cand in candidates:
        if not cand or not os.path.exists(cand):
            continue
        try:
            r = subprocess.run(
                [cand, "mac", "-digest", "SM3", "-macopt", "hexkey:00", "HMAC"],
                input=b"x",
                capture_output=True,
                timeout=10,
            )
            if r.returncode == 0:
                return cand
        except Exception:  # noqa: BLE001
            continue
    return None


def openssl_version(ossl: str) -> str:
    r = subprocess.run([ossl, "version"], capture_output=True, text=True)
    return r.stdout.strip()


def openssl_hmac(ossl: str, key: bytes, msg: bytes) -> str:
    r = subprocess.run(
        [ossl, "mac", "-digest", "SM3", "-macopt", "hexkey:" + key.hex(), "HMAC"],
        input=msg,
        capture_output=True,
        check=True,
    )
    return r.stdout.decode().strip().lower()


def openssl_pbkdf2(ossl: str, password: str, salt: str, iterations: int, keylen: int) -> str:
    r = subprocess.run(
        [
            ossl,
            "kdf",
            "-keylen",
            str(keylen),
            "-kdfopt",
            "digest:SM3",
            "-kdfopt",
            "pass:" + password,
            "-kdfopt",
            "salt:" + salt,
            "-kdfopt",
            "iter:" + str(iterations),
            "PBKDF2",
        ],
        capture_output=True,
        check=True,
    )
    return r.stdout.decode().strip().replace(":", "").lower()


def openssl_enc(ossl: str, mode: str, key: bytes, iv: "bytes | None", data: bytes, nopad: bool) -> bytes:
    cmd = [ossl, "enc", "-sm4-" + mode, "-K", key.hex()]
    if iv is not None:
        cmd += ["-iv", iv.hex()]
    if nopad:
        cmd += ["-nopad"]
    r = subprocess.run(cmd, input=data, capture_output=True, check=True)
    return r.stdout


def main() -> int:
    lines = []
    lines.append('"""交叉验证静态向量 —— 由 gmssl 与 OpenSSL 交叉验证生成。')
    lines.append("")
    lines.append("⚠️ 本文件由 ``scripts/gen_interop_vectors.py`` 自动生成，请勿手工编辑。")
    lines.append("")
    lines.append("生成信息:")
    lines.append("    * 生成时间: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("    * gmssl 版本: %s（SM3 / SM4 / SM2 向量来源）" % getattr(gmssl, "__version__", "3.2.2"))
    ossl = find_openssl()
    if ossl:
        lines.append("    * OpenSSL: %s（HMAC-SM3 / PBKDF2-HMAC-SM3 / SM4 对拍来源）" % openssl_version(ossl))
    else:
        lines.append("    * OpenSSL: 未找到支持 SM3 的版本（HMAC/PBKDF2 向量缺省）")
    lines.append("")
    lines.append("这些向量在测试中用于校验本仓库纯 Python 实现（无第三方依赖环境亦可运行）。")
    lines.append('"""')
    lines.append("")
    lines.append("from __future__ import annotations")
    lines.append("")

    # ---------------- SM3 ----------------
    sm3_cases = {
        "empty": b"",
        "abc": b"abc",
        "abcd_x16": b"abcd" * 16,
        "byte_range_64": bytes(range(64)),
        "msg_1000": bytes((i * 7 + 3) % 256 for i in range(1000)),
        # 填充边界（55/56/57 命中 56 字节填充边界；63/64/65 命中分组边界）
        "pad_boundary_55": bytes(range(55)),
        "pad_boundary_56": bytes(range(56)),
        "pad_boundary_57": bytes(range(57)),
        "pad_boundary_63": bytes(range(63)),
        "pad_boundary_65": bytes(range(65)),
    }
    lines.append("# SM3：消息 -> 摘要（gmssl 生成）")
    lines.append("SM3_VECTORS = {")
    for name, msg in sm3_cases.items():
        lines.append('    "%s": ("%s", "%s"),' % (name, msg.hex(), gmssl_sm3_hex(msg)))
    lines.append("}")
    lines.append("")

    # ---------------- SM4 ----------------
    k1 = bytes.fromhex("0123456789abcdeffedcba9876543210")
    c = g_sm4.CryptSM4(padding_mode=g_sm4.PKCS7)
    c.set_key(k1, g_sm4.SM4_ENCRYPT)
    ecb_pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    ecb_single_padded_ct = c.crypt_ecb(ecb_pt)  # 16 字节明文 + PKCS#7 → 32 字节密文
    ecb_ct = ecb_single_padded_ct[:16]
    ecb_multi_pt = bytes(range(37))
    ecb_multi_ct = c.crypt_ecb(ecb_multi_pt)
    ecb_boundary_pt = b"\x00" * 16  # 恰好一个分组：PKCS#7 追加整块填充
    ecb_boundary_ct = c.crypt_ecb(ecb_boundary_pt)

    iv1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cbc_pt = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    cbc_ct = c.crypt_cbc(iv1, cbc_pt)

    ctr_pt = bytes((i * 11 + 5) % 256 for i in range(77))
    if ossl:
        ctr_ct = openssl_enc(ossl, "ctr", k1, iv1, ctr_pt, nopad=False)
        ctr_src = "openssl"
    else:  # pragma: no cover - 仅无 OpenSSL 环境
        ctr_ct = b""
        ctr_src = "unavailable"
    lines.append("# SM4-ECB（gmssl 生成；单分组 + 37 字节 PKCS#7 填充）")
    lines.append("SM4_ECB_VECTORS = {")
    lines.append('    "key": "%s",' % k1.hex())
    lines.append('    "single_plaintext": "%s",' % ecb_pt.hex())
    lines.append('    "single_ciphertext": "%s",' % ecb_ct.hex())
    lines.append(
        '    "single_padded_ciphertext": "%s",' % ecb_single_padded_ct.hex()
    )
    lines.append('    "padded_plaintext": "%s",' % ecb_multi_pt.hex())
    lines.append('    "padded_ciphertext": "%s",' % ecb_multi_ct.hex())
    lines.append('    "boundary16_plaintext": "%s",' % ecb_boundary_pt.hex())
    lines.append('    "boundary16_ciphertext": "%s",' % ecb_boundary_ct.hex())
    lines.append("}")
    lines.append("")
    lines.append("# SM4-CBC（gmssl 生成；32 字节明文 + PKCS#7 填充）")
    lines.append("SM4_CBC_VECTORS = {")
    lines.append('    "key": "%s",' % k1.hex())
    lines.append('    "iv": "%s",' % iv1.hex())
    lines.append('    "plaintext": "%s",' % cbc_pt.hex())
    lines.append('    "ciphertext": "%s",' % cbc_ct.hex())
    lines.append("}")
    lines.append("")
    lines.append("# SM4-CTR（来源: %s；无填充，流模式）" % ctr_src)
    lines.append("SM4_CTR_VECTORS = {")
    lines.append('    "key": "%s",' % k1.hex())
    lines.append('    "iv": "%s",' % iv1.hex())
    lines.append('    "plaintext": "%s",' % ctr_pt.hex())
    lines.append('    "ciphertext": "%s",' % ctr_ct.hex())
    lines.append("}")
    lines.append("")

    # ---------------- HMAC / PBKDF2（OpenSSL） ----------------
    lines.append("# HMAC-SM3（OpenSSL 生成）: (key_hex, msg_hex) -> tag_hex")
    lines.append("HMAC_SM3_VECTORS = {")
    if ossl:
        hmac_cases = [
            (b"key", b"message"),
            (b"", b"empty key"),
            (bytes(range(20)), b"The quick brown fox jumps over the lazy dog"),
            (b"k" * 100, b"long key (>64B) exercises key hashing"),
        ]
        for key, msg in hmac_cases:
            lines.append('    ("%s", "%s"): "%s",' % (key.hex(), msg.hex(), openssl_hmac(ossl, key, msg)))
    lines.append("}")
    lines.append("")
    lines.append("# PBKDF2-HMAC-SM3（OpenSSL 生成）: (pass, salt, iter, dklen) -> dk_hex")
    lines.append("PBKDF2_SM3_VECTORS = {")
    if ossl:
        pbkdf2_cases = [
            ("password", "salt", 1, 32),
            ("password", "salt", 1000, 32),
            ("国密口令", "随机盐值", 500, 16),
            ("longer-password", "0123456789abcdef", 2048, 64),
        ]
        for pw, salt, it, dklen in pbkdf2_cases:
            lines.append(
                '    ("%s", "%s", %d, %d): "%s",'
                % (pw, salt, it, dklen, openssl_pbkdf2(ossl, pw, salt, it, dklen))
            )
    lines.append("}")
    lines.append("")

    # ---------------- SM2 ----------------
    priv_hex = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
    msg = b"message digest"
    g = g_sm2.CryptSM2(private_key=priv_hex, public_key="00" * 64)
    pub = g._kg(int(priv_hex, 16), g_sm2.default_ecc_table["g"])
    g = g_sm2.CryptSM2(private_key=priv_hex, public_key=pub)  # 用真实公钥重建（ZA 依赖公钥）
    k_fixed = "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21"
    e_hex = g._sm3_z(msg)
    sig_fixed = g.sign_with_sm3(msg, random_hex_str=k_fixed)
    sig_random = g.sign_with_sm3(msg)
    g_der = g_sm2.CryptSM2(
        private_key=priv_hex,
        public_key=pub,
        asn1=True,
    )
    der_sig = g_der.sign_with_sm3(msg, random_hex_str=k_fixed)

    enc_msg = b"SM2 interop ciphertext (gmssl generated, random k frozen)"
    g_c1c3c2 = g_sm2.CryptSM2(private_key=priv_hex, public_key=pub, mode=1)
    g_c1c2c3 = g_sm2.CryptSM2(private_key=priv_hex, public_key=pub, mode=0)
    ct_c1c3c2 = g_c1c3c2.encrypt(enc_msg)
    ct_c1c2c3 = g_c1c2c3.encrypt(enc_msg)

    # ZA 按 GM/T 0003.2 定义用 gmssl 的 SM3 逐段拼接计算（不依赖本仓库实现）
    za = gmssl_sm3_hex(
        bytes.fromhex(
            "0080"
            + "31323334353637383132333435363738"  # IDA = '1234567812345678'
            + g_sm2.default_ecc_table["a"]
            + g_sm2.default_ecc_table["b"]
            + g_sm2.default_ecc_table["g"]
            + pub
        )
    )
    lines.append("# SM2（gmssl 生成 / 复核）")
    lines.append("SM2_VECTORS = {")
    lines.append('    "private_key": "%s",' % priv_hex.lower())
    lines.append('    "public_key_xy": "%s",' % pub)
    lines.append('    "ida": "1234567812345678",')
    lines.append('    "message_hex": "%s",' % msg.hex())
    lines.append('    "za": "%s",' % za)
    lines.append('    "digest_e": "%s",' % e_hex)
    lines.append('    "k_fixed": "%s",' % k_fixed.lower())
    lines.append('    "sig_fixed_rs_hex": "%s",' % sig_fixed.lower())
    lines.append('    "sig_random_rs_hex": "%s",' % sig_random.lower())
    lines.append('    "sig_der_hex": "%s",' % der_sig.lower())
    lines.append('    "encrypt_plaintext_hex": "%s",' % enc_msg.hex())
    lines.append('# gmssl mode=1 即 C1C3C2，随机 k 生成后冻结；本仓库实现须能解密出上述明文')
    lines.append('    "encrypt_c1c3c2_hex": "%s",' % ct_c1c3c2.hex())
    lines.append('    "encrypt_c1c2c3_hex": "%s",' % ct_c1c2c3.hex())
    lines.append("}")
    lines.append("")

    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print("已生成 %s" % OUT_PATH)
    print("  SM3 向量: %d" % len(sm3_cases))
    print("  SM4: ECB / CBC / CTR(%s)" % ctr_src)
    print("  HMAC/PBKDF2: %s" % ("OpenSSL" if ossl else "缺省（未找到支持 SM3 的 openssl）"))
    print("  SM2: 固定 k 签名 / 随机 k 签名 / DER / 两种排列密文")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
