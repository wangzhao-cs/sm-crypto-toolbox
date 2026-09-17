"""CLI（``smctl``）冒烟测试 —— 以子进程方式运行真实命令行。

零安装运行（仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, SRC_DIR)  # 与其他测试文件一致：确保 src 布局可直接被导入
ENV = dict(os.environ, PYTHONPATH=SRC_DIR)

SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
HMAC_KEY_MSG = "34c90b291a80b7fd7f2be43d683935bab9d149164666c4ef8857c815cf2ef832"


def run_cli(*args: str, input_data: bytes = None):
    """以子进程运行 ``python -m smcrypto``，返回 CompletedProcess（bytes 输出）。"""
    return subprocess.run(
        [sys.executable, "-m", "smcrypto", *args],
        input=input_data,
        capture_output=True,
        env=ENV,
        timeout=300,
    )


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp(prefix="smctl_test_")
        cls.msg_path = os.path.join(cls.tmp, "msg.txt")
        with open(cls.msg_path, "wb") as fh:
            fh.write("国密工具箱 hello".encode())

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _path(self, name: str) -> str:
        return os.path.join(self.tmp, name)

    # ------------------------------------------------------------------ hash

    def test_hash_text_file_stdin(self) -> None:
        r = run_cli("hash", "-t", "abc")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.decode().strip(), SM3_ABC)

        r = run_cli("hash", self.msg_path)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(len(r.stdout.decode().strip()), 64)

        r = run_cli("hash", "-", input_data=b"abc")
        self.assertEqual(r.stdout.decode().strip(), SM3_ABC)

    def test_hash_upper_and_output_file(self) -> None:
        out = self._path("abc.hash")
        r = run_cli("hash", "-t", "abc", "--upper", "-o", out)
        self.assertEqual(r.returncode, 0)
        with open(out, encoding="utf-8") as fh:
            self.assertEqual(fh.read().strip(), SM3_ABC.upper())

    # ------------------------------------------------------------------ hmac

    def test_hmac(self) -> None:
        r = run_cli("hmac", "-k", "key", "-t", "message")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.decode().strip(), HMAC_KEY_MSG)

        r = run_cli("hmac", "-k", "6b6579", "--key-hex", "-t", "message")
        self.assertEqual(r.stdout.decode().strip(), HMAC_KEY_MSG)

    # ------------------------------------------------------------- key/sign

    def test_keygen_sign_verify_flow(self) -> None:
        prefix = self._path("k")
        r = run_cli("keygen", "-o", prefix)
        self.assertEqual(r.returncode, 0)
        priv_path, pub_path = prefix + ".sm2key", prefix + ".sm2pub"
        self.assertTrue(os.path.exists(priv_path) and os.path.exists(pub_path))
        mode = os.stat(priv_path).st_mode & 0o777
        self.assertEqual(mode, 0o600, "私钥文件权限应为 0600")

        sig_path = self._path("msg.sig")
        r = run_cli("sign", "--key", priv_path, self.msg_path, "-o", sig_path)
        self.assertEqual(r.returncode, 0)
        with open(sig_path, encoding="utf-8") as fh:
            self.assertEqual(len(fh.read().strip()), 128, "裸 r||s 应为 128 位十六进制")

        r = run_cli("verify", "--pub", pub_path, "--sig", sig_path, self.msg_path)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertIn("验签通过", r.stdout.decode())

    def test_verify_rejects_tampered_message(self) -> None:
        prefix = self._path("k2")
        run_cli("keygen", "-o", prefix)
        sig = run_cli("sign", "--key", prefix + ".sm2key", self.msg_path).stdout.decode().strip()
        r = run_cli(
            "verify",
            "--pub", prefix + ".sm2pub",
            "--sig-hex", sig,
            "-t", "被篡改的消息",
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("验签失败", r.stdout.decode())

    def test_sign_der_roundtrip(self) -> None:
        prefix = self._path("k3")
        run_cli("keygen", "-o", prefix)
        der_sig = run_cli("sign", "--key", prefix + ".sm2key", "--der", self.msg_path)
        self.assertEqual(der_sig.returncode, 0)
        hexsig = der_sig.stdout.decode().strip()
        self.assertTrue(hexsig.startswith("30"), "DER 应以 SEQUENCE 标签 0x30 开头")
        r = run_cli("verify", "--pub", prefix + ".sm2pub", "--sig-hex", hexsig, self.msg_path)
        self.assertEqual(r.returncode, 0)
        self.assertIn("验签通过", r.stdout.decode())

    def test_sign_with_custom_id(self) -> None:
        prefix = self._path("k4")
        run_cli("keygen", "-o", prefix)
        r_ok = run_cli(
            "sign", "--key", prefix + ".sm2key", "--id", "alice@corp", self.msg_path
        )
        sig = r_ok.stdout.decode().strip()
        r = run_cli(
            "verify", "--pub", prefix + ".sm2pub", "--sig-hex", sig, "--id", "alice@corp", self.msg_path
        )
        self.assertEqual(r.returncode, 0)
        # 用默认 ID 验签应失败（ID 参与 Z_A）
        r_bad = run_cli("verify", "--pub", prefix + ".sm2pub", "--sig-hex", sig, self.msg_path)
        self.assertEqual(r_bad.returncode, 1)

    # ------------------------------------------------------- encrypt/decrypt

    def test_encrypt_decrypt_password_all_ciphers(self) -> None:
        for cipher in ("cbc", "ctr", "ecb"):
            enc = self._path("m.%s.enc" % cipher)
            dec = self._path("m.%s.dec" % cipher)
            with self.subTest(cipher=cipher):
                r = run_cli(
                    "encrypt", "--password", "pw-测试", "--iterations", "600",
                    "--cipher", cipher, self.msg_path, enc,
                )
                self.assertEqual(r.returncode, 0, r.stderr.decode())
                # 密文不应包含明文
                with open(enc, "rb") as fh:
                    blob = fh.read()
                self.assertNotIn("国密工具箱".encode(), blob)
                r = run_cli("decrypt", "--password", "pw-测试", enc, dec)
                self.assertEqual(r.returncode, 0, r.stderr.decode())
                with open(self.msg_path, "rb") as fh1, open(dec, "rb") as fh2:
                    self.assertEqual(fh1.read(), fh2.read())

    def test_decrypt_wrong_password_fails(self) -> None:
        enc = self._path("wrongpw.enc")
        run_cli("encrypt", "--password", "correct", "--iterations", "500", self.msg_path, enc)
        r = run_cli("decrypt", "--password", "incorrect", enc, self._path("wrongpw.dec"))
        self.assertEqual(r.returncode, 1, "错误口令应返回非零退出码")
        self.assertIn("错误", r.stderr.decode())

    def test_encrypt_raw_key_mode(self) -> None:
        key_hex = "00112233445566778899aabbccddeeff"
        enc, dec = self._path("raw.enc"), self._path("raw.dec")
        r = run_cli("encrypt", "--key", key_hex, self.msg_path, enc)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        r = run_cli("decrypt", "--key", key_hex, enc, dec)
        self.assertEqual(r.returncode, 0)
        with open(self.msg_path, "rb") as fh1, open(dec, "rb") as fh2:
            self.assertEqual(fh1.read(), fh2.read())
        # 用 --password 解原始密钥模式的容器应报错
        r = run_cli("decrypt", "--password", "x", enc, self._path("raw.bad"))
        self.assertEqual(r.returncode, 1)

    def test_container_header_is_documented_format(self) -> None:
        enc = self._path("hdr.enc")
        run_cli(
            "encrypt", "--password", "pw", "--iterations", "777", "--cipher", "ctr",
            self.msg_path, enc,
        )
        with open(enc, "rb") as fh:
            blob = fh.read()
        self.assertEqual(blob[:4], b"SMCT", "魔数")
        self.assertEqual(blob[4], 1, "版本号")
        self.assertEqual(blob[5], 2, "算法编号 2 = SM4-CTR")
        self.assertEqual(blob[6], 1, "密钥来源 1 = 口令")
        self.assertEqual(blob[7], 0, "保留字节")
        self.assertEqual(int.from_bytes(blob[8:12], "big"), 777, "PBKDF2 迭代次数")
        self.assertNotEqual(blob[12:28], bytes(16), "盐值应为随机")
        self.assertNotEqual(blob[28:44], bytes(16), "IV 应为随机")

    def test_encrypt_requires_exactly_one_credential(self) -> None:
        r = run_cli("encrypt", self.msg_path, self._path("x.enc"))
        self.assertNotEqual(r.returncode, 0)
        r = run_cli(
            "encrypt", "--password", "p", "--key", "00" * 16, self.msg_path, self._path("y.enc")
        )
        self.assertEqual(r.returncode, 1)

    # ------------------------------------------------------- sm2-encrypt/dec

    def test_sm2_encrypt_decrypt_cli(self) -> None:
        prefix = self._path("k5")
        run_cli("keygen", "-o", prefix)
        enc, dec = self._path("sm2.enc"), self._path("sm2.dec")
        r = run_cli("sm2-encrypt", "--pub", prefix + ".sm2pub", self.msg_path, enc)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        r = run_cli("sm2-decrypt", "--key", prefix + ".sm2key", enc, dec)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        with open(self.msg_path, "rb") as fh1, open(dec, "rb") as fh2:
            self.assertEqual(fh1.read(), fh2.read())

    # -------------------------------------------------------------- self-test

    def test_self_test_exits_zero(self) -> None:
        r = run_cli("self-test")
        out = r.stdout.decode()
        self.assertEqual(r.returncode, 0, "self-test 应全部通过\n" + out)
        self.assertIn("13/13 通过", out)

    def test_no_command_prints_help(self) -> None:
        r = run_cli()
        self.assertEqual(r.returncode, 2)
        self.assertIn(b"usage", r.stdout.lower() + r.stderr.lower())

    def test_version(self) -> None:
        r = run_cli("--version")
        self.assertEqual(r.returncode, 0)
        self.assertIn(b"sm-crypto-toolbox", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
