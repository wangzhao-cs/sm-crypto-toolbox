"""``smctl`` —— 国密算法工具箱命令行入口。

子命令一览::

    smctl hash        SM3 杂凑
    smctl hmac        HMAC-SM3 消息认证码
    smctl keygen      生成 SM2 密钥对
    smctl sign        SM2 签名（含 DER 输出选项）
    smctl verify      SM2 验签
    smctl encrypt     SM4 文件加密（SMCT v1 容器；口令 / 原始密钥）
    smctl decrypt     SM4 文件解密
    smctl sm2-encrypt SM2 公钥加密
    smctl sm2-decrypt SM2 私钥解密
    smctl self-test   内置自检（标准向量 + 往返 + 曲线健全性）

设计约定：业务数据只写 stdout / 输出文件，提示信息一律走 stderr，
因此 ``smctl hash file > digest.txt`` 等管道用法安全。
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Tuple

from . import __version__
from .filecrypt import (
    DEFAULT_ITERATIONS,
    decrypt_bytes,
    encrypt_bytes,
    parse_header,
)
from .selftest import run_self_test
from .sm2 import (
    IDA_DEFAULT,
    decode_point,
    decode_signature_der,
    encode_signature_der,
    generate_keypair,
    sm2_decrypt,
    sm2_encrypt,
    sm2_sign,
    sm2_verify,
)
from .sm3 import hmac_sm3, sm3_hexdigest

__all__ = ["main", "build_parser"]


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------


def _read_input(args: argparse.Namespace) -> bytes:
    """按 --text / FILE / ``-``（stdin）解析输入数据。"""
    if getattr(args, "text", None) is not None:
        return args.text.encode("utf-8")
    path = getattr(args, "file", "-")
    if path in (None, "-"):
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def _write_output(data: bytes, path: Optional[str]) -> None:
    """写输出：``path`` 为空时写 stdout（自动补换行），否则写文件。"""
    if path:
        with open(path, "wb") as fh:
            fh.write(data)
        _info("已写入 %s（%d 字节）" % (path, len(data)))
        return
    sys.stdout.buffer.write(data)
    if not data.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()


def _info(msg: str) -> None:
    """提示信息写 stderr（保持 stdout 只承载业务数据）。"""
    print(msg, file=sys.stderr)


def _load_hex_file(path: str) -> bytes:
    """读取十六进制密钥文件（容忍空白、注释行与 0x 前缀）。"""
    with open(path, encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
    text = "".join(lines)
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("密钥文件 %s 不是合法十六进制：%s" % (path, exc)) from exc


def _load_private_key(args: argparse.Namespace) -> int:
    if getattr(args, "key_hex", None):
        return int(args.key_hex, 16)
    if getattr(args, "key", None):
        raw = _load_hex_file(args.key)
        if len(raw) != 32:
            raise ValueError("SM2 私钥应为 32 字节（64 位十六进制）")
        return int.from_bytes(raw, "big")
    raise ValueError("必须提供 --key（私钥文件）或 --key-hex")


def _load_public_key(args: argparse.Namespace):
    if getattr(args, "pub_hex", None):
        return decode_point(bytes.fromhex(args.pub_hex))
    if getattr(args, "pub", None):
        return decode_point(_load_hex_file(args.pub))
    raise ValueError("必须提供 --pub（公钥文件）或 --pub-hex")


def _load_signature(args: argparse.Namespace) -> bytes:
    """读取签名：支持 hex 文本（r||s 或 DER-hex）与二进制 DER。"""
    if getattr(args, "sig_hex", None):
        return bytes.fromhex(args.sig_hex)
    if getattr(args, "sig", None):
        with open(args.sig, "rb") as fh:
            raw = fh.read()
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            return raw
        if text and all(ch in "0123456789abcdefABCDEF" for ch in text):
            return bytes.fromhex(text)
        return raw
    raise ValueError("必须提供 --sig（签名文件）或 --sig-hex")


def _parse_sig_bytes(raw: bytes) -> Tuple[int, int]:
    """把签名原始字节解析为 (r, s)：支持 64 字节 r||s 或 DER。"""
    if len(raw) == 64:
        return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    return decode_signature_der(raw)


def _iterations_arg(value: str) -> int:
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("迭代次数必须是整数") from exc
    if n < 1:
        raise argparse.ArgumentTypeError("迭代次数必须 >= 1")
    return n


def _ida_arg(value: str) -> bytes:
    return value.encode("utf-8")


# ---------------------------------------------------------------------------
# 子命令实现
# ---------------------------------------------------------------------------


def _cmd_hash(args: argparse.Namespace) -> int:
    data = _read_input(args)
    digest = sm3_hexdigest(data)
    if args.upper:
        digest = digest.upper()
    _write_output(digest.encode("ascii"), args.output)


def _cmd_hmac(args: argparse.Namespace) -> int:
    data = _read_input(args)
    key = bytes.fromhex(args.key) if args.key_hex else args.key.encode("utf-8")
    tag = hmac_sm3(key, data).hex()
    if args.upper:
        tag = tag.upper()
    _write_output(tag.encode("ascii"), args.output)


def _cmd_keygen(args: argparse.Namespace) -> int:
    d, pub = generate_keypair()
    priv_hex = "%064x" % d
    pub_hex = "04" + "%064x%064x" % (pub.x, pub.y)
    if args.out:
        priv_path = args.out + ".sm2key"
        pub_path = args.out + ".sm2pub"
        with open(priv_path, "w", encoding="utf-8") as fh:
            fh.write(priv_hex + "\n")
        os.chmod(priv_path, 0o600)
        with open(pub_path, "w", encoding="utf-8") as fh:
            fh.write(pub_hex + "\n")
        _info("私钥: %s（权限 0600，切勿提交到版本库）" % priv_path)
        _info("公钥: %s" % pub_path)
    else:
        print("私钥: %s" % priv_hex)
        print("公钥: %s" % pub_hex)
        _info("提示：私钥请妥善保管；用 -o 前缀可写入 .sm2key/.sm2pub 文件")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    d = _load_private_key(args)
    data = _read_input(args)
    ida = _ida_arg(args.id) if args.id else IDA_DEFAULT
    r, s = sm2_sign(d, data, ida=ida)
    if args.der:
        out_bytes = encode_signature_der(r, s).hex().encode("ascii")
    else:
        out_bytes = ("%064x%064x" % (r, s)).encode("ascii")
    _write_output(out_bytes, args.output)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    pub = _load_public_key(args)
    data = _read_input(args)
    raw = _load_signature(args)
    ida = _ida_arg(args.id) if args.id else IDA_DEFAULT
    try:
        r, s = _parse_sig_bytes(raw)
    except ValueError as exc:
        print("验签失败：签名格式无法解析（%s）" % exc, file=sys.stderr)
        return 1
    ok = sm2_verify(pub, data, r, s, ida=ida)
    print("验签通过" if ok else "验签失败")
    return 0 if ok else 1


def _cmd_encrypt(args: argparse.Namespace) -> int:
    with open(args.infile, "rb") as fh:
        plaintext = fh.read()
    container = encrypt_bytes(
        plaintext,
        cipher="sm4-" + args.cipher,
        password=args.password,
        key=args.key,
        iterations=args.iterations,
    )
    with open(args.outfile, "wb") as fh:
        fh.write(container)
    _info(
        "已加密 %d 字节 → %s（SM4-%s，%s，容器共 %d 字节）"
        % (
            len(plaintext),
            args.outfile,
            args.cipher.upper(),
            "口令模式，PBKDF2 迭代 %d" % args.iterations if args.password else "原始密钥模式",
            len(container),
        )
    )
    return 0


def _cmd_decrypt(args: argparse.Namespace) -> int:
    with open(args.infile, "rb") as fh:
        container = fh.read()
    plaintext = decrypt_bytes(container, password=args.password, key=args.key)
    with open(args.outfile, "wb") as fh:
        fh.write(plaintext)
    header = parse_header(container)
    _info(
        "已解密 %s → %s（SM4-%s，明文 %d 字节）"
        % (args.infile, args.outfile, header.cipher.replace("sm4-", "").upper(), len(plaintext))
    )
    return 0


def _cmd_sm2_encrypt(args: argparse.Namespace) -> int:
    pub = _load_public_key(args)
    if args.text is not None:
        data = args.text.encode("utf-8")
    else:
        with open(args.infile, "rb") as fh:
            data = fh.read()
    ct = sm2_encrypt(pub, data, mode=args.mode)
    with open(args.outfile, "wb") as fh:
        fh.write(ct)
    _info("已加密 %d 字节 → %s（SM2，%s，密文 %d 字节）" % (len(data), args.outfile, args.mode, len(ct)))
    return 0


def _cmd_sm2_decrypt(args: argparse.Namespace) -> int:
    d = _load_private_key(args)
    with open(args.infile, "rb") as fh:
        ct = fh.read()
    pt = sm2_decrypt(d, ct, mode=args.mode)
    with open(args.outfile, "wb") as fh:
        fh.write(pt)
    _info("已解密 %s → %s（SM2，明文 %d 字节）" % (args.infile, args.outfile, len(pt)))
    return 0


def _cmd_self_test(args: argparse.Namespace) -> int:
    ok = run_self_test(full=args.full)
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smctl",
        description="国密算法工具箱 sm-crypto-toolbox：SM2/SM3/SM4 纯 Python 实现（教学与工具用途）",
    )
    parser.add_argument("--version", action="version", version="smctl (sm-crypto-toolbox) " + __version__)
    sub = parser.add_subparsers(dest="command", metavar="命令")

    def add_io(p: argparse.ArgumentParser) -> None:
        p.add_argument("file", nargs="?", default="-", help="输入文件（默认 '-' 读取标准输入）")
        p.add_argument("-t", "--text", help="直接对给定文本（UTF-8）操作，代替 FILE")
        p.add_argument("-o", "--output", help="输出文件（默认写 stdout）")

    # hash
    p = sub.add_parser("hash", help="计算 SM3 杂凑值")
    add_io(p)
    p.add_argument("--upper", action="store_true", help="输出大写十六进制")
    p.set_defaults(func=_cmd_hash)

    # hmac
    p = sub.add_parser("hmac", help="计算 HMAC-SM3 消息认证码")
    add_io(p)
    p.add_argument("-k", "--key", required=True, help="密钥（文本；--key-hex 时按十六进制解析）")
    p.add_argument("--key-hex", action="store_true", help="把 --key 视为十六进制")
    p.add_argument("--upper", action="store_true", help="输出大写十六进制")
    p.set_defaults(func=_cmd_hmac)

    # keygen
    p = sub.add_parser("keygen", help="生成 SM2 密钥对")
    p.add_argument("-o", "--out", help="输出前缀：生成 <前缀>.sm2key 与 <前缀>.sm2pub")
    p.set_defaults(func=_cmd_keygen)

    # sign
    p = sub.add_parser("sign", help="SM2 签名（SM2-with-SM3）")
    add_io(p)
    p.add_argument("--key", help="私钥文件（hex 文本）")
    p.add_argument("--key-hex", help="私钥十六进制字符串（与 --key 二选一）")
    p.add_argument("--id", help="签名者标识 ID_A（默认 1234567812345678）")
    p.add_argument("--der", action="store_true", help="输出 DER（十六进制文本）而不是裸 r||s")
    p.set_defaults(func=_cmd_sign)

    # verify
    p = sub.add_parser("verify", help="SM2 验签")
    add_io(p)
    p.add_argument("--pub", help="公钥文件（hex 文本，04||X||Y 或 X||Y）")
    p.add_argument("--pub-hex", help="公钥十六进制字符串（与 --pub 二选一）")
    p.add_argument("--sig", help="签名文件（hex 文本或二进制 DER）")
    p.add_argument("--sig-hex", help="签名十六进制字符串（与 --sig 二选一）")
    p.add_argument("--id", help="签名者标识 ID_A（默认 1234567812345678）")
    p.set_defaults(func=_cmd_verify)

    # encrypt / decrypt
    for name, fn, is_enc in (("encrypt", _cmd_encrypt, 1), ("decrypt", _cmd_decrypt, 0)):
        p = sub.add_parser(name, help="SM4 文件%s（SMCT v1 容器）" % ("加密" if is_enc else "解密"))
        p.add_argument("infile", help="输入文件")
        p.add_argument("outfile", help="输出文件")
        if is_enc:
            p.add_argument(
                "--cipher", choices=["cbc", "ctr", "ecb"], default="cbc", help="工作模式（默认 cbc）"
            )
            p.add_argument(
                "--iterations",
                type=_iterations_arg,
                default=DEFAULT_ITERATIONS,
                help="PBKDF2 迭代次数（默认 %d）" % DEFAULT_ITERATIONS,
            )
        p.add_argument("--password", help="口令（与 --key 二选一）")
        p.add_argument("--key", help="16 字节原始密钥（32 位十六进制；与 --password 二选一）")
        p.set_defaults(func=fn)

    # sm2-encrypt / sm2-decrypt
    p = sub.add_parser("sm2-encrypt", help="SM2 公钥加密（C1C3C2 排列）")
    p.add_argument("infile", help="明文文件")
    p.add_argument("outfile", help="密文输出文件")
    p.add_argument("--pub", help="公钥文件（hex 文本）")
    p.add_argument("--pub-hex", help="公钥十六进制字符串")
    p.add_argument("--mode", choices=["C1C3C2", "C1C2C3"], default="C1C3C2", help="密文排列")
    p.add_argument("-t", "--text", help="直接加密给定文本，代替 infile")
    p.set_defaults(func=_cmd_sm2_encrypt)

    p = sub.add_parser("sm2-decrypt", help="SM2 私钥解密")
    p.add_argument("infile", help="密文文件")
    p.add_argument("outfile", help="明文输出文件")
    p.add_argument("--key", help="私钥文件（hex 文本）")
    p.add_argument("--key-hex", help="私钥十六进制字符串")
    p.add_argument("--mode", choices=["C1C3C2", "C1C2C3"], default="C1C3C2", help="密文排列")
    p.set_defaults(func=_cmd_sm2_decrypt)

    # self-test
    p = sub.add_parser("self-test", help="运行内置自检")
    p.add_argument("--full", action="store_true", help="包含 SM4 100 万次迭代向量（约 25 秒）")
    p.set_defaults(func=_cmd_self_test)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI 入口，返回退出码（0 成功 / 1 失败 / 2 用法错误）。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print("错误：%s" % exc, file=sys.stderr)
        return 1
    except BrokenPipeError:  # pragma: no cover - 管道提前关闭
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
