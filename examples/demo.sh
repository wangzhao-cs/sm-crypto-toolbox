#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# 国密算法工具箱端到端演示（smctl 命令行）
#
# 用法:
#   bash examples/demo.sh          # 无需安装，自动使用仓库内 src/ 与 .venv
#
# 演示内容:
#   1. SM3 杂凑 / HMAC-SM3
#   2. SM2 密钥生成 → 签名 → 验签（含篡改验证）
#   3. SM4-CBC 口令加密 → 解密 → HMAC 完整性校验
#   4. SM2 公钥加密 → 私钥解密
#   5. 内置自检
# ---------------------------------------------------------------------------
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"

PY="${PY:-python3}"
if [ -x "$REPO/.venv/bin/python" ]; then
  PY="$REPO/.venv/bin/python"
fi
export PYTHONPATH="$REPO/src"

smctl() { "$PY" -m smcrypto "$@"; }

WORK="$HERE/demo_out"
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hr "0. 环境"
"$PY" -c "import sys, platform; print('Python', sys.version.split()[0], '|', platform.system(), platform.machine())"

hr "1. SM3 杂凑与 HMAC-SM3"
printf '国密算法工具箱 hello' > hello.txt
echo '$ smctl hash hello.txt'
smctl hash hello.txt
echo '$ smctl hash -t abc'
smctl hash -t abc
echo '$ smctl hmac -k secret-key hello.txt'
smctl hmac -k secret-key hello.txt

hr "2. SM2 密钥生成 / 签名 / 验签"
echo '$ smctl keygen -o demo'
smctl keygen -o demo
echo '$ cat demo.sm2key（演示用，实际请妥善保管）'
cat demo.sm2key
echo '$ smctl sign --key demo.sm2key hello.txt -o hello.sig'
smctl sign --key demo.sm2key hello.txt -o hello.sig
echo "signature = $(cat hello.sig)"
echo
echo '$ smctl verify --pub demo.sm2pub --sig hello.sig hello.txt'
smctl verify --pub demo.sm2pub --sig hello.sig hello.txt
echo
printf '被篡改的消息' > tampered.txt
echo '$ smctl verify --pub demo.sm2pub --sig hello.sig tampered.txt   # 预期失败'
if smctl verify --pub demo.sm2pub --sig hello.sig tampered.txt; then
  echo "!! 不应通过" >&2; exit 1
else
  echo "(exit code $? —— 签名校验按预期拒绝)"
fi

hr "3. SM4-CBC 口令加密 / 解密 + HMAC 完整性校验"
echo '$ smctl encrypt --password "正确密码" --iterations 20000 hello.txt hello.enc'
smctl encrypt --password "正确密码" --iterations 20000 hello.txt hello.enc
echo '$ xxd hello.enc | head -3'
if command -v xxd >/dev/null; then xxd hello.enc | head -3; else od -A x -t x1z hello.enc | head -3; fi
echo
echo '$ smctl decrypt --password "正确密码" hello.enc hello.dec'
smctl decrypt --password "正确密码" hello.enc hello.dec
cmp hello.txt hello.dec && echo "roundtrip OK: hello.dec 与 hello.txt 一致"
echo
echo '$ smctl hmac -k integrity-key hello.txt   # 解密后用 HMAC-SM3 校验完整性'
MAC1="$(smctl hmac -k integrity-key hello.txt)"
MAC2="$(smctl hmac -k integrity-key hello.dec)"
echo "原文 MAC   = $MAC1"
echo "解密后 MAC = $MAC2"
[ "$MAC1" = "$MAC2" ] && echo "MAC 一致 —— 文件完整性校验通过"
echo
echo '$ smctl hmac -k 6b6579 --key-hex -t message   # 十六进制密钥用法'
smctl hmac -k 6b6579 --key-hex -t message
echo
echo '$ smctl decrypt --password "错误密码" hello.enc bad.dec   # 预期失败'
if smctl decrypt --password "错误密码" hello.enc bad.dec 2>err.log; then
  echo "!! 不应通过" >&2; exit 1
else
  echo "(exit code $? —— 错误口令被拒绝: $(tail -1 err.log))"
fi

hr "4. SM2 公钥加密 / 私钥解密"
echo '$ smctl sm2-encrypt --pub demo.sm2pub hello.txt hello.sm2'
smctl sm2-encrypt --pub demo.sm2pub hello.txt hello.sm2
echo '$ smctl sm2-decrypt --key demo.sm2key hello.sm2 hello.sm2.dec'
smctl sm2-decrypt --key demo.sm2key hello.sm2 hello.sm2.dec
cmp hello.txt hello.sm2.dec && echo "roundtrip OK: SM2 加解密一致"

hr "5. 内置自检（标准向量 + 往返 + 曲线健全性）"
smctl self-test

hr "完成"
echo "演示产物位于: $WORK"
