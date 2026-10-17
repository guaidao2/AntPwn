#!/bin/bash
# i386 轻量冒烟：构建 fixture 并逐个跑 pwn（一次一个，不并行）。
# 用法：bash tests/fixtures/smoke_i386.sh [项目根]
cd "$(dirname "$0")/../.." || exit 1
bash tests/fixtures/build_i386.sh >/dev/null 2>&1 || {
  echo "skip: i386 fixture build failed (no gcc -m32 / 32-bit libc)"; exit 0; }
fail=0
for f in i386_ret2libc i386_write_leak i386_shellcode_leak i386_fmt i386_fmt_libc; do
  [ -x "tests/fixtures/$f" ] || { echo "SKIP $f (not built)"; continue; }
  timeout 120 python3 antpwn.py pwn "tests/fixtures/$f" --no-pheromone > "/tmp/smoke_$f.log" 2>&1
  if grep -q '目标已被拿下' "/tmp/smoke_$f.log"; then
    echo "PWNED $f"
  else
    echo "FAIL $f"; fail=1
  fi
  rm -f "/tmp/smoke_$f.log"
done
rm -f tests/fixtures/i386_ret2libc tests/fixtures/i386_write_leak \
      tests/fixtures/i386_shellcode_leak tests/fixtures/i386_fmt \
      tests/fixtures/i386_fmt_libc
exit $fail
