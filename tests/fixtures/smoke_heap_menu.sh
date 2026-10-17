#!/bin/bash
# 通用菜单堆利用冒烟：链式/stripped/跳转表/helper/PIE 泄露（一次一个，不并行）。
# 用法：bash tests/fixtures/smoke_heap_menu.sh
cd "$(dirname "$0")/../.." || exit 1
fail=0
run() { # name src cc...
  local name="$1" src="$2"; shift 2
  gcc "$@" -o "/tmp/$name" "$src" 2>/dev/null || { echo "SKIP $name (build)"; return; }
  timeout 120 python3 antpwn.py pwn "/tmp/$name" --no-pheromone > "/tmp/$name.log" 2>&1
  if grep -q '目标已被拿下' "/tmp/$name.log"; then echo "PWNED $name"; else echo "FAIL $name"; fail=1; fi
  rm -f "/tmp/$name" "/tmp/$name.log"
}
run hmo  tests/fixtures/heap_menu_overflow.c   -fno-stack-protector -no-pie
run hmos tests/fixtures/heap_menu_overflow.c   -fno-stack-protector -no-pie -s
run hmj  tests/fixtures/heap_menu_jumptable.c  -O2 -fno-inline -fno-stack-protector -no-pie
run hmh  tests/fixtures/heap_menu_helper.c     -O2 -fno-inline -fno-stack-protector -no-pie
run hmp  tests/fixtures/heap_menu_pie_leak.c   -fpie -pie -fno-stack-protector
run hml  tests/fixtures/heap_menu_pie_late.c   -fpie -pie -fno-stack-protector
exit $fail
