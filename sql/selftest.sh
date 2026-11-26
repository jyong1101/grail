#!/usr/bin/env bash
# selftest.sh - prove sqlauto.py works on THIS machine: starts the practice target, attacks it, counts flags. ~2 min.
cd "$(dirname "$0")" || exit 1
PORT=${1:-8097}; OUT=$(mktemp -d)
python3 practice_target.py "$PORT" >/dev/null 2>&1 & T=$!; trap 'kill $T 2>/dev/null' EXIT; sleep 1
python3 sqlauto.py "http://127.0.0.1:$PORT/" --out "$OUT" > "$OUT/selftest.log" 2>&1
got=$(sed -n '/^\[5\] REPORT/,$p' "$OUT/selftest.log" | grep -c '>>> ehCTF{')
tok=$(grep -c 'v4-bare-token-7f3a9c' "$OUT/loot.txt")
echo "flags found: $got / 13     bare token table dumped: $([ "$tok" -gt 0 ] && echo yes || echo no)     log: $OUT/selftest.log"
[ "$got" -eq 13 ] && [ "$tok" -gt 0 ] && echo "SELFTEST PASS" || { echo "SELFTEST FAIL"; exit 1; }
