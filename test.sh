#!/bin/sh
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
run() {
    expected=$1
    shift
    status=0
    ./whoran "$@" >"$tmp/out" 2>"$tmp/log" || status=$?
    if [ "$status" -ne "$expected" ]; then
        cat "$tmp/log" >&2
        echo "Expected exit $expected, got $status" >&2
        exit 1
    fi
}

run 2
run 0 --verbose -- /bin/sh -c '/bin/true; exec /bin/echo OK'
test "$(cat "$tmp/out")" = OK
awk '
    /^\[exec\]/ && !root {root=$2}
    /^\[exec\]/ && $3 ~ /\/echo$/ && $2 == root {replaced=1}
    /trace root$/ {parent_pid=$3}
    /└── true [(]PID [0-9]/ && /parent: .*sh \(PID [0-9]+\)$/ {
        child=($NF == parent_pid)
    }
    END {exit !(child && replaced)}
' "$tmp/log"
run 2 --lang invalid -- /bin/true
run 37 --lang ru -- /bin/sh -c 'exit 37'
grep -q 'код 37' "$tmp/log"
run 37 --lang en -- /bin/sh -c 'exit 37'
run 143 -- /bin/sh -c 'kill -TERM $$'
grep -q 'signal 15' "$tmp/log"
run 127 -- /nonexistent/whoran-test-command
run 0 --json "$tmp/report.json" -- /bin/sh -c '/bin/true; exec /bin/echo "$1"' sh 'два "слова"'
if grep -Eq '^\[(fork|exec)\]' "$tmp/log"; then exit 1; fi
grep -Eq '│  [0-9]+ ms  │  parent:' "$tmp/log"
grep -q '└── true [(]PID [0-9]' "$tmp/log"
python3 - "$tmp/report.json" <<'CHECK'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    report = json.load(source)
root, child = report["processes"]
assert root["parent"] is None and child["parent"] == root["id"]
assert root["exit_code"] == child["exit_code"] == 0
history = [e for e in report["execs"] if e["process"] == root["id"]]
assert len(history) == 2 and history[0]["pid"] == history[1]["pid"] == root["pid"]
assert history[1]["argv"] == ["/bin/echo", 'два "слова"']
assert root["start_ms"] <= history[0]["at_ms"] <= history[1]["at_ms"] <= root["end_ms"]
CHECK
cp "$tmp/report.json" "$tmp/original"
run 1 --json "$tmp/report.json" -- /bin/echo unexpected
cmp "$tmp/original" "$tmp/report.json"
test ! -s "$tmp/out"
echo "All tests passed"
