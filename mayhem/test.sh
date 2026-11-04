#!/usr/bin/env bash
#
# mayhem/test.sh — run the known-answer probe built by mayhem/build.sh against the expected values.
# The probe (mayhem/kat.cpp, built with the project's normal flags) exercises the same velocypack and
# ArangoDB code paths as the fuzz targets and prints `name=value` lines; every line is compared to the
# value recorded below, so a patch that breaks a parser or makes the program a no-op fails.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

KAT="$SRC/mayhem/build/arango_kat"
if [ ! -x "$KAT" ]; then
  echo "missing $KAT: mayhem/build.sh must build it" >&2
  emit_ctrf "arango-kat" 0 1 0
  exit 1
fi

ACTUAL="$(mktemp)"
trap 'rm -f "$ACTUAL"' EXIT
"$KAT" > "$ACTUAL" 2>/dev/null

EXPECTED='vpack.json={"a":[1,2.5,{"b":null}],"c":"dä"}
vpack.bytesize=35
vpack.a1=2.5
vpack.pretty_lines=9
vpack.validate_ok=1
vpack.bad_json=rejected
vpack.validate_truncated=rejected
date.parse_ok=1
date.millis=1582979696789
date.format=2020-02-29 12:34:56.789
date.parse_bad=0
date.duration=ok 1/2/3/4/5/6
date.duration_bad=0
str.urlencode=a%20b%2F%C3%BC%26%3D
str.urldecode=a b/c d
str.hex=616263ff
str.unhex=abc
str.int64=-1234
str.uint64=18446744073709551615
str.double=250
str.split=a|b||c
str.trim=[x y]
str.soundex=R163
str.levenshtein=3
str.escape=a\"\u00E4\n
str.formatsize=5.2 MB
str.replace=a--b--c
str.tolower=abc
str.itoa=9876543210
csv.fields=0:0[a]0:1[b,c]0:2[d]1:0[1]1:1[x"y]1:2[3]
attr.parse=a/b*/c/
attr.count=3
endpoint.unified=http+tcp://127.0.0.1:8529
endpoint.unified_ssl=http+ssl://127.0.0.1:8529
endpoint.unified_bad=
endpoint.uri=http://127.0.0.1:8529
endpoint.hostport=127.0.0.1:8530
endpoint.port=8530
endpoint.bad=null
enc.gunzip=ok:hello world
enc.zlib_roundtrip=1:1
enc.gunzip_bad=0
ini.parse=ok hello world/12/t
ini.unknown=fail
http.values=x=1;y=a b;
http.db=test
http.path=/_api/doc
http.array=1
http.cookie_b=hello world'

pass=0
fail=0
while IFS= read -r want; do
  key="${want%%=*}"
  got="$(grep -m1 -F -x -- "$want" "$ACTUAL" || true)"
  if [ -n "$got" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL $key: want '${want#*=}', got '$(grep -m1 "^$key=" "$ACTUAL" | cut -d= -f2-)'" >&2
  fi
done <<< "$EXPECTED"

emit_ctrf "arango-kat" "$pass" "$fail" 0
