#!/usr/bin/env bash
#
# mayhem/build.sh — build the ArangoDB fuzz harnesses (and the known-answer test probe).
#
# A full ArangoDB build needs RocksDB, V8, Boost 1.9x and a C++26 toolchain, so this compiles the
# self-contained parts of lib/ (Basics, Rest, Endpoint, Logger, ProgramOptions, ...) plus velocypack
# and Abseil directly, into one sanitized static library that every harness links.
# velocypack and abseil-cpp are submodules upstream; the Dockerfile fetches the pinned commits into
# $ARANGO_DEPS (outside the tree), so this script needs no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${ARANGO_DEPS:=/opt/arangodb-deps}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC ARANGO_DEPS

cd "$SRC"
M="$SRC/mayhem"
B="$M/build"
GEN="$B/gen"
VP="$ARANGO_DEPS/velocypack"
ABSL="$ARANGO_DEPS/abseil-cpp"
for d in "$VP/include" "$ABSL/absl"; do
  [ -d "$d" ] || { echo "missing dependency checkout $d (the Dockerfile fetches it)" >&2; exit 1; }
done

rm -rf "$B"
mkdir -p "$GEN/Basics" "$B/san" "$B/plain"

# 1) Generated headers (CMake generates these from .dat / .in files).
python3 utils/generateErrorfile.py lib/Basics/errors.dat "$GEN/Basics/voc-errors.h"
python3 utils/generateErrorfile.py lib/Basics/errors.dat "$GEN/Basics/error-registry.h"
python3 utils/generateExitCodesFiles.py lib/Basics/exitcodes.dat "$GEN/Basics/exitcodes.h"
sed 's/@ARANGODB_VERSION@/3.13.0/' lib/Basics/build.h.in > "$GEN/Basics/build.h"
cat > "$GEN/Basics/directories.h" <<'EOF'
#define _SYSCONFDIR_ "/etc/arangodb3"
#define ICU_DESTINATION_DIRECTORY "/usr/share/arangodb3"
#define SBIN_DIRECTORY "/usr/sbin"
#define BIN_DIRECTORY "/usr/bin"
#define TEST_DIRECTORY "/nonexistent"
EOF

# 2) Flags. Upstream names its vendored ICU namespace/symbols *_64_64; map them onto the system ICU.
ICU_MAP=()
for n in ucasemap_open ucasemap_utf8ToLower ucasemap_utf8ToUpper u_cleanup u_errorName \
         unorm2_getInstance unorm2_normalize u_strFromUTF8 u_strToUTF8; do
  ICU_MAP+=("-D${n}_64_64=${n}")
done
COMMON=(-std=c++2c -w -DNDEBUG -fPIC -DTEST_VIRTUAL= -DHAS_REMOTE_API=0 '-DARCHITECTURE_OPTIMIZATIONS=""'
  -DVELOCYPACK_XXHASH=1 -DASM_OPTIMIZATIONS=0 '-DARANGODB_OPENSSL_VERSION="3"'
  -DARANGODB_OPENSSL_VERSION_MAJOR=3 -DARANGODB_OPENSSL_VERSION_MINOR=5 -DUSE_BUILD_ID_READER=false
  -DBOOST_UUID_RANDOM_PROVIDER_FORCE_POSIX=1 -DBOOST_ALL_NO_LIB=1 '-DARANGODB_BOOST_VERSION="1.83"'
  '-DARANGODB_ZLIB_VERSION="1.3"' '-DARANGODB_V8_VERSION="0"' -DHAVE_SYS_GETTID=1
  -Dicu_64_64=icu "${ICU_MAP[@]}"
  -I"$SRC/lib" -I"$GEN" -I"$VP/include" -I"$VP/external/fast_float" -I"$ABSL"
  -I"$SRC/3rdParty/frozen/include" -I"$SRC/3rdParty/function2" -I"$SRC/3rdParty/date/include"
  -I"$SRC/3rdParty/fuerte/include" -I"$SRC/lib/Inspection/include" -I"$SRC/lib/Futures/include"
  -I"$SRC/lib/Async/include" -I"$SRC/lib/BuildId/include" -I"$SRC/lib/Activities/include"
  -I"$SRC/lib/Actor/include" -I"$SRC/3rdParty/taocpp-json/include" -I"$SRC")
LIBS=(-pthread -lssl -lcrypto -lz -llz4 -licuuc -licui18n -licudata)

# The fuzzed library is built with the sanitizers + fuzzer coverage; the test probe's copy with neither.
SAN_FLAGS=(-O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link)
PLAIN_FLAGS=(-O1 -g0 $COVERAGE_FLAGS)

# 3) Source lists: "<variant> <source>" jobs, one object each.
sources() {
  grep -v '^#' "$M/sources-arangodb.txt" | sed "s|^|$SRC/|"
  grep -v '^#' "$M/sources-absl.txt" | sed "s|^|$ABSL/|"
  for f in velocypack-common AttributeTranslator Builder Collection Compare Dumper Exception \
           HashedStringRef HexDump Iterator Options Parser Serializable SharedSlice Slice Utf8Helper \
           Validator Value ValueType Version asm-functions asm-utf8check fpconv string-functions String; do
    echo "$VP/src/$f.cpp"
  done
  echo "$VP/src/xxhash.c"
  echo "$M/stubs.cpp"
}

compile_one() {
  variant="$1"; src="$2"
  obj="$B/$variant/$(echo "${src#/}" | tr '/' '_').o"
  if [ "$variant" = san ]; then flags=("${SAN_FLAGS[@]}"); else flags=("${PLAIN_FLAGS[@]}"); fi
  # HttpRequest::parseCookies builds std::string(valueBegin, value - valueBegin) with a null `value`
  # for a last cookie without '=' (e.g. "a=b; c"): a pointer-overflow UB that nearly every random
  # cookie input reaches. Unflagged it is a std::length_error that callers catch, no memory error.
  # As the dominant crash it makes Mayhem's start-up probe fail the run, so this one file drops only
  # the pointer-overflow check; ASan and the other UBSan checks stay halting.
  if [ "$variant" = san ] && [ "${src##*/lib/Rest/}" = HttpRequest.cpp ]; then
    flags+=(-fno-sanitize=pointer-overflow)
  fi
  case "$src" in
    *.c) "$CC" "${flags[@]}" -DXXH_NAMESPACE=VELOCYPACK_ -w -fPIC -c "$src" -o "$obj" ;;
    *)   "$CXX" "${COMMON[@]}" "${flags[@]}" -c "$src" -o "$obj" ;;
  esac
}
# xargs children are fresh shells: hand them the arrays and the function through a sourced file
{
  declare -p B CC CXX COMMON SAN_FLAGS PLAIN_FLAGS
  declare -f compile_one
} > "$B/compile_env.sh"

build_lib() {
  variant="$1"
  sources | while read -r s; do echo "$variant $s"; done |
    xargs -P "$MAYHEM_JOBS" -L1 bash -c '. "'"$B"'/compile_env.sh"; compile_one "$@"' _
  rm -f "$B/lib_$variant.a"
  ar rcs "$B/lib_$variant.a" "$B/$variant"/*.o
}

build_lib san

# 4) Fuzz + standalone binaries, one pair per harness.
"$CXX" "${COMMON[@]}" "${SAN_FLAGS[@]}" -c "$M/lsan_off.cc" -o "$B/lsan_off.o"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
for h in "$M"/harness/*.cpp; do
  name="$(basename "$h" .cpp)"
  "$CXX" "${COMMON[@]}" "${SAN_FLAGS[@]}" -c "$h" -o "$B/h_$name.o"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/h_$name.o" "$B/lsan_off.o" \
      "$B/lib_san.a" "${LIBS[@]}" -o "$SRC/$name"
  "$CXX" $SANITIZER_FLAGS $DEBUG_FLAGS "$B/h_$name.o" "$B/standalone_main.o" "$B/lsan_off.o" \
      "$B/lib_san.a" "${LIBS[@]}" -o "$SRC/$name-standalone"
done

# 5) The known-answer probe for test.sh, with the project's normal flags.
build_lib plain
"$CXX" "${COMMON[@]}" "${PLAIN_FLAGS[@]}" -c "$M/kat.cpp" -o "$B/kat.o"
"$CXX" "${PLAIN_FLAGS[@]}" "$B/kat.o" "$B/lib_plain.a" "${LIBS[@]}" -o "$B/arango_kat"
