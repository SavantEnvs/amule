#!/usr/bin/env bash
#
# mayhem/build.sh: build aMule's fuzz harnesses (sanitized libs + harnesses + standalone reproducers)
# and, separately and with the project's normal flags, the unit tests and the known-answer probe that
# mayhem/test.sh runs. Idempotent and offline: every dependency is an apt -dev package in the image.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

COMMON_CMAKE=(
	-G Ninja
	-DCMAKE_BUILD_TYPE=Release
	-DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
	-DBUILD_DAEMON=ON -DBUILD_ED2K=ON -DBUILD_WEBSERVER=ON
	-DBUILD_MONOLITHIC=OFF -DBUILD_ALC=OFF -DBUILD_ALCC=OFF -DBUILD_AMULECMD=OFF -DBUILD_CAS=OFF
	-DBUILD_FILEVIEW=OFF -DBUILD_REMOTEGUI=OFF -DBUILD_WXCAS=OFF -DBUILD_EVERYTHING=OFF
	-DENABLE_UPNP=OFF -DENABLE_NLS=OFF -DENABLE_IP2COUNTRY=OFF -DENABLE_MMAP=OFF
	-DDOWNLOAD_AND_BUILD_DEPS=OFF
)

# Always configure from scratch: a cached tree configured under a different compiler path (the ccache
# pre-fill masquerade) makes CMake discard its cache mid-build and re-run with the -D options lost.
rm -rf "$SRC/build/fuzz" "$SRC/build/tests"

# 1) Sanitized project libraries for the fuzz targets. CMAKE_<LANG>_FLAGS_RELEASE is overridden so the
#    build keeps assertions (no -DNDEBUG) and stays at -O1 for readable ASan/UBSan reports.
# MULEUNIT is what upstream's own unit tests define: it turns the application logger (which would need
# the whole daemon) into no-op macros, leaving the parsers and codecs themselves unchanged.
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -DMULEUNIT"
cmake -S . -B build/fuzz "${COMMON_CMAKE[@]}" -DBUILD_TESTING=OFF \
	-DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
	-DCMAKE_C_FLAGS_RELEASE="-O1" -DCMAKE_CXX_FLAGS_RELEASE="-O1"
cmake --build build/fuzz -j"$MAYHEM_JOBS" --target ec muleappcommon mulecommon

# 2) Harnesses: fuzzer binary + standalone reproducer, each with LeakSanitizer switched off at build time.
B="$SRC/build/fuzz"
WX_FLAGS="$(wx-config --cxxflags base)"
WX_LIBS="$(wx-config --libs base)"
INCS=(-I"$B" -I"$B/src/libs/ec/cpp" -I"$SRC/src" -I"$SRC/src/include" -I"$SRC/src/libs" -I"$SRC/src/libs/ec/cpp")
LIBS=("$B/src/libmuleappcommon.a" "$B/src/libs/ec/cpp/libec.a" "$B/src/libs/common/libmulecommon.a"
	-lcryptopp -lz $WX_LIBS)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/lsan_off.o
# amuleIPV4Address (used by NetworkFunctions) lives in LibSocket; EC_REMOTE + env_stubs.cc is how
# upstream's NetworkFunctionsTest builds it standalone, without the daemon's event system. This one
# TU drops UBSan's vptr check: it references the daemon's CMuleUDPSocket type, which isn't linked in.
$CXX -std=c++17 $FUZZ_FLAGS -fno-sanitize=vptr -O1 -DEC_REMOTE -DwxUSE_GUI=0 -DWXUSINGDLL $WX_FLAGS "${INCS[@]}" \
	-c "$SRC/src/LibSocket.cpp" -o /tmp/LibSocket_fuzz.o
$CXX -std=c++17 $FUZZ_FLAGS -O1 -DEC_REMOTE -DwxUSE_GUI=0 -DWXUSINGDLL $WX_FLAGS "${INCS[@]}" \
	-c "$SRC/mayhem/env_stubs.cc" -o /tmp/env_stubs_fuzz.o
# RLE.cpp memset()s a NULL buffer with length 0 on a zero-length run, which trips UBSan's nonnull-attribute
# check on the very first inputs and masks everything behind it. Benign (no bytes touched), so that one
# check is relaxed for this one file; the object is linked ahead of libmuleappcommon.a so it wins.
$CXX -std=c++17 $FUZZ_FLAGS -fno-sanitize=nonnull-attribute -O1 -DwxUSE_GUI=0 -DWXUSINGDLL $WX_FLAGS "${INCS[@]}" \
	-c "$SRC/src/RLE.cpp" -o /tmp/RLE_fuzz.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

for t in ec_packet ed2k_link magnet_uri tag_stream rle_decode; do
	src="$SRC/mayhem/$t/fuzz_$t.cc"
	$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -DMULEUNIT -DwxUSE_GUI=0 -DWXUSINGDLL $WX_FLAGS "${INCS[@]}" \
		-c "$src" -o "/tmp/fuzz_$t.o"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "/tmp/fuzz_$t.o" /tmp/RLE_fuzz.o /tmp/LibSocket_fuzz.o /tmp/env_stubs_fuzz.o /tmp/lsan_off.o \
		"${LIBS[@]}" -o "$SRC/fuzz_$t"
	$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "/tmp/fuzz_$t.o" /tmp/RLE_fuzz.o /tmp/LibSocket_fuzz.o /tmp/env_stubs_fuzz.o /tmp/standalone_main.o /tmp/lsan_off.o \
		"${LIBS[@]}" -o "$SRC/fuzz_$t-standalone"
done

# 3) Test suite with the project's NORMAL flags: aMule's muleunit tests plus a known-answer probe
#    (mayhem/kat.cc) linked dynamically against the unsanitized libraries.
cmake -S . -B build/tests "${COMMON_CMAKE[@]}" -DBUILD_TESTING=ON \
	-DCMAKE_C_FLAGS="$COVERAGE_FLAGS -DMULEUNIT" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS -DMULEUNIT"
cmake --build build/tests -j"$MAYHEM_JOBS" --target \
	CTagTest CUInt128Test FileDataIOTest FormatTest NetworkFunctionsTest PathTest PhpArrayTest \
	RangeMapTest StringFunctionsTest TextFileTest ec muleappcommon mulecommon

T="$SRC/build/tests"
$CXX -std=c++17 -O3 -DNDEBUG $COVERAGE_FLAGS -DMULEUNIT -DEC_REMOTE -DwxUSE_GUI=0 -DWXUSINGDLL $WX_FLAGS \
	-I"$T" -I"$T/src/libs/ec/cpp" -I"$SRC/src" -I"$SRC/src/include" -I"$SRC/src/libs" -I"$SRC/src/libs/ec/cpp" \
	"$SRC/mayhem/kat.cc" "$SRC/mayhem/env_stubs.cc" "$SRC/src/LibSocket.cpp" "$T/src/libmuleappcommon.a" "$T/src/libs/ec/cpp/libec.a" \
	"$T/src/libs/common/libmulecommon.a" -lcryptopp -lz $WX_LIBS -o "$T/kat"
