#!/usr/bin/env bash
# hh-suite/mayhem/build.sh — cmake build (ASan+UBSan) + the uprstr libFuzzer harness.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS=-gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}" ; : "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS
# hh-suite has benign UB that fires on ~every input: its hashing (hhutil-inl.h) does signed
# overflow, and its fast float-pow2/log2 bit-twiddling (util-inl.h:213, `*px += (lx << 23)`) does a
# left shift of a negative integer exponent into the IEEE-754 exponent field. Under the default
# -fno-sanitize-recover both halt the target on valid MSA/a3m input (e.g. data/query.a3m), so it
# can't fuzz. Relax ONLY those two checks (keep ASan + the rest of UBSan halting) when UBSan is in
# play; guarded on *undefined* so the empty off-switch (SANITIZER_FLAGS=) stays clean.
FLAGS="$SANITIZER_FLAGS"
case "$SANITIZER_FLAGS" in *undefined*) FLAGS="$SANITIZER_FLAGS -fno-sanitize=signed-integer-overflow -fno-sanitize=shift" ;; esac
cd "$SRC"
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DHAVE_SSE2=1 \
      -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
      -DCMAKE_C_FLAGS="$FLAGS $DEBUG_FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS $DEBUG_FLAGS"
make -j"$MAYHEM_JOBS"                                   # builds libHH_OBJECTS.a + tools (hhmake at build/src/hhmake)
$CXX $FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$SRC/mayhem/fuzz_uprstr.cpp" \
     -I "$SRC/src/" -I "$SRC/lib/simd" -I "$SRC/lib/simde/" \
     src/libHH_OBJECTS.a -o /mayhem/fuzz_uprstr
# also a standalone (non-fuzzer) reproducer: same harness + LLVM's standalone main, no fuzzing engine.
# Compile the driver as C ($CC) so its LLVMFuzzerTestOneInput ref keeps C linkage (clang++ would mangle it).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX $FLAGS $DEBUG_FLAGS /tmp/standalone_main.o "$SRC/mayhem/fuzz_uprstr.cpp" \
     -I "$SRC/src/" -I "$SRC/lib/simd" -I "$SRC/lib/simde/" \
     src/libHH_OBJECTS.a -o /mayhem/fuzz_uprstr-standalone

# Build the FULL tool suite with NORMAL flags (separate dir) so mayhem/test.sh only RUNS hh-suite's
# integration pipeline (data/test.sh). Needs OpenMP (libomp-dev, in the Dockerfile) for the *_omp
# tools that pipeline invokes.
cd "$SRC"
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Release -DHAVE_SSE2=1 >/dev/null
cmake --build build-tests -j"$MAYHEM_JOBS"
