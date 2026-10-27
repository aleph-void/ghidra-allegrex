#!/usr/bin/env bash
# Allegrex module test suite: everything that needs no downloaded inputs.
#
#   GHIDRA_INSTALL_DIR=<scratch Ghidra 12.1.x> test/run-tests.sh [workdir] [--real]
#
# 1. the generator reproduces the checked-in VFPU SLEIGH (allegrexVfpuFields.sinc, allegrexVfpu.sinc)
# 2. the spec compiles (.sla well under 16 MB); the module (with its Kotlin classes) is linked into the install
# 3. decode differential against psp-objdump (pspdev binutils, Allegrex branch, with the VFPU) and rabbitizer
#    (MIT, R4000ALLEGREX): every sub-opcode field combination (1.3 million words) and 100,000 random words;
#    compare.py classifies every difference and fails on any unexplained one
# 4. every SLEIGH constructor is reached (Reach.java): the corpora, one instance of every core instruction
#    form (reach_base.s), and VFPU words decoded under 32 prefix context sets (reach_contexts.py)
# 5. p-code: hand-computed emulator tests (EmuCheck.java), one deliberately wrong expectation must be reported
# 6. if PPSSPP_HEADLESS is set: the VFPU semantics differential against PPSSPP, run as a black box
#    (vfpu_diff.py, EmuVfpu.java)
# --real adds step 7: PSPSDK samples built with the pspdev toolchain, auto-imported, analysed, decompiled and
#    compared with psp-objdump (test/real-binaries.sh; downloads the pinned toolchain release)
#
# Environment: GHIDRA_INSTALL_DIR (a scratch copy of Ghidra 12.1.x: the module is symlinked into its
# Ghidra/Processors/Allegrex; its jar and kotlin-stdlib are built into lib/ with Gradle, which needs Maven
# Central), JAVA_HOME (a JDK with javac), PSPDEV (the pspdev toolchain: psp-as, psp-objdump, psp-gcc ...;
# default: the download under the work directory), RABBITIZER_PYTHON (a python with rabbitizer==1.16.2),
# PPSSPP_HEADLESS (optional: a PPSSPPHeadless binary).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a scratch Ghidra 12.1.x}"
REAL=0
ARGS=()
for a in "$@"; do if [[ $a == --real ]]; then REAL=1; else ARGS+=("$a"); fi; done
W=$(readlink -m "${ARGS[0]:-${TMPDIR:-/tmp}/allegrex-tests}")
mkdir -p "$W"
export GHIDRA_INSTALL_DIR
fail=0
LANGID=Allegrex:LE:32:default
L=$MOD/data/languages
PSPBIN=${PSPDEV:-$HOME/.cache/ghidra-rare-scratch/tools/pspdev/pspdev}/bin
export PSP_OBJDUMP=${PSP_OBJDUMP:-$PSPBIN/psp-objdump} PSP_AS=${PSP_AS:-$PSPBIN/psp-as}
export PSP_LD=${PSP_LD:-$PSPBIN/psp-ld} PSP_OBJCOPY=${PSP_OBJCOPY:-$PSPBIN/psp-objcopy} PSP_NM=${PSP_NM:-$PSPBIN/psp-nm}

echo "== 1. generator reproduces the checked-in SLEIGH"
python3 "$MOD/tools/gen_vfpu.py" fields | cmp - "$L/allegrexVfpuFields.sinc" || { echo "   allegrexVfpuFields.sinc differs"; fail=1; }
python3 "$MOD/tools/gen_vfpu.py" vfpu | cmp - "$L/allegrexVfpu.sinc" || { echo "   allegrexVfpu.sinc differs"; fail=1; }

echo "== 2. SLEIGH compiles; Kotlin / Java classes built"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$L/allegrex.slaspec" 2>&1 | grep -E "^ERROR|^Error" && exit 1 || true
sz=$(stat -c %s "$L/allegrex.sla")
echo "   allegrex.sla: $sz bytes"
((sz < 16 * 1024 * 1024))
if [[ ! -f $MOD/lib/Allegrex.jar || -n $(find "$MOD/src" "$MOD/build.gradle" -newer "$MOD/lib/Allegrex.jar" -type f) ]]; then
	BT=$(mktemp -d "$W/build.XXXXXX")
	B=$BT/Allegrex
	mkdir -p "$B"
	# the module's own link in the install would make copyDependencies see its jars twice
	P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex"
	[[ -L $P && $(readlink -f "$P") == "$MOD" ]] && rm "$P"
	tar -C "$MOD" --exclude=.git --exclude=test --exclude=lib --exclude=build --exclude=.gradle -cf - . | tar -C "$B" -xf -
	(cd "$B" && ./gradlew --no-daemon -q buildExtension >/dev/null)
	mkdir -p "$MOD/lib"
	unzip -o -q -j "$B"/dist/*.zip '*/lib/*.jar' -d "$MOD/lib"
	touch "$MOD"/lib/*.jar
	rm -rf "$BT"
fi
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/Allegrex"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi

echo "== 3. decode differential (psp-objdump, rabbitizer)"
python3 "$HERE/gen_corpus.py" enum "$W/enum.bin" 1
python3 "$HERE/gen_corpus.py" random "$W/rand.bin" 100000 7
RPY=${RABBITIZER_PYTHON:-python3}
for c in enum rand; do
	"$HERE/ghidra-script.sh" raw $LANGID "$W/$c.bin" DumpSlots.java "$W/$c.gh" 4
	python3 "$HERE/oracle.py" objdump "$W/$c.bin" "$W/$c.od"
	python3 "$HERE/compare.py" "$W/$c.gh" "$W/$c.od" "$W/$c.bin" --show 6 > "$W/$c.cmp-objdump" || fail=1
	head -1 "$W/$c.cmp-objdump"
	if "$RPY" -I -c 'import rabbitizer' 2>/dev/null; then
		"$RPY" -I "$HERE/oracle.py" rabbitizer "$W/$c.bin" "$W/$c.rz"
		python3 "$HERE/compare.py" "$W/$c.gh" "$W/$c.rz" "$W/$c.bin" --oracle rabbitizer --show 6 > "$W/$c.cmp-rabbitizer" || fail=1
		head -1 "$W/$c.cmp-rabbitizer"
	else
		echo "   rabbitizer not installed: skipped (pip install rabbitizer==1.16.2; set RABBITIZER_PYTHON)"
	fi
done
for f in "$W"/*.cmp-*; do grep -q UNEXPLAINED "$f" && { echo "   unexplained differences in $f:"; grep -A6 UNEXPLAINED "$f" | head -40; fail=1; }; done

echo "== 4. every constructor is reached"
"$PSP_AS" -EL -march=allegrex -o "$W/reach_base.o" "$HERE/reach_base.s"
"$PSP_OBJCOPY" -O binary -j .text "$W/reach_base.o" "$W/base.bin"
python3 "$HERE/reach_contexts.py" "$W/ctx.txt" "$W/vfpu.bin"
cat "$W/enum.bin" "$W/rand.bin" "$W/base.bin" > "$W/reach.bin"
"$HERE/ghidra-script.sh" raw $LANGID "$W/reach.bin" Reach.java "$W/reach1.txt" 4
"$HERE/ghidra-script.sh" raw $LANGID "$W/vfpu.bin" Reach.java "$W/reach2.txt" 4 "@$W/ctx.txt"
"$HERE/ghidra-script.sh" raw $LANGID "$W/base.bin" Reach.java "$W/reach3.txt" 4 PAIR_INSTRUCTION_FLAG=1
cat "$W/reach1.txt" "$W/reach2.txt" "$W/reach3.txt" > "$W/reach.txt"
python3 "$HERE/reach_check.py" "$L" "$W/reach.txt" || fail=1

echo "== 5. p-code: hand-computed emulator tests"
python3 "$HERE/emu_tests.py" "$W/emu"
BASE_ADDR=0x100000 "$HERE/ghidra-script.sh" raw $LANGID "$W/emu/emu.bin" EmuCheck.java "$W/emu/tests.txt" "$W/emu/result.txt"
grep -v '^PASS' "$W/emu/result.txt" | grep -v '^emulator tests' || true
tail -1 "$W/emu/result.txt"
grep -q ' 0 failed, 1 broken expectations detected' "$W/emu/result.txt" || fail=1

echo "== 5b. calling convention: 64-bit arguments in aligned register pairs, results in v0:v1 (upstream #2)"
printf '\x08\x00\xe0\x03\x00\x00\x00\x00' > "$W/ret.bin"
"$HERE/ghidra-script.sh" raw $LANGID "$W/ret.bin" CspecCheck.java "$W/cspec.txt" \
	'longlong f(int a, longlong b, int c)' 'int g(longlong a, int b, longlong c, int d)' 'float h(float a, int b, float c)'
cat > "$W/cspec.want" <<'WANT'
longlong f(int a, longlong b, int c) => return v1:4,v0:4; a a0:4; b a3:4,a2:4; c t0:4
int g(longlong a, int b, longlong c, int d) => return v0:4; a a1:4,a0:4; b a2:4; c t1:4,t0:4; d t2:4
float h(float a, int b, float c) => return f0:4; a f12:4; b a0:4; c f13:4
WANT
if diff "$W/cspec.want" "$W/cspec.txt"; then echo "   3/3 prototypes as expected"; else fail=1; fi

if [[ -n ${PPSSPP_HEADLESS:-} ]]; then
	echo "== 6. VFPU semantics vs PPSSPP (black box)"
	for seed in 1 2 3; do
		V=$W/vfpu-diff-$seed
		rm -rf "$V"
		python3 "$HERE/vfpu_diff.py" gen "$V" 6 $seed >/dev/null
		(cd "$V" && PATH=$PSPBIN:$PATH make PSPSDK="$(dirname "$PSPBIN")/psp/sdk" >/dev/null 2>&1)
		(cd "$V" && timeout 900 "$PPSSPP_HEADLESS" -i -l --graphics=software "$V/vfpudiff.elf" 2>&1 |
			grep 'stdout: C ' | sed 's/^.*stdout: //' > "$V/ppsspp.txt")
		"$HERE/ghidra-script.sh" auto-noanalysis - "$V/vfpudiff.elf" EmuVfpu.java "$V/ghidra.txt"
		python3 "$HERE/vfpu_diff.py" compare "$V" > "$V/result.txt" || fail=1
		head -1 "$V/result.txt"
	done
fi

if ((REAL)); then
	echo "== 7. real code: PSPSDK samples (pspdev toolchain)"
	"$HERE/real-binaries.sh" "$W/real" || fail=1
fi

if ((fail)); then echo "FAILED"; exit 1; fi
echo "all tests passed"
