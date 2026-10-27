#!/usr/bin/env bash
# Real-code check: build the PSPSDK sample programs with the pspdev toolchain (GCC, binutils, newlib: GPL/LGPL
# tools; PSPSDK: BSD), import each ELF into Ghidra without forcing the language (the PSP loader / ELF opinion
# must pick Allegrex:LE:32:default), analyse, count functions / bookmarks / decompile failures, and compare
# every disassembled instruction with psp-objdump. Three gu samples are also linked against libpspgum_vfpu, so
# the matrix code runs on the VFPU.
#
#   GHIDRA_INSTALL_DIR=... test/real-binaries.sh <workdir>
#
# Nothing downloaded here is committed. The toolchain release is pinned by URL and SHA-256; set PSPDEV_TARBALL
# to a local copy to skip the download.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "${1:?workdir}")
mkdir -p "$W"
URL=https://github.com/pspdev/pspdev/releases/download/v20261001/pspdev-ubuntu-latest-x86_64.tar.gz
SHA=a86efe624e770005290919617859e9df24bd8fcd3e364f4587f23ec7364b0acd
TAR=${PSPDEV_TARBALL:-$W/pspdev-ubuntu-latest-x86_64.tar.gz}
if [[ ! -f $TAR ]]; then curl -sSL -o "$TAR" "$URL"; fi
echo "$SHA  $TAR" | sha256sum -c --quiet
if [[ ! -d $W/pspdev ]]; then tar -xzf "$TAR" -C "$W"; fi
export PSPDEV=$W/pspdev PATH=$W/pspdev/bin:$PATH PSP_OBJDUMP=$W/pspdev/bin/psp-objdump
rm -rf "$W/samples" && cp -r "$PSPDEV/psp/sdk/samples" "$W/samples"
for s in cube envmap celshading; do
	cp -r "$W/samples/gu/$s" "$W/samples/gu/${s}_vfpu"
	sed -i 's/-lpspgum\b/-lpspgum_vfpu -lpspvfpu/' "$W/samples/gu/${s}_vfpu/Makefile"
done
SAMPLES=$(cd "$W/samples" && find . -name Makefile -printf '%h\n' | sed 's|^\./||' | sort)
fail=0
mkdir -p "$W/out"
printf '%-24s %8s %6s %6s %6s %6s %s\n' sample insns funcs errors warns decomp-fail psp-objdump
for s in $SAMPLES; do
	(cd "$W/samples/$s" && make -s BUILD_PRX=0 PSPSDK="$PSPDEV/psp/sdk" >/dev/null 2>&1) || { echo "build failed: $s"; fail=1; continue; }
	elf=$(ls "$W/samples/$s"/*.elf | head -1)
	n=$(echo "$s" | tr / _)
	"$HERE/ghidra-script.sh" auto - "$elf" RealCheck.java "$W/out/$n.sum" "$W/out/$n.lst" 100000
	grep -q '^language Allegrex:LE:32:default' "$W/out/$n.sum" || { echo "$s: wrong language"; fail=1; }
	python3 "$HERE/real_compare.py" "$W/out/$n.lst" "$elf" > "$W/out/$n.cmp" || fail=1
	cmp=$(head -1 "$W/out/$n.cmp")
	# expected: flow into 0 (crt0 calls weak symbols that are not linked) and Ghidra's limit on runs of identical
	# words (pspSdkDisableInterrupts pads with nops): both are reported as such below, not counted
	errs=$(grep '^Error/' "$W/out/$n.sum" | grep -v -c 'Maximum run of repeated byte instructions' || true)
	warns=$(grep '^Warning/' "$W/out/$n.sum" | grep -v -c 'non-existing memory at 00000000' || true)
	df=$(sed -n 's/^decompiled [0-9]* failed \([0-9]*\).*/\1/p' "$W/out/$n.sum")
	printf '%-24s %8s %6s %6s %6s %6s %s\n' "$s" "$(sed -n 's/^instructions //p' "$W/out/$n.sum")" \
		"$(sed -n 's/^functions //p' "$W/out/$n.sum")" "$errs" "$warns" "$df" "${cmp#*: }"
	if ((errs > 0 || df > 0)); then fail=1; fi
done
exit $fail
