# Ghidra-Rare notes: Allegrex (PSP)

This is the [Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare) fork of kotcrab's
[ghidra-allegrex](https://github.com/kotcrab/ghidra-allegrex) (Apache-2.0), verified to Ghidra-Rare's
[verification bar](https://github.com/aleph-void/Ghidra-Rare/blob/main/docs/VERIFICATION.md). Authors, upstream
commit and the full list of changes: [CREDITS.md](CREDITS.md).

## What it covers

Language `Allegrex:LE:32:default`: the PSP's Allegrex core (MIPS32 with the Allegrex additions: EXT / INS,
WSBH / WSBW / BITREV, MAX / MIN, CLZ / CLO, MADD / MSUB, MFIC / MTIC, the debug instructions), the
single-precision FPU, and the VFPU (128 single-precision registers addressed as singles, pairs, triples and
quads in rows or columns, 2x2 / 3x3 / 4x4 matrices, the VPFXS / VPFXT / VPFXD prefixes, the control
registers). Plus upstream's PSP ELF / PRX loader with type A / B relocations, the analyzers, the PPSSPP `.sym`
scripts and the relocatable kernel-object exporter, unchanged apart from the 12.1 build fix.

## Semantics in this fork

Upstream implemented every VFPU instruction as a pcodeop (`vadd_q(...)`) and gathered the vector registers
with a Kotlin p-code injection library. `tools/gen_vfpu.py` generates the VFPU instead (decode and p-code):

- Registers: V00..V7F hold S<m><c><r> at index m * 16 + r * 4 + c. A vector or matrix operand is a set of lane
  subtables whose register is computed from the 7-bit register field at disassembly time (column / row from
  bit 5, the start offset from bit 6), so the p-code names the registers directly: the decompiler shows the
  arithmetic, and Ghidra's emulator runs VFPU code (the injection library is gone).
- Prefixes: VPFXS / VPFXT / VPFXD write context bits for the next instruction that is not a prefix. Source lanes
  apply the swizzle, abs, constant (0, 1, 2, 1/2, 3, 1/3, 1/4, 1/6) and negate; destination lanes the [0:1] /
  [-1:1] saturation and the write mask. Reading SPFX / TPFX / DPFX gives the pending prefix's encoding
  (0xe4 = identity).
- Every instruction: add / sub / mul / div, min / max, compares (VSGE, VSLT, VSCMP, VCMP into CC with the any /
  all bits), VCMOVT / VCMOVF, dot products (VDOT, VHDP), VSCL, VDET, VCRS, VCRSP, VQMUL, VFAD, VAVG, the
  butterfly and sort operations, abs / neg / sat0 / sat1 / sign / rcp / rsq / sqrt / VOCP / VSOCP, the integer
  and float conversions with their power-of-two scale (VI2F, VF2IN / IZ / IU / ID with ties-to-even and
  saturation), the pack / unpack operations (VI2UC, VI2C, VI2US, VI2S, VUC2IFS, VC2I, VUS2I, VS2I), half floats
  (VF2H, VH2F, VFIM), the colour conversions (VT4444, VT5551, VT5650), VSBN, VSBZ, VLGB, VIIM, VCST, VIDT,
  VZERO, VONE, the matrix operations (VMMUL, VTFM, VHTFM, VMSCL, VMMOV, VMIDT, VMZERO, VMONE), VROT's lane
  layout, the control-register moves, the loads and stores including LVL.Q / LVR.Q / SVL.Q / SVR.Q, BVF / BVT.
- Still pcodeops, by necessity: VSIN, VCOS, VEXP2, VLOG2, VASIN (and the sine / exponential inside VNSIN,
  VREXP2, VROT): p-code has no transcendental operations, and the hardware's approximations are not documented;
  the random number generator (VRNDS, VRNDI, VRNDF1, VRNDF2: its algorithm is not documented in any non-GPL
  source); VWBN (no non-GPL description; PPSSPP's outputs do not reveal a simple rule).

Where the behaviour is not plain arithmetic, the fork follows what PPSSPP executes (run as a black box, see
"How to test"): quad and matrix register fields with the offset bit wrap (C002.q is rows 2, 3, 0, 1), VMMUL,
VTFM and VHTFM read their matrix operand transposed, VABS / VNEG / VOCP set the prefix abs / negate bit (which
for a constant prefix selects the other half of the constant table), VSAT0 / VSAT1 and the VF2I* conversions
ignore the VPFXD saturation, VCRSP and VQMUL the whole VPFXD, VSBN sets the exponent to 127 + n, VSBZ keeps the
mantissa, VLGB gives the unbiased exponent, VCST's 2/sqrt(pi) is 0x3f906eba, VAVG and VQMUL round as the
hardware's evaluation order does, SQRT of -0 is +0, CC keeps six bits, REV reads 0x7772ceab.

Core fixes: the instructions the Allegrex does not have are no longer decoded (traps, SYNCI, RDPGPR, WRPGPR,
WAIT, RDHWR, DERET, DI, EI), reserved fields are checked, JALR with rd = rs, CVT.W.S / ROUND.W.S rounding, the
debug and COP0 / COP2 moves added (CREDITS.md has the full list). The compiler spec uses the EABI argument
rules, so 64-bit arguments and results need no custom storage (upstream #2).

## How to test

```
GHIDRA_INSTALL_DIR=<scratch copy of Ghidra 12.1.x> JAVA_HOME=<JDK with javac> PSPDEV=<pspdev toolchain> \
RABBITIZER_PYTHON=<python with rabbitizer 1.16.2> [PPSSPP_HEADLESS=<PPSSPPHeadless>] \
test/run-tests.sh <workdir> [--real]
```

`test/run-tests.sh` symlinks the module into the given Ghidra, builds its jar (Kotlin) into `lib/`, then:

1. `tools/gen_vfpu.py` reproduces the checked-in `allegrexVfpu.sinc` and `allegrexVfpuFields.sinc`;
2. `allegrex.slaspec` compiles;
3. decode differential (`gen_corpus.py`, `DumpSlots.java`, `oracle.py`, `compare.py`, `explain.py`) against
   psp-objdump (pspdev binutils, Allegrex branch, the only disassembler with the whole VFPU) and rabbitizer 1.16.2
   (R4000ALLEGREX): 1,327,168 words walking every sub-opcode field, and 100,000 random words;
4. every SLEIGH constructor is reached (`Reach.java`, `reach_check.py`): the corpora, one instance of every core
   instruction form (`reach_base.s`), and VFPU words decoded under 32 prefix context sets
   (`reach_contexts.py`);
5. hand-computed emulator cases (`emu_cases.py`, assembled with psp-as by `emu_tests.py`, run by
   `EmuCheck.java`), including one wrong expectation that must be reported; 5b. `CspecCheck.java` applies
   prototypes with 64-bit arguments and checks their storage;
6. with `PPSSPP_HEADLESS`: the VFPU differential (`vfpu_diff.py`, `EmuVfpu.java`). A generated PSP program loads
   all 128 VFPU registers and CC from random states, runs one instruction (with random prefixes where they are
   meaningful) and stores the registers; PPSSPP (GPL, built locally and only run, as a black box) executes it,
   and Ghidra's emulator runs the same compiled program; all 129 words are compared;
7. with `--real`: `real-binaries.sh` downloads the pinned pspdev release, builds the PSPSDK samples (and three gu
   samples linked against libpspgum_vfpu, so the matrix code runs on the VFPU), imports each ELF without forcing
   the language, analyses it, decompiles every function, and compares every disassembled instruction with
   psp-objdump (`RealCheck.java`, `real_compare.py`).

## Results

Run on Ghidra 12.1.4 (`test/run-tests.sh <workdir> --real` with `PPSSPP_HEADLESS` set); the release zips
build on 12.1.3, 12.1.4 and 12.2, and on each of the three an import of a PSPSDK sample picks the PSP loader and
`Allegrex:LE:32:default` and decompiles a VFPU function (the Kotlin classes and kotlin-stdlib load).

| Area | Result |
|---|---|
| Build | `allegrex.slaspec` compiles (`.sla` 163 KB); release zips (`tools/build-module.sh --standard --keep-build`) for 12.1.3, 12.1.4, 12.2 |
| Decode vs psp-objdump | 1,327,168 enumerated words: exact 123,727, semantic 712,474, both invalid 420,822, explained 70,145, **unexplained 0**; 100,000 random words: exact 5,261, semantic 55,203, both invalid 33,786, explained 5,750, **unexplained 0** |
| Decode vs rabbitizer 1.16.2 | enumerated: exact 46, semantic 744,881, both invalid 376,220, explained 206,021, **unexplained 0**; random: exact 1, semantic 58,838, both invalid 30,220, explained 10,941, **unexplained 0** (rabbitizer's `$` register and hex spellings: few exact matches) |
| Every constructor reached | 2,203/2,203 (VFPU prefix lanes under 32 context sets) |
| P-code, hand-computed | 47 emulator cases (ALU incl. the Allegrex additions, multiply / divide / MADD, unaligned loads and stores, branches, likely branches, delay slots, JALR rd = rs, FPU arithmetic, conversions in every rounding mode, compare and branch, VFPU loads / stores incl. LVL.Q / LVR.Q, arithmetic, dot product, VCMP to BVT, MTV / MFV, VIIM / VFIM / VCST, prefixes, conversions, matrix identity / multiply / transform, VFAD, VSBN), plus 1 deliberately wrong expectation, which is detected; 3/3 prototypes with 64-bit arguments placed as the EABI requires |
| VFPU vs PPSSPP (black box) | 3 x 1,410 random cases (every VFPU instruction except the random number generator and VWBN; random prefixes where meaningful; all 128 registers and CC compared): 3,630 identical, 127 VRCP / VNRCP within 5 units in the last place of PPSSPP's hardware approximation, 473 transcendental results within tolerance of PPSSPP's approximations, **0 different** |
| Real code | 26 PSPSDK samples built with the pinned pspdev v20261001 toolchain (3 of them linked against libpspgum_vfpu): 830,172 instructions, 10,989 functions, all imported through the PSP loader as `Allegrex:LE:32:default`; 0 unexpected error / warning bookmarks, **0 decompile failures**; every disassembled instruction agrees with psp-objdump (**0 unexplained**) |

Expected bookmarks only: per sample, crt0's calls to weak symbols that are not linked ("flow into non-existing
memory at 00000000") and Ghidra's stop on long runs of identical words in `pspSdkDisableInterrupts`, which pads
with nops ("Maximum run of repeated byte instructions exceeded"; a disassembler safety limit, not a decode error).

Per sample (`test/real-binaries.sh`):

| Sample | Instructions | Functions | Errors | Decompile failures | vs psp-objdump: exact / semantic / unexplained |
|---|---|---|---|---|---|
| audio/polyphonic | 30,255 | 399 | 0 | 0 | 9,262 / 20,993 / 0 |
| audio/wavegen | 31,492 | 409 | 0 | 0 | 9,811 / 21,681 / 0 |
| controller/basic | 29,559 | 379 | 0 | 0 | 8,979 / 20,580 / 0 |
| debug/debugkb | 30,262 | 385 | 0 | 0 | 9,178 / 21,084 / 0 |
| debug/exception | 29,761 | 389 | 0 | 0 | 9,016 / 20,745 / 0 |
| debug/gdb | 31,457 | 463 | 0 | 0 | 9,517 / 21,940 / 0 |
| debug/kprintf | 29,478 | 382 | 0 | 0 | 8,963 / 20,515 / 0 |
| debug/profiler | 29,587 | 383 | 0 | 0 | 8,995 / 20,592 / 0 |
| debug/prxdecrypt | 29,535 | 383 | 0 | 0 | 8,973 / 20,562 / 0 |
| debug/sio | 29,943 | 424 | 0 | 0 | 9,144 / 20,799 / 0 |
| gprof/basic | 34,327 | 392 | 0 | 0 | 10,159 / 24,168 / 0 |
| gprof/custom | 34,557 | 388 | 0 | 0 | 10,356 / 24,201 / 0 |
| gu/beginobject | 33,478 | 464 | 0 | 0 | 10,613 / 22,865 / 0 |
| gu/blend | 31,656 | 441 | 0 | 0 | 9,904 / 21,752 / 0 |
| gu/blit | 31,624 | 436 | 0 | 0 | 9,837 / 21,787 / 0 |
| gu/celshading | 32,992 | 442 | 0 | 0 | 10,436 / 22,556 / 0 |
| gu/celshading_vfpu | 33,354 | 441 | 0 | 0 | 10,526 / 22,828 / 0 |
| gu/clut | 30,687 | 412 | 0 | 0 | 9,498 / 21,189 / 0 |
| gu/copy | 31,451 | 430 | 0 | 0 | 9,811 / 21,640 / 0 |
| gu/cube | 32,614 | 438 | 0 | 0 | 10,316 / 22,298 / 0 |
| gu/cube_vfpu | 31,683 | 428 | 0 | 0 | 9,811 / 21,872 / 0 |
| gu/doublelist | 31,854 | 446 | 0 | 0 | 9,945 / 21,909 / 0 |
| gu/envmap | 34,055 | 477 | 0 | 0 | 10,878 / 23,177 / 0 |
| gu/envmap_vfpu | 34,417 | 476 | 0 | 0 | 10,968 / 23,449 / 0 |
| gu/font | 30,996 | 415 | 0 | 0 | 9,640 / 21,356 / 0 |
| irkeyb | 39,098 | 467 | 0 | 0 | 11,398 / 27,700 / 0 |

## Confirmed reference-tool bugs and disagreements

- **psp-objdump** (pspdev binutils 2.44, Allegrex branch): decodes JALX (MIPS16) and the generic
  coprocessor-operation fallback `c0`..`c3`, none of which the Allegrex has (psp-as rejects them); accepts VMFVC /
  VMTVC with control-register numbers below 128; prints `mfvc zero,$255` for 0x486000ff (rabbitizer: VSYNC2);
  has no decode for 0x70000000 (rabbitizer: SLEEP, upstream: HALT); prints `???` for quad / matrix register
  fields with the offset bit, which PPSSPP executes with a wrapping offset.
- **rabbitizer 1.16.2**: falls back to its generic R4000 table for words its R4000ALLEGREX tables leave open
  (LDL / LDR / LWU / SDL / SDR / PREF, the traps, the 64-bit shifts and multiplies, DMFC0 ...), all rejected by
  psp-as and psp-objdump; lists LVL.Q / LVR.Q but prints them as `.word`; accepts only VSYNC 0x320; rejects
  SYSCALL with a code (PSP import stubs use it), VPFX words with reserved bits set, MFVC / MTVC above 143; lacks
  the debug instructions (MFDR, MTDR, DBREAK, DRET); prints the VPFXD saturations as 0 / 1.
- **GNU objdump 2.45** (`-m mips:allegrex`): knows the core but not the VFPU (not used as a reference for it).
- **PPSSPP** (used as the semantic reference; not a bug list): its VRCP / VNRCP differ from an exact division in
  the last 1..5 bits (the hardware approximation), and its transcendental functions from double-precision
  results by up to a few thousand units in the last place; prefixes on the special-function instructions (VRCP,
  VRSQ, VSQRT, VSIN ...), on VDIV, and T prefixes on unary or reducing operations give results no plain reading
  reproduces (the hardware implements some of these with hidden prefixes of its own); those combinations are
  not tested and stay unverified.

## Upstream known limitations and issues

Collected from the upstream README (limitations section), the open and closed issues of kotcrab/ghidra-allegrex,
and the TODO / FIXME comments.

| Issue | Status in this fork |
|---|---|
| README: VFPU operations decompile to function calls (`vadd_q(...)`); #40 "Improving the VFPU decompilation"; #10 | **Fixed**: every VFPU instruction has p-code; only the transcendental functions, the random number generator and VWBN stay pcodeops (reasons under "Semantics"). #40's control-register side effects: prefix writes now act on the following instruction; SPFX / TPFX / DPFX reads give the pending prefix. |
| README: VPFXS / VPFXT / VPFXD not modelled | **Fixed** (context-carried prefixes, checked against PPSSPP). |
| README: `vfim.s` operand shown as an integer (SLEIGH has no float tokens) | **Remaining (SLEIGH display limit)**: SLEIGH cannot print a float operand; the half-float value the instruction loads is computed correctly in p-code. |
| README: changing the image base of relocatable object files (`.o`) not supported | **Remaining (loader feature)**: outside the processor module; unchanged. |
| README: 64-bit arguments need custom storage (Ghidra #2762); #2 "long long value decompile" | **Fixed**: EABI parameter rules in the cspec; `test/CspecCheck.java` checks a3:a2 / t1:t0 pairs and v1:v0 results. |
| FIXME in the old `allegrexVfpu.sinc`: VMFVC / VMTVC of read-only and out-of-range control registers | **Fixed**: registers above 143 read 0 / discard writes; REV reads its constant; CC keeps six bits. |
| #49: image base relocation broken with emotionengine-reloaded installed | **Fixed in the EmotionEngine fork** (its ELF extension claimed every MIPS ELF). |
| #29: recover sections from segment-only binaries | **Remaining (loader feature)**: outside the processor module. |
| #16: psplink gdbserver debugger integration | **Remaining (debugger feature)**: outside the processor module. |
| TODO in `RelocatableKernelObjectExporter.kt` (recursion guard, ori-paired offsets) | **Remaining (exporter)**: the exporter is unchanged and was not exercised (no kernel modules that may legally be used). |
| TODO in `AllegrexPreAnalyzer` (delay-slot adjustment), `AllegrexAddressAnalyzer` (gp from .reginfo), `Allegrex_ElfExtension` (MIPS options) | Inherited from Ghidra's MIPS module; behaviour unchanged. |
| Closed issues on relocations, NIDs and retail games (#45, #44, #36, #28, #27, #25, #17, #9, #7, #6) | Fixed upstream; **unverified** here: they concern commercial games and firmware, which cannot be used. The PSPSDK samples import with their relocations and imports applied. |

## Works / doesn't / unverified

| Area | State |
|---|---|
| Decode | 1,427,168 words against psp-objdump and rabbitizer 1.16.2: 0 unexplained differences (every class explained, reference-tool bugs listed); 2,203/2,203 constructors reached |
| Semantics | Full p-code for the core, the FPU and every VFPU instruction including the prefixes, except the transcendental functions, the random number generator and VWBN; 47/47 emulator cases, broken expectation detected; 4,230 VFPU cases identical to PPSSPP or within its approximations, 0 different |
| Real code | 26 PSPSDK samples (pspdev v20261001): 830,172 instructions, 10,989 functions, 0 errors, 0 decompile failures, 100% agreement with psp-objdump; loads and decompiles on 12.1.3, 12.1.4, 12.2 |
| Fixed here | VFPU semantics (were pcodeops, #40) and prefixes (README); VFPU and core decode accepted many encodings the Allegrex lacks; JALR rd = rs; CVT.W.S / ROUND.W.S rounding; TLB p-code; 64-bit argument storage (#2); missing BC0x, COP2 moves, debug instructions; 12.1.x build |
| Doesn't work | VSIN / VCOS / VEXP2 / VLOG2 / VASIN (and inside VNSIN, VREXP2, VROT) are pcodeops: p-code has no transcendental operations and the hardware approximations are undocumented. VRNDS / VRNDI / VRNDF1 / VRNDF2: the generator's algorithm is not in any non-GPL source. VWBN: no non-GPL description, and PPSSPP's outputs show no simple rule. VRCP / VNRCP divide exactly (the hardware approximates; 1..5 ulp). A prefix written with MTVC / VMTVC (rather than VPFX*) or separated from its instruction by non-VFPU code is not applied (prefixes are carried in the disassembly context). `vfim.s` shows its immediate in hex (SLEIGH cannot print floats). Image base change for `.o` files, section recovery (#29), psplink debugging (#16): loader / debugger features outside the processor module |
| Unverified | Hardware itself (PPSSPP is the reference); prefixes on the special-function instructions, on VDIV, VCRSP, VQMUL, and T prefixes on unary / reducing instructions (PPSSPP's results follow hidden prefixes of its own); swizzles outside an operand's size; denormal half floats (PPSSPP gives m * 2^-25); VSBN with scale factors beyond the exponent range; commercial games and firmware (relocation / NID issues #45, #44, #28 ...) |
