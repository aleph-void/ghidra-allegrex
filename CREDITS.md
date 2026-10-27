# Credits

## Upstream

This is the Ghidra-Rare fork of **ghidra-allegrex**, the Ghidra processor module for the PlayStation Portable's
Allegrex CPU:

- Repository: https://github.com/kotcrab/ghidra-allegrex
- Forked at commit `abcf97659260b11a9a4781ff72fff30ede2f073f` (2026-10-25, "Fix options", tag `v21.5`)
- License: Apache License 2.0 (`LICENSE`, unchanged). Every file keeps its upstream license; the Ghidra-Rare
  changes are released under the same license.

Original authors, from the upstream commit history:

| Author | Commits | Notes |
|---|---|---|
| Paweł Pastuszak (kotcrab) | 154 | author and maintainer |
| Kieron (KieronJ) | 2 | |
| illusion0001 | 1 | |
| artart78 | 1 | |
| Sakimotor | 1 | |
| Chris Bridges (CB9001) | 1 | |
| Antonio Vázquez Blanco (antoniovazquezblanco) | 1 | |

As upstream's README says, the module is derived from Ghidra's MIPS module (Apache-2.0, National Security
Agency), and its type B relocation parsing is based on [prxtool](https://github.com/pspdev/prxtool) (AFL 2.0).

## Ghidra-Rare changes

All in this repository's `ghidra-rare` branch, by the Ghidra-Rare project (`GHIDRA-RARE.md` describes the
verification that motivated each one):

- **Build for Ghidra 12.1.x and 12.2**: the `Option` constructor instead of the 12.2-only `Option.newString` /
  `newBoolean` builders (`PspElfLoader.kt`, `RelocatableKernelObjectExporter.kt`); Kotlin and Java compiled for
  the Java release of the Ghidra being built against (`build.gradle`); the release zip leaves out the Gradle
  wrapper, Kotlin session data, tests and generators.
- **VFPU rewritten** (`tools/gen_vfpu.py` generates `data/languages/allegrexVfpu.sinc` and
  `allegrexVfpuFields.sinc`, replacing `allegrexVfpuBase.sinc`, `allegrexVfpuGenerated.sinc`, the hand-written
  `allegrexVfpu.sinc`, the Kotlin `VfpuSincGenerator` and the Kotlin p-code injection classes in
  `allegrex.pcode`):
  - real p-code semantics for every VFPU instruction (upstream: a pcodeop per instruction, `vadd_q(...)`,
    upstream issue #40 and the README's VFPU limitation); vector and matrix operands are lane subtables whose
    register is computed from the register field, so no injection library is needed and Ghidra's emulator can
    run VFPU code;
  - VPFXS / VPFXT / VPFXD prefixes modelled (README limitation): swizzle, abs, constants and negate on the
    source lanes, saturation and write mask on the destination lanes, carried to the next instruction in the
    context;
  - decode: every VFPU instruction matches exactly the bits both reference disassemblers fix (upstream accepted
    nonexistent sizes such as `vdot.s`, `vdet.q`, `vwbn.q`, `vcmp` / `vcst` / `vzero` with non-zero register
    fields, `lv.q ... wb`, any word of primary opcode 63 as `vflush`); added `vsync` with a code, `vsync2`,
    `vnop`; `vuc2i` renamed `vuc2ifs` (the name both references use); VCST constant names as psp-as spells them;
    VPFXD shown as psp-objdump shows it; VCMP shows both register fields;
  - the mapping of quad / matrix register fields with the offset bit and of misaligned matrices follows what
    PPSSPP executes (upstream used "the closest legal register"); VMMUL, VTFM, VHTFM read their matrix
    operand transposed; VSAT0 / VSAT1 and VF2I* ignore the VPFXD saturation, VCRSP / VQMUL the whole VPFXD;
    VABS / VNEG / VOCP set the prefix abs / negate bit; VCST, VSBN, VSBZ, VLGB, VAVG and VQMUL rounding as the
    hardware delivers them (see GHIDRA-RARE.md).
- **Core decode**: removed instructions the Allegrex does not have (the trap instructions, SYNCI, RDPGPR,
  WRPGPR, WAIT, RDHWR, DERET, DI, EI, the SEB / SEH / WSBH / WSBW / BITREV alternative with function 0x18,
  SYNC with a type); JR / JALR require the hint field to be zero; `b` / `bl` only for `beq` / `beql` on `$zero`;
  FPU compares and `abs.s` / `mov.s` / `neg.s` require their reserved fields to be zero; added `bc0f` / `bc0t` /
  `bc0fl` / `bc0tl`, the generic COP2 moves `mfc2` / `cfc2` / `mtc2` / `ctc2`, the debug instructions `dbreak`,
  `dret`, `mfdr`, `mtdr`; `syscall` shows its code (the import stubs' function number); dead subtable entries
  removed.
- **Core semantics**: `jalr rd, rs` read the link register as the target when rd = rs; `cvt.w.s` used round()
  (ties away from zero) for RM 0 and floor for RM 1..3 (now nearest-even / toward zero / up / down);
  `round.w.s` rounds ties to even; the TLB instructions had no p-code (`unimpl`).
- **Calling convention** (upstream issue #2): the cspec uses Ghidra's EABI parameter rules, so 64-bit arguments
  take an aligned register pair and 64-bit results v0:v1, without custom storage.
- Added `GHIDRA-RARE.md`, this file, `tools/gen_vfpu.py` and the test suite in `test/`; README updated.

## Sources used for Ghidra-Rare's changes

- Reference disassemblers, run as black boxes: psp-objdump and psp-as from the pspdev toolchain (binutils
  Allegrex branch, release `v20261001`), GNU objdump 2.45; rabbitizer 1.16.2 (MIT, Decompollaborate), whose MIT
  R4000ALLEGREX tables were also read.
- PPSSPP v1.19.3 (GPL), built locally and run only as a black box (PPSSPPHeadless executing test programs);
  none of its source was read.
- PSPSDK (BSD, pspdev/pspsdk at `6f15c154c902963864ea5c4538cc94febf8a2dad`): `src/gum/pspgum.c` and
  `pspgum_vfpu.c`, the C and VFPU versions of the same matrix functions, for the operand conventions.
- No GPL source code (binutils opcode tables, PPSSPP, vfpu-docs) was read.
