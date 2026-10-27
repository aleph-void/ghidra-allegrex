#!/usr/bin/env python3
"""VFPU semantics differential: the module's p-code (Ghidra's emulator) against PPSSPP (GPL, run only as a
black box: PPSSPPHeadless executes a PSP program and prints the results).

  vfpu_diff.py gen <workdir> [n-per-instruction] [seed]   write cases.json, vfpu_cases.S, main.c, Makefile
  vfpu_diff.py compare <workdir>                          compare ppsspp.txt with ghidra.txt

Each case loads all 128 VFPU registers and CC from its own random state block (lv.q), optionally executes
a random VPFXS / VPFXT / VPFXD prefix, executes one instruction word, and stores all 128 registers and CC
(sv.q, mfvc). The same compiled program is imported into Ghidra and every case function is emulated
(EmuVfpu.java). Transcendental and random-number instructions are excluded (pcodeops by design).
"""
import json
import os
import random
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
import gen_vfpu  # noqa: E402

SKIP = {'vrnds', 'vrndi', 'vrndf1', 'vrndf2', 'vwbn', 'vnop', 'vflush', 'vsync', 'vsync2', 'bvf', 'bvfl', 'bvt', 'bvtl',
        'lv', 'sv', 'lvl', 'lvr', 'svl', 'svr', 'mfv', 'mtv', 'mfvc', 'mtvc', 'vpfxs', 'vpfxt', 'vpfxd'}
# PPSSPP implements these with hidden prefixes of its own; its results with a user S / T prefix are emulator
# specific (they disagree with any plain reading); only the destination prefix is tested on them
NO_ST_PFX = {'vdiv', 'vhdp', 'vqmul', 'vavg', 'vfad', 'vbfy1', 'vbfy2', 'vsrt1', 'vsrt2', 'vsrt3', 'vsrt4', 'vcrs',
             'vcrsp', 'vdet', 'vscl', 'vsocp', 'vsbn'}
# a T-prefix constant with negate on VDOT gives results no plain reading reproduces (PPSSPP): S prefix only
NO_T_PFX = {'vdot'}
# PPSSPP applies prefixes to the special-function unit (rcp, rsq, sqrt, sin, cos, exp2, log2, asin) in a way no
# plain reading reproduces; those combinations are not tested
NO_PFX = {'vdiv', 'vcrsp', 'vqmul', 'vrcp', 'vnrcp', 'vrsq', 'vsqrt', 'vsin', 'vcos', 'vexp2', 'vlog2', 'vasin', 'vnsin',
          'vrexp2', 'vrot'}
# integer-input operations: PPSSPP turns a constant prefix into an integer (exotic; not tested)
INT_IN = {'vi2f', 'vi2uc', 'vi2c', 'vi2us', 'vi2s', 'vuc2ifs', 'vc2i', 'vus2i', 'vs2i', 'vt4444', 'vt5551', 'vt5650',
          'vh2f'}
NOPFX = {'vmmul', 'vtfm2', 'vtfm3', 'vtfm4', 'vhtfm2', 'vhtfm3', 'vhtfm4', 'vmscl', 'vmmov', 'vmidt', 'vmzero',
         'vmone', 'vmfvc', 'vmtvc', 'viim', 'vfim', 'vcst', 'vzero', 'vone', 'vidt'}


def rand_word(rng, mask, val):
    return val | (rng.getrandbits(32) & ~mask & 0xffffffff)


def fl(x):
    return struct.unpack('<I', struct.pack('<f', x))[0]


def rand_state(rng, kind):
    vals = []
    for _ in range(128):
        r = rng.random()
        if kind == 'int':
            v = rng.choice([rng.getrandbits(32), rng.randrange(-300, 300) & 0xffffffff, rng.getrandbits(16),
                            rng.getrandbits(8) << 24])
        elif r < 0.08:
            v = rng.choice([0, 0x80000000, fl(1.0), fl(-1.0), fl(0.5), fl(2.0), fl(-0.5)])
        elif r < 0.12:
            v = fl(rng.randrange(-5, 6) + 0.5)
        else:
            v = fl(rng.uniform(-4, 4) * (10 ** rng.randrange(-1, 3) if rng.random() < 0.3 else 1))
        vals.append(v)
    cc = rng.getrandbits(6)
    return vals, cc


INT_OPS = {'vi2f', 'vi2uc', 'vi2c', 'vi2us', 'vi2s', 'vuc2ifs', 'vc2i', 'vus2i', 'vs2i', 'vh2f', 'vt4444',
           'vt5551', 'vt5650', 'vsbn'}


def gen(work, n, seed):
    rng = random.Random(seed)
    cases = []
    only = os.environ.get('VFPU_ONLY')
    clean = os.environ.get('VFPU_CLEAN')
    for name, mask, val, kinds in gen_vfpu.ENCODINGS:
        base = name.split('.')[0]
        if (base in SKIP and not (only and base in only.split(','))) or (only and base not in only.split(',')):
            continue
        for k in range(n):
            w = rand_word(rng, mask, val)
            if clean:   # register fields with column/row 0 and the offset bit clear (only matrix and transpose bits)
                for sh in (0, 8, 16):
                    if (mask >> sh) & 0x7f == 0:
                        w &= ~(0x43 << sh)
            pfx = []
            if base not in NOPFX and k % 3 == 2:
                nl = gen_vfpu.SIZES[name.split('.')[1][0]] if '.' in name else 4
                has_t = any(k.endswith('_vt') for k in kinds)
                for pv in (0xdc000000, 0xdd000000, 0xde000000):
                    # a T prefix only on instructions with a vt operand (PPSSPP applies it to hidden operands of
                    # VOCP, VSGN, VBFY, VSRT ...; compilers do not emit that)
                    if pv == 0xdd000000 and not has_t:
                        continue
                    if base in NO_PFX or (base in NO_ST_PFX | INT_IN and pv != 0xde000000) or \
                            (base in NO_T_PFX and pv == 0xdd000000):
                        continue
                    if rng.random() < 0.6:
                        bits = rng.getrandbits(20) if pv != 0xde000000 else rng.getrandbits(12)
                        if pv != 0xde000000:
                            # swizzles stay inside the operand (lanes outside it are undefined); constants are free
                            for i in range(4):
                                if not (bits >> (12 + i)) & 1:
                                    bits = (bits & ~(3 << (2 * i))) | (rng.randrange(nl) << (2 * i))
                        pfx.append(pv | bits)
            st, cc = rand_state(rng, 'int' if base in INT_OPS and rng.random() < 0.7 else 'float')
            if base == 'vsbn':      # a float scaled by an integer of real use (|n| < 64); huge ones: see GHIDRA-RARE.md
                st, cc = rand_state(rng, 'float')
                ft = (w >> 16) & 0x7f
                st[((ft >> 2) & 7) * 16 + ((ft >> 5) & 3) * 4 + (ft & 3)] = rng.randrange(-63, 64) & 0xffffffff
            if base == 'vfim' and (w >> 10) & 0x1f == 0:
                w |= 1 << 10        # denormal half immediates: PPSSPP gives m * 2^-25, IEEE m * 2^-24 (unverified)
            if base == 'vmfvc' and ((w >> 8) & 0x7f) >= 8:
                w = (w & ~0x7f00) | (rng.randrange(8) << 8)   # RCX0-7 hold the random generator state
            cases.append({'name': name, 'words': pfx + [w], 'state': st, 'cc': cc})
    os.makedirs(work, exist_ok=True)
    json.dump(cases, open(os.path.join(work, 'cases.json'), 'w'))
    asm = ['.set noreorder', '.set noat', '.text']
    for i, c in enumerate(cases):
        asm += [f'.globl case_{i}', f'.ent case_{i}', f'case_{i}:', f'  lui $8, %hi(st_{i})', f'  addiu $8, $8, %lo(st_{i})']
        for m in range(8):
            for col in range(4):
                asm.append(f'  lv.q C{m}{col}0, {(m * 4 + col) * 16}($8)')
        asm += ['  lw $9, 512($8)', '  mtvc $9, $131']
        asm += [f'  .word 0x{x:08x}' for x in c['words']]
        for m in range(8):
            for col in range(4):
                asm.append(f'  sv.q C{m}{col}0, {(m * 4 + col) * 16}($4)')
        asm += ['  mfvc $9, $131', '  sw $9, 512($4)', '  jr $31', '  nop', f'.end case_{i}']
    asm.append('.data')
    for i, c in enumerate(cases):
        # state block: lane order of lv.q C<m><c>0 is S<m><c>0..3 -> V index m*16 + r*4 + c
        words = []
        for m in range(8):
            for col in range(4):
                for r in range(4):
                    words.append(c['state'][m * 16 + r * 4 + col])
        words.append(c['cc'])
        asm += ['.align 4', f'st_{i}:'] + [f'  .word 0x{x:08x}' for x in words]
    open(os.path.join(work, 'vfpu_cases.S'), 'w').write('\n'.join(asm) + '\n')
    n_cases = len(cases)
    decls = '\n'.join(f'void case_{i}(unsigned *out);' for i in range(n_cases))
    table = ',\n'.join(f'    case_{i}' for i in range(n_cases))
    main = f'''#include <pspkernel.h>
#include <stdio.h>
PSP_MODULE_INFO("vfpudiff", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER | PSP_THREAD_ATTR_VFPU);
{decls}
static void (*const cases[])(unsigned *) = {{
{table}
}};
static unsigned out[132] __attribute__((aligned(16)));
int main(void) {{
    unsigned i, j;
    for (i = 0; i < {n_cases}; i++) {{
        cases[i](out);
        for (j = 0; j < 129; j++) {{
            if (j % 16 == 0) printf("C %u %u", i, j);
            printf(" %08x", out[j]);
            if (j % 16 == 15 || j == 128) printf("\\n");
        }}
    }}
    sceKernelExitGame();
    return 0;
}}
'''
    open(os.path.join(work, 'main.c'), 'w').write(main)
    open(os.path.join(work, 'Makefile'), 'w').write(
        'TARGET = vfpudiff\nOBJS = main.o vfpu_cases.o\nCFLAGS = -O1 -G0\nASFLAGS = $(CFLAGS)\nLIBS =\n'
        'BUILD_PRX = 0\ninclude $(PSPSDK)/lib/build.mak\n')
    print(f'{n_cases} cases')


# VRCP / VNRCP: the hardware reciprocal is an approximation PPSSPP reproduces bit-exactly; p-code divides exactly
APPROX = {'vrcp', 'vnrcp'}
# transcendental functions: the pcodeops are evaluated in double precision by EmuVfpu.java; the hardware's
# approximations (reproduced by PPSSPP) differ by a few hundred units in the last place at most
TRANSC = {'vsin', 'vcos', 'vexp2', 'vlog2', 'vasin', 'vnsin', 'vrexp2', 'vrot'}


def fv(b):
    return struct.unpack('<f', struct.pack('<I', b))[0]


def isnan(b):
    return (b & 0x7f800000) == 0x7f800000 and (b & 0x7fffff) != 0


def ulps(a, b):
    def key(x):
        return x if x < 0x80000000 else 0x80000000 - x
    return abs(key(a) - key(b))


def load(path, tag):
    """Lines 'C <case> <first-index> <values...>' (PPSSPP's log truncates long lines, so 16 values per line)."""
    parts = {}
    for line in open(path):
        p = line.split()
        if len(p) >= 4 and p[0] == tag:
            parts.setdefault(int(p[1]), {})[int(p[2])] = [int(x, 16) for x in p[3:]]
    out = {}
    for i, ch in parts.items():
        vals = []
        for k in sorted(ch):
            vals += ch[k]
        if len(vals) == 129:
            out[i] = vals
    return out


def compare(work):
    cases = json.load(open(os.path.join(work, 'cases.json')))
    pp = load(os.path.join(work, 'ppsspp.txt'), 'C')
    gh = load(os.path.join(work, 'ghidra.txt'), 'C')
    from collections import Counter, defaultdict
    bad = Counter()
    ex = defaultdict(list)
    ok = ok_approx = ok_transc = 0
    approx, transc = {}, {}
    for i, c in enumerate(cases):
        if i not in pp or i not in gh:
            bad[c['name'] + ' (missing)'] += 1
            continue
        diffs = [(j, pp[i][j], gh[i][j]) for j in range(129) if pp[i][j] != gh[i][j] and not (isnan(pp[i][j]) and isnan(gh[i][j]))]
        if not diffs:
            ok += 1
            continue
        base = c['name'].split('.')[0]
        if base in TRANSC and all(ulps(a, b) <= 4096 or abs(fv(a) - fv(b)) < 1e-3 * max(1.0, abs(fv(a))) for _, a, b in diffs):
            transc[c['name']] = max(transc.get(c['name'], 0), max(ulps(a, b) for _, a, b in diffs))
            ok_transc += 1
            continue
        if base in APPROX and all(ulps(a, b) <= 8 for _, a, b in diffs):
            approx[c['name']] = max(approx.get(c['name'], 0), max(ulps(a, b) for _, a, b in diffs))
            ok_approx += 1
            continue
        key = c['name'] + (' +pfx' if len(c['words']) > 1 else '')
        bad[key] += 1
        if len(ex[key]) < 2:
            ex[key].append((i, [f'{x:08x}' for x in c['words']], diffs[:4]))
    print(f'VFPU differential vs PPSSPP: {ok}/{len(cases)} cases identical (NaN payloads compared as NaN), '
          f'{ok_approx} within 8 units in the last place (hardware reciprocal approximation), '
          f'{ok_transc} transcendental within tolerance, {len(cases) - ok - ok_approx - ok_transc} different')
    for k in sorted(transc):
        print(f'        transcendental: {k} (max {transc[k]} ulp)')
    for k in sorted(approx):
        print(f'        approximate: {k} (max {approx[k]} ulp)')
    for k, v in sorted(bad.items()):
        print(f'  {v:5d} {k}')
        for e in ex[k]:
            print('        ', e)
    return 0 if not bad else 1


if __name__ == '__main__':
    if sys.argv[1] == 'gen':
        gen(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 6, int(sys.argv[4]) if len(sys.argv) > 4 else 1)
    else:
        sys.exit(compare(sys.argv[2]))
