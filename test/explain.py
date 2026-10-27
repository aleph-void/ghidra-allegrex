"""Normalisation and explained difference classes for the Allegrex decode differential (used by compare.py).

normalise() maps both disassemblers' spellings onto one form; explain() classifies a remaining difference.
A class is only accepted here with its reason.
"""
import re
import struct

NUM = re.compile(r'^[-+]?(0x[0-9a-f]+|\d+)$')
VREG = re.compile(r'^([scrme])([0-7?])([0-3?])([0-3?])(\.[sptq])?$')

# psp-objdump names of the VCST constants -> the module's
VCST = {'vfpu_huge': 'maxfloat', 'vfpu_sqrt2': 'sqrt(2)', 'vfpu_sqrt1_2': 'sqrt(1/2)', 'vfpu_2_sqrtpi': '2/sqrt(pi)',
        'vfpu_2_pi': '2/pi', 'vfpu_1_pi': '1/pi', 'vfpu_pi_4': 'pi/4', 'vfpu_pi_2': 'pi/2', 'vfpu_pi': 'pi',
        'vfpu_e': 'e', 'vfpu_log2e': 'log2(e)', 'vfpu_log10e': 'log10(e)', 'vfpu_ln2': 'ln(2)', 'vfpu_ln10': 'ln(10)',
        'vfpu_2pi': '2*pi', 'vfpu_pi_6': 'pi/6', 'vfpu_log10two': 'log10(2)', 'vfpu_log2ten': 'log2(10)',
        'vfpu_sqrt3_2': 'sqrt(3)/2'}
GPR_ALIAS = {'s8': 'fp'}
CTRL = ['spfx', 'tpfx', 'dpfx', 'cc', 'inf4', 'rsv5', 'rsv6', 'rev', 'rcx0', 'rcx1', 'rcx2', 'rcx3', 'rcx4', 'rcx5',
        'rcx6', 'rcx7']
# the module's COP0 register names (Allegrex usage, from upstream) -> numbers
COP0D = ['cop0_reg0d', 'cop0_reg1d', 'cop0_reg2d', 'cop0_reg3d', 'cop0_reg4d', 'cop0_reg5d', 'cop0_reg6d',
         'cop0_reg7d', 'badvaddr', 'count', 'cop0_reg10d', 'compare', 'status', 'cause', 'epc', 'prid', 'config',
         'cop0_reg17d', 'cop0_reg18d', 'cop0_reg19d', 'cop0_reg20d', 'syscallcode', 'cpuid', 'cop0_reg23d',
         'cop0_reg24d', 'exceptionbase', 'cop0_reg26d', 'cop0_reg27d', 'taglo', 'taghi', 'errorepc', 'cop0_reg31d']
COP0C = ['savedepc', 'savederrorepc', 'savedstatus', 'savedcause', 'savedv0', 'savedv1', 'savederrorv0',
         'savederrorv1', 'exceptiontable', 'errorhandler', 'debughandler', 'syscallhandler', 'syscalltable',
         'syscallmax', 'kernelsp', 'usersp', 'tcb'] + [f'cop0_reg{i}c' for i in range(17, 32)]
FCR = {'fir': 0, 'fccr': 25, 'fexr': 26, 'fenr': 28, 'fcsr': 31}


def half(h):
    return struct.unpack('<e', struct.pack('<H', h & 0xffff))[0]


def _num(tok):
    t = tok.lower()
    neg = t.startswith('-')
    t = t.lstrip('+-')
    v = int(t, 16) if t.startswith('0x') else int(t)
    return -v if neg else v


def dealias(mn, toks, word):
    prime, fct = word >> 26, word & 0x3f
    if mn == 'move' and len(toks) == 2:
        base = {0x21: 'addu', 0x25: 'or'}.get(fct, 'move') if prime == 0 else 'move'
        return base, ([toks[0], 'zero', toks[1]] if (word >> 21) & 31 == 0 else [toks[0], toks[1], 'zero'])
    if mn == 'li' and len(toks) == 2 and prime == 0:      # li rd, 0 = addu / or rd, zero, zero
        return {0x21: 'addu', 0x25: 'or'}.get(fct, 'li'), [toks[0], 'zero', 'zero']
    if mn == 'li' and len(toks) == 2:
        return {9: 'addiu', 13: 'ori', 8: 'addi'}.get(prime, 'li'), [toks[0], 'zero', toks[1]]
    if mn == 'b' and len(toks) == 1:
        return ('beq', ['zero', 'zero', toks[0]]) if prime == 4 else ('bgez', ['zero', toks[0]])
    if mn == 'bl' and len(toks) == 1:
        return 'beql', ['zero', 'zero', toks[0]]
    if mn == 'bal' and len(toks) == 1:
        return 'bgezal', ['zero', toks[0]]
    if mn in ('beqz', 'bnez', 'beqzl', 'bnezl') and len(toks) == 2:
        return mn.replace('z', ''), [toks[0], 'zero', toks[1]]
    if mn in ('neg', 'negu') and len(toks) == 2:
        return {'neg': 'sub', 'negu': 'subu'}[mn], [toks[0], 'zero', toks[1]]
    if mn == 'not' and len(toks) == 2:
        return 'nor', [toks[0], toks[1], 'zero']
    if mn in ('ror', 'rorv'):
        return mn.replace('ror', 'rotr'), toks
    return mn, toks


def normalise(text, oracle, word):
    t = text.lower().replace('$', '').replace('\t', ' ')
    t = re.sub(r'cc\[([^\]]*)\]', r'\1', t)
    parts = t.split(None, 1)
    mn = parts[0]
    ops = parts[1] if len(parts) > 1 else ''
    if mn in ('vpfxs', 'vpfxt', 'vpfxd'):
        toks = [x.strip() for x in ops.replace('[', '').replace(']', '').split(',')]
        return mn, tuple(toks)
    toks = [x for x in re.split(r'[,\s()\[\]]+', ops) if x]
    if mn == 'vfim.s' and len(toks) == 2:
        v = half(word & 0xffff)
        return mn, (toks[0].split('.')[0], f'{v:.6g}')
    mn, toks = dealias(mn, toks, word)
    if mn in ('div', 'divu') and len(toks) == 3 and toks[0] == 'zero':
        toks = toks[1:]
    if mn == 'break':
        code = (word >> 6) & 0xfffff
        vals = [_num(x) for x in toks]
        # the module prints the 20-bit code; GNU objdump prints code >> 10 [, code & 0x3ff]
        if vals in ([code], [code >> 10] if code & 0x3ff == 0 else None, [code >> 10, code & 0x3ff],
                    [] if code == 0 else None):
            toks = [str(code)]
    if mn in ('mfc0', 'mtc0') and toks[1] in COP0D:
        toks = [toks[0], str(COP0D.index(toks[1]))]
    if mn in ('cfc0', 'ctc0') and toks[1] in COP0C:
        toks = [toks[0], str(COP0C.index(toks[1]))]
    if mn in ('cfc1', 'ctc1') and toks[1] in FCR:
        toks = [toks[0], str(FCR[toks[1]])]
    if mn in ('mfvc', 'mtvc', 'vmfvc', 'vmtvc'):
        toks = [str(128 + CTRL.index(t)) if t in CTRL else t for t in toks]
    if mn.startswith('vcst.') and len(toks) == 1:
        toks.append('vfpu_undef')
    if mn in ('mfic', 'mtic') and len(toks) == 2 and toks[1] == '0':
        toks = toks[:1]
    out = []
    for x in toks:
        m = VREG.match(x)
        if m:
            out.append(''.join(m.group(i) for i in range(1, 5)))
        elif x in VCST:
            out.append(VCST[x])
        elif x.startswith('cc') and x[2:].isdigit():
            out.append(str(int(x[2:])))
        elif NUM.match(x):
            out.append(str(_num(x) & 0xffffffff))
        else:
            out.append(GPR_ALIAS.get(x, x))
    return mn, tuple(out)


def wild_equal(gh, ref, oracle, word):
    """Equal when every '???' register of the reference matches the module's register of the same kind."""
    a, b = normalise(gh, oracle, word), normalise(ref, oracle, word)
    if a[0] != b[0] or len(a[1]) != len(b[1]):
        return False
    for x, y in zip(a[1], b[1]):
        if x == y:
            continue
        if '?' in y and len(x) == len(y) and all(c == '?' or c == d for c, d in zip(y, x)):
            continue
        return False
    return True


def explain(word, gh, ref, oracle):
    """Reason string for an accepted difference class, or None."""
    gm = gh.split()[0] if gh != 'BAD' else 'BAD'
    rm = ref.split()[0] if ref != 'BAD' else 'BAD'
    prime = word >> 26
    if gh != 'BAD' and ref != 'BAD' and '???' in ref and wild_equal(gh, ref, oracle, word):
        return ('register field psp-objdump prints as ??? (a quad vector or matrix with the offset bit set, or a '
                'misaligned 2x2 / 3x3 matrix); decoded with the lane mapping PPSSPP executes (the offset wraps), '
                'hardware behaviour unverified')
    if gh == 'BAD' and rm == 'jalx':
        return 'psp-objdump decodes JALX (MIPS16 jump); the Allegrex has no MIPS16 and psp-as rejects it'
    if gh == 'BAD' and rm in ('c0', 'c1', 'c2', 'c3'):
        return ('psp-objdump\'s generic coprocessor-operation fallback (cN); the Allegrex defines only the listed '
                'COP0/COP1/COP2 operations and has no COP3 (rabbitizer: invalid)')
    if oracle == 'rabbitizer':
        r = explain_rabbitizer(word, gh, ref, gm, rm)
        if r:
            return r
    if gh == 'BAD' and rm in ('vmfvc', 'vmtvc'):
        return ('psp-objdump also accepts VMFVC / VMTVC with the high bit of the control register number clear '
                '(registers below 128 do not exist); rabbitizer requires it set')
    if gm == 'halt' and ref == 'BAD':
        return '0x70000000: psp-objdump has no decode; rabbitizer decodes it (as sleep), upstream as halt'
    if gm == 'vsync2' and rm == 'mfvc':
        return '0x486000ff: rabbitizer decodes VSYNC2; psp-objdump prints mfvc of the nonexistent control register 255'
    return None


# GNU MIPS III / R4000 instructions rabbitizer falls back to for words its R4000ALLEGREX tables leave open
R4000_FALLBACK = {'ldl', 'ldr', 'lwu', 'sdl', 'sdr', 'pref', 'ld', 'sd', 'lld', 'scd', 'ldc1', 'sdc1', 'ldc2', 'sdc2',
                  'teq', 'tge', 'tgeu', 'tlt', 'tltu', 'tne', 'teqi', 'tgei', 'tgeiu', 'tlti', 'tltiu', 'tnei',
                  'dmfc0', 'dmtc0', 'dmfc1', 'dmtc1', 'dsllv', 'dsrlv', 'dsrav', 'dmult', 'dmultu', 'ddiv', 'ddivu',
                  'dadd', 'daddu', 'dsub', 'dsubu', 'dsll', 'dsrl', 'dsra', 'dsll32', 'dsrl32', 'dsra32', 'daddi',
                  'daddiu', 'lwc2', 'swc2', 'lwc3', 'swc3', 'beql', 'eret', 'tlbp', 'tlbr', 'tlbwi', 'tlbwr'}


def explain_rabbitizer(word, gh, ref, gm, rm):
    if gh == 'BAD' and rm in R4000_FALLBACK:
        return ('rabbitizer falls back to its generic R4000 table for this word (its own R4000ALLEGREX tables do not '
                'define it); psp-objdump and psp-as reject it')
    if gm in ('lvl.q', 'lvr.q') and ref.startswith('.word'):
        return 'rabbitizer 1.16.2 lists LVL.Q / LVR.Q but cannot print them (.word); psp-objdump decodes them'
    if gm == 'vsync' and ref == 'BAD':
        return 'rabbitizer accepts only VSYNC 0x320; psp-objdump decodes every 0xffffNNNN as VSYNC with a code'
    if gm in ('vpfxs', 'vpfxt', 'vpfxd') and (ref == 'BAD' or 'INVALID' in ref):
        return ('VPFX reserved bits: rabbitizer requires them clear (and rejects VPFXD saturation code 2 / masked '
                'lanes with a code); psp-objdump decodes them, as does the module')
    if gm in ('mfvc', 'mtvc') and ref == 'BAD':
        return ('MFVC / MTVC of a control register above 143: rabbitizer rejects it, psp-objdump decodes it '
                '($N); the module follows psp-objdump')
    if gm in ('mfdr', 'mtdr', 'dbreak', 'dret') and ref == 'BAD':
        return 'the Allegrex debug instructions: psp-as and psp-objdump know them, rabbitizer does not'
    if gm == 'syscall' and ref == 'BAD':
        return 'rabbitizer rejects SYSCALL with a non-zero code field; PSP imports use the code (psp-objdump decodes it)'
    if gm.startswith('vcst.') and 'INVALID_' in ref:
        return 'VCST constant 0 and 20..31 are undefined: rabbitizer prints INVALID_n, the module VFPU_UNDEF'
    if gm == rm and gm.startswith('vcmp.') and normalise(gh, 'rabbitizer', word)[1][0] == ref.split()[1].rstrip(','):
        gt = normalise(gh, 'rabbitizer', word)[1]
        rt = normalise(ref, 'rabbitizer', word)[1]
        if gt[:len(rt)] == rt:
            return 'VCMP: rabbitizer omits the register operands a condition does not use; the module and psp-objdump show both'
    if (gm, rm) in (('halt', 'sleep'), ('mfic', 'mfie'), ('mtic', 'mtie')):
        return f'name: the module (upstream) calls it {gm}, rabbitizer {rm} (psp-objdump: see that comparison)'
    if gm == rm == 'vpfxd':
        rz = [t.strip() for t in ref.split(None, 1)[1].split(',')] if len(ref.split(None, 1)) > 1 else []
        rz = [{'0': '0:1', '1': '-1:1', 'm': 'm'}.get(t.lower(), t.lower()) for t in rz]
        if tuple(rz) == normalise(gh, 'rabbitizer', word)[1]:
            return 'VPFXD: rabbitizer spells the saturations [0:1] / [-1:1] as 0 / 1'
    if gm == rm and gm in ('mfc0', 'mtc0', 'cfc0', 'ctc0'):
        if ref.split()[1].rstrip(',').lstrip('$') == gh.split()[1].split(',')[0]:
            return 'COP0 register names: rabbitizer uses the R4000 names, the module the Allegrex names (upstream)'
    return None
