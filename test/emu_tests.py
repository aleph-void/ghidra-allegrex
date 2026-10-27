#!/usr/bin/env python3
"""Assemble the Allegrex p-code test sequences of emu_cases.py; write emu.bin + tests.txt.

  emu_tests.py <workdir>

Each case is a short instruction sequence with initial registers / memory and the registers and memory it
must leave, worked out by hand (never from the module's output). The sequences are assembled with the GNU
assembler of the pspdev toolchain (PSP_AS, default psp-as on PATH or in the pspdev download), each at
BASE + n * STRIDE, followed by a stop label. EmuCheck.java runs them in Ghidra's emulator.
"""
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import emu_cases  # noqa: E402

BASE = 0x100000
STRIDE = 0x200
PSPDEV = os.path.expanduser('~/.cache/ghidra-rare-scratch/tools/pspdev/pspdev/bin')


def tool(name):
    env = os.environ.get('PSP_' + name.upper())
    if env:
        return env
    t = 'psp-' + name
    return shutil.which(t) or os.path.join(PSPDEV, t)


def main():
    work = os.path.abspath(sys.argv[1])
    os.makedirs(work, exist_ok=True)
    lines = ['\t.set noreorder', '\t.set noat', '\t.text']
    for n, (name, asm, init, expect) in enumerate(emu_cases.CASES):
        lines.append(f'\t.org {n * STRIDE:#x}')
        lines.append(f't{n:04d}:')
        for l in asm.strip('\n').split('\n'):
            l = l.strip()
            if not l:
                continue
            l = re.sub(r'\b(L\d+)\b', lambda m: f'{m.group(1)}_{n}', l)
            lines.append(l if l.endswith(':') else '\t' + l)
        lines.append(f't{n:04d}_end:')
        lines.append('\tnop')
    lines.append('\t.org 0x10000')   # pad: the data scratch area (emu_cases.D) is inside the image
    lines.append('\t.word 0')
    src = os.path.join(work, 'emu.s')
    open(src, 'w').write('\n'.join(lines) + '\n')
    obj, elf, binf = (os.path.join(work, x) for x in ('emu.o', 'emu.elf', 'emu.bin'))
    subprocess.run([tool('as'), '-EL', '-march=allegrex', '-o', obj, src], check=True)
    subprocess.run([tool('objcopy'), '-R', '.MIPS.abiflags', '-R', '.reginfo', '-R', '.gnu.attributes', obj], check=True)
    subprocess.run([tool('ld'), '-Ttext', f'{BASE:#x}', '-e', f'{BASE:#x}', '-o', elf, obj], check=True)
    subprocess.run([tool('objcopy'), '-O', 'binary', '-j', '.text', elf, binf], check=True)
    sym = {}
    for line in subprocess.run([tool('nm'), elf], capture_output=True, text=True, check=True).stdout.split('\n'):
        p = line.split()
        if len(p) == 3:
            sym[p[2]] = int(p[0], 16)
    with open(os.path.join(work, 'tests.txt'), 'w') as f:
        for n, (name, asm, init, expect) in enumerate(emu_cases.CASES):
            s, e = sym[f't{n:04d}'], sym[f't{n:04d}_end']

            def subst(text):
                text = text.replace('@END@', f'{e:x}').replace('@START@', f'{s:x}')
                return re.sub(r'@(L\d+)@', lambda m: f'{sym[m.group(1) + "_" + str(n)]:x}', text)
            f.write(f'{name} {s:x} {e:x} {subst(init) or "-"} {subst(expect) or "-"}\n')
    print(f'{len(emu_cases.CASES)} cases assembled')


if __name__ == '__main__':
    main()
