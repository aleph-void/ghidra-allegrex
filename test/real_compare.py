#!/usr/bin/env python3
"""Compare Ghidra's listing of an analysed PSP ELF (RealCheck.java) with psp-objdump at the same addresses.

  real_compare.py <ghidra-listing> <elf> [--show N]

Uses the same normalisation and explained classes as the decode differential (explain.py).
Exit status 1 if any instruction differs without an explanation.
"""
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from explain import explain, normalise  # noqa: E402
from oracle import PSP_OBJDUMP as OBJDUMP  # noqa: E402


def main():
    lst, elf = sys.argv[1], sys.argv[2]
    show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 4
    out = subprocess.run([OBJDUMP, '-d', '-z', '-m', 'mips:allegrex', elf], capture_output=True, text=True).stdout
    ref = {}
    for line in out.split('\n'):
        m = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$', line)
        if m:
            text = m.group(3).split('<')[0].strip().replace('\t', ' ')
            if text.startswith('.word') or text.startswith('(bad)'):
                text = 'BAD'
            # objdump -d prints branch / jump targets in hex without 0x
            if re.match(r'^(b\w*|j|jal|bc[012]\w*|bv\w*)\s', text):
                text = re.sub(r'([ ,])([0-9a-f]+)$', r'\g<1>0x\2', text)
            ref[int(m.group(1), 16)] = (int(m.group(2), 16), text)
    counts, ex = Counter(), defaultdict(list)
    for line in open(lst):
        a, ln, text = line.rstrip('\n').split(' ', 2)
        text = text[1:] if text.startswith('_') else text   # Ghidra marks delay-slot instructions with '_'
        a = int(a, 16)
        if a not in ref:
            counts['not in objdump (outside its code sections)'] += 1
            continue
        w, r = ref[a]
        if ' '.join(text.split()) == ' '.join(r.replace('$', '').split()):
            cls = 'exact'
        elif r != 'BAD' and normalise(text, 'objdump', w) == normalise(r, 'objdump', w):
            cls = 'semantic'
        else:
            why = explain(w, text, r, 'objdump')
            if isinstance(why, tuple):
                why = why[2]   # canonical re-check is done by the decode differential; same class here
            cls = 'explained: ' + why if why else f'UNEXPLAINED {text.split()[0]} / {r.split()[0]}'
        counts[cls] += 1
        if len(ex[cls]) < show:
            ex[cls].append(f'{a:08x} {w:08x}  ghidra: {text:<36} objdump: {r}')
    total = sum(counts.values())
    print(f'{os.path.basename(elf)}: {total} instructions: exact {counts["exact"]}, semantic {counts["semantic"]}, '
          f'unexplained {sum(v for k, v in counts.items() if k.startswith("UNEXPLAINED"))}')
    for k, v in counts.most_common():
        if k in ('exact', 'semantic'):
            continue
        print(f'  {v:6d} {k}')
        if k.startswith('UNEXPLAINED'):
            for e in ex[k]:
                print('         ' + e)
    sys.exit(1 if any(k.startswith('UNEXPLAINED') for k in counts) else 0)


if __name__ == '__main__':
    main()
