#!/usr/bin/env python3
"""Every-entry check: every SLEIGH constructor (file:line of each ':' line) must appear in Reach.java's output.

  reach_check.py <languages dir> <reach.txt> [--allow file:line ...]
"""
import os
import re
import sys


def constructors(langdir):
    out = set()
    for fn in sorted(os.listdir(langdir)):
        if not fn.endswith('.sinc') and not fn.endswith('.slaspec'):
            continue
        for i, line in enumerate(open(os.path.join(langdir, fn)), 1):
            # a constructor starts with ':' (instruction table) or 'Name:' (subtable); skip macros/defines
            if re.match(r'^\s*(:\S|[A-Za-z_]\w*:\s)', line) and not re.match(r'^\s*(define|macro|attach|with)\b', line):
                out.add(f'{fn}:{i}')
    return out


def main():
    langdir, reach = sys.argv[1], sys.argv[2]
    allow = set(sys.argv[sys.argv.index('--allow') + 1:]) if '--allow' in sys.argv else set()
    cons = constructors(langdir)
    seen = {l.strip() for l in open(reach) if l.strip()}
    # Ghidra reports the bare file name
    seen = {os.path.basename(x.split(':')[0]) + ':' + x.split(':')[1] for x in seen}
    missing = sorted(cons - seen - allow, key=lambda x: (x.split(':')[0], int(x.split(':')[1])))
    print(f'   constructors reached {len(cons & seen)}/{len(cons)}' + (f' ({len(allow & cons)} allowed unreachable)' if allow else ''))
    for m in missing[:40]:
        fn, ln = m.split(':')
        print('   unreached', m, open(os.path.join(langdir, fn)).read().split('\n')[int(ln) - 1].strip()[:110])
    sys.exit(1 if missing else 0)


if __name__ == '__main__':
    main()
