#!/usr/bin/env python3
"""Compare Ghidra's decode (DumpSlots.java output) with a reference disassembler (oracle.py output).

  compare.py <ghidra.txt> <oracle.txt> <corpus.bin> [--oracle objdump|gnu|rabbitizer] [--show N]

Every word lands in one class:
  exact        same text after whitespace / '$' cleanup
  semantic     same instruction after normalisation (numbers by value, register size suffixes, the
               documented spelling differences in explain.normalise)
  both-bad     neither decodes it
  explained:*  a difference class with its reason (explain.explain)
  UNEXPLAINED  anything else; the exit status is 1 if there is any
"""
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from explain import explain, normalise  # noqa: E402


def load(path):
    out = {}
    for line in open(path):
        parts = line.rstrip('\n').split(' ', 2)
        if len(parts) == 3 and parts[1].isdigit():   # DumpSlots: idx len text
            out[int(parts[0])] = parts[2] if parts[1] != '0' else 'BAD'
        else:
            out[int(parts[0])] = ' '.join(parts[1:]) if len(parts) > 1 else 'BAD'
    return out


def main():
    gh, ref, corpus = load(sys.argv[1]), load(sys.argv[2]), open(sys.argv[3], 'rb').read()
    oracle, show = 'objdump', 5
    args = sys.argv[4:]
    while args:
        a = args.pop(0)
        if a == '--oracle':
            oracle = args.pop(0)
        elif a == '--show':
            show = int(args.pop(0))
    counts = Counter()
    examples = defaultdict(list)
    n = len(corpus) // 4
    for i in range(n):
        w = struct.unpack_from('<I', corpus, i * 4)[0]
        g, r = gh.get(i, 'BAD'), ref.get(i, 'BAD')
        if g == 'BAD' and r == 'BAD':
            cls = 'both-bad'
        elif g != 'BAD' and r != 'BAD' and ' '.join(g.replace('$', '').split()) == ' '.join(r.replace('$', '').split()):
            cls = 'exact'
        elif g != 'BAD' and r != 'BAD' and normalise(g, oracle, w) == normalise(r, oracle, w):
            cls = 'semantic'
        else:
            why = explain(w, g, r, oracle)
            if why:
                cls = 'explained: ' + why
            else:
                gm = g.split()[0] if g != 'BAD' else 'BAD'
                rm = r.split()[0] if r != 'BAD' else 'BAD'
                cls = f'UNEXPLAINED {gm} / {rm}'
        counts[cls] += 1
        if len(examples[cls]) < show:
            examples[cls].append(f'{w:08x}  ghidra: {g:<44} {oracle}: {r}')
    total = sum(counts.values())
    print(f'{oracle}: {total} words: exact {counts["exact"]}, semantic {counts["semantic"]}, '
          f'both-bad {counts["both-bad"]}, explained {sum(v for k, v in counts.items() if k.startswith("explained"))}, '
          f'unexplained {sum(v for k, v in counts.items() if k.startswith("UNEXPLAINED"))}')
    for k, v in sorted(counts.items(), key=lambda kv: (kv[0].startswith('UNEXPLAINED'), -kv[1])):
        if k in ('exact', 'semantic', 'both-bad'):
            continue
        print(f'  {v:7d}  {k}')
        if k.startswith('UNEXPLAINED') or '--dump' in sys.argv:
            for e in examples[k]:
                print('             ' + e)
    sys.exit(1 if any(k.startswith('UNEXPLAINED') for k in counts) else 0)


if __name__ == '__main__':
    main()
