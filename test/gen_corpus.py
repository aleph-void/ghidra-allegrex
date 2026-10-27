#!/usr/bin/env python3
"""Instruction-word corpora for the Allegrex decode differential (little-endian 32-bit words).

  gen_corpus.py enum   <out.bin> [seed]      every opcode / sub-opcode field combination
  gen_corpus.py random <out.bin> <n> [seed]  n uniformly random words

The enumeration walks, for every primary opcode, every value of the fields that select an instruction
on the Allegrex: the function field (bits 5..0), the rs / format field (bits 25..21), the rt field
(bits 20..16), the VFPU sub-opcode bits (25..23, 22..16) and the VFPU vector-size bits (15 and 7). The
remaining register and immediate fields get random values, plus all-zero, so that the zero-register
aliases (move, li, b, nop ...) are covered too.
"""
import random
import struct
import sys


def enum(rng):
    words = []
    for op in range(64):
        hi = op << 26
        # bits 25..21 x bits 5..0 x the two VFPU size bits (15, 7)
        for f21 in range(32):
            for fn in range(64):
                for sz in range(4):
                    w = hi | (f21 << 21) | fn | ((sz >> 1) << 15) | ((sz & 1) << 7)
                    w |= rng.getrandbits(32) & 0x001f7f40   # rt, rd/vs (14..8 minus 15), sa bit 6
                    words.append(w)
        # bits 25..16 (format / VFPU opcode and vt) x the two size bits, low bits random or zero
        for f16 in range(1024):
            for sz in range(4):
                s = ((sz >> 1) << 15) | ((sz & 1) << 7)
                words.append(hi | (f16 << 16) | s | (rng.getrandbits(16) & 0x7f7f))
            words.append(hi | (f16 << 16))
            # only the vd field set (one-operand VFPU forms: vzero, vidt, vmidt, vrndi ...)
            for sz in range(4):
                s = ((sz >> 1) << 15) | ((sz & 1) << 7)
                words.append(hi | (f16 << 16) | s | rng.getrandbits(7))
        # bits 10..6 (sa / ext-ins position / bshfl op) x function
        for sa in range(32):
            for fn in range(64):
                words.append(hi | (rng.getrandbits(15) << 11) | (sa << 6) | fn)
        words.append(hi)
    # fixed encodings: vnop / vsync / vflush and their neighbours, mfvc / mtvc control registers
    for low in range(0x10000):
        words.append(0xffff0000 | low)
    for rt in range(32):
        for low in range(256):
            words.append(0x48600000 | (rt << 16) | low)
            words.append(0x48e00000 | (rt << 16) | low)
    return words


def main():
    mode, out = sys.argv[1], sys.argv[2]
    if mode == 'enum':
        rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
        words = enum(rng)
    else:
        n = int(sys.argv[3])
        rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 7)
        words = [rng.getrandbits(32) for _ in range(n)]
    with open(out, 'wb') as f:
        f.write(b''.join(struct.pack('<I', w) for w in words))
    print(f'{out}: {len(words)} words')


if __name__ == '__main__':
    main()
