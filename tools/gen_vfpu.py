#!/usr/bin/env python3
"""Generate the Allegrex VFPU SLEIGH (Ghidra-Rare).

  tools/gen_vfpu.py fields > data/languages/allegrexVfpuFields.sinc   (token fields, included in allegrex.sinc)
  tools/gen_vfpu.py vfpu   > data/languages/allegrexVfpu.sinc         (registers, operands, instructions)

Decode: every VFPU instruction is matched on the exact fixed bits listed in ENCODINGS. The table was
derived by flipping each bit of sample words in two independent reference disassemblers run as black
boxes (rabbitizer 1.16.2, MIT, R4000ALLEGREX tables; psp-objdump from the pspdev Allegrex binutils) and
keeping the bits on which both agree; the few rows where they differ are commented.

Semantics: real p-code on the 128 VFPU registers (V00..V7F = S<m><c><r> at m*16 + r*4 + c). Vector and
matrix operands are lane subtables whose register is computed from the 7-bit register field at
disassembly time. The VPFXS / VPFXT / VPFXD prefixes set context bits for the next instruction only
(noflow); the source-lane subtables apply swizzle / abs / constant / negate and the destination-lane
subtables apply the write mask and saturation, so a prefixed instruction decompiles to plain arithmetic.
Only operations p-code cannot express (transcendental functions, the hardware random number generator)
stay pcodeops.
"""
import struct
import sys

XYZW = 'xyzw'
SIZES = {'s': 1, 'p': 2, 't': 3, 'q': 4}
# start row / column selected by register bit 6; for quads PPSSPP (black box) starts at 2 and wraps (C002.q is
# rows 2, 3, 0, 1), which psp-objdump prints as ??? and upstream treated as 0
OFFS = {'p': 2, 't': 1, 'q': 2, 's': 0}

# (name, mask, value, operand kinds): see the module docstring
ENCODINGS = [
    ('bvf', 0xffe30000, 0x49000000, ['imm3', 'cpu_branch_target_label']),
    ('bvfl', 0xffe30000, 0x49020000, ['imm3', 'cpu_branch_target_label']),
    ('bvt', 0xffe30000, 0x49010000, ['imm3', 'cpu_branch_target_label']),
    ('bvtl', 0xffe30000, 0x49030000, ['imm3', 'cpu_branch_target_label']),
    ('lv.q', 0xfc000002, 0xd8000000, ['q_vt_imm', 'offset14_base']),
    ('lv.s', 0xfc000000, 0xc8000000, ['s_vt_imm', 'offset14_base']),
    ('lvl.q', 0xfc000002, 0xd4000000, ['q_vt_imm', 'offset14_base']),
    ('lvr.q', 0xfc000002, 0xd4000002, ['q_vt_imm', 'offset14_base']),
    ('mfv', 0xffe0ff80, 0x48600000, ['cpu_rt', 's_vd']),
    ('mfvc', 0xffe0ff80, 0x48600080, ['cpu_rt', 'cop2cdr']),      # rabbitizer: only 128..143 (mask ffe0fff0)
    ('mtv', 0xffe0ff80, 0x48e00000, ['cpu_rt', 's_vd']),
    ('mtvc', 0xffe0ff80, 0x48e00080, ['cpu_rt', 'cop2cd']),
    ('sv.q', 0xfc000002, 0xf8000000, ['q_vt_imm', 'offset14_base']),
    ('sv.q', 0xfc000002, 0xf8000002, ['q_vt_imm', 'offset14_base', 'wb']),
    ('sv.s', 0xfc000000, 0xe8000000, ['s_vt_imm', 'offset14_base']),
    ('svl.q', 0xfc000002, 0xf4000000, ['q_vt_imm', 'offset14_base']),
    ('svr.q', 0xfc000002, 0xf4000002, ['q_vt_imm', 'offset14_base']),
    ('vabs.p', 0xffff8080, 0xd0010080, ['p_vd', 'p_vs']),
    ('vabs.q', 0xffff8080, 0xd0018080, ['q_vd', 'q_vs']),
    ('vabs.s', 0xffff8080, 0xd0010000, ['s_vd', 's_vs']),
    ('vabs.t', 0xffff8080, 0xd0018000, ['t_vd', 't_vs']),
    ('vadd.p', 0xff808080, 0x60000080, ['p_vd', 'p_vs', 'p_vt']),
    ('vadd.q', 0xff808080, 0x60008080, ['q_vd', 'q_vs', 'q_vt']),
    ('vadd.s', 0xff808080, 0x60000000, ['s_vd', 's_vs', 's_vt']),
    ('vadd.t', 0xff808080, 0x60008000, ['t_vd', 't_vs', 't_vt']),
    ('vasin.p', 0xffff8080, 0xd0170080, ['p_vd', 'p_vs']),
    ('vasin.q', 0xffff8080, 0xd0178080, ['q_vd', 'q_vs']),
    ('vasin.s', 0xffff8080, 0xd0170000, ['s_vd', 's_vs']),
    ('vasin.t', 0xffff8080, 0xd0178000, ['t_vd', 't_vs']),
    ('vavg.p', 0xffff8080, 0xd0470080, ['s_vd', 'p_vs']),
    ('vavg.q', 0xffff8080, 0xd0478080, ['s_vd', 'q_vs']),
    ('vavg.t', 0xffff8080, 0xd0478000, ['s_vd', 't_vs']),
    ('vbfy1.p', 0xffff8080, 0xd0420080, ['p_vd', 'p_vs']),
    ('vbfy1.q', 0xffff8080, 0xd0428080, ['q_vd', 'q_vs']),
    ('vbfy2.q', 0xffff8080, 0xd0438080, ['q_vd', 'q_vs']),
    ('vc2i.s', 0xffff8080, 0xd0390000, ['q_vd', 's_vs']),
    ('vcmovf.p', 0xfff88080, 0xd2a80080, ['p_vd', 'p_vs', 'vfpu_cc_bit']),
    ('vcmovf.q', 0xfff88080, 0xd2a88080, ['q_vd', 'q_vs', 'vfpu_cc_bit']),
    ('vcmovf.s', 0xfff88080, 0xd2a80000, ['s_vd', 's_vs', 'vfpu_cc_bit']),
    ('vcmovf.t', 0xfff88080, 0xd2a88000, ['t_vd', 't_vs', 'vfpu_cc_bit']),
    ('vcmovt.p', 0xfff88080, 0xd2a00080, ['p_vd', 'p_vs', 'vfpu_cc_bit']),
    ('vcmovt.q', 0xfff88080, 0xd2a08080, ['q_vd', 'q_vs', 'vfpu_cc_bit']),
    ('vcmovt.s', 0xfff88080, 0xd2a00000, ['s_vd', 's_vs', 'vfpu_cc_bit']),
    ('vcmovt.t', 0xfff88080, 0xd2a08000, ['t_vd', 't_vs', 'vfpu_cc_bit']),
    ('vcmp.p', 0xff8080f0, 0x6c000080, ['vcmp_p']),
    ('vcmp.q', 0xff8080f0, 0x6c008080, ['vcmp_q']),
    ('vcmp.s', 0xff8080f0, 0x6c000000, ['vcmp_s']),
    ('vcmp.t', 0xff8080f0, 0x6c008000, ['vcmp_t']),
    ('vcos.p', 0xffff8080, 0xd0130080, ['p_vd', 'p_vs']),
    ('vcos.q', 0xffff8080, 0xd0138080, ['q_vd', 'q_vs']),
    ('vcos.s', 0xffff8080, 0xd0130000, ['s_vd', 's_vs']),
    ('vcos.t', 0xffff8080, 0xd0138000, ['t_vd', 't_vs']),
    ('vcrs.t', 0xff808080, 0x66808000, ['t_vd', 't_vs', 't_vt']),
    ('vcrsp.t', 0xff808080, 0xf2808000, ['t_vd', 't_vs', 't_vt']),
    ('vcst.p', 0xffe0ff80, 0xd0600080, ['p_vd', 'vconstant']),
    ('vcst.q', 0xffe0ff80, 0xd0608080, ['q_vd', 'vconstant']),
    ('vcst.s', 0xffe0ff80, 0xd0600000, ['s_vd', 'vconstant']),
    ('vcst.t', 0xffe0ff80, 0xd0608000, ['t_vd', 'vconstant']),
    ('vdet.p', 0xff808080, 0x67000080, ['s_vd', 'p_vs', 'p_vt']),
    ('vdiv.p', 0xff808080, 0x63800080, ['p_vd', 'p_vs', 'p_vt']),
    ('vdiv.q', 0xff808080, 0x63808080, ['q_vd', 'q_vs', 'q_vt']),
    ('vdiv.s', 0xff808080, 0x63800000, ['s_vd', 's_vs', 's_vt']),
    ('vdiv.t', 0xff808080, 0x63808000, ['t_vd', 't_vs', 't_vt']),
    ('vdot.p', 0xff808080, 0x64800080, ['s_vd', 'p_vs', 'p_vt']),
    ('vdot.q', 0xff808080, 0x64808080, ['s_vd', 'q_vs', 'q_vt']),
    ('vdot.t', 0xff808080, 0x64808000, ['s_vd', 't_vs', 't_vt']),
    ('vexp2.p', 0xffff8080, 0xd0140080, ['p_vd', 'p_vs']),
    ('vexp2.q', 0xffff8080, 0xd0148080, ['q_vd', 'q_vs']),
    ('vexp2.s', 0xffff8080, 0xd0140000, ['s_vd', 's_vs']),
    ('vexp2.t', 0xffff8080, 0xd0148000, ['t_vd', 't_vs']),
    ('vf2h.p', 0xffff8080, 0xd0320080, ['s_vd', 'p_vs']),
    ('vf2h.q', 0xffff8080, 0xd0328080, ['p_vd', 'q_vs']),
    ('vf2id.p', 0xffe08080, 0xd2600080, ['p_vd', 'p_vs', 'power_of_two']),
    ('vf2id.q', 0xffe08080, 0xd2608080, ['q_vd', 'q_vs', 'power_of_two']),
    ('vf2id.s', 0xffe08080, 0xd2600000, ['s_vd', 's_vs', 'power_of_two']),
    ('vf2id.t', 0xffe08080, 0xd2608000, ['t_vd', 't_vs', 'power_of_two']),
    ('vf2in.p', 0xffe08080, 0xd2000080, ['p_vd', 'p_vs', 'power_of_two']),
    ('vf2in.q', 0xffe08080, 0xd2008080, ['q_vd', 'q_vs', 'power_of_two']),
    ('vf2in.s', 0xffe08080, 0xd2000000, ['s_vd', 's_vs', 'power_of_two']),
    ('vf2in.t', 0xffe08080, 0xd2008000, ['t_vd', 't_vs', 'power_of_two']),
    ('vf2iu.p', 0xffe08080, 0xd2400080, ['p_vd', 'p_vs', 'power_of_two']),
    ('vf2iu.q', 0xffe08080, 0xd2408080, ['q_vd', 'q_vs', 'power_of_two']),
    ('vf2iu.s', 0xffe08080, 0xd2400000, ['s_vd', 's_vs', 'power_of_two']),
    ('vf2iu.t', 0xffe08080, 0xd2408000, ['t_vd', 't_vs', 'power_of_two']),
    ('vf2iz.p', 0xffe08080, 0xd2200080, ['p_vd', 'p_vs', 'power_of_two']),
    ('vf2iz.q', 0xffe08080, 0xd2208080, ['q_vd', 'q_vs', 'power_of_two']),
    ('vf2iz.s', 0xffe08080, 0xd2200000, ['s_vd', 's_vs', 'power_of_two']),
    ('vf2iz.t', 0xffe08080, 0xd2208000, ['t_vd', 't_vs', 'power_of_two']),
    ('vfad.p', 0xffff8080, 0xd0460080, ['s_vd', 'p_vs']),
    ('vfad.q', 0xffff8080, 0xd0468080, ['s_vd', 'q_vs']),
    ('vfad.t', 0xffff8080, 0xd0468000, ['s_vd', 't_vs']),
    ('vfim.s', 0xff800000, 0xdf800000, ['s_vt', 'float16']),
    ('vflush', 0xffffffff, 0xffff040d, []),
    ('vh2f.p', 0xffff8080, 0xd0330080, ['q_vd', 'p_vs']),
    ('vh2f.s', 0xffff8080, 0xd0330000, ['p_vd', 's_vs']),
    ('vhdp.p', 0xff808080, 0x66000080, ['s_vd', 'p_vs', 'p_vt']),
    ('vhdp.q', 0xff808080, 0x66008080, ['s_vd', 'q_vs', 'q_vt']),
    ('vhdp.t', 0xff808080, 0x66008000, ['s_vd', 't_vs', 't_vt']),
    ('vhtfm2.p', 0xff808080, 0xf0800000, ['p_vd', 'mp_vs', 'p_vt']),
    ('vhtfm3.t', 0xff808080, 0xf1000080, ['t_vd', 'mt_vs', 't_vt']),
    ('vhtfm4.q', 0xff808080, 0xf1808000, ['q_vd', 'mq_vs', 'q_vt']),
    ('vi2c.q', 0xffff8080, 0xd03d8080, ['s_vd', 'q_vs']),
    ('vi2f.p', 0xffe08080, 0xd2800080, ['p_vd', 'p_vs', 'power_of_two']),
    ('vi2f.q', 0xffe08080, 0xd2808080, ['q_vd', 'q_vs', 'power_of_two']),
    ('vi2f.s', 0xffe08080, 0xd2800000, ['s_vd', 's_vs', 'power_of_two']),
    ('vi2f.t', 0xffe08080, 0xd2808000, ['t_vd', 't_vs', 'power_of_two']),
    ('vi2s.p', 0xffff8080, 0xd03f0080, ['s_vd', 'p_vs']),
    ('vi2s.q', 0xffff8080, 0xd03f8080, ['p_vd', 'q_vs']),
    ('vi2uc.q', 0xffff8080, 0xd03c8080, ['s_vd', 'q_vs']),
    ('vi2us.p', 0xffff8080, 0xd03e0080, ['s_vd', 'p_vs']),
    ('vi2us.q', 0xffff8080, 0xd03e8080, ['p_vd', 'q_vs']),
    ('vidt.p', 0xffffff80, 0xd0030080, ['p_vd']),
    ('vidt.q', 0xffffff80, 0xd0038080, ['q_vd']),
    ('viim.s', 0xff800000, 0xdf000000, ['s_vt', 'int16']),
    ('vlgb.s', 0xffff8080, 0xd0370000, ['s_vd', 's_vs']),
    ('vlog2.p', 0xffff8080, 0xd0150080, ['p_vd', 'p_vs']),
    ('vlog2.q', 0xffff8080, 0xd0158080, ['q_vd', 'q_vs']),
    ('vlog2.s', 0xffff8080, 0xd0150000, ['s_vd', 's_vs']),
    ('vlog2.t', 0xffff8080, 0xd0158000, ['t_vd', 't_vs']),
    ('vmax.p', 0xff808080, 0x6d800080, ['p_vd', 'p_vs', 'p_vt']),
    ('vmax.q', 0xff808080, 0x6d808080, ['q_vd', 'q_vs', 'q_vt']),
    ('vmax.s', 0xff808080, 0x6d800000, ['s_vd', 's_vs', 's_vt']),
    ('vmax.t', 0xff808080, 0x6d808000, ['t_vd', 't_vs', 't_vt']),
    ('vmfvc', 0xffff8080, 0xd0508000, ['s_vd', 'cop2cs']),      # psp-objdump also accepts bit 15 clear
    ('vmidt.p', 0xffffff80, 0xf3830080, ['mp_vd']),
    ('vmidt.q', 0xffffff80, 0xf3838080, ['mq_vd']),
    ('vmidt.t', 0xffffff80, 0xf3838000, ['mt_vd']),
    ('vmin.p', 0xff808080, 0x6d000080, ['p_vd', 'p_vs', 'p_vt']),
    ('vmin.q', 0xff808080, 0x6d008080, ['q_vd', 'q_vs', 'q_vt']),
    ('vmin.s', 0xff808080, 0x6d000000, ['s_vd', 's_vs', 's_vt']),
    ('vmin.t', 0xff808080, 0x6d008000, ['t_vd', 't_vs', 't_vt']),
    ('vmmov.p', 0xffff8080, 0xf3800080, ['mp_vd', 'mp_vs']),
    ('vmmov.q', 0xffff8080, 0xf3808080, ['mq_vd', 'mq_vs']),
    ('vmmov.t', 0xffff8080, 0xf3808000, ['mt_vd', 'mt_vs']),
    ('vmmul.p', 0xff808080, 0xf0000080, ['mp_vd', 'mp_vs_transpose', 'mp_vt']),
    ('vmmul.q', 0xff808080, 0xf0008080, ['mq_vd', 'mq_vs_transpose', 'mq_vt']),
    ('vmmul.t', 0xff808080, 0xf0008000, ['mt_vd', 'mt_vs_transpose', 'mt_vt']),
    ('vmone.p', 0xffffff80, 0xf3870080, ['mp_vd']),
    ('vmone.q', 0xffffff80, 0xf3878080, ['mq_vd']),
    ('vmone.t', 0xffffff80, 0xf3878000, ['mt_vd']),
    ('vmov.p', 0xffff8080, 0xd0000080, ['p_vd', 'p_vs']),
    ('vmov.q', 0xffff8080, 0xd0008080, ['q_vd', 'q_vs']),
    ('vmov.s', 0xffff8080, 0xd0000000, ['s_vd', 's_vs']),
    ('vmov.t', 0xffff8080, 0xd0008000, ['t_vd', 't_vs']),
    ('vmscl.p', 0xff808080, 0xf2000080, ['mp_vd', 'mp_vs', 's_vt']),
    ('vmscl.q', 0xff808080, 0xf2008080, ['mq_vd', 'mq_vs', 's_vt']),
    ('vmscl.t', 0xff808080, 0xf2008000, ['mt_vd', 'mt_vs', 's_vt']),
    ('vmtvc', 0xffff8080, 0xd0510080, ['cop2cd', 's_vs']),      # psp-objdump also accepts bit 7 clear
    ('vmul.p', 0xff808080, 0x64000080, ['p_vd', 'p_vs', 'p_vt']),
    ('vmul.q', 0xff808080, 0x64008080, ['q_vd', 'q_vs', 'q_vt']),
    ('vmul.s', 0xff808080, 0x64000000, ['s_vd', 's_vs', 's_vt']),
    ('vmul.t', 0xff808080, 0x64008000, ['t_vd', 't_vs', 't_vt']),
    ('vmzero.p', 0xffffff80, 0xf3860080, ['mp_vd']),
    ('vmzero.q', 0xffffff80, 0xf3868080, ['mq_vd']),
    ('vmzero.t', 0xffffff80, 0xf3868000, ['mt_vd']),
    ('vneg.p', 0xffff8080, 0xd0020080, ['p_vd', 'p_vs']),
    ('vneg.q', 0xffff8080, 0xd0028080, ['q_vd', 'q_vs']),
    ('vneg.s', 0xffff8080, 0xd0020000, ['s_vd', 's_vs']),
    ('vneg.t', 0xffff8080, 0xd0028000, ['t_vd', 't_vs']),
    ('vnop', 0xffffffff, 0xffff0000, []),
    ('vnrcp.p', 0xffff8080, 0xd0180080, ['p_vd', 'p_vs']),
    ('vnrcp.q', 0xffff8080, 0xd0188080, ['q_vd', 'q_vs']),
    ('vnrcp.s', 0xffff8080, 0xd0180000, ['s_vd', 's_vs']),
    ('vnrcp.t', 0xffff8080, 0xd0188000, ['t_vd', 't_vs']),
    ('vnsin.p', 0xffff8080, 0xd01a0080, ['p_vd', 'p_vs']),
    ('vnsin.q', 0xffff8080, 0xd01a8080, ['q_vd', 'q_vs']),
    ('vnsin.s', 0xffff8080, 0xd01a0000, ['s_vd', 's_vs']),
    ('vnsin.t', 0xffff8080, 0xd01a8000, ['t_vd', 't_vs']),
    ('vocp.p', 0xffff8080, 0xd0440080, ['p_vd', 'p_vs']),
    ('vocp.q', 0xffff8080, 0xd0448080, ['q_vd', 'q_vs']),
    ('vocp.s', 0xffff8080, 0xd0440000, ['s_vd', 's_vs']),
    ('vocp.t', 0xffff8080, 0xd0448000, ['t_vd', 't_vs']),
    ('vone.p', 0xffffff80, 0xd0070080, ['p_vd']),
    ('vone.q', 0xffffff80, 0xd0078080, ['q_vd']),
    ('vone.s', 0xffffff80, 0xd0070000, ['s_vd']),
    ('vone.t', 0xffffff80, 0xd0078000, ['t_vd']),
    ('vpfxd', 0xff000000, 0xde000000, ['wp']),       # rabbitizer: bits 23..12 must be 0
    ('vpfxs', 0xff000000, 0xdc000000, ['rp']),       # rabbitizer: bits 23..20 must be 0
    ('vpfxt', 0xff000000, 0xdd000000, ['rp']),       # rabbitizer: bits 23..20 must be 0
    ('vqmul.q', 0xff808080, 0xf2808080, ['q_vd', 'q_vs', 'q_vt']),
    ('vrcp.p', 0xffff8080, 0xd0100080, ['p_vd', 'p_vs']),
    ('vrcp.q', 0xffff8080, 0xd0108080, ['q_vd', 'q_vs']),
    ('vrcp.s', 0xffff8080, 0xd0100000, ['s_vd', 's_vs']),
    ('vrcp.t', 0xffff8080, 0xd0108000, ['t_vd', 't_vs']),
    ('vrexp2.p', 0xffff8080, 0xd01c0080, ['p_vd', 'p_vs']),
    ('vrexp2.q', 0xffff8080, 0xd01c8080, ['q_vd', 'q_vs']),
    ('vrexp2.s', 0xffff8080, 0xd01c0000, ['s_vd', 's_vs']),
    ('vrexp2.t', 0xffff8080, 0xd01c8000, ['t_vd', 't_vs']),
    ('vrndf1.p', 0xffffff80, 0xd0220080, ['p_vd']),
    ('vrndf1.q', 0xffffff80, 0xd0228080, ['q_vd']),
    ('vrndf1.s', 0xffffff80, 0xd0220000, ['s_vd']),
    ('vrndf1.t', 0xffffff80, 0xd0228000, ['t_vd']),
    ('vrndf2.p', 0xffffff80, 0xd0230080, ['p_vd']),
    ('vrndf2.q', 0xffffff80, 0xd0238080, ['q_vd']),
    ('vrndf2.s', 0xffffff80, 0xd0230000, ['s_vd']),
    ('vrndf2.t', 0xffffff80, 0xd0238000, ['t_vd']),
    ('vrndi.p', 0xffffff80, 0xd0210080, ['p_vd']),
    ('vrndi.q', 0xffffff80, 0xd0218080, ['q_vd']),
    ('vrndi.s', 0xffffff80, 0xd0210000, ['s_vd']),
    ('vrndi.t', 0xffffff80, 0xd0218000, ['t_vd']),
    ('vrnds.s', 0xffff80ff, 0xd0200000, ['s_vs']),
    ('vrot.p', 0xffe08080, 0xf3a00080, ['p_vd', 's_vs', 'vrot']),
    ('vrot.q', 0xffe08080, 0xf3a08080, ['q_vd', 's_vs', 'vrot']),
    ('vrot.t', 0xffe08080, 0xf3a08000, ['t_vd', 's_vs', 'vrot']),
    ('vrsq.p', 0xffff8080, 0xd0110080, ['p_vd', 'p_vs']),
    ('vrsq.q', 0xffff8080, 0xd0118080, ['q_vd', 'q_vs']),
    ('vrsq.s', 0xffff8080, 0xd0110000, ['s_vd', 's_vs']),
    ('vrsq.t', 0xffff8080, 0xd0118000, ['t_vd', 't_vs']),
    ('vs2i.p', 0xffff8080, 0xd03b0080, ['q_vd', 'p_vs']),
    ('vs2i.s', 0xffff8080, 0xd03b0000, ['p_vd', 's_vs']),
    ('vsat0.p', 0xffff8080, 0xd0040080, ['p_vd', 'p_vs']),
    ('vsat0.q', 0xffff8080, 0xd0048080, ['q_vd', 'q_vs']),
    ('vsat0.s', 0xffff8080, 0xd0040000, ['s_vd', 's_vs']),
    ('vsat0.t', 0xffff8080, 0xd0048000, ['t_vd', 't_vs']),
    ('vsat1.p', 0xffff8080, 0xd0050080, ['p_vd', 'p_vs']),
    ('vsat1.q', 0xffff8080, 0xd0058080, ['q_vd', 'q_vs']),
    ('vsat1.s', 0xffff8080, 0xd0050000, ['s_vd', 's_vs']),
    ('vsat1.t', 0xffff8080, 0xd0058000, ['t_vd', 't_vs']),
    ('vsbn.s', 0xff808080, 0x61000000, ['s_vd', 's_vs', 's_vt']),
    ('vsbz.s', 0xffff8080, 0xd0360000, ['s_vd', 's_vs']),
    ('vscl.p', 0xff808080, 0x65000080, ['p_vd', 'p_vs', 's_vt']),
    ('vscl.q', 0xff808080, 0x65008080, ['q_vd', 'q_vs', 's_vt']),
    ('vscl.t', 0xff808080, 0x65008000, ['t_vd', 't_vs', 's_vt']),
    ('vscmp.p', 0xff808080, 0x6e800080, ['p_vd', 'p_vs', 'p_vt']),
    ('vscmp.q', 0xff808080, 0x6e808080, ['q_vd', 'q_vs', 'q_vt']),
    ('vscmp.s', 0xff808080, 0x6e800000, ['s_vd', 's_vs', 's_vt']),
    ('vscmp.t', 0xff808080, 0x6e808000, ['t_vd', 't_vs', 't_vt']),
    ('vsge.p', 0xff808080, 0x6f000080, ['p_vd', 'p_vs', 'p_vt']),
    ('vsge.q', 0xff808080, 0x6f008080, ['q_vd', 'q_vs', 'q_vt']),
    ('vsge.s', 0xff808080, 0x6f000000, ['s_vd', 's_vs', 's_vt']),
    ('vsge.t', 0xff808080, 0x6f008000, ['t_vd', 't_vs', 't_vt']),
    ('vsgn.p', 0xffff8080, 0xd04a0080, ['p_vd', 'p_vs']),
    ('vsgn.q', 0xffff8080, 0xd04a8080, ['q_vd', 'q_vs']),
    ('vsgn.s', 0xffff8080, 0xd04a0000, ['s_vd', 's_vs']),
    ('vsgn.t', 0xffff8080, 0xd04a8000, ['t_vd', 't_vs']),
    ('vsin.p', 0xffff8080, 0xd0120080, ['p_vd', 'p_vs']),
    ('vsin.q', 0xffff8080, 0xd0128080, ['q_vd', 'q_vs']),
    ('vsin.s', 0xffff8080, 0xd0120000, ['s_vd', 's_vs']),
    ('vsin.t', 0xffff8080, 0xd0128000, ['t_vd', 't_vs']),
    ('vslt.p', 0xff808080, 0x6f800080, ['p_vd', 'p_vs', 'p_vt']),
    ('vslt.q', 0xff808080, 0x6f808080, ['q_vd', 'q_vs', 'q_vt']),
    ('vslt.s', 0xff808080, 0x6f800000, ['s_vd', 's_vs', 's_vt']),
    ('vslt.t', 0xff808080, 0x6f808000, ['t_vd', 't_vs', 't_vt']),
    ('vsocp.p', 0xffff8080, 0xd0450080, ['q_vd', 'p_vs']),
    ('vsocp.s', 0xffff8080, 0xd0450000, ['p_vd', 's_vs']),
    ('vsqrt.p', 0xffff8080, 0xd0160080, ['p_vd', 'p_vs']),
    ('vsqrt.q', 0xffff8080, 0xd0168080, ['q_vd', 'q_vs']),
    ('vsqrt.s', 0xffff8080, 0xd0160000, ['s_vd', 's_vs']),
    ('vsqrt.t', 0xffff8080, 0xd0168000, ['t_vd', 't_vs']),
    ('vsrt1.q', 0xffff8080, 0xd0408080, ['q_vd', 'q_vs']),
    ('vsrt2.q', 0xffff8080, 0xd0418080, ['q_vd', 'q_vs']),
    ('vsrt3.q', 0xffff8080, 0xd0488080, ['q_vd', 'q_vs']),
    ('vsrt4.q', 0xffff8080, 0xd0498080, ['q_vd', 'q_vs']),
    ('vsub.p', 0xff808080, 0x60800080, ['p_vd', 'p_vs', 'p_vt']),
    ('vsub.q', 0xff808080, 0x60808080, ['q_vd', 'q_vs', 'q_vt']),
    ('vsub.s', 0xff808080, 0x60800000, ['s_vd', 's_vs', 's_vt']),
    ('vsub.t', 0xff808080, 0x60808000, ['t_vd', 't_vs', 't_vt']),
    ('vsync', 0xffffffff, 0xffff0320, []),
    ('vsync', 0xffff0000, 0xffff0000, ['code16']),   # psp-objdump; rabbitizer: only ffff0320
    ('vsync2', 0xffffffff, 0x486000ff, []),          # rabbitizer only (psp-objdump: mfvc zero,$255)
    ('vt4444.q', 0xffff8080, 0xd0598080, ['p_vd', 'q_vs']),
    ('vt5551.q', 0xffff8080, 0xd05a8080, ['p_vd', 'q_vs']),
    ('vt5650.q', 0xffff8080, 0xd05b8080, ['p_vd', 'q_vs']),
    ('vtfm2.p', 0xff808080, 0xf0800080, ['p_vd', 'mp_vs', 'p_vt']),
    ('vtfm3.t', 0xff808080, 0xf1008000, ['t_vd', 'mt_vs', 't_vt']),
    ('vtfm4.q', 0xff808080, 0xf1808080, ['q_vd', 'mq_vs', 'q_vt']),
    ('vuc2ifs.s', 0xffff8080, 0xd0380000, ['q_vd', 's_vs']),   # named so by psp-objdump and rabbitizer
    ('vus2i.p', 0xffff8080, 0xd03a0080, ['q_vd', 'p_vs']),
    ('vus2i.s', 0xffff8080, 0xd03a0000, ['p_vd', 's_vs']),
    ('vwbn.s', 0xff008080, 0xd3000000, ['s_vd', 's_vs', 'bn']),
    ('vzero.p', 0xffffff80, 0xd0060080, ['p_vd']),
    ('vzero.q', 0xffffff80, 0xd0068080, ['q_vd']),
    ('vzero.s', 0xffffff80, 0xd0060000, ['s_vd']),
    ('vzero.t', 0xffffff80, 0xd0068000, ['t_vd']),
]

FIELD = {'vs': 8, 'vt': 16, 'vd': 0}


def fbits(x):
    return struct.unpack('<I', struct.pack('<f', x))[0]


ONE, ZERO, NEG1 = 0x3f800000, 0, 0xbf800000
# VPFXS / VPFXT constants: index = swizzle + 4 * abs
PFX_CONST = [0.0, 1.0, 2.0, 0.5, 3.0, 1.0 / 3.0, 0.25, 1.0 / 6.0]
# VCST constants as the hardware delivers them (PPSSPP, black box): index 0 and 20..31 read as 0; 2/sqrt(pi) is
# 0x3f906eba, one unit below the nearest float
VCST_BITS = [0x0, 0x7f7fffff, 0x3fb504f3, 0x3f3504f3, 0x3f906eba, 0x3f22f983, 0x3ea2f983, 0x3f490fdb, 0x3fc90fdb,
             0x40490fdb, 0x402df854, 0x3fb8aa3b, 0x3ede5bd9, 0x3f317218, 0x40135d8e, 0x40c90fdb, 0x3f060a92,
             0x3e9a209b, 0x40549a78, 0x3f5db3d7] + [0] * 12
# the names psp-as / psp-objdump use; 0 and 20..31 are undefined
VCST_NAMES = ['VFPU_UNDEF', 'VFPU_HUGE', 'VFPU_SQRT2', 'VFPU_SQRT1_2', 'VFPU_2_SQRTPI', 'VFPU_2_PI', 'VFPU_1_PI',
              'VFPU_PI_4', 'VFPU_PI_2', 'VFPU_PI', 'VFPU_E', 'VFPU_LOG2E', 'VFPU_LOG10E', 'VFPU_LN2', 'VFPU_LN10',
              'VFPU_2PI', 'VFPU_PI_6', 'VFPU_LOG10TWO', 'VFPU_LOG2TEN', 'VFPU_SQRT3_2'] + ['VFPU_UNDEF'] * 12
CTRL = ['SPFX', 'TPFX', 'DPFX', 'CC', 'INF4', 'RSV5', 'RSV6', 'REV', 'RCX0', 'RCX1', 'RCX2', 'RCX3', 'RCX4', 'RCX5',
        'RCX6', 'RCX7']


# ------------------------------------------------------------------------------------------------------
# register naming and lane mapping (V index = m*16 + r*4 + c for S<m><c><r>)

def parts(f):
    return (f >> 2) & 7, f & 3, (f >> 5) & 1, (f >> 6) & 1   # matrix, column/row index, transpose, offset bit


def vec_name(f, sz):
    m, a, t, o = parts(f)
    if sz == 's':
        return f'S{m}{a}{(f >> 5) & 3}'
    k = OFFS[sz] * o if sz != 'q' else 2 * o
    return f'R{m}{k}{a}' if t else f'C{m}{a}{k}'


def mat_name(f, sz, transposed=False):
    m, a, t, o = parts(f)
    k = o if sz == 't' else 2 * o
    tt = t ^ transposed
    return f'E{m}{k}{a}' if tt else f'M{m}{a}{k}'


def vec_lane_expr(field, sz, lane_expr):
    """SLEIGH disassembly expression of the register offset of lane `lane_expr` (an expression) of a vector."""
    f = field
    if sz == 's':
        return (f'0x5000 + 4 * ((({f} >> 2) $and 7) * 16 + (((({f} >> 5) $and 3) + ({lane_expr})) $and 3) * 4 + '
                f'({f} $and 3))'), None
    k = OFFS[sz]
    col = f'0x5000 + 4 * ((({f} >> 2) $and 7) * 16 + (((({f} >> 6) $and 1) * {k} + ({lane_expr})) $and 3) * 4 + ({f} $and 3))'
    row = f'0x5000 + 4 * ((({f} >> 2) $and 7) * 16 + ({f} $and 3) * 4 + (((({f} >> 6) $and 1) * {k} + ({lane_expr})) $and 3))'
    return col, row


def mat_base(field, sz):
    """(r0, c0) expressions of a matrix operand (the mapping of illegal encodings follows upstream)."""
    f = field
    if sz == 'q':
        return '0', '0'
    if sz == 't':
        return f'(({f} >> 6) $and 1)', f'((({f} $and 3) $or (({f} $and 3) >> 1)) $and 1)'
    return f'((({f} >> 6) $and 1) * 2)', f'({f} $and 2)'


class Gen:
    def __init__(self):
        self.out = []
        self.ctors = 0

    def w(self, s=''):
        self.out.append(s)


def fields():
    """Token fields used by the generated constraints (one per bit range)."""
    rng = set()
    for _, mask, _, _ in ENCODINGS:
        for lo, hi in runs(mask & 0x03ffffff):
            rng.add((lo, hi))
    for f, b in FIELD.items():
        rng.add((b + 5, b + 5))
    rng |= {(0, 3), (5, 5), (7, 7), (15, 15), (16, 17), (18, 19), (20, 20), (16, 20), (16, 23)}
    lines = ['# Generated by tools/gen_vfpu.py fields: do not edit.']
    for lo, hi in sorted(rng):
        lines.append(f'    vf_{lo}_{hi} = ({lo},{hi})')
    return '\n'.join(lines) + '\n'


def runs(mask):
    out, b = [], 0
    while b < 32:
        if (mask >> b) & 1:
            e = b
            while e + 1 < 32 and (mask >> (e + 1)) & 1:
                e += 1
            out.append((b, e))
            b = e + 1
        else:
            b += 1
    return out


def constraint(mask, val):
    cs = [f'prime={val >> 26}']
    for lo, hi in runs(mask & 0x03ffffff):
        v = (val >> lo) & ((1 << (hi - lo + 1)) - 1)
        cs.append(f'vf_{lo}_{hi}={v}')
    return ' & '.join(cs)


# ------------------------------------------------------------------------------------------------------
# expression helpers (32-bit float lanes as raw bits)

def sel(c, a, b):
    return f'((zext({c}) * ({a})) | (zext(!({c})) * ({b})))'


def K(bits):
    return f'0x{bits:08x}:4'


def clamp(x, lo, hi):
    # x <= lo gives lo, so -0.0 saturates to +0.0 for [0:1] (PPSSPP, black box)
    return sel(f'{x} f<= {K(lo)}', K(lo), sel(f'{x} f> {K(hi)}', K(hi), x))


def fsum(terms):
    e = terms[0]
    for t in terms[1:]:
        e = f'({e}) f+ ({t})'
    return e


class VfpuGen(Gen):
    def lane_tables(self):
        w = self.w
        w('# ---- source lanes: g<R><size><lane> is the register of the (swizzled) lane, r<R><size><lane> applies')
        w('# the VPFXS / VPFXT prefix (abs, negate, constant). Context fields hold the swizzle XOR the lane number,')
        w('# so all-zero context means "no prefix".')
        for R, fld, px in (('S', 'vs', 'pfs'), ('T', 'vt', 'pft')):
            for sz, n in SIZES.items():
                for i in range(n):
                    lane = f'({px}_x{i} $xor {i})'
                    col, row = vec_lane_expr(fld, sz, lane)
                    g = f'g{R}{sz}{i}'
                    if row is None:
                        w(f'{g}: off is {fld} [ off = {col}; ] {{ export *[register]:4 off; }}')
                    else:
                        tb = FIELD[fld] + 5
                        w(f'{g}: off is {fld} & vf_{tb}_{tb}=0 [ off = {col}; ] {{ export *[register]:4 off; }}')
                        w(f'{g}: off is {fld} & vf_{tb}_{tb}=1 [ off = {row}; ] {{ export *[register]:4 off; }}')
                    for r, fa, fn in ((f'r{R}{sz}{i}', None, None), (f'r{R}A{sz}{i}', 1, None), (f'r{R}N{sz}{i}', None, 1)):
                        if R == 'T' and (fa or fn):
                            continue
                        self.src_lane(r, g, px, i, fa, fn)
                    continue
                    r = f'r{R}{sz}{i}'
                    c = f'{px}_c{i}=0'
                    w(f'{r}: is {c} & {px}_a{i}=0 & {px}_n{i}=0 & {g} {{ export {g}; }}')
                    w(f'{r}: is {c} & {px}_a{i}=1 & {px}_n{i}=0 & {g} {{ t:4 = abs({g}); export t; }}')
                    w(f'{r}: is {c} & {px}_a{i}=0 & {px}_n{i}=1 & {g} {{ t:4 = f- {g}; export t; }}')
                    w(f'{r}: is {c} & {px}_a{i}=1 & {px}_n{i}=1 & {g} {{ t:4 = f- abs({g}); export t; }}')
                    for x in range(4):
                        for a in range(2):
                            for ng in range(2):
                                v = PFX_CONST[(x ^ i) + 4 * a] * (-1 if ng else 1)
                                w(f'{r}: is {px}_c{i}=1 & {px}_x{i}={x} & {px}_a{i}={a} & {px}_n{i}={ng} '
                                  f'{{ export {K(fbits(v))}; }}')
        w('')
        w('# ---- destination lanes: the VPFXD write mask discards a lane; d<size><lane> applies the saturation')
        w('# to the lane result held in vfpuR<lane>.')
        for sz, n in SIZES.items():
            for i in range(n):
                col, row = vec_lane_expr('vd', sz, str(i))
                wd = f'wD{sz}{i}'
                w(f'{wd}: is pfd_m{i}=1 {{ local d:4 = 0; export d; }}')
                if row is None:
                    w(f'{wd}: off is pfd_m{i}=0 & vd [ off = {col}; ] {{ export *[register]:4 off; }}')
                else:
                    w(f'{wd}: off is pfd_m{i}=0 & vd & vf_5_5=0 [ off = {col}; ] {{ export *[register]:4 off; }}')
                    w(f'{wd}: off is pfd_m{i}=0 & vd & vf_5_5=1 [ off = {row}; ] {{ export *[register]:4 off; }}')
        for sz, n in SIZES.items():
            for i in range(n):
                col, row = vec_lane_expr('vd', sz, str(i))
                if row is None:
                    w(f'gD{sz}{i}: off is vd [ off = {col}; ] {{ export *[register]:4 off; }}')
                else:
                    w(f'gD{sz}{i}: off is vd & vf_5_5=0 [ off = {col}; ] {{ export *[register]:4 off; }}')
                    w(f'gD{sz}{i}: off is vd & vf_5_5=1 [ off = {row}; ] {{ export *[register]:4 off; }}')
        for i in range(4):
            w(f'satD{i}: is pfd_s{i}=0 {{ export vfpuR{i}; }}')
            w(f'satD{i}: is pfd_s{i}=1 {{ t:4 = {clamp(f"vfpuR{i}", ZERO, ONE)}; export t; }}')
            w(f'satD{i}: is pfd_s{i}=2 {{ export vfpuR{i}; }}')
            w(f'satD{i}: is pfd_s{i}=3 {{ t:4 = {clamp(f"vfpuR{i}", NEG1, ONE)}; export t; }}')
        w('')
        w('# ---- matrix elements m<R><size><row><col> (no prefixes); x<size><row><col> is vs read transposed (VMMUL)')
        for R, fld in (('S', 'vs'), ('T', 'vt'), ('D', 'vd'), ('X', 'vs')):
            for sz in 'ptq':
                n = SIZES[sz]
                k = OFFS[sz]
                tb = FIELD[fld] + 5
                for i in range(n):
                    for j in range(n):
                        nm = f'm{R}{sz}{i}{j}'
                        # M: columns a+j, rows k*o+i; E (transposed): the same vectors read as rows
                        normal = (f'0x5000 + 4 * ((({fld} >> 2) $and 7) * 16 + (((({fld} >> 6) $and 1) * {k} + {i}) $and 3) * 4'
                                  f' + ((({fld} $and 3) + {j}) $and 3))')
                        trans = (f'0x5000 + 4 * ((({fld} >> 2) $and 7) * 16 + ((({fld} $and 3) + {j}) $and 3) * 4'
                                 f' + (((({fld} >> 6) $and 1) * {k} + {i}) $and 3))')
                        if R == 'X':
                            # the transpose of the matrix the field names: element (i, j) is element (j, i) of mS
                            normal = (f'0x5000 + 4 * ((({fld} >> 2) $and 7) * 16 + (((({fld} >> 6) $and 1) * {k} + {j}) $and 3) * 4'
                                      f' + ((({fld} $and 3) + {i}) $and 3))')
                            trans = (f'0x5000 + 4 * ((({fld} >> 2) $and 7) * 16 + ((({fld} $and 3) + {i}) $and 3) * 4'
                                     f' + (((({fld} >> 6) $and 1) * {k} + {j}) $and 3))')
                        a, b = normal, trans
                        w(f'{nm}: off is {fld} & vf_{tb}_{tb}=0 [ off = {a}; ] {{ export *[register]:4 off; }}')
                        w(f'{nm}: off is {fld} & vf_{tb}_{tb}=1 [ off = {b}; ] {{ export *[register]:4 off; }}')
        w('')

    def src_lane(self, r, g, px, i, force_abs, force_neg):
        """Source lane r with the prefix of lane i; VABS / VNEG set the prefix abs / negate bit (PPSSPP, black box),
        which for a constant prefix selects the constant of the other half of the table."""
        w = self.w
        for a in range(2):
            for ng in range(2):
                ea, en = force_abs or a, force_neg or ng
                cond = f'{px}_c{i}=0 & {px}_a{i}={a} & {px}_n{i}={ng}'
                e = g if not ea else f'abs({g})'
                if en:
                    e = f'f- {e}'
                if e == g:
                    w(f'{r}: is {cond} & {g} {{ export {g}; }}')
                else:
                    w(f'{r}: is {cond} & {g} {{ t:4 = {e}; export t; }}')
        for x in range(4):
            for a in range(2):
                for ng in range(2):
                    ea, en = force_abs or a, force_neg or ng
                    v = PFX_CONST[(x ^ i) + 4 * ea] * (-1 if en else 1)
                    w(f'{r}: is {px}_c{i}=1 & {px}_x{i}={x} & {px}_a{i}={a} & {px}_n{i}={ng} '
                      f'{{ export {K(fbits(v))}; }}')

    def names(self):
        w = self.w
        w('# ---- register names for display')
        for fld in ('vs', 'vt', 'vd'):
            w(f'attach names [ {fld}_s ] [ ' + ' '.join(vec_name(f, 's') for f in range(128)) + ' ];')
            w(f'attach names [ {fld}_p {fld}_q ] [ ' + ' '.join(vec_name(f, 'q') for f in range(128)) + ' ];')
            w(f'attach names [ {fld}_t ] [ ' + ' '.join(vec_name(f, 't') for f in range(128)) + ' ];')
            w(f'attach names [ {fld}_m ] [ ' + ' '.join(mat_name(f, 'q') for f in range(128)) + ' ];')
            w(f'attach names [ {fld}_tm ] [ ' + ' '.join(mat_name(f, 't') for f in range(128)) + ' ];')
            w(f'attach names [ {fld}_e ] [ ' + ' '.join(mat_name(f, 'q', True) for f in range(128)) + ' ];')
            w(f'attach names [ {fld}_te ] [ ' + ' '.join(mat_name(f, 't', True) for f in range(128)) + ' ];')
        w('attach names [ vd_cmp ] [ ' + ' '.join(['FL', 'EQ', 'LT', 'LE', 'TR', 'NE', 'GE', 'GT', 'EZ', 'EN', 'EI', 'ES',
                                                  'NZ', 'NN', 'NI', 'NS'] * 8) + ' ];')
        w('attach names [ vt_cst ] [ ' + ' '.join(f'"{n}"' for n in VCST_NAMES) + ' ];')
        w('')


# display text of each operand kind, and the pattern pieces it needs
def disp(kind):
    if kind.startswith('vcmp_'):
        return kind
    if kind in ('imm3',):
        return 'vcc'
    if kind == 'cpu_branch_target_label':
        return 'Rel16'
    if kind == 'cpu_rt':
        return 'rt'
    if kind.endswith('_vt_imm'):
        return 'VmemS' if kind[0] == 's' else 'VmemQ'
    if kind == 'offset14_base':
        return 'OFF_VBASE'
    if kind == 'wb':
        return '"wb"'
    if kind in ('cop2cd',):
        return 'VctlD'
    if kind == 'cop2cdr':
        return 'VctlDr'
    if kind in ('cop2cs',):
        return 'VctlS'
    if kind == 'vconstant':
        return 'vt_cst'
    if kind == 'power_of_two':
        return 'vtimm5'
    if kind == 'vfpu_cc_bit':
        return 'VcmovCC'
    if kind == 'int16':
        return 'Viim'
    if kind == 'float16':
        return 'Vfim'
    if kind == 'bn':
        return 'vwbnimm8'
    if kind == 'vrot':
        return 'Vrot'
    if kind == 'code16':
        return 'immed'
    if kind[0] in 'sptq' and kind[1] == '_':
        sz, fld = kind[0], kind[2:]
        return f'{fld}_{sz}'
    if kind[0] == 'm':
        sz = {'p': 'q', 't': 't', 'q': 'q'}[kind[1]]
        fld = kind.split('_')[1]
        tr = kind.endswith('_transpose')
        return f'{fld}_' + ({'q': 'e', 't': 'te'}[sz] if tr else {'q': 'm', 't': 'tm'}[sz])
    raise KeyError(kind)


# ------------------------------------------------------------------------------------------------------
# lane semantics: f(nd, ns, S, T) -> (pre-statements, [lane expression] * nd); S(i) / T(i) are source lanes

def bin_(op):
    return lambda nd, ns, S, T: ([], [f'{S(i)} {op} {T(i)}' for i in range(nd)])


def un(fn):
    return lambda nd, ns, S, T: ([], [fn(S(i)) for i in range(nd)])


def sgn(x):
    return sel(f'{x} f> {K(ZERO)}', K(ONE), sel(f'{x} f< {K(ZERO)}', K(NEG1), K(ZERO)))


def fmin(a, b):
    return sel(f'{a} f< {b}', a, b)


def fmax(a, b):
    return sel(f'{a} f> {b}', a, b)


def op_dot(nd, ns, S, T):
    return [], [fsum([f'{S(i)} f* {T(i)}' for i in range(ns)])]


def op_hdp(nd, ns, S, T):
    return [], [fsum([f'{S(i)} f* {T(i)}' for i in range(ns - 1)] + [T(ns - 1)])]


def op_bfy1(nd, ns, S, T):
    out = []
    for p in range(0, nd, 2):
        out += [f'{S(p)} f+ {S(p + 1)}', f'{S(p)} f- {S(p + 1)}']
    return [], out


def op_bfy2(nd, ns, S, T):
    return [], [f'{S(0)} f+ {S(2)}', f'{S(1)} f+ {S(3)}', f'{S(0)} f- {S(2)}', f'{S(1)} f- {S(3)}']


def srt(pairs):
    # pairs: lane -> (min|max, a, b)
    def f(nd, ns, S, T):
        return [], [(fmin if m == 'min' else fmax)(S(a), S(b)) for m, a, b in pairs]
    return f


def op_crs(nd, ns, S, T):
    return [], [f'{S(1)} f* {T(2)}', f'{S(2)} f* {T(0)}', f'{S(0)} f* {T(1)}']


def op_crsp(nd, ns, S, T):
    return [], [f'({S(1)} f* {T(2)}) f- ({S(2)} f* {T(1)})', f'({S(2)} f* {T(0)}) f- ({S(0)} f* {T(2)})',
                f'({S(0)} f* {T(1)}) f- ({S(1)} f* {T(0)})']


def op_qmul(nd, ns, S, T):
    """Quaternion product (x, y, z, w = vector, scalar part); terms summed in s-lane order (PPSSPP's rounding)."""
    terms = [[(0, 3, 1), (1, 2, 1), (2, 1, -1), (3, 0, 1)],
             [(0, 2, -1), (1, 3, 1), (2, 0, 1), (3, 1, 1)],
             [(0, 1, 1), (1, 0, -1), (2, 3, 1), (3, 2, 1)],
             [(0, 0, -1), (1, 1, -1), (2, 2, -1), (3, 3, 1)]]
    out = []
    for lane in terms:
        e = None
        for a, b, sg in lane:
            p = f'({S(a)} f* {T(b)})'
            if e is None:
                e = p if sg > 0 else f'f- {p}'
            else:
                e = f'({e}) {"f+" if sg > 0 else "f-"} {p}'
        out.append(e)
    return [], out


def userop(name):
    return lambda nd, ns, S, T: ([], [f'{name}({S(i)})' for i in range(nd)])


def f2i(mode):
    """VF2IN / VF2IZ / VF2IU / VF2ID: scale by 2^imm, round, convert with saturation."""
    def f(nd, ns, S, T):
        pre = ['big:4 = 0x4f000000:4;']       # 2^31
        out = []
        for i in range(nd):
            pre.append(f'x{i}:4 = {S(i)} f* p2pos;')
            if mode == 'z':
                pre.append(f'q{i}:4 = x{i};')
            elif mode == 'u':
                pre.append(f'q{i}:4 = ceil(x{i});')
            elif mode == 'd':
                pre.append(f'q{i}:4 = floor(x{i});')
            else:   # nearest, ties to even
                pre += [f'l{i}:4 = floor(x{i}); d{i}:4 = x{i} f- l{i}; h{i}:4 = l{i} f+ {K(ONE)};',
                        f'tl{i}:4 = trunc(l{i}); e{i}:1 = (tl{i} & 1) == 0;',
                        f'q{i}:4 = ' + sel(f'd{i} f> {K(fbits(0.5))}', f'h{i}',
                                           sel(f'd{i} f< {K(fbits(0.5))}', f'l{i}', sel(f'e{i}', f'l{i}', f'h{i}'))) + ';']
            pre += [f'o{i}:1 = q{i} f>= big; u{i}:1 = q{i} f< f- big; n{i}:1 = nan(q{i});',
                    f'iv{i}:4 = (zext(o{i} || n{i}) * 0x7fffffff) | (zext(u{i}) * 0x80000000) | '
                    f'(zext(!(o{i} || u{i} || n{i})) * trunc(q{i}));']
            out.append(f'iv{i}')
        return pre, out
    return f


def op_i2f(nd, ns, S, T):
    return [], [f'int2float({S(i)}) f* p2neg' for i in range(nd)]


def pack(nd_out, ns, S, conv, bits):
    """Pack ns integer lanes into nd_out words, `bits` bits each, using conv(lane) -> integer expression."""
    per = 32 // bits
    pre, out = [], []
    for i in range(ns):
        pre.append(f'c{i}:4 = {conv(S(i))};')
    for wi in range(nd_out):
        terms = [f'(c{wi * per + k} << {k * bits})' if k else f'c{wi * per}' for k in range(per)]
        out.append(' | '.join(terms))
    return pre, out


def op_i2uc(nd, ns, S, T):
    return pack(nd, ns, S, lambda x: sel(f'{x} s< 0', '0:4', f'({x} >> 23) & 0xff'), 8)


def op_i2c(nd, ns, S, T):
    return pack(nd, ns, S, lambda x: f'({x} >> 24) & 0xff', 8)


def op_i2us(nd, ns, S, T):
    return pack(nd, ns, S, lambda x: sel(f'{x} s< 0', '0:4', f'({x} >> 15) & 0xffff'), 16)


def op_i2s(nd, ns, S, T):
    return pack(nd, ns, S, lambda x: f'({x} >> 16) & 0xffff', 16)


def unpack(bits, conv):
    def f(nd, ns, S, T):
        per = 32 // bits
        out = []
        for i in range(nd):
            src = S(i // per)
            out.append(conv(f'(({src} >> {(i % per) * bits}) & {(1 << bits) - 1})'))
        return [], out
    return f


def h2f(h):
    """IEEE half (low 16 bits of an expression) -> float bits, with denormals, Inf and NaN."""
    return (f'vfpuHalfToFloat({h})')


def op_color(kind):
    def conv(x):
        r, g, b, a = (f'(({x} >> {s}) & 0xff)' for s in (0, 8, 16, 24))
        if kind == '4444':
            return f'({r} >> 4) | (({g} >> 4) << 4) | (({b} >> 4) << 8) | (({a} >> 4) << 12)'
        if kind == '5551':
            return f'({r} >> 3) | (({g} >> 3) << 5) | (({b} >> 3) << 10) | (({a} >> 7) << 15)'
        return f'({r} >> 3) | (({g} >> 2) << 5) | (({b} >> 3) << 11)'
    return lambda nd, ns, S, T: pack(nd, ns, S, conv, 16)


def op_socp(nd, ns, S, T):
    out = []
    for i in range(ns):
        out += [clamp(f'({K(ONE)} f- {S(i)})', ZERO, ONE), clamp(S(i), ZERO, ONE)]
    return [], out


OPS = {
    'vadd': bin_('f+'), 'vsub': bin_('f-'), 'vmul': bin_('f*'), 'vdiv': bin_('f/'),
    'vmin': lambda nd, ns, S, T: ([], [fmin(S(i), T(i)) for i in range(nd)]),
    'vmax': lambda nd, ns, S, T: ([], [fmax(S(i), T(i)) for i in range(nd)]),
    'vsge': lambda nd, ns, S, T: ([], [sel(f'{S(i)} f>= {T(i)}', K(ONE), K(ZERO)) for i in range(nd)]),
    'vslt': lambda nd, ns, S, T: ([], [sel(f'{S(i)} f< {T(i)}', K(ONE), K(ZERO)) for i in range(nd)]),
    'vscmp': lambda nd, ns, S, T: ([], [sel(f'{S(i)} f< {T(i)}', K(NEG1), sel(f'{S(i)} f> {T(i)}', K(ONE), K(ZERO)))
                                         for i in range(nd)]),
    'vscl': lambda nd, ns, S, T: ([], [f'{S(i)} f* {T(0)}' for i in range(nd)]),
    'vdot': op_dot, 'vhdp': op_hdp,
    'vdet': lambda nd, ns, S, T: ([], [f'({S(0)} f* {T(1)}) f- ({S(1)} f* {T(0)})']),
    'vcrs': op_crs, 'vcrsp': op_crsp, 'vqmul': op_qmul,
    # VSBN: the mantissa of s (as 1.m) scaled by 2^t, i.e. exponent := 127 + t (PPSSPP, black box); zero,
    # denormals, Inf and NaN pass unchanged
    'vsbn': lambda nd, ns, S, T: (
        [f'xa:4 = {S(0)}; xb:4 = {T(0)}; se:4 = (xa >> 23) & 0xff; ne:4 = 127 + xb;',
         'sr:4 = ' + sel('(se == 0) || (se == 255)', 'xa', sel('ne s>= 255', '(xa & 0x80000000) | 0x7f800000',
                                             sel('ne s<= 0', 'xa & 0x80000000', '(xa & 0x807fffff) | (ne << 23)'))) + ';'],
        ['sr']),
    'vmov': un(lambda x: x),
    # VABS / VNEG: VMOV with the source prefix abs / negate bit set (rSA / rSN lanes)
    'vabs': un(lambda x: x.replace('rS', 'rSA')), 'vneg': un(lambda x: x.replace('rS', 'rSN')),
    'vsat0': un(lambda x: clamp(x, ZERO, ONE)), 'vsat1': un(lambda x: clamp(x, NEG1, ONE)),
    'vrcp': un(lambda x: f'{K(ONE)} f/ {x}'), 'vnrcp': un(lambda x: f'{K(NEG1)} f/ {x}'),
    'vrsq': un(lambda x: f'{K(ONE)} f/ sqrt({x})'), 'vsqrt': un(lambda x: sel(f'{x} f== 0:4', '0:4', f'sqrt({x})')),
    # VOCP: 1 + (source with the negate prefix bit set) (PPSSPP, black box)
    'vocp': un(lambda x: f'{K(ONE)} f+ {x.replace("rS", "rSN")}'), 'vsgn': un(sgn),
    'vsin': userop('vfpuSin'), 'vcos': userop('vfpuCos'), 'vexp2': userop('vfpuExp2'),
    'vlog2': userop('vfpuLog2'), 'vasin': userop('vfpuAsin'),
    'vnsin': un(lambda x: f'f- vfpuSin({x})'), 'vrexp2': un(lambda x: f'{K(ONE)} f/ vfpuExp2({x})'),
    # VLGB: the unbiased exponent as a float; VSBZ: the mantissa with exponent 0 (1.m, sign cleared) (PPSSPP, black box)
    'vlgb': un(lambda x: f'int2float((({x} >> 23) & 0xff) - 127)'),
    'vsbz': un(lambda x: f'({x} & 0x7fffff) | 0x3f800000'),
    'vfad': lambda nd, ns, S, T: ([], [fsum([S(i) for i in range(ns)])]),
    # VAVG: sum of x * (1/n) in lane order (PPSSPP's rounding, black box)
    'vavg': lambda nd, ns, S, T: ([], [fsum([f'{S(i)} f* {K(fbits(1.0 / ns))}' for i in range(ns)])]),
    'vbfy1': op_bfy1, 'vbfy2': op_bfy2,
    'vsrt1': srt([('min', 0, 1), ('max', 0, 1), ('min', 2, 3), ('max', 2, 3)]),
    'vsrt2': srt([('min', 0, 3), ('min', 1, 2), ('max', 1, 2), ('max', 0, 3)]),
    'vsrt3': srt([('max', 0, 1), ('min', 0, 1), ('max', 2, 3), ('min', 2, 3)]),
    'vsrt4': srt([('max', 0, 3), ('max', 1, 2), ('min', 1, 2), ('min', 0, 3)]),
    'vi2f': op_i2f, 'vf2in': f2i('n'), 'vf2iz': f2i('z'), 'vf2iu': f2i('u'), 'vf2id': f2i('d'),
    'vi2uc': op_i2uc, 'vi2c': op_i2c, 'vi2us': op_i2us, 'vi2s': op_i2s,
    'vuc2ifs': unpack(8, lambda b: f'({b} * 0x01010101) >> 1'),
    'vc2i': unpack(8, lambda b: f'({b} << 24)'),
    'vus2i': unpack(16, lambda h: f'({h} << 15)'),
    'vs2i': unpack(16, lambda h: f'({h} << 16)'),
    'vh2f': unpack(16, h2f),
    'vf2h': lambda nd, ns, S, T: pack(nd, ns, S, lambda x: f'vfpuFloatToHalf({x})', 16),
    'vt4444': op_color('4444'), 'vt5551': op_color('5551'), 'vt5650': op_color('5650'),
    'vsocp': op_socp,
}


# the VPFXD saturation does not apply to these (PPSSPP, black box): float-to-int conversions, and VSAT0 / VSAT1,
# which are a move with a forced saturation of their own
NO_DPFX = {'vcrsp', 'vqmul'}
INT_RESULT = {'vf2in', 'vf2iz', 'vf2iu', 'vf2id', 'vsat0', 'vsat1'}


def vec_kind(k):
    return len(k) >= 4 and k[0] in 'sptq' and k[1] == '_' and k[2:] in ('vd', 'vs', 'vt')


def vfpu():
    g = VfpuGen()
    w = g.w
    w('# Generated by tools/gen_vfpu.py vfpu: do not edit. See the generator for the design.')
    w('')
    w('define register offset=0x5400 size=4 [ vfpuR0 vfpuR1 vfpuR2 vfpuR3 ];   # lane results before VPFXD')
    w('')
    for op in ('vfpuSin', 'vfpuCos', 'vfpuExp2', 'vfpuLog2', 'vfpuAsin', 'vfpuWbn',
               'vfpuRandSeed', 'vfpuRandInt', 'vfpuRandFloat1', 'vfpuRandFloat2'):
        w(f'define pcodeop {op};')
    w('')
    g.names()
    g.lane_tables()
    # small operand tables
    w('p2pos: s is vtimm5 [ s = (127 + vtimm5) << 23; ] { export *[const]:4 s; }')
    w('p2neg: s is vtimm5 [ s = (127 - vtimm5) << 23; ] { export *[const]:4 s; }')
    for i, bits in enumerate(VCST_BITS):
        w(f'Vcst: is vt_cst={i} {{ export {K(bits)}; }}')
    w('VcmovCC: "CC["^vcmov_cc^"]" is vcmov_cc { export *[const]:1 vcmov_cc; }')
    w('Viim: simmed is simmed { export *[const]:2 simmed; }')
    w('Vfim: immed is immed { export *[const]:2 immed; }')
    # the pending prefixes live in the context: reading SPFX / TPFX / DPFX gives their encoding (0xe4 = identity)
    for nm, px in (('pfxS', 'pfs'), ('pfxT', 'pft')):
        e = ' $or '.join(f'(({px}_x{i} $xor {i}) << {2 * i}) $or ({px}_a{i} << {8 + i}) $or ({px}_c{i} << {12 + i}) $or '
                         f'({px}_n{i} << {16 + i})' for i in range(4))
        w(f'{nm}: v is prime [ v = {e}; ] {{ export *[const]:4 v; }}')
    e = ' $or '.join(f'(pfd_s{i} << {2 * i}) $or (pfd_m{i} << {8 + i})' for i in range(4))
    w(f'pfxD: v is prime [ v = {e}; ] {{ export *[const]:4 v; }}')
    for i, n in enumerate(CTRL):
        w(f'VctlD: "{n}" is vd={i} & vf_7_7=1 {{ export {n}; }}')
        if i < 3:
            src = ['pfxS', 'pfxT', 'pfxD'][i]
            w(f'VctlDr: "{n}" is vd={i} & vf_7_7=1 & {src} {{ export {src}; }}')
            w(f'VctlS: "{n}" is vs={i} & vf_15_15=1 & {src} {{ export {src}; }}')
        elif n == 'REV':
            # VFPU revision register: reads 0x7772ceab (PPSSPP, black box)
            w(f'VctlDr: "{n}" is vd={i} & vf_7_7=1 {{ export 0x7772ceab:4; }}')
            w(f'VctlS: "{n}" is vs={i} & vf_15_15=1 {{ export 0x7772ceab:4; }}')
        else:
            w(f'VctlDr: "{n}" is vd={i} & vf_7_7=1 {{ export {n}; }}')
            w(f'VctlS: "{n}" is vs={i} & vf_15_15=1 {{ export {n}; }}')
    w('VctlD: "$"^num is vd & vf_7_7=1 [ num = vd + 128; ] { local z:4 = 0; export z; }')
    w('VctlDr: "$"^num is vd & vf_7_7=1 [ num = vd + 128; ] { local z:4 = 0; export z; }')
    w('VctlS: "$"^num is vs & vf_15_15=1 [ num = vs + 128; ] { local z:4 = 0; export z; }')
    for h in range(4):
        for l in range(32):
            f = l | (h << 5)
            v = ((l >> 2) & 7) * 16 + h * 4 + (l & 3)
            w(f'VmemS: "{vec_name(f, "s")}" is vm_l={l} & vms_h={h} {{ export V{v >> 4}{v & 15:X}; }}')
    for h in range(2):
        for l in range(32):
            w(f'VmemQ: "{vec_name(l | (h << 5), "q")}" is vm_l={l} & vmq_h={h} {{ }}')
    w('OFF_VBASE: voffset(base) is vsimmed & base [ voffset = vsimmed << 2; ] { tmp:4 = base + (vsimmed << 2); export tmp; }')
    w('')
    # prefix display subtables
    for i in range(4):
        sw = ['X', 'Y', 'Z', 'W']
        for x in range(4):
            for a in range(2):
                for c in range(2):
                    for ng in range(2):
                        if c:
                            v = ['0', '1', '2', '1/2', '3', '1/3', '1/4', '1/6'][x + 4 * a]
                            t = ('-' if ng else '') + v
                        else:
                            t = sw[x]
                            if a:
                                t = f'|{t}|'
                            if ng:
                                t = '-' + t
                        w(f'Vpfxst{i}: "{t}" is vpfxst_op{i}={x} & vpfxst_abs{i}={a} & vpfxst_cst{i}={c} & '
                          f'vpfxst_neg{i}={ng} {{ }}')
        for s, t in enumerate(['', '0:1', '', '-1:1']):
            w(f'Vpfxd{i}: "{t}" is vpfxd_op{i}={s} & vpfxd_mask{i}=0 {{ }}')
            w(f'Vpfxd{i}: "M" is vpfxd_op{i}={s} & vpfxd_mask{i}=1 {{ }}')
    w('# VPFXS / VPFXT / VPFXD: the prefix applies to the next instruction (context, noflow); the control')
    w('# registers SPFX / TPFX / DPFX are written as well')
    for nm, px, tb in (('vpfxs', 'pfs', 'SPFX'), ('vpfxt', 'pft', 'TPFX')):
        sets = []
        for i in range(4):
            sets += [f'{px}_x{i} = vpfxst_op{i} $xor {i}', f'{px}_a{i} = vpfxst_abs{i}',
                     f'{px}_c{i} = vpfxst_cst{i}', f'{px}_n{i} = vpfxst_neg{i}']
        # the other prefixes stay pending (a prefix applies to the next instruction that is not a prefix)
        other = 'pft' if px == 'pfs' else 'pfs'
        gl = []
        for i in range(4):
            gl += [f'globalset(inst_next, {q}_{k}{i})' for q in (px, other) for k in 'xacn']
            gl += [f'globalset(inst_next, pfd_{k}{i})' for k in 'sm']
        enc = [e for e in ENCODINGS if e[0] == nm][0]
        g.con(f'{nm} [Vpfxst0, Vpfxst1, Vpfxst2, Vpfxst3]',
              f'{constraint(enc[1], enc[2])} & Vpfxst0 & Vpfxst1 & Vpfxst2 & Vpfxst3 & immed & vf_16_23 & '
              + ' & '.join(f'vpfxst_{k}{i}' for i in range(4) for k in ('op', 'abs', 'cst', 'neg')) + ' '
              f'[ {"; ".join(sets + gl)}; ]',
              [f'{tb} = zext(vf_16_23:3 << 16) | immed;'])
    sets, gl = [], []
    for i in range(4):
        sets += [f'pfd_s{i} = vpfxd_op{i}', f'pfd_m{i} = vpfxd_mask{i}']
        gl += [f'globalset(inst_next, pfd_s{i})', f'globalset(inst_next, pfd_m{i})']
        gl += [f'globalset(inst_next, {q}_{k}{i})' for q in ('pfs', 'pft') for k in 'xacn']
    enc = [e for e in ENCODINGS if e[0] == 'vpfxd'][0]
    g.con('vpfxd [Vpfxd0, Vpfxd1, Vpfxd2, Vpfxd3]',
          f'{constraint(enc[1], enc[2])} & Vpfxd0 & Vpfxd1 & Vpfxd2 & Vpfxd3 & immed & '
          + ' & '.join(f'vpfxd_{k}{i}' for i in range(4) for k in ('op', 'mask')) + f' [ {"; ".join(sets + gl)}; ]',
          ['DPFX = zext(immed:2);'])
    w('')
    done = {'vpfxs', 'vpfxt', 'vpfxd'}
    for name, mask, val, kinds in ENCODINGS:
        if name in done:
            continue
        base, _, sz = name.partition('.')
        cons = constraint(mask, val)
        ds = ', '.join(disp(k) for k in kinds)
        dpat = ' & '.join(disp(k) for k in kinds if not disp(k).startswith('"'))
        pat = cons + (' & ' + dpat if dpat else '')
        if base in OPS or base in ('vzero', 'vone', 'vidt', 'vcst', 'vi2f', 'vrot', 'vcmovt', 'vcmovf',
                                   'vrndi', 'vrndf1', 'vrndf2', 'vwbn') and kinds and vec_kind(kinds[0]):
            g.vector_op(name, base, kinds, pat, ds)
        else:
            g.special(name, base, sz, kinds, pat, ds)
    return '\n'.join(g.out) + '\n'


def con(self, display, pattern, body):
    self.w(f':{display} is {pattern} {{')
    for b in body:
        self.w('    ' + b)
    self.w('}')
    self.w('')
    self.ctors += 1


Gen.con = con


def write_lanes(dsz, nd, lanes, pre=()):
    body = list(pre)
    for i in range(nd):
        body.append(f'vfpuR{i} = {lanes[i]};')
    for i in range(nd):
        body.append(f'build satD{i}; wD{dsz}{i} = satD{i};')
    return body


def h2f_stmts(h, out):
    """p-code: IEEE half in the low 16 bits of `h` -> float bits in `out` (denormals, Inf, NaN)."""
    return [f'{out}s:4 = ({h} >> 15) & 1; {out}e:4 = ({h} >> 10) & 0x1f; {out}m:4 = {h} & 0x3ff;',
            f'{out}d:4 = int2float({out}m) f* 0x33800000:4;',
            f'{out}d = {out}d | ({out}s << 31);',
            f'{out}:4 = ' + sel(f'{out}e == 0', f'{out}d',
                                sel(f'{out}e == 31', f'({out}s << 31) | 0x7f800000 | {out}m',
                                    f'({out}s << 31) | (({out}e + 112) << 23) | ({out}m << 13)')) + ';']


def f2h_stmts(x, out):
    """p-code: float bits `x` -> IEEE half, rounding to nearest even (overflow -> Inf, NaN kept, denormals)."""
    o = out
    return [f'{o}s:4 = ({x} >> 31) & 1; {o}e:4 = ({x} >> 23) & 0xff; {o}m:4 = {x} & 0x7fffff;',
            f'{o}h:4 = {o}e - 112;',
            f'{o}nn:4 = ({o}h << 10) | ({o}m >> 13); {o}r:4 = {o}m & 0x1fff;',
            f'{o}up:4 = zext(({o}r > 0x1000) || (({o}r == 0x1000) && (({o}nn & 1) == 1)));',
            f'{o}n:4 = {o}nn + {o}up;',
            f'{o}f:4 = {o}m | 0x800000; {o}sh:4 = 14 - {o}h; {o}dd:4 = {o}f >> {o}sh;',
            f'{o}rd:4 = {o}f & ((1 << {o}sh) - 1); {o}hf:4 = 1 << ({o}sh - 1);',
            f'{o}dup:4 = zext(({o}rd > {o}hf) || (({o}rd == {o}hf) && (({o}dd & 1) == 1)));',
            f'{o}dn:4 = {o}dd + {o}dup;',
            f'{o}:4 = ({o}s << 15) | ' + sel(
                f'{o}e == 255', f'0x7c00 | (zext({o}m != 0) * 0x200) | ({o}m >> 13)',
                sel(f'({o}h s>= 31) || (({o}h s> 0) && ({o}n >= 0x7c00))', '0x7c00',
                    sel(f'{o}h s> 0', f'{o}n', sel(f'{o}h s> -11', f'{o}dn', '0')))) + ';']


def vector_op(self, name, base, kinds, pat, ds):
    dkind = kinds[0]
    dsz = dkind[0]
    nd = SIZES[dsz]
    ssz = tsz = None
    for k in kinds[1:]:
        if vec_kind(k) and k.endswith('_vs'):
            ssz = k[0]
        if vec_kind(k) and k.endswith('_vt'):
            tsz = k[0]
    ns = SIZES[ssz] if ssz else 0
    nt = SIZES[tsz] if tsz else 0
    S = lambda i: f'rS{ssz}{i}'
    T = lambda i: f'rT{tsz}{i}'
    extra = [f'rS{ssz}{i}' for i in range(ns)] + [f'rT{tsz}{i}' for i in range(nt)]
    extra += [f'wD{dsz}{i}' for i in range(nd)] + [f'satD{i}' for i in range(nd)]
    pre = []
    if base in OPS and base not in ('vh2f', 'vf2h'):
        pre, lanes = OPS[base](nd, ns, S, T)
        if base == 'vi2f':
            extra.append('p2neg')
        if base.startswith('vf2i'):
            extra.append('p2pos')
    elif base == 'vh2f':
        lanes = []
        for i in range(nd):
            pre.append(f'hv{i}:4 = ({S(i // 2)} >> {16 * (i % 2)}) & 0xffff;')
            pre += h2f_stmts(f'hv{i}', f'hf{i}')
            lanes.append(f'hf{i}')
    elif base == 'vf2h':
        for i in range(ns):
            pre += f2h_stmts(S(i), f'hh{i}')
        lanes = [f'hh{2 * i} | (hh{2 * i + 1} << 16)' for i in range(nd)]
    elif base == 'vzero':
        lanes = [K(ZERO)] * nd
    elif base == 'vone':
        lanes = [K(ONE)] * nd
    elif base == 'vidt':
        pre = ['ix:4 = vms_h;' if nd == 4 else 'ix:4 = vms_h & 1;']
        pat += ' & vms_h'
        lanes = [sel(f'ix == {i}', K(ONE), K(ZERO)) for i in range(nd)]
    elif base == 'vcst':
        extra.append('Vcst')
        lanes = ['Vcst'] * nd
    elif base in ('vrndi', 'vrndf1', 'vrndf2'):
        op = {'vrndi': 'vfpuRandInt', 'vrndf1': 'vfpuRandFloat1', 'vrndf2': 'vfpuRandFloat2'}[base]
        lanes = [f'{op}()'] * nd
    elif base in ('vcmovt', 'vcmovf'):
        want = 1 if base == 'vcmovt' else 0
        pre = ['cb:4 = zext(VcmovCC);']
        lanes = []
        for i in range(nd):
            pre.append(f'kc{i}:4 = {sel("cb == 6", f"{i}:4", "cb")};')
            # condition code 7: never moves (PPSSPP, black box)
            pre.append(f'c{i}:1 = (cb != 7) && (((CC >> kc{i}) & 1) == {want});')
            lanes.append(sel(f'c{i}', S(i), f'wD{dsz}{i}'))
    elif base == 'vrot':
        pre = ['ang:4 = rSs0;', 'co:4 = vfpuCos(ang); si:4 = vfpuSin(ang);',
               'rc:4 = vf_16_17; rsn:4 = vf_18_19; rn:4 = vf_20_20;',
               'sn:4 = ' + sel('rn == 1', 'f- si', 'si') + ';']
        extra = [e for e in extra if not e.startswith('rSs')] + ['rSs0', 'vf_16_17', 'vf_18_19', 'vf_20_20']
        lanes = [sel(f'rc == {i}', 'co', sel(f'(rsn == {i}) || (rsn == rc)', 'sn', K(ZERO)))
                 for i in range(nd)]
        ds = ds.replace('Vrot', 'Vrot' + dsz)
        pat = pat.replace('Vrot', 'Vrot' + dsz)
    elif base == 'vwbn':
        lanes = ['vfpuWbn(rSs0, vwbnimm8:1)']
    else:
        raise KeyError(base)
    if base in ('vabs', 'vneg', 'vocp'):
        v = 'rSA' if base == 'vabs' else 'rSN'
        extra = [e.replace('rS', v) if e.startswith('rS') else e for e in extra]
    if base in NO_DPFX:
        # a VPFXD of the program does not apply (PPSSPP, black box)
        extra = [e for e in extra if not e.startswith('satD') and not e.startswith('wD')] + [f'gD{dsz}{i}' for i in range(nd)]
        body = list(pre) + [f'vfpuR{i} = {lanes[i]};' for i in range(nd)] + [f'gD{dsz}{i} = vfpuR{i};' for i in range(nd)]
    elif base in INT_RESULT:
        # integer results: the VPFXD saturation does not apply (PPSSPP, black box), the write mask does
        extra = [e for e in extra if not e.startswith('satD')]
        body = list(pre) + [f'wD{dsz}{i} = {lanes[i]};' for i in range(nd)] if nd == 1 else \
            list(pre) + [f'vfpuR{i} = {lanes[i]};' for i in range(nd)] + [f'wD{dsz}{i} = vfpuR{i};' for i in range(nd)]
    else:
        body = write_lanes(dsz, nd, lanes, pre)
    pat_full = pat + (' & ' + ' & '.join(dict.fromkeys(extra)) if extra else '')
    self.con(f'{name} {ds}'.rstrip(), pat_full, body)


def special(self, name, base, sz, kinds, pat, ds):
    w = self.w
    if base == 'vcmp':
        n = SIZES[sz]
        conds = ['FL', 'EQ', 'LT', 'LE', 'TR', 'NE', 'GE', 'GT', 'EZ', 'EN', 'EI', 'ES', 'NZ', 'NN', 'NI', 'NS']
        for c, cn in enumerate(conds):
            S = lambda i: f'rS{sz}{i}'
            T = lambda i: f'rT{sz}{i}'
            inf = '0x7f800000:4'
            ex = {
                'FL': lambda i: '0:1', 'TR': lambda i: '1:1',
                'EQ': lambda i: f'{S(i)} f== {T(i)}', 'LT': lambda i: f'{S(i)} f< {T(i)}',
                'LE': lambda i: f'{S(i)} f<= {T(i)}', 'NE': lambda i: f'{S(i)} f!= {T(i)}',
                'GE': lambda i: f'{S(i)} f>= {T(i)}', 'GT': lambda i: f'{S(i)} f> {T(i)}',
                'EZ': lambda i: f'{S(i)} f== 0:4', 'NZ': lambda i: f'{S(i)} f!= 0:4',
                'EN': lambda i: f'nan({S(i)})', 'NN': lambda i: f'!nan({S(i)})',
                'EI': lambda i: f'abs({S(i)}) f== {inf}', 'NI': lambda i: f'abs({S(i)}) f!= {inf}',
                'ES': lambda i: f'nan({S(i)}) || (abs({S(i)}) f== {inf})',
                'NS': lambda i: f'!(nan({S(i)}) || (abs({S(i)}) f== {inf}))',
            }[cn]
            # both register fields are shown for every condition, as psp-objdump does
            d = f'vcmp.{sz} "{cn}", vs_{sz}, vt_{sz}'
            used = ([f'rS{sz}{i}' for i in range(n)] if cn not in ('FL', 'TR') else []) + \
                   ([f'rT{sz}{i}' for i in range(n)] if c < 8 and cn not in ('FL', 'TR') else [])
            p = pat.replace(' & vcmp_' + sz, '') + f' & vf_0_3={c}' + (' & vs_' + sz if 'vs_' in d else '') + \
                (' & vt_' + sz if 'vt_' in d else '') + (' & ' + ' & '.join(used) if used else '')
            body = [f'b{i}:4 = zext({ex(i)});' for i in range(n)]
            body.append('any:4 = ' + ' | '.join(f'b{i}' for i in range(n)) + ';')
            body.append('all:4 = ' + ' & '.join(f'b{i}' for i in range(n)) + ';')
            lanes = ' | '.join(f'(b{i} << {i})' if i else 'b0' for i in range(n))
            keep = 0xffffffff & ~(((1 << n) - 1) | 0x30)
            body.append(f'CC = (CC & 0x{keep:x}) | {lanes} | (any << 4) | (all << 5);')
            self.con(d, p, body)
        return
    if base in ('vmmul', 'vtfm2', 'vtfm3', 'vtfm4', 'vhtfm2', 'vhtfm3', 'vhtfm4', 'vmscl', 'vmmov', 'vmidt',
                'vmzero', 'vmone'):
        n = SIZES[sz]
        D = lambda i, j: f'mD{sz}{i}{j}'
        Sm = lambda i, j: f'mS{sz}{i}{j}'
        body, extra = [], []
        if base in ('vmmul', 'vmscl', 'vmmov', 'vmidt', 'vmzero', 'vmone'):
            for i in range(n):
                for j in range(n):
                    if base == 'vmmul':
                        e = fsum([f'mX{sz}{i}{k} f* mT{sz}{k}{j}' for k in range(n)])
                        extra += [f'mX{sz}{i}{k}' for k in range(n)] + [f'mT{sz}{k}{j}' for k in range(n)]
                    elif base == 'vmscl':
                        e = f'{Sm(i, j)} f* rTs0'
                        extra += [Sm(i, j), 'rTs0']
                    elif base == 'vmmov':
                        e = Sm(i, j)
                        extra.append(Sm(i, j))
                    else:
                        e = K({'vmidt': ONE if i == j else ZERO, 'vmzero': ZERO, 'vmone': ONE}[base])
                    body.append(f'e{i}{j}:4 = {e};')
                    extra.append(D(i, j))
            for i in range(n):
                for j in range(n):
                    body.append(f'{D(i, j)} = e{i}{j};')
        else:
            # the matrix field is read transposed, as VMMUL's vs (PPSSPP, black box): d = X * t
            homog = base.startswith('vh')
            Xm = lambda i, j: f'mX{sz}{i}{j}'
            lanes = []
            for i in range(n):
                terms = [f'{Xm(i, j)} f* rT{sz}{j}' for j in range(n - (1 if homog else 0))]
                if homog:
                    terms.append(Xm(i, n - 1))
                lanes.append(fsum(terms))
                extra += [Xm(i, j) for j in range(n)] + [f'rT{sz}{j}' for j in range(n - (1 if homog else 0))]
            extra += [f'wD{sz}{i}' for i in range(n)] + [f'satD{i}' for i in range(n)]
            body = write_lanes(sz, n, lanes)
        self.con(f'{name} {ds}', pat + ' & ' + ' & '.join(dict.fromkeys(extra)), body)
        return
    simple = {
        'mfv': ['rt = sregD;'], 'mtv': ['sregD = rt;'],
        'mfvc': ['rt = VctlDr;'], 'mtvc': ['VctlD = rt;', 'CC = CC & 0x3f;'],
        'vmfvc': ['sregD = VctlS;'], 'vmtvc': ['VctlD = sregS;', 'CC = CC & 0x3f;'],
        'viim': ['iv:4 = sext(Viim); sregT = int2float(iv);'],
        'vrnds': ['vfpuRandSeed(sregS);'],
        'vnop': [], 'vflush': [], 'vsync': [], 'vsync2': [],
    }
    regs = {'mfv': 'sregD', 'mtv': 'sregD', 'vmfvc': 'sregD', 'vmtvc': 'sregS', 'viim': 'sregT', 'vrnds': 'sregS',
            'vfim': 'sregT'}
    if base in simple or base == 'vfim':
        body = simple.get(base, [])
        if base == 'vfim':
            body = ['hv:4 = zext(Vfim);'] + h2f_stmts('hv', 'hf') + ['sregT = hf;']
        p = pat + (f' & {regs[base]}' if base in regs else '')
        self.con(f'{name} {ds}'.rstrip(), p, body)
        return
    if base in ('bvf', 'bvfl', 'bvt', 'bvtl'):
        want = 0 if base.startswith('bvf') else 1
        likely = base.endswith('l')
        body = ['c:1 = ((CC >> vcc) & 1) == ' + str(want) + ';']
        if likely:
            body += ['if (!c) goto inst_next;', 'delayslot(1);', 'goto Rel16;']
        else:
            body += ['delayslot(1);', 'if (!c) goto inst_next;', 'goto Rel16;']
        self.con(f'{name} {ds}', pat, body)
        return
    if base in ('lv', 'sv'):
        if sz == 's':
            body = ['VmemS = *[ram]:4 OFF_VBASE;'] if base == 'lv' else ['*[ram]:4 OFF_VBASE = VmemS;']
            self.con(f'{name} {ds}', pat, body)
        else:
            body = ['a:4 = OFF_VBASE;']
            for j in range(4):
                body.append(f'qmem{j} = *[ram]:4 (a + {4 * j});' if base == 'lv' else f'*[ram]:4 (a + {4 * j}) = qmem{j};')
            self.con(f'{name} {ds}', pat + ' & ' + ' & '.join(f'qmem{j}' for j in range(4)), body)
        return
    if base in ('lvl', 'lvr', 'svl', 'svr'):
        body = ['a:4 = OFF_VBASE;', 'k:4 = (a >> 2) & 3;']
        for i in range(4):
            if base[2] == 'l':     # lanes 3 .. 3-k from addr downwards
                lane, addr = 3 - i, f'a - {4 * i}'
            else:                  # lanes 0 .. 3-k from addr upwards
                lane, addr = i, f'a + {4 * i}'
            op = f'qmem{lane} = *[ram]:4 ({addr});' if base[0] == 'l' else f'*[ram]:4 ({addr}) = qmem{lane};'
            if i:
                cond = f'k < {i}' if base[2] == 'l' else (f'k > {3 - i}' if i < 3 else 'k != 0')
                body.append(f'if ({cond}) goto <skip{i}>; {op} <skip{i}>')
            else:
                body.append(op)
        self.con(f'{name} {ds}', pat + ' & ' + ' & '.join(f'qmem{j}' for j in range(4)), body)
        return
    raise KeyError(name)


VfpuGen.vector_op = vector_op
VfpuGen.special = special
_old_lane_tables = VfpuGen.lane_tables


def lane_tables2(self):
    _old_lane_tables(self)
    w = self.w
    for fld, nm in (('vd', 'sregD'), ('vs', 'sregS'), ('vt', 'sregT')):
        e, _ = vec_lane_expr(fld, 's', '0')
        w(f'{nm}: off is {fld} [ off = {e}; ] {{ export *[register]:4 off; }}')
    for j in range(4):
        col = f'0x5000 + 4 * (((vm_l >> 2) $and 7) * 16 + {j} * 4 + (vm_l $and 3))'
        row = f'0x5000 + 4 * (((vm_l >> 2) $and 7) * 16 + (vm_l $and 3) * 4 + {j})'
        w(f'qmem{j}: off is vm_l & vmq_h=0 [ off = {col}; ] {{ export *[register]:4 off; }}')
        w(f'qmem{j}: off is vm_l & vmq_h=1 [ off = {row}; ] {{ export *[register]:4 off; }}')
    for sz in 'ptq':
        n = SIZES[sz]
        for code in range(32):
            ci, si, ng = code & 3, (code >> 2) & 3, code >> 4
            lanes = []
            for i in range(n):
                if i == ci:
                    lanes.append('C')
                elif i == si or si == ci:
                    lanes.append('-S' if ng else 'S')
                else:
                    lanes.append('0')
            w(f'Vrot{sz}: "[{",".join(lanes)}]" is vf_16_20={code} {{ }}')
    w('')


VfpuGen.lane_tables = lane_tables2


if __name__ == '__main__':
    sys.stdout.write({'fields': fields, 'vfpu': vfpu}[sys.argv[1]]())
