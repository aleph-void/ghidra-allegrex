"""Hand-computed p-code test cases for the Allegrex module (assembled by emu_tests.py, run by EmuCheck.java).

T(name, asm, init, expect): asm is a short sequence in GNU assembler syntax (.set noreorder: the instruction
after a branch is its delay slot); init / expect are comma-separated 'reg=hex' items (Ghidra register names;
VFPU single registers are V<m><r*4+c> for S<m><c><r>, e.g. S000 = V00, S001 = V04, S010 = V01) or
'm<size>:<addr>=hex' (little-endian memory). '@END@' is the address after the sequence, '@START@' its first
instruction, '@Lname@' the address of a local label Lname.

Every expectation is worked out by hand from the instruction descriptions (MIPS32 / Allegrex manuals for the
core, the semantics summarised in GHIDRA-RARE.md for the VFPU), never copied from the module's output. Names
starting with XFAIL_ carry a deliberately wrong expectation that must be reported as a failure.
"""

CASES = []


def T(name, asm, init='', expect=''):
    CASES.append((name, asm, init, expect))


D = 0x10f000   # scratch data inside the image (emu_tests.py pads the image past it)
F1, F2, F3, F4, F6, F8, F05, FM1 = (0x3f800000, 0x40000000, 0x40400000, 0x40800000, 0x40c00000, 0x41000000,
                                    0x3f000000, 0xbf800000)


def q(*w):
    v = 0
    for i, x in enumerate(w):
        v |= (x & 0xffffffff) << (32 * i)
    return f'{v:x}'


# ---- core ALU -------------------------------------------------------------------------------------------
T('addu', 'addu $2,$4,$5', 'a0=5,a1=7', 'v0=c')
T('subu_wraps', 'subu $2,$4,$5', 'a0=1,a1=2', 'v0=ffffffff')
T('slt_signed_sltu_unsigned', 'slt $2,$4,$5\nsltu $3,$4,$5', 'a0=ffffffff,a1=1', 'v0=1,v1=0')
T('max_min_signed', 'max $2,$4,$5\nmin $3,$4,$5', 'a0=fffffffb,a1=3', 'v0=3,v1=fffffffb')
T('clz_clo', 'clz $2,$4\nclo $3,$5', 'a0=10000,a1=ffff0000', 'v0=f,v1=10')
T('ext_field', 'ext $2,$4,4,8', 'a0=12345678', 'v0=67')
T('ins_field', 'ins $2,$4,8,4', 'a0=5,v0=ffffffff', 'v0=fffff5ff')
T('seb_seh', 'seb $2,$4\nseh $3,$5', 'a0=80,a1=8000', 'v0=ffffff80,v1=ffff8000')
T('wsbh_wsbw', 'wsbh $2,$4\nwsbw $3,$4', 'a0=11223344', 'v0=22114433,v1=44332211')
T('bitrev', 'bitrev $2,$4', 'a0=1', 'v0=80000000')
T('rotr_rotrv', 'rotr $2,$4,8\nrotrv $3,$4,$5', 'a0=12345678,a1=4', 'v0=78123456,v1=81234567')
T('mult_signed', 'mult $4,$5\nmflo $2\nmfhi $3', 'a0=fffffffe,a1=3', 'v0=fffffffa,v1=ffffffff')
T('multu_unsigned', 'multu $4,$5\nmflo $2\nmfhi $3', 'a0=ffffffff,a1=2', 'v0=fffffffe,v1=1')
T('madd_msub', 'madd $4,$5\nmflo $2\nmsub $4,$5\nmsub $4,$5\nmflo $3', 'a0=2,a1=3,lo=a,hi=0', 'v0=10,v1=4')
T('div_signed', 'div $0,$4,$5\nmflo $2\nmfhi $3', 'a0=fffffff9,a1=2', 'v0=fffffffd,v1=ffffffff')
T('divu_unsigned', 'divu $0,$4,$5\nmflo $2\nmfhi $3', 'a0=ffffffff,a1=2', 'v0=7fffffff,v1=1')
T('movz_movn', 'movz $2,$4,$5\nmovn $3,$4,$5', 'a0=1234,a1=0,v0=0,v1=99', 'v0=1234,v1=99')
# ---- loads and stores -------------------------------------------------------------------------------------
T('lwl_lwr_unaligned', 'lwr $2,0($4)\nlwl $2,3($4)', f'a0={D + 1:x},m8:{D:x}=8877665544332211', 'v0=55443322')
T('swl_swr_unaligned', 'swr $5,0($4)\nswl $5,3($4)', f'a0={D + 1:x},a1=aabbccdd,m8:{D:x}=0',
  f'm8:{D:x}=000000aabbccdd00')
T('lb_lbu_lh_extend', 'lb $2,0($4)\nlbu $3,0($4)\nlh $5,2($4)', f'a0={D:x},m4:{D:x}=80010080',
  'v0=ffffff80,v1=80,a1=ffff8001')
# ---- branches and delay slots -----------------------------------------------------------------------------
T('beq_delay_slot_runs', 'beq $4,$4,L1\naddiu $2,$0,1\naddiu $2,$0,2\nL1:', 'v0=0', 'v0=1')
T('bnel_not_taken_nullifies', 'bnel $4,$4,L1\naddiu $2,$0,1\nL1:', 'v0=0', 'v0=0')
T('bal_links', 'bal L1\nnop\nL1:', '', 'ra=@L1@')
T('jalr_rd_equals_rs', '.word 0x00802009   # jalr $4,$4 (psp-as refuses rd = rs)\nnop\nL0:\nnop\nL1:', 'a0=@L1@', 'a0=@L0@')
# ---- FPU ------------------------------------------------------------------------------------------------
T('add_s', 'add.s $f2,$f0,$f1', 'f0=3fc00000,f1=40100000', 'f2=40700000')
T('cvt_w_s_nearest_even', 'cvt.w.s $f2,$f0\ncvt.w.s $f3,$f1', 'f0=c0200000,f1=40600000,fcsr=0', 'f2=fffffffe,f3=4')
T('cvt_w_s_toward_zero', 'cvt.w.s $f2,$f0', 'f0=c02ccccd,fcsr=1', 'f2=fffffffe')
T('cvt_w_s_toward_minus_inf', 'cvt.w.s $f2,$f0', 'f0=c02ccccd,fcsr=3', 'f2=fffffffd')
T('round_w_s_ties_even', 'round.w.s $f2,$f0', 'f0=40200000', 'f2=2')
T('c_lt_s_bc1t', 'c.lt.s $f0,$f1\nbc1t L1\nnop\naddiu $2,$0,1\nL1:', f'f0={F1:x},f1={F2:x},v0=0', 'v0=0')
# ---- VFPU -----------------------------------------------------------------------------------------------
T('lv_q_vadd_q_sv_q', 'lv.q C000,0($4)\nvadd.q C010,C000,C000\nsv.q C010,16($4)',
  f'a0={D:x},m16:{D:x}=' + q(F1, F2, F3, F4), f'm16:{D + 16:x}=' + q(F2, F4, F6, F8))
T('vdot_q', 'vdot.q S100,C000,C000', 'V00=3f800000,V04=40000000,V08=40400000,V0C=40800000', 'V10=41f00000')
T('vcmp_lt_cc_bvt', 'vcmp.q LT,C000,C010\nbvt 4,L1\nnop\naddiu $2,$0,1\nL1:',
  f'V00={F1:x},V04={F2:x},V08={F3:x},V0C={F4:x},V01={F2:x},V05={F2:x},V09={F2:x},V0D={F2:x},CC=0,v0=0',
  'CC=11,v0=0')
T('mtv_mfv', 'mtv $4,S000\nmfv $2,S000', 'a0=12345678', 'V00=12345678,v0=12345678')
T('viim_vfim', 'viim.s S000,-3\nvfim.s S010,1.5', '', f'V00=c0400000,V01=3fc00000')
T('vcst_pi', 'vcst.s S000,VFPU_PI', '', 'V00=40490fdb')
T('vpfxs_negate_x', 'vpfxs -x,y,z,w\nvmov.q C010,C000', f'V00={F1:x},V04={F2:x},V08={F3:x},V0C={F4:x}',
  f'V01={FM1:x},V05={F2:x},V09={F3:x},V0D={F4:x}')
T('vpfxd_saturate', 'vpfxd [0:1],[0:1],[0:1],[0:1]\nvsub.q C010,C000,C100',
  f'V00={F1:x},V04={F2:x},V08={F3:x},V0C={F4:x},V10=0,V14=0,V18=0,V1C=0',
  f'V01={F1:x},V05={F1:x},V09={F1:x},V0D={F1:x}')
T('vpfxd_write_mask', 'vpfxd ,m,,\nvzero.q C010', f'V01={F1:x},V05={F1:x},V09={F1:x},V0D={F1:x}',
  f'V01=0,V05={F1:x},V09=0,V0D=0')
T('vi2f_scale', 'vi2f.s S000,S010,1', 'V01=3', 'V00=3fc00000')
T('vf2iz_truncates', 'vf2iz.s S000,S010,0', 'V01=c02ccccd', 'V00=fffffffe')
T('vmidt_q', 'vmidt.q M000', 'V01=12345678', f'V00={F1:x},V05={F1:x},V0A={F1:x},V0F={F1:x},V01=0,V04=0')
T('vmmul_identity', 'vmidt.q M000\nvmmul.q M200,M000,M100', f'V10={F2:x},V11={F3:x},V14=40a00000',
  f'V20={F2:x},V21={F3:x},V24=40a00000')
T('vtfm4_identity', 'vmidt.q M000\nvtfm4.q C110,M000,C100', f'V10={F1:x},V14={F2:x},V18={F3:x},V1C={F4:x}',
  f'V11={F1:x},V15={F2:x},V19={F3:x},V1D={F4:x}')
T('vfad_sum', 'vfad.q S100,C000', f'V00={F1:x},V04={F2:x},V08={F3:x},V0C={F4:x}', 'V10=41200000')
T('vsbn_scale', 'vsbn.s S000,S010,S020', f'V01={F3:x},V02=2', 'V00=40c00000')
T('lvl_q_lvr_q', 'lvl.q C000,8($4)\nlvr.q C010,8($4)', f'a0={D:x},m16:{D:x}=' + q(1, 2, 3, 4),
  'V0C=3,V08=2,V04=1,V01=3,V05=4')
# ---- the deliberately wrong expectation ---------------------------------------------------------------
T('XFAIL_addu_wrong_expectation', 'addu $2,$4,$5', 'a0=1,a1=2', 'v0=4')
