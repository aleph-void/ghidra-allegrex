# One instance of each core instruction form (assembled by run-tests.sh with psp-as for the every-constructor
# check: random words rarely hit the forms with several fixed fields).
	.set noreorder
	.set noat
	add $2,$3,$4; addu $2,$3,$4; addu $2,$0,$4; addu $2,$3,$0; addu $2,$0,$0; and $2,$3,$4; nor $2,$3,$4; or $2,$3,$4
	or $2,$0,$4; or $2,$3,$0; or $2,$0,$0; xor $2,$3,$4; sub $2,$3,$4; subu $2,$3,$4; slt $2,$3,$4; sltu $2,$3,$4
	sll $2,$3,4; sll $0,$0,0; srl $2,$3,4; sra $2,$3,4; sllv $2,$3,$4; srlv $2,$3,$4; srav $2,$3,$4; rotr $2,$3,4
	rotrv $2,$3,$4; clz $2,$3; clo $2,$3; max $2,$3,$4; min $2,$3,$4; movz $2,$3,$4; movn $2,$3,$4
	seb $2,$3; seh $2,$3; wsbh $2,$3; wsbw $2,$3; bitrev $2,$3; ext $2,$3,1,4; ins $2,$3,1,4
	mult $3,$4; multu $3,$4; div $0,$3,$4; divu $0,$3,$4; madd $3,$4; maddu $3,$4; msub $3,$4; msubu $3,$4
	mfhi $2; mflo $2; mthi $2; mtlo $2; mfic $2,$0; mtic $2,$0
	lb $2,4($3); lbu $2,4($3); lh $2,4($3); lhu $2,4($3); lw $2,4($3); lwl $2,4($3); lwr $2,4($3); ll $2,4($3)
	sb $2,4($3); sh $2,4($3); sw $2,4($3); swl $2,4($3); swr $2,4($3); sc $2,4($3); cache 0x14,4($3)
	lwc1 $f2,4($3); swc1 $f2,4($3)
	j 0x100; jal 0x100; jr $2; jr $31; jalr $2; jalr $3,$2
	beq $2,$3,.+8; beq $0,$0,.+8; bne $2,$3,.+8; beql $2,$3,.+8; beql $0,$0,.+8; bnel $2,$3,.+8
	blez $2,.+8; bgtz $2,.+8; bltz $2,.+8; bgez $2,.+8; bgez $0,.+8; bltzal $2,.+8; bgezal $2,.+8; bgezal $0,.+8
	blezl $2,.+8; bgtzl $2,.+8; bltzl $2,.+8; bgezl $2,.+8; bltzall $2,.+8; bgezall $2,.+8
	syscall 0x1234; break 0x12; sync; eret; tlbp; tlbr; tlbwi; tlbwr; dbreak; dret; mfdr $2,$1; mtdr $2,$1
	mfc0 $2,$12; mtc0 $2,$12; cfc0 $2,$3; ctc0 $2,$3; bc0f .+8; bc0t .+8; bc0fl .+8; bc0tl .+8
	mfc1 $2,$f3; mtc1 $2,$f3; cfc1 $2,$31; ctc1 $2,$31; cfc1 $2,$5; ctc1 $2,$5
	bc1f .+8; bc1t .+8; bc1fl .+8; bc1tl .+8
	add.s $f1,$f2,$f3; sub.s $f1,$f2,$f3; mul.s $f1,$f2,$f3; div.s $f1,$f2,$f3; sqrt.s $f1,$f2; abs.s $f1,$f2
	mov.s $f1,$f2; neg.s $f1,$f2; round.w.s $f1,$f2; trunc.w.s $f1,$f2; ceil.w.s $f1,$f2; floor.w.s $f1,$f2
	cvt.s.w $f1,$f2; cvt.w.s $f1,$f2
	c.f.s $f1,$f2; c.un.s $f1,$f2; c.eq.s $f1,$f2; c.ueq.s $f1,$f2; c.olt.s $f1,$f2; c.ult.s $f1,$f2
	c.ole.s $f1,$f2; c.ule.s $f1,$f2; c.sf.s $f1,$f2; c.ngle.s $f1,$f2; c.seq.s $f1,$f2; c.ngl.s $f1,$f2
	c.lt.s $f1,$f2; c.nge.s $f1,$f2; c.le.s $f1,$f2; c.ngt.s $f1,$f2
	mfc2 $2,$3; mtc2 $2,$3; cfc2 $2,$3; ctc2 $2,$3
	.word 0x70000000    # halt
	.word 0x00000000    # nop
