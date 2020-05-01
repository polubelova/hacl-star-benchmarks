	.file	"rq_round3.c"
	.text
	.p2align 4
	.globl	crypto_kem_sntrup4591761_avx_rq_round3
	.type	crypto_kem_sntrup4591761_avx_rq_round3, @function
crypto_kem_sntrup4591761_avx_rq_round3:
.LFB5289:
	.cfi_startproc
	vmovdqa	.LC0(%rip), %ymm2
	xorl	%eax, %eax
	.p2align 4,,10
	.p2align 3
.L2:
	vpmulhrsw	(%rsi,%rax), %ymm2, %ymm1
	vpaddw	%ymm1, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, (%rdi,%rax)
	addq	$32, %rax
	cmpq	$1536, %rax
	jne	.L2
	vzeroupper
	ret
	.cfi_endproc
.LFE5289:
	.size	crypto_kem_sntrup4591761_avx_rq_round3, .-crypto_kem_sntrup4591761_avx_rq_round3
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC0:
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.value	10923
	.ident	"GCC: (GNU) 9.2.1 20190827 (Red Hat 9.2.1-1)"
	.section	.note.GNU-stack,"",@progbits