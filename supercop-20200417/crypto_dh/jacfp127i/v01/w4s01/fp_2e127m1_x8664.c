//Huseyin Hisil, 2012.

#include <stdio.h>
#include "_core.h"
#include "finite128.h"

void fp_inv_2e127m1_x8664(uni zn, void *NOPARAM1, void *NOPARAM2, uni an){
	TEMP_INV_FP_2e127m1_t t;

#ifdef GENERATED_ASM
	fp_inv_2e127m1_x8664_asm(t, NULL, NULL, zn, an);
#else
	fp_sqr_2e127m1_x8664_asm(t->n02, NULL, NULL, an);
	fp_mul_2e127m1_x8664_asm(t->n02, NULL, NULL, t->n02, an);
	fp_sqr_2e127m1_x8664_asm(t->n03, NULL, NULL, t->n02);
	fp_sqr_2e127m1_x8664_asm(t->n03, NULL, NULL, t->n03);
	fp_mul_2e127m1_x8664_asm(t->n03, NULL, NULL, t->n03, t->n02);
	fp_sqr_2e127m1_x8664_asm(t->n04, NULL, NULL, t->n03);
	fp_sqr_2e127m1_x8664_asm(t->n04, NULL, NULL, t->n04);
	fp_sqr_2e127m1_x8664_asm(t->n04, NULL, NULL, t->n04);
	fp_sqr_2e127m1_x8664_asm(t->n04, NULL, NULL, t->n04);
	fp_mul_2e127m1_x8664_asm(t->n04, NULL, NULL, t->n04, t->n03);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n04);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05);
	fp_mul_2e127m1_x8664_asm(t->n05, NULL, NULL, t->n05, t->n04);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06);
	fp_mul_2e127m1_x8664_asm(t->n06, NULL, NULL, t->n06, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01, t->n06);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01, t->n05);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01, t->n04);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01, t->n03);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01, an);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_sqr_2e127m1_x8664_asm(t->n01, NULL, NULL, t->n01);
	fp_mul_2e127m1_x8664_asm(zn, NULL, NULL, t->n01, an);
#endif
}

/*
void fp_sqt_2e127m1_x8664(uni zn, void *NOPARAM1, void *NOPARAM2, uni an){
#ifdef GENERATED_ASM
	fp_sqt_2e127m1_x8664_asm(NULL, NULL, NULL, zn, an);
#else
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, an);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
	fp_sqr_2e127m1_x8664_asm(zn, NULL, NULL, zn);
#endif
}
*/