BENCH_HOME ?= /home/mpolubel/work/hacl-star-benchmarks
LIB_HOME = $(BENCH_HOME)/libraries
RES_HOME ?= $(BENCH_HOME)/240820/xps13-hacl

SUPERCOP_HOME = $(BENCH_HOME)/supercop-20200417
DATA_HOME ?= $(SUPERCOP_HOME)/bench/pl28pro

SNAPSHOT_HOME = $(BENCH_HOME)/hacl-snapshot-ccomp
CC_CCOMP ?= ccomp
CFLAGS_CCOMP ?= -O3 -S -fstruct-passing -D_BSD_SOURCE -D_DEFAULT_SOURCE -DKRML_VERIFIED_UINT128 \
	-I $(SNAPSHOT_HOME) -I $(SNAPSHOT_HOME)/kremlin/include/ -I $(SNAPSHOT_HOME)/kremlin/kremlib/dist/minimal/


#run as "make -i supercop"
supercop: refresh-libs-supercop do-init do-blake2b do-blake2s do-sha256 do-sha512 print-best
#refresh-libs-supercop do-init do-chacha20 do-poly1305 do-blake2b do-blake2s do-sha256 do-sha512 print-best

kbench-no-avx512:
	cd $(LIB_HOME) && ./print-no-avx512 && \
	cp $(LIB_HOME)/results-no-avx512.txt $(RES_HOME)/results-no-avx512.txt

kbench-avx512:
	cd $(LIB_HOME) && ./print-avx512 && \
	cp $(LIB_HOME)/results-avx512.txt $(RES_HOME)/results-avx512.txt

refresh-libs-supercop:
	cp $(LIB_HOME)/libcrypto_no_asm.a $(SUPERCOP_HOME)/crypto_hash/sha224/openssl-new/no-asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_no_asm.a $(SUPERCOP_HOME)/crypto_hash/sha256/openssl-new/no-asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_no_asm.a $(SUPERCOP_HOME)/crypto_hash/sha384/openssl-new/no-asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_no_asm.a $(SUPERCOP_HOME)/crypto_hash/sha512/openssl-new/no-asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_no_asm.a $(SUPERCOP_HOME)/crypto_onetimeauth/poly1305/openssl/no_asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_no_asm.a $(SUPERCOP_HOME)/crypto_stream/chacha20/openssl/no_asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_asm.a $(SUPERCOP_HOME)/crypto_hash/sha224/openssl-new/asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_asm.a $(SUPERCOP_HOME)/crypto_hash/sha256/openssl-new/asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_asm.a $(SUPERCOP_HOME)/crypto_hash/sha384/openssl-new/asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_asm.a $(SUPERCOP_HOME)/crypto_hash/sha512/openssl-new/asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_asm.a $(SUPERCOP_HOME)/crypto_onetimeauth/poly1305/openssl/asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto_asm.a $(SUPERCOP_HOME)/crypto_stream/chacha20/openssl/asm/libcrypto.a

refresh-ccomp-supercop:
	cd $(SNAPSHOT_HOME) && \
	$(CC_CCOMP) $(CFLAGS_CCOMP) Hacl_Chacha20_Vec32.c && \
	$(CC_CCOMP) $(CFLAGS_CCOMP) Hacl_Poly1305_32.c && \
	$(CC_CCOMP) $(CFLAGS_CCOMP) Hacl_Blake2b_32.c && \
	$(CC_CCOMP) $(CFLAGS_CCOMP) Hacl_Blake2s_32.c && \
	$(CC_CCOMP) $(CFLAGS_CCOMP) Hacl_SHA2_Scalar32.c && \
	cp $(SNAPSHOT_HOME)/Hacl_Chacha20_Vec32.s $(SUPERCOP_HOME)/crypto_stream/chacha20/hacl_star/ccomp_O3/Hacl_Chacha20_Vec32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_Poly1305_32.s $(SUPERCOP_HOME)/crypto_onetimeauth/poly1305/hacl_star/ccomp_O3/Hacl_Poly1305_32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_Blake2b_32.s $(SUPERCOP_HOME)/crypto_hash/blake2b/hacl_star/ccomp_O3/Hacl_Blake2b_32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_Blake2s_32.s $(SUPERCOP_HOME)/crypto_hash/blake2s/hacl_star/ccomp_O3/Hacl_Blake2s_32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_SHA2_Scalar32.s $(SUPERCOP_HOME)/crypto_hash/sha224/hacl_star/ccomp_O3/Hacl_SHA2_Scalar32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_SHA2_Scalar32.s $(SUPERCOP_HOME)/crypto_hash/sha256/hacl_star/ccomp_O3/Hacl_SHA2_Scalar32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_SHA2_Scalar32.s $(SUPERCOP_HOME)/crypto_hash/sha384/hacl_star/ccomp_O3/Hacl_SHA2_Scalar32.s && \
	cp $(SNAPSHOT_HOME)/Hacl_SHA2_Scalar32.s $(SUPERCOP_HOME)/crypto_hash/sha512/hacl_star/ccomp_O3/Hacl_SHA2_Scalar32.s

do-init:
	cd $(SUPERCOP_HOME) && ./do-part init

do-verify:
	cd $(SUPERCOP_HOME) && ./do-part crypto_verify 16

do-chacha20:
	cd $(SUPERCOP_HOME) && ./do-part crypto_stream chacha20 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-chacha20.raw

do-poly1305:
	cd $(SUPERCOP_HOME) && \
	./do-part crypto_onetimeauth poly1305 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-poly1305.raw

do-blake2b:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash blake2b && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-blake2b.raw

do-blake2s:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash blake2s && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-blake2s.raw

do-sha224:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash sha224 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-sha224.raw

do-sha256:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash sha256 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-sha256.raw

do-sha384:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash sha384 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-sha384.raw

do-sha512:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash sha512 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-sha512.raw

print-best:
	cp $(LIB_HOME)/print-best.sh $(RES_HOME)/print-best.sh && \
	cd $(RES_HOME) && ./print-best.sh

print-paper:
	cp $(LIB_HOME)/print-best.sh $(RES_HOME)/print-best.sh && \
	cp $(LIB_HOME)/paper-names $(RES_HOME)/paper-names && \
	cp $(LIB_HOME)/print-paper.sh $(RES_HOME)/print-paper.sh && \
	cd $(RES_HOME) && ./print-best.sh && ./print-paper.sh

print-paper-avx512:
	cp $(LIB_HOME)/print-best.sh $(RES_HOME)/print-best.sh && \
	cp $(LIB_HOME)/paper-names-avx512 $(RES_HOME)/paper-names-avx512 && \
	cp $(LIB_HOME)/print-paper-avx512.sh $(RES_HOME)/print-paper-avx512.sh && \
	cd $(RES_HOME) && ./print-best.sh && ./print-paper-avx512.sh

print-paper-arm:
	cp $(LIB_HOME)/print-best.sh $(RES_HOME)/print-best.sh && \
	cp $(LIB_HOME)/paper-names-arm $(RES_HOME)/paper-names-arm && \
	cp $(LIB_HOME)/print-paper-arm.sh $(RES_HOME)/print-paper-arm.sh && \
	cd $(RES_HOME) && ./print-best.sh && ./print-paper-arm.sh
