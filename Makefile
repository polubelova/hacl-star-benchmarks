BENCH_HOME ?= /home/mpolubel/work/hacl-star-benchmarks
LIB_HOME = $(BENCH_HOME)/libraries
RES_HOME ?= $(BENCH_HOME)/100520

SUPERCOP_HOME = $(BENCH_HOME)/supercop-20200417
DATA_HOME ?= $(SUPERCOP_HOME)/bench/pl28pro

#run as "make -i supercop"
supercop: refresh-libs-supercop do-init do-blake2b do-blake2s do-sha256 do-sha512 print-best
#refresh-libs-supercop do-init do-chacha20 do-poly1305 do-blake2b do-blake2s do-sha256 do-sha512 print-best

refresh-libs-supercop:
	cp $(LIB_HOME)/libcrypto.a $(SUPERCOP_HOME)/crypto_hash/sha256/openssl-new/no-asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto.a $(SUPERCOP_HOME)/crypto_hash/sha512/openssl-new/no-asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto.a $(SUPERCOP_HOME)/crypto_onetimeauth/poly1305/openssl/no_asm/libcrypto.a && \
	cp $(LIB_HOME)/libcrypto.a $(SUPERCOP_HOME)/crypto_stream/chacha20/openssl/no_asm/libcrypto.a && \
	cp $(LIB_HOME)/libossl_asm.a $(SUPERCOP_HOME)/crypto_hash/sha256/openssl-new/asm/libcrypto.a && \
	cp $(LIB_HOME)/libossl_asm.a $(SUPERCOP_HOME)/crypto_hash/sha512/openssl-new/asm/libcrypto.a && \
	cp $(LIB_HOME)/libossl_asm.a $(SUPERCOP_HOME)/crypto_onetimeauth/poly1305/openssl/asm/libcrypto.a && \
	cp $(LIB_HOME)/libossl_asm.a $(SUPERCOP_HOME)/crypto_stream/chacha20/openssl/asm/libcrypto.a

do-init:
	cd $(SUPERCOP_HOME) && ./do-part init

do-chacha20:
	cd $(SUPERCOP_HOME) && ./do-part crypto_stream chacha20 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-chacha20.raw

do-poly1305:
	cd $(SUPERCOP_HOME) && \
	./do-part crypto_verify 16 && \
	./do-part crypto_onetimeauth poly1305 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-poly1305.raw

do-blake2b:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash blake2b && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-blake2b.raw

do-blake2s:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash blake2s && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-blake2s.raw

do-sha256:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash sha256 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-sha256.raw

do-sha512:
	cd $(SUPERCOP_HOME) && ./do-part crypto_hash sha512 && \
	cp $(DATA_HOME)/data $(RES_HOME)/data-sha512.raw

print-best:
	cp print-best.sh $(RES_HOME)/print-best.sh && \
	cd $(RES_HOME) && ./print-best.sh
