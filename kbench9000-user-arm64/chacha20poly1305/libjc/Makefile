.PHONY: clean libjc_avx2.a

SRC := \
src/crypto_stream/chacha20/avx2/chacha20.s \
src/crypto_onetimeauth/poly1305/avx2/poly1305.s

libjc_avx2.a: $(SRC)
	$(CC) -c $(SRC)
	ar -rc $@ *.o && ranlib $@
	objcopy --prefix-symbols=libjc_avx2_ $@
	rm *.o

clean:
	rm -f libjc_avx2.a *.o
