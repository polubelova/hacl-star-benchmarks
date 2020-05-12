objs := main.o poly1305-openssl.o poly1305-hacl_scalar.o poly1305-hacl_vec128.o poly1305-hacl_vec256.o poly1305-hacl_vec512.o poly1305-hacl256_52.o poly1305-hacl256_53.o poly1305-hacl256_55.o poly1305-ref.o poly1305-libsodium.o poly1305-jasmin_avx2-asm.o poly1305-jasmin_avx2.o poly1305-openssl.o poly1305-openssl_c.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $^ -L ./../../libraries -lcrypto_no_asm_pre -lcrypto_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
