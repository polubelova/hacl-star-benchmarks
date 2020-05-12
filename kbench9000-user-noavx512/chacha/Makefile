objs := main.o chacha20-hacl_scalar.o chacha20-hacl_vec128.o chacha20-hacl_vec256.o chacha20-openssl.o chacha20-openssl_c.o chacha20-libsodium.o chacha20-jasmin_avx2-asm.o chacha20-jasmin_avx2.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh chacha20_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20_bench.exe $^ -L ./../../libraries -lcrypto_asm -lcrypto_no_asm_pre -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
