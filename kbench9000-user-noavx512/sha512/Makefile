objs := main.o sha512-hacl_scalar.o sha512-hacl_vec256.o sha512-openssl.o sha512-openssl_c.o sha512-libsodium.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha512_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha512_bench.exe $^ -L ./../../libraries -lcrypto_no_asm_pre -lcrypto_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
