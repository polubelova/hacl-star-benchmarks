objs := main.o sha256-hacl_scalar.o sha256-hacl_vec128.o sha256-hacl_vec256.o sha256-openssl.o sha256-openssl_c.o sha256-libsodium.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha2_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha2_bench.exe $(objs) -L ./../../libraries -lcrypto_no_asm_pre -lcrypto_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
