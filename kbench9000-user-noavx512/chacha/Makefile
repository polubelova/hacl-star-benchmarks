objs := main.o chacha20-hacl_scalar.o chacha20-hacl_vec128.o chacha20-hacl_vec256.o chacha20-lossl.o chacha20-lossl_no_asm.o chacha20-libsodium.o chacha20-jazz256-asm.o chacha20-jazz256.o

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native

OPENSSL_HOME ?=../../../openssl
chacha20-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh chacha20_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20_bench.exe $(objs) -L . -lossl_no_asm -lossl_asm -lsodium_local

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
