objs := main.o sha512-hacl_scalar.o sha512-hacl_vec256.o sha512-hacl_vec512.o sha512-lossl.o sha512-lossl_no_asm.o sha512-libsodium.o

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha512_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha512_bench.exe $(objs) -lsodium -L . -lossl_no_asm -lossl_asm

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
