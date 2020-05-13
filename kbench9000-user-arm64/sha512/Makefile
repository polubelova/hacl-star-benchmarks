objs := main.o sha512-hacl_scalar.o sha512-lossl.o sha512-lossl_no_asm.o sha512-libsodium.o

CFLAGS += -O3 -g -march=armv8-a+simd -mtune=native -L.

default: build

run: build
	sudo ./run.sh sha512_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha512_bench.exe $^ -L ./../../libraries -lossl_no_asm -lossl_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
