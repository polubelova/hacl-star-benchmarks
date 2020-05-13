objs := main.o chacha20-hacl_scalar.o chacha20-hacl_vec128.o chacha20-lossl.o chacha20-lossl_no_asm.o chacha20-libsodium.o 

CFLAGS += -O3 -g -march=armv8-a+simd -mtune=native -L .

OPENSSL_HOME ?=../../../openssl
chacha20-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh chacha20_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20_bench.exe $^ -L ./../../libraries -lossl_no_asm -lossl_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
