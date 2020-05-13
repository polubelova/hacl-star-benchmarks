objs := main.o blake2s-hacl_scalar.o blake2s-hacl_vec128.o blake2s-lossl.o blake2s-reference.o blake2s-libsodium.o

CFLAGS += -O3 -g -march=armv8-a+simd -mtune=native -I ~/openssl/include -L .

default: build

run: build
	sudo ./run.sh blake2s_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o blake2s_bench.exe $^ -L ./../../libraries -lossl_asm -lpthread -ldl

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
