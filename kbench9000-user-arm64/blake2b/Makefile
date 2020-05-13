objs := main.o blake2b-hacl_scalar.o blake2b-libsodium.o blake2b-lossl.o blake2b-reference.o

CFLAGS += -O3 -g -march=armv8-a+simd -mtune=native -I ~/openssl/include -L .

default: build

run: build
	sudo ./run.sh blake2b_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o blake2b_bench.exe $^ -L ./../../libraries -lossl_asm -lsodium -lpthread -ldl

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
