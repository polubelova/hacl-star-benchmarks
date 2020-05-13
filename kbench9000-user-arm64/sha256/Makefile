objs := main.o sha256-hacl_scalar.o sha256-hacl_vec128.o sha256-lossl.o sha256-lossl_no_asm.o sha256-libsodium.o

CFLAGS += -O3 -g -march=armv8-a+simd -mtune=native -L. 


default: build

run: build
	sudo ./run.sh sha2_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha2_bench.exe $(objs) -L ./../../libraries -lossl_no_asm -lossl_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
