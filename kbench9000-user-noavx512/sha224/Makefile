objs := main.o sha224-hacl_scalar.o sha224-hacl_vec128.o sha224-hacl_vec256.o sha224-openssl.o sha224-openssl_c.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha224_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha224_bench.exe $(objs) -L ./../../libraries -lcrypto_no_asm_pre -lcrypto_asm

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
