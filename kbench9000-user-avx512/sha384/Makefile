objs := main.o sha384-hacl_scalar.o sha384-hacl_vec256.o sha384-hacl_vec512.o sha384-openssl.o sha384-openssl_c.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha384_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha384_bench.exe $^ -L ./../../libraries -lcrypto_no_asm_pre -lcrypto_asm

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
