objs := main.o chacha20_hacl32.o chacha20_vec128.o chacha20_vec256.o chacha20_openssl.o chacha20_nacl.o chacha20.s chacha20_jazz.o chacha20_openssl_lib.o

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native

OPENSSL_HOME ?=../../openssl
chacha20_hacl.o: CFLAGS +=
chacha20_hacl32.o: CFLAGS +=
chacha20_vec128.o: CFLAGS +=
chacha20_vec256.o: CFLAGS +=
chacha20_jazz.o : CFLAGS +=
chacha20_jazz_asm.o: ASFLAGS +=
chacha20_openssl_lib.o: CFLAGS += -I $(OPENSSL_HOME)/include/crypto -I $(OPENSSL_HOME)/crypto
default: build

run: build
	sudo ./run.sh chacha20_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20_bench.exe $(objs) -lsodium  $(OPENSSL_HOME)/libcrypto.a -lpthread -ldl

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
