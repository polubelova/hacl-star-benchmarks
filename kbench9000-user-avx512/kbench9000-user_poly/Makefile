objs := main.o poly1305-hacl32x1.o poly1305-openssl.c  poly1305-hacl128.o poly1305-hacl256.o Hacl_Poly1305_512.c poly1305-hacl256_52.o poly1305-hacl256_53.o poly1305-hacl256_55.o poly1305-hacl32.o poly1305-hacl64.o poly1305-ref.o poly1305-donna32.o poly1305-donna64.o poly1305-jazz256-asm.o poly1305-jazz256.o  poly1305-openssl_lib.o

OPENSSL_HOME ?=../../openssl
CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native
poly1305-hacl128.o: CFLAGS +=
poly1305-hacl256.o: CFLAGS +=
poly1305-hacl256_52.o: CFLAGS +=
poly1305-hacl256_53.o: CFLAGS +=
poly1305-hacl256_55.o: CFLAGS +=
poly1305-jazz256-asm.o: ASFLAGS =
poly1305-openssl_lib.o: CFLAGS += -I $(OPENSSL_HOME)/include/crypto -I $(OPENSSL_HOME)/crypto


default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $(objs)   -lpthread -ldl $(OPENSSL_HOME)/libcrypto.agi

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
