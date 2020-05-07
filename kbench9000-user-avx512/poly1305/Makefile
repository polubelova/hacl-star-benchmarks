objs := main.o poly1305-openssl.o poly1305-hacl_scalar.o poly1305-hacl_vec128.o poly1305-hacl_vec256.o poly1305-hacl_vec512.o poly1305-hacl256_52.o poly1305-hacl256_53.o poly1305-hacl256_55.o poly1305-ref.o poly1305-donna32.o poly1305-donna64.o poly1305-jazz256-asm.o poly1305-jazz256.o poly1305-lossl.o poly1305-lossl_no_asm.o

OPENSSL_HOME ?=../../../openssl
CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native
poly1305-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $(objs) -L . -lossl_no_asm -lossl_asm

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
