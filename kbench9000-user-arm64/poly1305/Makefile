objs := main.o poly1305-openssl.o poly1305-hacl_scalar.o poly1305-hacl_vec128.o poly1305-ref.o poly1305-libsodium.o poly1305-lossl.o poly1305-lossl_no_asm.o

OPENSSL_HOME ?=../../../openssl
CFLAGS += -O3 -g -march=armv8-a+simd -mtune=native -L .
poly1305-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $^ -L ./../../libraries -lossl_no_asm -lossl_asm -lsodium

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
