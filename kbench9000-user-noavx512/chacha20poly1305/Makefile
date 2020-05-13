objs := main.o chacha20poly1305-openssl.o chacha20poly1305-jasmin_avx2.o

CFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh chacha20poly1305_bench.exe

libjc/libjc_avx2.a:
	make -C libjc/

build: $(objs) libjc/libjc_avx2.a
	$(CC) $(CFLAGS) -o chacha20poly1305_bench.exe $^ -L ./../../libraries -lcrypto_asm -lpthread -ldl

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
