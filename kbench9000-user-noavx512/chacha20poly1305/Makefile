objs := main.o chacha20poly1305-lossl.o chacha20poly1305-jazz256.o

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native

default: build

run: build
	sudo ./run.sh chacha20poly1305_bench.exe

libjc/libjc_avx2.a:
	make -C libjc/

build: $(objs) libjc/libjc_avx2.a
	$(CC) $(CFLAGS) -o chacha20poly1305_bench.exe $^ -lcrypto  -L/usr/local/lib

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
