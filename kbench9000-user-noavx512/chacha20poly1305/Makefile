objs := main.o chacha20poly1305-lossl.o 

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native

chacha20poly1305-lossl.o: CFLAGS += -I $(OPENSSL_HOME)/include -I $(OPENSSL_HOME)/include/crypto -I $(OPENSSL_HOME)/crypto

default: build

run: build
	sudo ./run.sh chacha20poly1305_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20poly1305_bench.exe $(objs) -lcrypto  -L/usr/local/lib  #-L . -lossl_no_asm -lossl_asm

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
