objs := main.o Hacl_Blake2s_32.c Hacl_Blake2s_128.c blake2s_nacl.c blake2s_openssl.c blake2s_ref.c

CC = gcc-9

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native
# blake2b_ref.o: CFLAGS += 
# blake2b_nacl.o: CFLAGS += 
Hacl_Blake2s_32.o: CFLAGS += 
Hacl_Blake2s_128.o: CFLAGS += 
# poly1305-hacl128.o: CFLAGS +=
# poly1305-hacl256.o: CFLAGS +=
# poly1305-hacl256_52.o: CFLAGS +=
# poly1305-hacl256_53.o: CFLAGS +=
# poly1305-hacl256_55.o: CFLAGS +=
# poly1305-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh blake2s_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o blake2s_bench.exe $(objs) -lsodium  -lssl -lcrypto -L/usr/local/lib 

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
