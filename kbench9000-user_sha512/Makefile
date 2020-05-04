objs := main.o Hacl_SHA2.c sha2_openssl.c hash_sha512_cp.c 

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native
# blake2b_hacl.o: CFLAGS +=
# blake2b_nacl.o: CFLAGS += 
# poly1305-hacl128.o: CFLAGS +=
# poly1305-hacl256.o: CFLAGS +=
# poly1305-hacl256_52.o: CFLAGS +=
# poly1305-hacl256_53.o: CFLAGS +=
# poly1305-hacl256_55.o: CFLAGS +=
# poly1305-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh sha512_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha512_bench.exe $(objs) -lsodium -lssl -lcrypto -L/usr/local/lib 

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
