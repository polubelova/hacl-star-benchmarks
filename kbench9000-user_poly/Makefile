objs := main.o poly1305-openssl.c poly1305-hacl32x1.o poly1305-hacl128.o poly1305-hacl256.o poly1305-hacl512.o poly1305-hacl32.o poly1305-hacl64.o poly1305-ref.o poly1305-donna32.o poly1305-donna64.o

CFLAGS += -O3 -pg -march=native -mtune=native
ASFLAGS += -O3 -pg -march=native -mtune=native
poly1305-hacl128.o: CFLAGS +=
poly1305-hacl256.o: CFLAGS +=
poly1305-hacl512.o: CFLAGS += -mprefer-vector-width=512

default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $(objs)

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
