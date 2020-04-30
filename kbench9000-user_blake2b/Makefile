objs := main.o blake2b_hacl.c

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native
poly1305-hacl128.o: CFLAGS +=
poly1305-hacl256.o: CFLAGS +=
poly1305-hacl256_52.o: CFLAGS +=
poly1305-hacl256_53.o: CFLAGS +=
poly1305-hacl256_55.o: CFLAGS +=
poly1305-jazz256-asm.o: ASFLAGS =

default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $(objs)

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
