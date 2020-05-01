objs := main.o chacha20_hacl.c chacha20_hacl32.c chacha20_vec128.c chacha20_vec256.c

CFLAGS += -O3 -g -march=native -mtune=native
ASFLAGS += -O3 -g -march=native -mtune=native

chacha20_hacl.o: CFLAGS += 
chacha20_hacl32.o: CFLAGS += 
chacha20_vec128.o: CFLAGS += 
chacha20_vec256.o: CFLAGS += 

default: build

run: build
	sudo ./run.sh chacha20_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20_bench.exe $(objs)

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
