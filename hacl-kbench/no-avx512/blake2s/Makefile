objs := main.o blake2s-hacl_scalar.o blake2s-hacl_vec128.o Hacl_Blake2s_32.o blake2s-hacl_ccomp.o

CFLAGS += -O3 -march=native -mtune=native

default: build

run: build
	sudo ./run.sh blake2s_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o blake2s_bench.exe $^

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
