objs := main.o blake2b-hacl_scalar.o blake2b-hacl_vec256.o Hacl_Blake2b_32.o blake2b-hacl_ccomp.o

CFLAGS += -O3 -march=native -mtune=native

default: build

run: build
	sudo ./run.sh blake2b_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o blake2b_bench.exe $^

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
