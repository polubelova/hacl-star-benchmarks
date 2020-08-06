objs := main.o sha512-hacl_scalar.o sha512-hacl_vec256.o sha512-hacl_vec512.o sha512-hacl_ccomp.o Hacl_SHA2_Scalar32.o

CFLAGS += -O3 -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha512_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha512_bench.exe $^

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
