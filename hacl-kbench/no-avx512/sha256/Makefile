objs := main.o sha256-hacl_scalar.o sha256-hacl_vec128.o sha256-hacl_vec256.o Hacl_SHA2_Scalar32.o sha256-hacl_ccomp.o

CFLAGS += -O3 -march=native -mtune=native

default: build

run: build
	sudo ./run.sh sha2_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o sha2_bench.exe $(objs)

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
