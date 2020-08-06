objs := main.o chacha20-hacl_scalar.o chacha20-hacl_vec128.o chacha20-hacl_vec256.o chacha20-hacl_vec512.o Hacl_Chacha20_Vec32.o chacha20-hacl_ccomp.o

CFLAGS += -O3 -march=native -mtune=native

default: build

run: build
	sudo ./run.sh chacha20_bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o chacha20_bench.exe $^

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
