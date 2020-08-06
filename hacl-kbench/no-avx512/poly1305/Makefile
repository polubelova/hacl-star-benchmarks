objs := main.o poly1305-hacl_scalar.o poly1305-hacl_vec128.o poly1305-hacl_vec256.o Hacl_Poly1305_32.o poly1305-hacl_ccomp.o

CFLAGS += -O3 -march=native -mtune=native

default: build

run: build
	sudo ./run.sh poly-bench.exe

build: $(objs)
	$(CC) $(CFLAGS) -o poly-bench.exe $^

clean:
	rm -f *.o *~ *.exe

.PHONY: default run build clean
