ifneq ($(KERNELRELEASE),)
kbench9000-y := main.o poly1305-hacl32x1.o poly1305-hacl128.o poly1305-hacl256.o poly1305-hacl512.o poly1305-hacl32.o poly1305-hacl64.o poly1305-ref.o poly1305-openssl-asm.o poly1305-openssl.o poly1305-donna32.o poly1305-donna64.o
obj-m := kbench9000.o
ccflags-y += -O3
CFLAGS_poly1305-hacl128.o += -mmmx -mavx2 -mavx -msse
CFLAGS_poly1305-hacl256.o += -mmmx -mavx2 -mavx -msse -std=gnu99
CFLAGS_poly1305-hacl512.o += -mmmx -mavx512f -mavx512cd -mavx512bw -mavx512dq -mavx512vl -mavx512ifma -mavx512vbmi -mavx2 -mavx -msse -std=gnu99
ccflags-y += -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default: build

run: build
	sudo ./run.sh
build:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
.PHONY: default run build clean
endif
