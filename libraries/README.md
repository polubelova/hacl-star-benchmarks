Required libraries
==================
- libsodium.a (compiled with `env CC=gcc-9 CFLAGS="-O3 -march=native -mtune=native" ./configure && make check`)
- libossl_asm.a
- libcrypto.a (compiled with the `no-asm` flag)


To get `libossl_no_asm.a`, one needs to run ./rename
