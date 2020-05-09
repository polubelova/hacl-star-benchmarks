Required libraries
==================
- libsodium.a (compiled with `env CC=gcc-9 CFLAGS="-O3 -march=native -mtune=native" ./configure && make check`)
- libossl_asm.a
- libcrypto.a (compiled with the `no-asm` flag)


To get `libossl_no_asm.a`, one needs to run ./rename


INSTALL
=======

-libsodium
```
git clone https://github.com/jedisct1/libsodium --branch stable
env CC=gcc-9 CFLAGS="-O3 -march=native -mtune=native" ./configure && make check
```

-openssl
```
git clone https://github.com/openssl/openssl
./config && make
```

-openssl-no-asm
```
git clone https://github.com/openssl/openssl
./config no-asm && make
```


Example
======
```
cp /home/marina/libsodium/src/libsodium/.libs/libsodium.a libsodium.a
cp /home/marina/openssl/libcrypto.a libossl_asm.a
cp /home/marina/openssl-no-asm/openssl/libcrypto.a libcrypto.a
./rename
./print-avx512
```