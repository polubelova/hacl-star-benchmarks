We use the SUPERCOP benchmarking to compare HACL* with assembly and C implementations.

```
./do-part init
./do-part crypto_stream chacha20

 ./do-part crypto_verify 16
 ./do-part crypto_onetimeauth poly1305
```
