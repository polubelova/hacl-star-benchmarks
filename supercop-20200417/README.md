We use the SUPERCOP benchmarking to compare HACL* with assembly and C implementations.

```
./do-part init
./do-part crypto_stream chacha20

./do-part crypto_verify 16
./do-part crypto_onetimeauth poly1305

./do-part crypto_hash blake2b
./do-part crypto_hash blake2s

./do-part crypto_hash sha256
./do-part crypto_hash sha512
```

Script to print a table.

```
#!/bin/bash

for file in $( ls data )
do
 egrep -o " ok [0-9]+ [0-9]+ [0-9]+ [^ ]+ [^_]+" "$file" |
 awk '{printf("%0.2f, %s  %s\n", ($2/16384), $5, $6)}' |
 sort -n  > "${file%}.csv"
done
```
