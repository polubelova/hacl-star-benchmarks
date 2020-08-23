#!/bin/bash
for file in $( ls data*.raw )
do
 egrep -o " ok [0-9]+ [0-9]+ [0-9]+ [^ ]+ [^ ]+" "$file" |
     sort -n -k2 | awk '{gsub("-march=native_-mtune=native_-w", ""); printf("%s %s %0.2f\n", $5, $6, ($2/16384))}' > "${file%}.txt"
done
