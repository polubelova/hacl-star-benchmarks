#!/bin/bash
for file in $( ls data*.raw )
do
 egrep -o " ok [0-9]+ [0-9]+ [0-9]+ [^ ]+ [^ ]+" "$file" |
     sort -n -k2 | awk '{gsub("_-march=native_-mtune=native_-Wno-discarded-qualifiers_-fomit-frame-pointer_-fwrapv_-fPIC", ""); gsub("_-march=native_-mtune=native_-fomit-frame-pointer_-fwrapv_-fPIC", ""); printf("%s %s %0.2f\n", $5, $6, ($2/16384))}' > "${file%}.txt"
done
