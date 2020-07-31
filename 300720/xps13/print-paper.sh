#!/bin/bash
for file in $( ls data*.raw )
do
 egrep -o " ok [0-9]+ [0-9]+ [0-9]+ [^ ]+ [^ ]+" "$file" |
     awk '{gsub("_-march=native_-mtune=native_-Wno-discarded-qualifiers_-fomit-frame-pointer_-fwrapv_-fPIC", ""); gsub("_-march=native_-mtune=native_-fomit-frame-pointer_-fwrapv_-fPIC", ""); printf("%s %s %0.2f\n", $5, $6, ($2/16384))}' |
     sort -k1,1 -k2 |
     awk '{a[$1]=a[$1]?a[$1]" "$3:$3;}END{for (i in a) print i, a[i];}' |
     sed -e 's/ / \& /g; $!s/$/ \\\\/' > "${file%}.paper"
done
