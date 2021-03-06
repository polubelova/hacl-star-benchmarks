#!/bin/bash
for file in $( ls data*.raw )
do
 egrep -o " ok [0-9]+ [0-9]+ [0-9]+ [^ ]+ [^ ]+" "$file" |
     sort -n -k2 | awk '{printf("%s %s %0.2f\n", $5, $6, ($2/16384))}' > "${file%}.txt"
done
