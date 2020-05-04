#!/bin/bash

for file in $( ls data*.raw )
do
 egrep -o " ok [0-9]+ [0-9]+ [0-9]+ [^ ]+ [^_]+" "$file" |
 awk '{printf("%0.2f, %s  %s\n", ($2/16384), $5, $6)}' |
 sort -t, -k1 -k2  > "${file%}.short.txt"
done
