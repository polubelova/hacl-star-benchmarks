#!/bin/bash
for file in $( ls data*.raw.best.txt )
do
    awk -F: 'FNR==NR{a[$1]=$2;next} {for (i in a)sub(i, a[i]);print}' paper-names ${file%} |
	awk '{ if (!($1 == "remove")) { print }}' |
	sed -e 's/ / \& /g; $!s/$/ \\\\/' > "${file%}.paper"
done
