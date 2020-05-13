#!/bin/bash
set -e

nob_cpus() {
	echo "[+] Setting non-boot CPUs to status $1"
	for i in /sys/devices/system/cpu/*/online; do
		echo "$1" > "$i"
	done
}

noturbo() {
     for i in /sys/devices/system/cpu/cpu*/cpufreq; do
       echo userspace > $i/scaling_governor
       echo 1400000 > $i/scaling_setspeed
     done
}

trap "nob_cpus 1; noturbo 0;" INT TERM EXIT
noturbo 1
nob_cpus 0

./$1
