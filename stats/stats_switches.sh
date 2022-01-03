#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

sudo ovs-vsctl show | grep Bridge | cut -d" " -f 6 | tr -d '"' > aux.txt
sort aux.txt > aux2.txt

while read switch; do
    packets=`sudo ovs-ofctl dump-flows ${switch} -OOpenFlow13 | grep n_packets | awk '{sub(/.*n_packets=/,X,$0);print $1}' | sed 's/,*$//g' | awk '{s+=$1} END {print s}'`
    if [[ $packets == "" ]]; then packets=0; fi
    echo "Switch ${switch}: ${packets} packets"
done <aux2.txt

rm aux.txt
rm aux2.txt
