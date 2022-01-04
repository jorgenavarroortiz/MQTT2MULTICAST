#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

# Remove previous auxiliary files
rm aux*.txt 2> /dev/null

# Get switches
sudo ovs-vsctl show | grep Bridge | cut -d" " -f 6 | tr -d '"' > aux.txt
sort aux.txt > aux2.txt

# Get statistics per switch
totalPackets=0
while read switch; do
    packets=`sudo ovs-ofctl dump-flows ${switch} -OOpenFlow13 | grep n_packets | awk '{sub(/.*n_packets=/,X,$0);print $1}' | sed 's/,*$//g' | awk '{s+=$1} END {print s}'`
    lldppackets=`sudo ovs-ofctl dump-flows ${switch} -OOpenFlow13 | grep dl_type=0x88cc | grep n_packets | awk '{sub(/.*n_packets=/,X,$0);print $1}' | sed 's/,*$//g' | awk '{s+=$1} END {print s}'`
    if [[ $packets == "" ]]; then packets=0; fi
    if [[ $lldppackets == "" ]]; then lldppackets=0; fi
    packets=$(($packets - $lldppackets))
    echo "Switch ${switch}: ${packets} packets + ${lldppackets} LLDP packets"
    totalPackets=$(($totalPackets + $packets))
    totalLLDPPackets=$(($totalLLDPPackets + $lldppackets))
done <aux2.txt
echo "Total: ${totalPackets} packets + ${totalLLDPPackets} LLDP packets"

# Remove auxiliary files
rm aux*.txt 2> /dev/null

