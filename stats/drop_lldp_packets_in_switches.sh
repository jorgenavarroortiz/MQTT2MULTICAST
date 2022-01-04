#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

# Remove previous auxiliary files
rm aux*.txt 2> /dev/null

sudo ovs-vsctl show | grep Bridge | cut -d" " -f 6 | tr -d '"' > aux.txt
sort aux.txt > aux2.txt

while read switch; do
    echo "Drop LLDP packets in switch ${switch}"
    # Remove flows related to LLDP (e.g. to forward LLDP packets to CONTROLLER)
    sudo ovs-ofctl del-flows ${switch} dl_type=0x000088cc -OOpenFlow13
    # Add a flow to drop LLDP packets
    sudo ovs-ofctl add-flow ${switch} dl_type=0x000088cc,actions=drop -OOpenFlow13
done <aux2.txt

# Remove auxiliary files
rm aux*.txt 2> /dev/null

