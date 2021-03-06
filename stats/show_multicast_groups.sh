#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

# Remove previous auxiliary files
rm aux*.txt 2> /dev/null

# Get switches
sudo ovs-vsctl show | grep Bridge | cut -d" " -f 6 | tr -d '"' > aux.txt
sort aux.txt > aux2.txt

# Get multicast groups
while read switch; do
    sudo ovs-ofctl dump-flows ${switch} -OOpenFlow13 | grep group: | awk '{sub(/.*actions=group:/,X,$0);print $1}' | sed 's/,*$//g' >> aux3.txt
done <aux2.txt
   # Remove empty lines and duplicates
sed -i '/^$/d' aux3.txt
sort aux3.txt | uniq > aux4.txt

# Show groups
while read group; do
    echo "Multicast group ${group}:"
    while read switch; do

        packets=`sudo ovs-ofctl dump-flows ${switch} -OOpenFlow13 | grep group:${group} | awk '{sub(/.*n_packets=/,X,$0);print $1}' | sed 's/,*$//g' | awk '{s+=$1} END {print s}'`
        if [[ $packets != "" ]]; then 
            echo "   Switch ${switch} has a rule for this multicast group"
        fi

    done <aux2.txt
done <aux4.txt

# Remove auxiliary files
rm aux*.txt 2> /dev/null


