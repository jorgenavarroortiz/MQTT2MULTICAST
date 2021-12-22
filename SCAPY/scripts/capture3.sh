touch $1.pcap
tshark -i h3-eth0 -w $1.pcap tcp port 1883
