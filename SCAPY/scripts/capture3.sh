touch $1_h3.pcap
tshark -i h3-eth0 -w $1_h3.pcap tcp port 1883
