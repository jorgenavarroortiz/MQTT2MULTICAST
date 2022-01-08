touch $1_h2.pcap
tshark -i h2-eth0 -w $1_h2.pcap tcp port 1883
