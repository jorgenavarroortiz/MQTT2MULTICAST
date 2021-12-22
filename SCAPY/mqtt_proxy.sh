#!/bin/bash

MQTTPORT=1883
IFACE="h1-eth0"

# To avoid accessibility problems (which avoids Scapy sniffing to work)
export NO_AT_BRIDGE=1

# To avoid TCP RST from kernel (since no application is listening to this port)
iptables -C OUTPUT -p tcp --sport ${MQTTPORT} --tcp-flags RST RST -j DROP
if [[ $? == 1 ]]; then
   iptables -A OUTPUT -p tcp --sport ${MQTTPORT} --tcp-flags RST RST -j DROP
fi

python3 ./mqtt_proxy.py -i h1-eth0 -t 1883 -u jorge -p passwd -F 192.168.1.100 -U 1883
