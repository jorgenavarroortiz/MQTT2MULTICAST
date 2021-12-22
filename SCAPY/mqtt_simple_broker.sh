#!/bin/bash

USERNAME="jorge"
PASSWORD="passwd"
MQTTPORT=1883
IFACE="h1-eth0"

# To avoid accessibility problems (which avoids Scapy sniffing to work)
export NO_AT_BRIDGE=1

# To avoid TCP RST from kernel (since no application is listening to this port)
iptables -C OUTPUT -p tcp --sport ${MQTTPORT} --tcp-flags RST RST -j DROP
if [[ $? == 1 ]]; then
   iptables -A OUTPUT -p tcp --sport ${MQTTPORT} --tcp-flags RST RST -j DROP
fi

python3 ./mqtt_simple_broker.py -i ${IFACE} -t ${MQTTPORT} -u ${USERNAME} -p ${PASSWORD}
