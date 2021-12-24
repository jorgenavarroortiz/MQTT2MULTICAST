#!/bin/bash

USERNAME="jorge"
PASSWORD="passwd"
MQTTPORT=1883
UDPPORT=1883
#FORWARDER="192.168.1.101"
FORWARDER="192.168.1.104" # This host
MQTT2MULTICAST_IP_ADDR_SERVER="192.168.1.100"
MQTT2MULTICAST_UDP_PORT_SERVER=11883
MQTT2MULTICAST_UDP_PORT_CLIENT=11882

# To avoid accessibility problems (which avoids Scapy sniffing to work)
#export NO_AT_BRIDGE=1

# To avoid TCP RST from kernel (since no application is listening to this port)
iptables -C OUTPUT -p tcp --sport ${MQTTPORT} --tcp-flags RST RST -j DROP
if [[ $? == 1 ]]; then
   iptables -A OUTPUT -p tcp --sport ${MQTTPORT} --tcp-flags RST RST -j DROP
fi

# To avoid this host generating ICMP destination unreachable messages (since no application is listening to UDP packets on this port)
iptables -C OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
if [[ $? == 1 ]]; then
   iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
fi

# Execute Python MQTT proxy program
python3 ./mqtt_proxy_m2m.py -t ${MQTTPORT} -u ${USERNAME} -p ${PASSWORD} -F ${FORWARDER} -U ${UDPPORT} -s ${MQTT2MULTICAST_IP_ADDR_SERVER} -S ${MQTT2MULTICAST_UDP_PORT_SERVER} -C ${MQTT2MULTICAST_UDP_PORT_CLIENT}
#python3 ./mqtt_proxy_m2m.py -t ${MQTTPORT} -u ${USERNAME} -p ${PASSWORD} -F ${FORWARDER} -s ${MQTT2MULTICAST_IP_ADDR_SERVER} -S ${MQTT2MULTICAST_UDP_PORT_SERVER} -C ${MQTT2MULTICAST_UDP_PORT_CLIENT}
