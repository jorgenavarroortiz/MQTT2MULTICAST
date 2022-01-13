#!/bin/bash

DELAY=`cat /tmp/DELAY`
DELAY=${DELAY:0:-2} # Remove trailing ms
DELAY=`echo "4 * ${DELAY}" | bc -l | sed '/\./ s/\.\{0,1\}0\{1,\}$//'`
DELAY=`echo ${DELAY}ms`
echo "DELAY: ${DELAY}"

cd /home/jorge/MQTT2MULTICAST/SCAPY/scripts

echo "Starting packet capture..."
./capture3.sh p$DELAY &

sleep 1

echo "Subscribing to topic..."
./subscribe2.sh &
