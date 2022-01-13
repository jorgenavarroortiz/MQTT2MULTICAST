#!/bin/bash

DELAY=`cat /tmp/DELAY`
DELAY=${DELAY:0:-2} # Remove trailing ms
DELAY=`echo "4 * ${DELAY}" | bc -l | sed '/\./ s/\.\{0,1\}0\{1,\}$//'`
DELAY=`echo ${DELAY}ms`
echo "DELAY: ${DELAY}"

cd ~/MQTT2MULTICAST/SCAPY/scripts

echo "Starting packet capture on h2..."
./capture2.sh b${DELAY} &

# Wait until h3 has launched the subscriber
echo "Waiting for subscriber..."
until pids=$(pidof mosquitto_sub)
do   
    sleep 1
done

echo "Starting experiment..."
./test_mqtt_broker.sh

echo "Experiment has finished!"

echo "Stopping packet captures..."
./stop_captures.sh

echo "Processing packet captures..."
./process_pcap.sh b${DELAY} broker
