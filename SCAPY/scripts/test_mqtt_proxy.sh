#!/bin/bash

DELAY=10
BROKER='192.168.1.101'
TOPIC='topic'
USER='jorge'
PASS='passwd'

for i in {001..050}
do
  sleep ${DELAY}
  mosquitto_pub -h ${BROKER} -t ${TOPIC} -u ${USER} -P ${PASS} -m "message${i}"
done
