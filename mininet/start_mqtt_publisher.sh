#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2022

SERVER=$1
TIMEPERIOD=2

i=0
while [[ 1 ]]; do
    ts=$(date +%s%N)
    i=$(($i + 1))
    mosquitto_pub -h ${SERVER} -t "topic1" -u "jorge" -P "passwd" -m "message1" 2> /dev/null 1> /dev/null
    executionTime=$((($(date +%s%N) - $ts)/1000000))
    timeToSleep=`echo "scale=3; (1000*${TIMEPERIOD} - ${executionTime}) / 1000" | bc`
#    echo "executionTime: ${executionTime}"
#    echo "timeToSleep:   ${timeToSleep}"
    echo "MQTT publish message ${i}..."
    sleep ${timeToSleep}
done
