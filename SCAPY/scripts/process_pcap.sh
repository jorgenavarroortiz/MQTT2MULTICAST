#!/bin/bash
FIRSTPCAPFILE=${1}_h2.pcap
SECONDPCAPFILE=${1}_h3.pcap
CSVFILE=${1}.csv

TYPE=$2

BROKER="192.168.1.104"
PUBLISHER="192.168.1.102"
SUBSCRIBER="192.168.1.103"

tshark -r ${FIRSTPCAPFILE} -T fields -E separator=";" -Y "tcp" -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.len -e _ws.col.Info -e mqtt.msg > ${CSVFILE}
tshark -r ${SECONDPCAPFILE} -T fields -E separator=";" -Y "tcp" -e frame.number -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e frame.len -e _ws.col.Info -e mqtt.msg >> ${CSVFILE}

rm $1.log 2> /dev/null

for i in {001..050}
do
  if [[ $TYPE == "broker" ]]; then
    # Publish message sent by publisher
    publisherPort=`cat ${CSVFILE} | grep Publish | grep message${i} | grep "${PUBLISHER};${BROKER}" | cut -d";" -f 5`
      # Format 12:28:28.563678266
    timePublisher=`cat ${CSVFILE} | grep "SYN]" | grep "${publisherPort};1883;" | cut -d";" -f 2 | cut -d" " -f 4`
#    echo "timePublisher: ${timePublisher}"
    timePublisherHour=`echo $timePublisher | cut -d":" -f 1`
    timePublisherMinute=`echo $timePublisher | cut -d":" -f 2`
    timePublisherSecond=`echo $timePublisher | cut -d":" -f 3`

    # Publish message received by subscriber
    timeSubscriber=`cat ${CSVFILE} | grep Publish | grep message${i} | grep "${BROKER};${SUBSCRIBER}" | cut -d";" -f 2 | cut -d" " -f 4`
#    echo "timeSubscriber: ${timeSubscriber}"
    timeSubscriberHour=`echo $timeSubscriber | cut -d":" -f 1`
    timeSubscriberMinute=`echo $timeSubscriber | cut -d":" -f 2`
    timeSubscriberSecond=`echo $timeSubscriber | cut -d":" -f 3`

    # Time difference
    auxTP=`bc <<< 3600*$timePublisherHour+60*$timePublisherMinute+$timePublisherSecond`
    auxTS=`bc <<< 3600*$timeSubscriberHour+60*$timeSubscriberMinute+$timeSubscriberSecond`
    timeDiff=`bc <<< $auxTS-$auxTP | awk '{printf "%f", $0}'`
#    echo "auxTP: ${auxTP}"
#    echo "auxTS: ${auxTS}"
#    echo "timeDiff: ${timeDiff}"

    echo $timeDiff >> ${1}.log

  elif [[ $TYPE == "proxy" ]]; then
    #echo message$i
    cat $CSVFILE | grep Publish | grep message${i} > tmp.txt
    timeDiff=`awk 'BEGIN{prev=0.0} {split($4,a,":"); TIME=a[3]+a[2]*60+a[1]*3600; DIFF=TIME-prev; prev=DIFF;} END{printf("%f\n", DIFF)}' tmp.txt`

    echo $timeDiff >> ${1}.log

  else
    echo "Select proxy or broker as the second parameter. Exit."
    exit
  fi
done

rm tmp.txt 2> /dev/null
