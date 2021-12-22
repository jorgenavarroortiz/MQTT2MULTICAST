#!/bin/bash
FIRSTPCAPFILE=$1
SECONDPCAPFILE=$2
CSVFILE=$3

tshark -r ${FIRSTPCAPFILE} -T fields -E separator=";" -e frame.number -e frame.time -e ip.src -e ip.dst -e frame.len -e _ws.col.Info -e mqtt.msg > ${CSVFILE}
tshark -r ${SECONDPCAPFILE} -T fields -E separator=";" -e frame.number -e frame.time -e ip.src -e ip.dst -e frame.len -e _ws.col.Info -e mqtt.msg >> ${CSVFILE}

for i in {001..050}
do
#  echo message$i
  cat $CSVFILE | grep Publish | grep message${i} > tmp.txt
  awk 'BEGIN{prev=0.0} {split($4,a,":"); TIME=a[3]+a[2]*60+a[1]*3600; DIFF=TIME-prev; prev=DIFF;} END{printf("%f\n", DIFF)}' tmp.txt
done

rm tmp.txt
