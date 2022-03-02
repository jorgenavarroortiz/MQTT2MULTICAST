#!/bin/bash

# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2022

REPETITIONS=10
FILENAME="tree.log"

for i in 5 10 15 20 25 30 35 40 45 50; do
#   echo "fanout: ${i}"
   for j in $(seq 1 1 $REPETITIONS); do
#      echo "repetition: ${j}"
      python ./tree_scalability.py -f ${i} | tee -a ${FILENAME}
   done
done
