#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2022

SERVER=$1

mosquitto_sub -h ${SERVER} -t "topic1" -u "jorge" -P "passwd"
