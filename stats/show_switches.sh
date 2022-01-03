#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

sudo ovs-vsctl show | grep Bridge | cut -d" " -f 6 | tr -d '"'

