#!/bin/bash
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada 2022

# Default value
DIRECTORY="/usr/local/quagga/etc"

#############################
# Parsing inputs parameters
#############################

usage() {
  echo "Usage: $0 [-d <directory>] -f <fanout level 1> -f <fanout level 2> ..." 1>&2;
  echo " E.g.: $0 -d /usr/local/quagga/etc -f 2 -f 3 -f 2";
  echo "       <directory> ......... directory to save quagga configuration files"
  echo "       <fanout level N> .... fanout of the tree topology on that level"
  echo "                             The last level are the hosts"
  exit 1;
}

f=0
while getopts ":d:f:" o; do
    case "${o}" in
        d)
            d=1
            DIRECTORY=${OPTARG}
            echo "DIRECTORY="$DIRECTORY
            ;;
        f)
            f=$(($f+1))
            FANOUT+=("$OPTARG")
            echo "FANOUT="$OPTARG
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${f}" ]; then
    usage
fi

# Check if it is executed as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "Saving configuration files to directory ${DIRECTORY}. Deleting previous configuration files..."

rm ${DIRECTORY}/zebra-R*.conf 2> /dev/null
rm ${DIRECTORY}/ripd-R*.conf 2> /dev/null
rm ${DIRECTORY}/pimd-R*.conf 2> /dev/null
rm ${DIRECTORY}/*.pid 2> /dev/null

routeNo=0
level=0
firstRouterInPreviousLevel=0
noRoutersInPreviousLevel=0
fanoutPreviousLevel=1
for val in "${FANOUT[@]}"; do
    if [[ $level == 0 ]]; then
        noRoutersInThisLevel=1
    else
        fanoutPreviousLevel=${FANOUT[$((level-1))]}
        noRoutersInThisLevel=$(($fanoutPreviousLevel * $noRoutersInPreviousLevel))
        #echo "noRoutersInThisLevel: ${noRoutersInThisLevel} (fanout=${fanoutPreviousLevel}, noRoutersInPreviousLevel=${noRoutersInPreviousLevel})"
    fi
    routerNoInThisLevel=0
    echo "# level: ${level}, noRoutersInThisLevel: ${noRoutersInThisLevel}"
    firstRouterInThisLevel=$(($routerNo+1))
    for i in $(seq 1 $noRoutersInThisLevel); do
        routerNo=$(($routerNo+1))
        routerNoInThisLevel=$(($routerNoInThisLevel+1)) 

        # Start of zebra configuration file
        echo "! -*- zebra -*-" > ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "hostname R${routerNo}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "password en" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "enable password en" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "interface lo" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "  ip address 127.0.0.1/32" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/zebra-R${routerNo}.conf

        # Start of ripd configuration file
        echo "! -*- rip -*-" > ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "! RIPd sample configuration file" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "! $Id: ripd.conf.sample,v 1.1 2002/12/13 20:15:30 paul Exp $" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "hostname R${routerNo}" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "password zebra" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "! debug rip events" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "! debug rip packet" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "router rip" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf

        # Start of pimd configuration file
        echo "! pimd" > ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "hostname R${routerNo}" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "password zebra" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "log file /tmp/pimd-R${routerNo}.log" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "line vty" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo " exec-timeout 60" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "ip multicast-routing" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf

        fanoutThisLevel=${FANOUT[$((level))]}
        noInterfaces=1
        previousRouter=0
        if [[ $level == 0 ]]; then
            previousRouter=0
            noInterfaces=$fanoutThisLevel
            echo "  # Router R${routerNo} (root) has ${noInterfaces} interfaces"
        elif [[ $level != $(($f-1)) ]]; then
            noInterfaces=$(($fanoutThisLevel + 1))
            previousRouter=$((($routerNoInThisLevel - 1) / $fanoutPreviousLevel + $firstRouterInPreviousLevel))
            echo "  # Router R${routerNo} (previous router R${previousRouter}) has ${noInterfaces} interfaces"
        else
            noInterfaces=2
            previousRouter=$((($routerNoInThisLevel - 1) / $fanoutPreviousLevel + $firstRouterInPreviousLevel))
            echo "  # Router R${routerNo} (previous router R${previousRouter}) has 2 interfaces"
        fi

        # Interface for upper level
        linkNo=$((($routerNoInThisLevel - 1)%fanoutPreviousLevel + 1))
        if [[ $level != 0 ]]; then
            #echo "routerNoInThisLevel: ${routerNoInThisLevel}, linkNo: ${linkNo}, firstRouterInPreviousLevel: ${firstRouterInPreviousLevel}, fanoutPreviousLevel: ${fanoutPreviousLevel}"
            intName="R${routerNo}-eth1"
            ipAddress="10.${previousRouter}.${linkNo}.2/24"
            echo "    # Interface $intName with IP address $ipAddress"

            # Interfaces in the zebra configuration file
            echo "interface ${intName}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
            echo "  ip address ${ipAddress}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
            echo "!" >> ${DIRECTORY}/zebra-R${routerNo}.conf

            # Interfaces in the ripd configuration file
            echo "network ${intName}" >> ${DIRECTORY}/ripd-R${routerNo}.conf
            echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf

            # Interfaces in the pimd configuration file
            echo "interface ${intName}" >> ${DIRECTORY}/pimd-R${routerNo}.conf
            echo "ip pim ssm" >> ${DIRECTORY}/pimd-R${routerNo}.conf
            echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf

        fi        

        # Interfaces for lower levels
        if [[ $level != $(($f-1)) ]]; then
            # Not the last level

            noDLInterfaces=$fanoutThisLevel
            for j in $(seq 1 $noDLInterfaces); do
                intName=""
                if [[ $level == 0 ]]; then
                    intName="R${routerNo}-eth${j}"
                else
                    intName="R${routerNo}-eth$(($j+1))"
                fi

                ipAddress="10.${routerNo}.${j}.1/24"
                echo "    # Interface $intName with IP address $ipAddress"

                # Interfaces in the zebra configuration file
                echo "interface ${intName}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
                echo "  ip address ${ipAddress}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
                echo "!" >> ${DIRECTORY}/zebra-R${routerNo}.conf

                # Interfaces in the ripd configuration file
                echo "network ${intName}" >> ${DIRECTORY}/ripd-R${routerNo}.conf
                echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf

                # Interfaces in the pimd configuration file
                echo "interface ${intName}" >> ${DIRECTORY}/pimd-R${routerNo}.conf
                echo "ip pim ssm" >> ${DIRECTORY}/pimd-R${routerNo}.conf
                #echo "level: ${level}, f: ${f}"
                echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf

            done
        else
            # Last level (router connected to one switch, so all hosts are in the same network and the router only has one interface towards that network)
            intName="R${routerNo}-eth2"
            # Last level of routers, using the same networks than the connected hosts in the mininet topology
            #ipAddress="192.168.$((($i-1)*$noDLInterfaces + $j)).1/24"
            ipAddress="192.168.${i}.1/24"
            echo "    # Interface $intName with IP address $ipAddress"

            # Interfaces in the zebra configuration file
            echo "interface ${intName}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
            echo "  ip address ${ipAddress}" >> ${DIRECTORY}/zebra-R${routerNo}.conf
            echo "!" >> ${DIRECTORY}/zebra-R${routerNo}.conf

            # Interfaces in the ripd configuration file
            echo "network ${intName}" >> ${DIRECTORY}/ripd-R${routerNo}.conf
            echo "!" >> ${DIRECTORY}/ripd-R${routerNo}.conf

            # Interfaces in the pimd configuration file
            echo "interface ${intName}" >> ${DIRECTORY}/pimd-R${routerNo}.conf
            echo "ip pim ssm" >> ${DIRECTORY}/pimd-R${routerNo}.conf
            # Last level of routers, activating IGMP in pimd configuration file
            echo "ip igmp" >> ${DIRECTORY}/pimd-R${routerNo}.conf
            echo "!" >> ${DIRECTORY}/pimd-R${routerNo}.conf
        fi

        # End of zebra configuration file
        echo "log file /tmp/zebra-R${routerNo}.log" >> ${DIRECTORY}/zebra-R${routerNo}.conf
        echo "" >> ${DIRECTORY}/zebra-R${routerNo}.conf

        # End of ripd configuration file
        echo "log file /tmp/ripd-R${routerNo}.log" >> ${DIRECTORY}/ripd-R${routerNo}.conf
        echo "" >> ${DIRECTORY}/ripd-R${routerNo}.conf

        # End of pimd configuration file
        echo "end" >> ${DIRECTORY}/pimd-R${routerNo}.conf

    done
   
    level=$(($level+1))
    noRoutersInPreviousLevel=$noRoutersInThisLevel
    firstRouterInPreviousLevel=$firstRouterInThisLevel
done

sudo chown quagga:quagga /usr/local/quagga/etc/*

