#!/usr/bin/env python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, info, setLogLevel
from mininet.util import dumpNodeConnections, quietRun, moveIntf
from mininet.cli import CLI
from mininet.node import Switch, OVSKernelSwitch

from subprocess import Popen, PIPE, check_output
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

import sys
import os
#import termcolor as T
import time

PACKETCAPTURE=True

setLogLevel('info')

parser = ArgumentParser("Configure a network composed of routers in Mininet.")
parser.add_argument('--sleep', default=3, type=int)
args = parser.parse_args()

def log(s, col="green"):
#    print (T.colored(s, col))
    print (s)


class Router(Switch):
    """Defines a new router that is inside a network namespace so that the
    individual routing entries don't collide.   """
    ID = 0
    def __init__(self, name, **kwargs):
        kwargs['inNamespace'] = True
        Switch.__init__(self, name, **kwargs)
        Router.ID += 1    
        self.switch_id = Router.ID

    @staticmethod
    def setup():
        return

    def start(self, controllers):
        pass

    def stop(self):
        self.deleteIntfs()

    def log(self, s, col="magenta"):
#        print (T.colored(s, col))
        print (s)


class SimpleTopo(Topo):
    """The topology is a simple straight-line topology between R1 -- R2 -- R3.  R4 connects to R1 directly.

    """


    def __init__(self):

        # Add default members to class
        super(SimpleTopo, self ).__init__()
        num_host=5
        num_routers = 9
        routers = []
        for i in range(num_routers):
            router = self.addSwitch('R%d' % (i+1))
            routers.append(router)
            hosts = []
       
        for i in range(num_host):
            hostname = 'h%d' % (i+1)
            host = self.addNode(hostname)
            hosts.append(host)

        self.addLink('R1','h1')
        self.addLink('R6','h2')
        self.addLink('R7','h3')
        self.addLink('R8','h4')
        self.addLink('R9','h5')

        self.addLink('R1','R2')
        self.addLink('R1','R3')
        self.addLink('R1','R4')
        self.addLink('R1','R5')
        self.addLink('R2','R6')
        self.addLink('R3','R7')
        self.addLink('R4','R8')
        self.addLink('R5','R9')
       

        return

def main():

    os.system("rm -f /tmp/R*.log /tmp/R*.pid logs/*")
    os.system("mn -c >/dev/null 2>&1")
    os.system("killall -9 zebra ripd pimd tshark > /dev/null 2>&1")

    net = Mininet(topo=SimpleTopo(), switch=Router, controller=None)
    net.start()

    print ("*** Configure IP forwarding in routers")
    for router in net.switches:
        router.cmd("sysctl -w net.ipv4.ip_forward=1")
        router.waitOutput()

    # Disable IPv6
    print ("*** Disable IPv6 in hosts")
    for h in net.hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    print ("*** Disable IPv6 in routers")
    for router in net.switches:
        router.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        router.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        router.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

    log("Waiting %d seconds for sysctl changes to take effect..." % args.sleep)
    sleep(args.sleep)

    # Packet capture
    if PACKETCAPTURE:
        print ("*** Capture packet traces in all hosts and routers")
        for h in net.hosts:
            h.cmd("sudo tshark -i any -w /tmp/%s.pcap 2>&1 &" % (h.name))
        for router in net.switches:
            router.cmd("sudo tshark -i any -w /tmp/%s.pcap 2>&1 &" % (router.name))

    # Configure hosts IP addresses and default routes
    print ("*** Configure hosts IP addresses")
    net.hosts[0].cmd("ifconfig h1-eth0 10.0.0.1/24")
    net.hosts[1].cmd("ifconfig h2-eth0 6.0.0.1/24")
    net.hosts[2].cmd("ifconfig h3-eth0 7.0.0.1/24")
    net.hosts[3].cmd("ifconfig h4-eth0 8.0.0.1/24")
    net.hosts[4].cmd("ifconfig h5-eth0 9.0.0.1/24")
    net.hosts[0].cmd("route add default gw 10.0.0.2")
    net.hosts[1].cmd("route add default gw 6.0.0.2")
    net.hosts[2].cmd("route add default gw 7.0.0.2")
    net.hosts[3].cmd("route add default gw 8.0.0.2")
    net.hosts[4].cmd("route add default gw 9.0.0.2")

    # Start zebra (quagga)
    for router in net.switches:
        log("Start zebra on %s" % router.name)
        router.cmd("/usr/local/quagga/sbin/zebra -f /usr/local/quagga/etc/zebra-%s.conf -d -i /usr/local/quagga/etc/zebra-%s.pid > /tmp/%s-zebra-stdout 2>&1" %(router.name, router.name, router.name))
        router.waitOutput()

    log("Waiting %d seconds for zebra changes to take effect..." % args.sleep)
    sleep(args.sleep)

    # Start RIPD on routers
    for router in net.switches:
        router.cmd("/usr/local/quagga/sbin/ripd -f /usr/local/quagga/etc/ripd-%s.conf -d -i /usr/local/quagga/etc/ripd-%s.pid > /tmp/%s-ripd-stdout 2>&1" %(router.name, router.name, router.name), shell=True) 
        router.waitOutput()
        log("Start ripd on %s" % router.name)

    log("Waiting %d seconds for ripd changes to take effect..." % args.sleep)
    sleep(args.sleep)

    # Start PIMD on routers
    for router in net.switches:
#        router.cmd("/usr/local/quagga/sbin/pimd -f /usr/local/quagga/etc/pimd-%s.conf -d -i /usr/local/quagga/etc/pimd-%s.pid > /tmp/%s-pimd-stdout 2>&1" %(router.name, router.name, router.name), shell=True)
        router.cmd("/usr/local/quagga/sbin/pimd -f /usr/local/quagga/etc/pimd-%s.conf -d -i /usr/local/quagga/etc/pimd-%s.pid" %(router.name, router.name), shell=True)  
        router.waitOutput()
        log("Start pimd on %s" % router.name)


    CLI(net)
    net.stop()
    os.system("killall -9 zebra pimd ripd tshark")

if __name__ == "__main__":
    main()

