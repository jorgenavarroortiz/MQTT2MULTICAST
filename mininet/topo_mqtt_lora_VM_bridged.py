#!/usr/bin/python

# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller, OVSKernelSwitch, RemoteController, OVSSwitch
from mininet.log import setLogLevel, info, error
from mininet.link import Intf, TCLink
from mininet.util import quietRun

from mininet.nodelib import NAT
from mininet.topolib import TreeNet

import re
import sys
import getopt

# Default values
verbose = False
delayLinkHost = '0ms'
delayLinkSwitches = '0ms'
fanoutPerLevel = [2,2] # Last fanout is for hosts
realNetworkInterface = None
elementToConnectRealNetworkInterface = None
RH = 0 # 1 if a real network interface is connected to a host
RS = 0 # 1 if a real network interface is connected to a switch
numberElement = 0 # Host or switch connected using a real network interface


def checkIntf( intf ):
	"Make sure intf exists and is not configured."
	if ( ' %s:' % intf ) not in quietRun( 'ip link show' ):
		error( 'Error:', intf, 'does not exist!\n' )
		exit( 1 )
	ips = re.findall( r'\d+\.\d+\.\d+\.\d+', quietRun( 'ifconfig ' + intf ) )
	if ips:
		error( 'Error:', intf, 'has an IP address,' 'and is probably in use!\n' )
		exit( 1 )

def myNetwork():
	# Create mininet network
	net = Mininet(controller=RemoteController,switch=OVSKernelSwitch, listenPort=6634)

	# Create controller
	info( '*** Add controller\n' )
	c0 = net.addController(name='c0',controller=RemoteController,protocols='OpenFlow13',ip='127.0.0.1',port=6633)

	########################
        ### Create tree topology
	########################
	noSwitches = 0
	nameOfSwitches = []

	    # Root of the tree topology
	noSwitchesInThisLevel = 1
	if verbose: print("Switches in level 0: %d" % (noSwitches + noSwitchesInThisLevel))
	nameOfSwitchesInThisLevel = []
	for s in range(noSwitchesInThisLevel):
		switchThisLevel = 's' + str(noSwitches + s + 1)
		nameOfSwitches.append(switchThisLevel)
		nameOfSwitchesInThisLevel.append(switchThisLevel)
	noSwitches = noSwitches + noSwitchesInThisLevel
	noSwitchesInPreviousLevel = noSwitchesInThisLevel
	nameOfSwitchesInPreviousLevel = nameOfSwitchesInThisLevel
	if verbose: print("Name of switches up to level 0: %s" % (nameOfSwitches))
	if verbose: print("Name of switches in level 0: %s" % (nameOfSwitchesInThisLevel))

	    # Switches of the tree (except the root)
	linksU = [] # Switch on the upper level
	linksB = [] # Switch on the bottom level
	for i in range(len(fanoutPerLevel) - 1):
		noSwitchesInThisLevel = noSwitchesInPreviousLevel * fanoutPerLevel[i]
		if verbose: print("Switches in level %d: %d" % (i+1, noSwitchesInThisLevel))
		if verbose: print("Switches up to level %d: %d" % (i+1, noSwitches + noSwitchesInThisLevel))
		nameOfSwitchesInThisLevel = []
		for switchPreviousLevel in nameOfSwitchesInPreviousLevel:
			for s in range(fanoutPerLevel[i]):
				switchThisLevel = 's' + str(noSwitches + s + 1)
				linksU.append(switchPreviousLevel)
				linksB.append(switchThisLevel)
				nameOfSwitches.append(switchThisLevel)
				nameOfSwitchesInThisLevel.append(switchThisLevel)
			noSwitches = noSwitches + fanoutPerLevel[i]

		if verbose: print("Name of switches up to level %d: %s" % (i+1, nameOfSwitches))
		if verbose: print("Name of switches in level %d: %s" % (i+1, nameOfSwitchesInThisLevel))
		if verbose: print("Name of switches in level %d: %s" % (i, nameOfSwitchesInPreviousLevel))
		noSwitchesInPreviousLevel = noSwitchesInThisLevel
		nameOfSwitchesInPreviousLevel = nameOfSwitchesInThisLevel

	print("Total no. switches: %d" % (noSwitches))
	if verbose: print("Name of switches: %s" % (nameOfSwitches))

	    # Hosts
	i = len(fanoutPerLevel) - 1
	noHostsInThisLevel = noSwitchesInPreviousLevel * fanoutPerLevel[i]
	if verbose: print("Hosts in level %d: %d" % (i+1, noHostsInThisLevel))
	nameOfHosts = []
	noHosts = 0
	for switchPreviousLevel in nameOfSwitchesInPreviousLevel:
		for h in range(fanoutPerLevel[i]):
			hostThisLevel = 'h' + str(noHosts + h + 1)
			linksU.append(switchPreviousLevel)
			linksB.append(hostThisLevel)
			nameOfHosts.append(hostThisLevel)
		noHosts = noHosts + fanoutPerLevel[i]
	if verbose: print("Name of hosts in level %d: %s" % (i+1, nameOfHosts))
	print("Total no. hosts:    %d" % (noHosts))

	for i in range(len(linksU)):
		if verbose: print("Link %d: %s - %s" % (i, linksU[i], linksB[i]))


	# Check if element (host or switch) with a real network interface exists
	if (RH == 1 and numberElement > noHosts) or (RS == 1 and numberElement > noSwitches):
		print("Host %s does not exist. Exiting." % (elementToConnectRealNetworkInterface))
		sys.exit()


	# Create hosts
	info( '*** Add hosts\n' )
	hosts = []
	for i in xrange(noHosts):
		hostname = 'h%d' % (i+1)
		host = net.addHost(hostname, mac='00:00:00:00:00:%d' % (i+1), ip='192.168.1.%d' % (100+i+1))
		hosts.append(host)

	# Create switches
	info( '*** Add switches\n' )
	switches = []
	for i in xrange(noSwitches):
		switch = net.addSwitch('s%d' % (i+1), cls=OVSSwitch, protocols='OpenFlow13')
		switches.append(switch)

	# "Real" network interface connected to host
	if realNetworkInterface is not None:
		print("*** Add %s to %s" % (realNetworkInterface, elementToConnectRealNetworkInterface))
		intfName=realNetworkInterface
#		info( '*** Checking', intfName, '\n' )
#		checkIntf( intfName )                               # Not required, just for checking if the real network interface is in use...
		Intf( intfName, node=net.get(elementToConnectRealNetworkInterface) )

	# Create links
	info( '*** Add links\n')
	for i in range(len(linksU)):

		element = linksB[i]
		if element[0] == 'h':
			# Add delay between a host and its switch
			if delayLinkHost == '0ms':
				net.addLink( net.get(linksU[i]), net.get(linksB[i]) )
			else:
				net.addLink( net.get(linksU[i]), net.get(linksB[i]), cls=TCLink, delay=delayLinkHost )
		else:
			# Link between switches
			if delayLinkSwitches == '0ms':
				net.addLink( net.get(linksU[i]), net.get(linksB[i]) )
			else:
				net.addLink( net.get(linksU[i]), net.get(linksB[i]), cls=TCLink, delay=delayLinkSwitches )

#	net.addLink( net.get('s1'), net.get('s2') )
	
	# Create network
	info( '\n*** Starting network\n')
	net.build()
	net.start()

	# Start controller
	info( '*** Starting controllers\n')
	for controller in net.controllers:
		controller.start()
	net.get('s1').start([c0])

#	net.get('h1').cmd("XXX")    # Example on how to execute a command on a particular host
#	net.get('h1').waitOutput()

	# Disable IPv6
	print ("*** Disable IPv6 in hosts")
	for h in net.hosts:
		h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
		h.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

	print ("*** Disable IPv6 in switches")
	for sw in net.switches:
		sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
		sw.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
		sw.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

	# "Real" network interface connected to host
	if RH == 1:
		# Adjust the IP addresses of this host. The real network interface will be in the 192.168.2.0/24 network, and the hX-eth1 will be in the 192.168.1.0/24 network (like the rest of the hosts).
		lastByteIPAddress = str(100 + numberElement)
		commandStr1 = 'ifconfig ' + realNetworkInterface + ' 192.168.2.' + lastByteIPAddress + '/24'
		commandStr2 = 'ifconfig ' + elementToConnectRealNetworkInterface + '-eth1 192.168.1.' + lastByteIPAddress + '/24'
		print("*** Configure host %s: ip_forward=1, real network interface %s with IP address %s and interface %s-eth1 with IP address %s" % (elementToConnectRealNetworkInterface, realNetworkInterface, '192.168.2.' + lastByteIPAddress, elementToConnectRealNetworkInterface, '192.168.1.' + lastByteIPAddress))
		net.get(elementToConnectRealNetworkInterface).cmd(commandStr1)
		net.get(elementToConnectRealNetworkInterface).cmd(commandStr2)
		net.get(elementToConnectRealNetworkInterface).cmd("sysctl -w net.ipv4.ip_forward=1")

	elif RS == 1:
		print("*** Nothing to configure in switch %s with real network interface" % (elementToConnectRealNetworkInterface))

	# Open Mininet Command Line Interface
	CLI(net)

	# Teardown and cleanup
	net.stop()

def usage():
	print("This script will create a tree topology in Mininet. All levels are composed of switches except the last level, which is composed of hosts.")
	print("Usage:   %s [-h] [-v] -f <fanout first level> -f <fanout second level> ... [-r <real network interface> -R <host to connect the real network interface>] [-d <delay in links to hosts>] [-D <delay in links between switches>]" % (sys.argv[0]))
        print("Example to create a tree with root, 2 more levels of switches and one last level of hosts (L0 = root, L1 = 2 switches, L2 = 2 x 3 switches, L3 = 2 x 3 x 2 hosts):")
	print("         %s -v -f 2 -f 3 -f 2 -d 10ms" % (sys.argv[0]))

def main():
	global delayLinkHost, delayLinkSwitches, fanoutPerLevel, realNetworkInterface, elementToConnectRealNetworkInterface, RH, RS, numberElement

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hf:d:D:r:R:v", ["help", "output="])
	except getopt.GetoptError as err:
		# print help information and exit:
		print(err)
		usage()
		sys.exit(2)

	f, r, R = 0, 0, 0
	for o, a in opts:
		if o == "-v":
			verbose = True
		elif o in ("-h", "--help"):
			usage()
			sys.exit()
		elif o == "-d":
			delayLinkHost = a
			print("Delay in links to hosts: %s" % (delayLinkHost))
		elif o == "-D":
			delayLinkSwitches = a
			print("Delay in links between switches: %s" % (delayLinkSwitches))
		elif o in ("-f", "--fanout"):
			if f == 0:
				f = 1
				fanoutPerLevel = [int(a)]
				print("Fanout in level %d: %d" % (f, int(a)))
			else:
				f = f + 1
				fanoutPerLevel.append(int(a))
				print("Fanout in level %d: %d" % (f, int(a)))
		elif o in ("-r", "--realnetworkinterface"):
			r = 1
			realNetworkInterface = a
			print("Real network interface: %s" % (realNetworkInterface))
		elif o in ("-R", "--elementToConnectRealNetworkInterface"):
			R = 1
			elementToConnectRealNetworkInterface = a
			if elementToConnectRealNetworkInterface[0] == 'h':
				RH = 1
				print("This host (%s) will connect using a real network interface and will act as a router (ip_forward = 1)" % (elementToConnectRealNetworkInterface))
			elif elementToConnectRealNetworkInterface[0] == 's':
				RS = 1
				print("This switch (%s) will connect using a real network interface" % (elementToConnectRealNetworkInterface))
			else:
				print("A switch or a host have to be selected to connect using a real network interface. Exiting.")
				sys.exit()

			numberElementStr=unicode(elementToConnectRealNetworkInterface[-1:], 'utf-8')
			if not numberElementStr.isnumeric():
				print("The format of the element is not hX or sX (X being an integer). Exiting.")
				sys.exit()
			else:
				numberElement = int(numberElementStr)

		else:
			assert False, "unhandled option"

	if r != R:
		print("If you specify a real network interface (%d) or a host to connect the real network interface (%d), you shall also specify the other parameter. Exiting..." % (r, R))
		sys.exit()


if __name__ == '__main__':
	main()
	setLogLevel( 'info' )
	myNetwork()

