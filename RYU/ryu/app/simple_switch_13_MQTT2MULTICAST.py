# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import udp
from ryu.lib import addrconv
from ryu.lib.packet import mqtt2multicast
from datetime import datetime
import struct, socket

from ryu.topology import event
# Below is the library used for topo discovery
# Taken information from https://github.com/Ehsan70/RyuApps/blob/master/TopoDiscoveryInRyu.md
# Taken information from https://github.com/castroflavio/ryu/blob/master/ryu/app/shortestpath.py
# Taken information from https://github.com/YanHaoChen/Learning-SDN/blob/master/Controller/Ryu/ShortestPath/shortest_path_with_networkx.py
from ryu.topology.api import get_switch, get_link
import copy
import networkx as nx
import time

LEARNING_SWITCH = False # True for learning switch. If False, shortest path will be employed.


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # "Virtual" MAC and IP addresses of the SDN-based application at the SDN controller
        self.mac_addr = '11:22:33:44:55:66'
        self.ip_addr  = '192.168.1.100'
        self.topicToMulticast = {}
        self.multicastTransmitterForTopic = {}
        self.multicastTransmitterForTopicLastTimeSeen = {}
        self.multicastTransmitterTimeout = 3600 # If an MQTT publisher is not seen after this time, it should be removed from self.multicastTransmitterForTopic.
        self.multicastReceiverForTopic = {}
        self.firstMulticastIPAddress = '225.0.0.0'

        # Holds the topology data and structure
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.switchMap = {} # Maps switch ID (datapath.id) to switch object (datapath)

        # Holds the ARP cache
        self.arpCache = {}

    # Handy function that lists all attributes in the given object
    def ls(self,obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # For shortest path
        self.switchMap.update({datapath.id: datapath})

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to OVS bug. At this moment, if we specify a lesser number, e.g., 128, OVS will send Packet-In 
        # with invalid buffer_id and truncated packet data. In that case, we cannot output packets correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Rule to send all MQTT2MULTICAST packets to the SDN controller
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_src=int(mqtt2multicast.UDP_SERVER_PORT))
        self.add_flow(datapath, 100, match, actions)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_dst=int(mqtt2multicast.UDP_SERVER_PORT))
        self.add_flow(datapath, 100, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return


        #################################################
        # Add host/switch to topology if not included yet
        #################################################
	# forwarded by shortest path
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            if not self.net.has_node(eth.src):
                self.logger.info("### [TOPOLOGY] Add %s in self.net (switch %d, port %d)", eth.src, datapath.id, in_port)
                self.net.add_node(eth.src)
                self.net.add_edge(eth.src, datapath.id)
                self.net.add_edge(datapath.id, eth.src, port=in_port)
                self.logger.info("### [TOPOLOGY] List of nodes: %s", self.net.nodes())
                self.logger.info("### [TOPOLOGY] List of links: %s", self.net.edges())

                #self.logger.info("### [TOPOLOGY] pkt_arp: %s", pkt_arp)
                if pkt_arp.opcode == 1:
                    # ARP REQUEST
                    self.arpCache.update({pkt_arp.src_mac: pkt_arp.src_ip})
                    #pkt_arp: arp(dst_ip='192.168.1.102',dst_mac='00:00:00:00:00:00',hlen=6,hwtype=1,opcode=1,plen=4,proto=2048,src_ip='192.168.1.101',src_mac='00:00:00:00:00:01')
                    self.logger.info("### [TOPOLOGY] ARP request (src_mac=%s, src_ip=%s, dst_ip=%s)", pkt_arp.src_mac, pkt_arp.src_ip, pkt_arp.dst_ip)
                elif pkt_arp.opcode == 2:
                    # ARP REPLY
                    self.arpCache.update({pkt_arp.src_mac: pkt_arp.src_ip})
                    #arp(dst_ip='192.168.1.101',dst_mac='00:00:00:00:00:01',hlen=6,hwtype=1,opcode=2,plen=4,proto=2048,src_ip='192.168.1.102',src_mac='00:00:00:00:00:02')
                    self.logger.info("### [TOPOLOGY] ARP reply (src_mac=%s, src_ip=%s, dst_mac=%s, dst_ip=%s)", pkt_arp.src_mac, pkt_arp.src_ip, pkt_arp.dst_mac, pkt_arp.dst_ip)

                self.logger.info("### [TOPOLOGY] ARP cache: %s", self.arpCache)


        ################################
        # Handling UDP packets (over IP)
        ################################
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        self.logger.info("### pkt_ipv4: %s", pkt_ipv4)
        if pkt_ipv4:
            self.logger.info("### pkt_ipv4.proto: %d", pkt_ipv4.proto)
            if pkt_ipv4.proto == in_proto.IPPROTO_UDP:
                pkt_udp = pkt.get_protocol(udp.udp)

                self.logger.info("### pkt_udp: %s, pkt_ipv4.dst: %s, dst_port: %d", pkt_udp, pkt_ipv4.dst, pkt_udp.dst_port)

                if pkt_udp and pkt_ipv4.dst == self.ip_addr:
                    if pkt_udp.dst_port == mqtt2multicast.UDP_SERVER_PORT:

                        data = msg.data
                        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
                        #self.logger.debug("##### %s > Full message: %s", now, data)
                        #self.logger.debug("##### %s > pkt.protocols: %s", now, pkt.protocols)
                        #self.logger.debug("##### %s > UDP packet: %s", now, pkt_udp)

                        #########################
                        # Handling MQTT2MULTICAST messages sent to the SDN-based APP
                        #########################
                        pkt_mqtt2multicast = pkt.get_protocol(mqtt2multicast.mqtt2multicast)
                        
                        self.logger.debug("##### %s > pkt_mqtt2multicast: %s", now, pkt_mqtt2multicast)

                        if pkt_mqtt2multicast is not None:
                            self._handle_mqtt2multicast(datapath, in_port, msg.data, eth, pkt_ipv4, pkt_udp, pkt_mqtt2multicast)
                            # Packets sent to the controller should not continue through the SDN network
                            return


        # The previous handler will exit this function if required. If not, the learning switch has to be executed for the current packet.


        ###################
	### Learning switch
        ###################
        if LEARNING_SWITCH:
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("[LEARNING SWITCH] packet in dpid=%s, src=%s, dst=%s, in_port=%s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                self.logger.info("[LEARNING SWITCH] Send packet in switch %s to port %s", dpid, out_port)
            else:
                out_port = ofproto.OFPP_FLOOD
                self.logger.info("[LEARNING SWITCH] Send packet in switch %s to all ports (flooding)", dpid)

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


        else:
            ###############
            # SHORTEST PATH
            ###############
            self.logger.info("[SHORTEST PATH] packet in dpid=%s (in_port=%s), src=%s, dst=%s, packet=%s", dpid, in_port, src, dst, pkt)
            if self.net.has_node(eth.dst):
                # Compute the shortest path and install the corresponding flow entries
                #self.logger.info("[SHORTEST PATH] %s in self.net", eth.dst)
                #self.logger.info("[SHORTEST PATH] Topology - nodes: %s", self.net.nodes())
                #self.logger.info("[SHORTEST PATH] Topology - links: %s", self.net.edges())
                path = nx.shortest_path(self.net, eth.src, eth.dst)
                self.logger.info("[SHORTEST PATH] Shortest path from src=%s to dst=%s: %s", src, dst, path)
                next_match = parser.OFPMatch(eth_dst=eth.dst)
                back_match = parser.OFPMatch(eth_dst=eth.src)
                #self.logger.info("path: %s", path)
                for on_path_switch in range(1, len(path)-1):
                     now_switch = path[on_path_switch]
                     next_switch = path[on_path_switch+1]
                     back_switch = path[on_path_switch-1]
                     next_port = self.net[now_switch][next_switch]['port']
                     back_port = self.net[now_switch][back_switch]['port']
                     actions = [parser.OFPActionOutput(next_port)]
                     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                         self.add_flow(self.switchMap[now_switch], 1, next_match, actions, msg.buffer_id)
                     else:
                         self.add_flow(self.switchMap[now_switch], 1, next_match, actions)
                     actions = [parser.OFPActionOutput(next_port)]
                     if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                         self.add_flow(self.switchMap[now_switch], 1, next_match, actions, msg.buffer_id)
                     else:
                         self.add_flow(self.switchMap[now_switch], 1, next_match, actions)

            else:
                # If we do not know the switch and port of the destination, flood the message (e.g. for ARP requests)
                out_port = ofproto.OFPP_FLOOD
                self.logger.info("[SHORTEST PATH] %s not in self.net.nodes (%s), so send packet in switch %s to all ports (flooding)", eth.dst, self.net.nodes(), dpid)

                actions = [parser.OFPActionOutput(out_port)]
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)


    #########################
    ### MQTT to MULTICAST APP
    #########################
    def _handle_mqtt2multicast(self, datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_udp, pkt_mqtt2multicast):

        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        self.logger.info("### %s > MQTT2MULTICAST message received! MQTT2MULTICAST packet type: %d", now, pkt_mqtt2multicast.mqtt2multicastPacketType)

        if pkt_mqtt2multicast.mqtt2multicastPacketType == mqtt2multicast.MQTT2MULTICAST_REQUEST:
            # REQUEST received

            # Check if the topic was already included (so it has a corresponding multicast IP address) or it is new (so it requires a new multicast IP address)
            # multicastIPAddress is a string representing the IP address, e.g. '225.0.0.0'
            topic = pkt_mqtt2multicast.mqtt2multicastTopic
            flags = pkt_mqtt2multicast.mqtt2multicastFlags

            if topic in self.topicToMulticast:
                # Topic already exists
                multicastIPAddress = self.topicToMulticast[topic]
                self.logger.info("### %s > MQTT2MULTICAST - multicast IP address already assigned to existing topic ('%s'): %s", now, topic.decode(), multicastIPAddress)

            else:
                # New topic
                numberOfTopics = len(self.topicToMulticast)

                multicastIPAddress = self._get_nth_multicast_ip_address(numberOfTopics) # The first multicast IP address has index=0
                self.logger.info("### %s > MQTT2MULTICAST - multicast IP address assigned to new topic ('%s'): %s", now, topic.decode(), multicastIPAddress)
                self.topicToMulticast[topic] = multicastIPAddress

            if flags == 0:
                # The sender is going to publish to this multicast IP address
                self.logger.info("### %s > MQTT2MULTICAST - %s will publish to the multicast IP address %s", now, pkt_ipv4.src, multicastIPAddress)
                if topic.decode() in self.multicastTransmitterForTopic:
                    multicastTransmitterForThisTopic = self.multicastTransmitterForTopic[topic.decode()]
                    multicastTransmitterForThisTopic.append(pkt_ipv4.src)
                else:
                    self.multicastTransmitterForTopic[topic.decode()] = [pkt_ipv4.src]
                self.multicastTransmitterForTopicLastTimeSeen[pkt_ipv4.src + ' - ' + topic.decode()] = now
                self.logger.info("### %s > MQTT2MULTICAST - multicast transmitters for topic %s: %s", now, topic.decode(), self.multicastTransmitterForTopic[topic.decode()])

            elif flags == 1:
                # The sender subscribes to this multicast IP address
                self.logger.info("### %s > MQTT2MULTICAST - subscribe %s to the multicast IP address %s", now, pkt_ipv4.src, multicastIPAddress)
                if topic.decode() in self.multicastReceiverForTopic:
                    multicastReceiverForThisTopic = self.multicastReceiverForTopic[topic.decode()]
                    multicastReceiverForThisTopic.append(pkt_ipv4.src)
                else:
                    self.multicastReceiverForTopic[topic.decode()] = [pkt_ipv4.src]
                self.logger.info("### %s > MQTT2MULTICAST - multicast receivers for topic %s: %s", now, topic.decode(), self.multicastReceiverForTopic[topic.decode()])

            elif flags == 2:
                # The sender unsubscribes to this multicast IP address
                self.logger.info("### %s > MQTT2MULTICAST - unsubscribe %s from the multicast IP address %s (topic: %s)", now, pkt_ipv4.src, multicastIPAddress, topic.decode())
                #for topic in self.multicastReceiverForTopic.copy():
                multicastReceiverList = self.multicastReceiverForTopic[topic.decode()]
                multicastReceiverList = [x for x in multicastReceiverList if not(x == pkt_ipv4.src)] # Removing based on the content of the first element. 
                                                                                                     # Maybe list comprehension is not the best for performance, but it works...
                self.multicastReceiverForTopic[topic.decode()] = multicastReceiverList               # Required since subscribersList is now a different object
                # If this key has no content, remove it from the dictionary
                if not self.multicastReceiverForTopic[topic.decode()]:
                    del self.multicastReceiverForTopic[topic.decode()]
                    self.logger.info("### %s > MQTT2MULTICAST - no multicast receivers for topic %s", now, topic.decode())
                else:
                    self.logger.info("### %s > MQTT2MULTICAST - multicast receivers for topic %s: %s", now, topic.decode(), self.multicastReceiverForTopic[topic.decode()])


            # Create a new packet MQTT2MULTICAST REPLY to be sent
            if flags == 0 or flags == 1:
                pkt = packet.Packet()

                    # Add Ethernet header
                pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                                   dst=pkt_ethernet.src,
                                                   src=self.mac_addr))

                    # Add IP header
                pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                           src=self.ip_addr,
                                           proto=pkt_ipv4.proto))

                    # Add UDP header
                pkt.add_protocol(udp.udp(src_port=pkt_udp.dst_port, 
                                         dst_port=pkt_udp.src_port))

                    # Add MQTT2MULTICAST application packet
                pkt.add_protocol(mqtt2multicast.mqtt2multicast(mqtt2multicastPacketType=2,
                                                               mqtt2multicastTransactionID=pkt_mqtt2multicast.mqtt2multicastTransactionID,
                                                               mqtt2multicastFlags=0,
                                                               mqtt2multicastTopicSize=None,
                                                               mqtt2multicastTopic=None,
                                                               mqtt2multicastIPAddress=addrconv.ipv4.text_to_bin(multicastIPAddress)))

                # Send packet
                now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
                self.logger.info("### %s > MQTT2MULTICAST REPLY sent (%s) to %s", now, pkt, pkt_ipv4.src)

                self._send_packet(datapath, in_port, pkt)

            return

    def _send_packet(self, datapath, port, pkt):
        # Send packet
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def _get_nth_multicast_ip_address(self, n):
        # n starts at 0, i.e. the first multicast IP address would be self._get_nth_multicast_ip_address(0)
        (forthByte, thirdByte, secondByte, firstByte) = struct.unpack('BBBB', socket.inet_aton(self.firstMulticastIPAddress))
        #self.logger.info("### multicastIPAddress: %s.%s.%s.%s", forthByte, thirdByte, secondByte, firstByte)

        auxFirstByte = firstByte + n
        auxSecondByte = secondByte + int(auxFirstByte / 256)
        auxThirdByte = thirdByte + int(auxSecondByte / 256)
        auxForthByte = forthByte + int(auxThirdByte / 256)
        auxFirstByte = auxFirstByte % 256
        auxSecondByte = auxSecondByte % 256
        auxThirdByte = auxThirdByte % 256

        # TO BE DONE: We should check if we have too many topics converted to multicast IP addresses.
        # Anyway, if we employ 225.0.0.0-231.0.0.1 (reserved according to https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml), this gives as more than 117 million of topics!
        multicastIPAddress = str(auxForthByte) + '.' + str(auxThirdByte) + '.' + str(auxSecondByte) + '.' + str(auxFirstByte)

        return multicastIPAddress

    ###################################################################################
    """
    The event EventSwitchEnter will trigger the activation of get_topology_data().
    """
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        time.sleep(1.0) # Some time is required or some links may not appear.

        # The Function get_switch(self, None) outputs the list of switches.
        switch_list = copy.copy(get_switch(self.topology_api_app, None))
        # For networkx
        switches =[switch.dp.id for switch in switch_list]
        self.net.add_nodes_from(switches)
        self.logger.info("### [TOPOLOGY] List of nodes: %s", self.net.nodes())

        # The Function get_link(self, None) outputs the list of links.
        links_list = copy.copy(get_link(self.topology_api_app, None))
        # For networkx
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        links=[(link.dst.dpid,link.src.dpid,{'port':link.dst.port_no}) for link in links_list]
        self.net.add_edges_from(links)
        self.logger.info("### [TOPOLOGY] List of links: %s", self.net.edges())


        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """

#        print(" \t" + "Current Links:")
#        for l in switch_list:
#            print (" \t\t" + str(l))

#        print(" \t" + "Current Switches:")
#        for s in links_list:
#            print (" \t\t" + str(s))

    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")


