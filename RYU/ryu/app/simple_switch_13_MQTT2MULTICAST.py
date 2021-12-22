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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import udp
from ryu.lib import addrconv
from ryu.lib.packet import mqtt2multicast
from datetime import datetime

import struct, socket


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # "Virtual" MAC and IP addresses of the SDN-based application at the SDN controller
        self.mac_addr = '11:22:33:44:55:66'
        self.ip_addr  = '192.168.1.100'
        self.topic_to_multicast = {}
        self.firstMulticastIPAddress = '225.0.0.0'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return


        ##############
        # Handling UDP packets (over IP)
        ##############
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


        # The previous handler will exit this function if required.
        # If not, the learning switch has to be executed for the current packet.


        ###################
	### Learning switch
        ###################
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
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
            if topic in self.topic_to_multicast:
                # Topic already exists
                multicastIPAddress = self.topic_to_multicast[topic]
                self.logger.info("### %s > MQTT2MULTICAST - multicast IP address already assigned to existing topic ('%s'): %s", now, topic.decode(), multicastIPAddress)

            else:
                # New topic
                numberOfTopics = len(self.topic_to_multicast)

                multicastIPAddress = self._get_nth_multicast_ip_address(numberOfTopics) # The first multicast IP address has index=0
                self.logger.info("### %s > MQTT2MULTICAST - multicast IP address assigned to new topic ('%s'): %s", now, topic.decode(), multicastIPAddress)
                self.topic_to_multicast[topic] = multicastIPAddress

            # Create a new packet MQTT2MULTICAST REPLY to be sent
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
        #self.logger.info("*** multicastIPAddress: %s.%s.%s.%s", forthByte, thirdByte, secondByte, firstByte)

        auxFirstByte = firstByte + n
        auxSecondByte = secondByte + int(auxFirstByte / 256)
        auxThirdByte = thirdByte + int(auxSecondByte / 256)
        auxForthByte = forthByte + int(auxThirdByte / 256)
        auxFirstByte = auxFirstByte % 256
        auxSecondByte = auxSecondByte % 256
        auxThirdByte = auxThirdByte % 256

        # *** We should check if we have too many topics converted to multicast IP addresses ***
        # If we employ 225.0.0.0-231.0.0.1 (reserved according to https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml), this gives as more than 117 million of topics!
        multicastIPAddress = str(auxForthByte) + '.' + str(auxThirdByte) + '.' + str(auxSecondByte) + '.' + str(auxFirstByte)

        return multicastIPAddress


    def ip2int(addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def int2ip(addr):
        return socket.inet_ntoa(struct.pack("!I", addr))

