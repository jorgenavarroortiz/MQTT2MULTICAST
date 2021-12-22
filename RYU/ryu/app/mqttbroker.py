# Copyright (C) 2021 Jorge Navarro-Ortiz (jorgenavarro@ugr.es),
# University of Granada
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

#import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import mqtt
from datetime import datetime
import random


class SimpleSwitch13_MQTT(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13_MQTT, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # "Virtual" MAC and IP addresses of the SDN-based MQTT broker (i.e. this APP in the SDN controller)
        self.mac_addr = '11:22:33:44:55:66'
        self.ip_addr  = '192.168.1.100'
        self.mqtt_user = 'jorge'
        self.mqtt_pass = 'passwd'
        # Dictionary with key=topic, value=list of subscribers and QoS ([IP address + TCP port, QoS])
        # With this dictionary, we can search which subscribers are subscribed to one topic (e.g. to forward a PUBLISH message), i.e. topic -> subscribers
        self.topicsSubscribers = {}
        # Dictionary with key=subscriber (IP address + TCP port), value=list of subscribers' TCP info ([TCP seq, TCP ack, ts_val])
        # Once we know which subscribers are subscribed to one topic, we need more information to forward PUBLISH messages, i.e. TCP related information (seq + ack).
        # This information cannot be included in the previous dictionary (topicsSubscribers) because one subscriber's TCP connection may be used to subscribe to several topics.
        self.subscribersTCPInfo = {}
        # Dictionary with key=IP address, value=MAC address
        self.ipToMAC = {}
        # Dictionary with topics for a given subscriber (IP address + TCP port), to allow easy lookup on the opposite direction (subscriber -> topics)
        self.subscribersTopics = {}

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

        # Rule to send all MQTT packets to the SDN controller
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_src=int(mqtt.TCP_SERVER_PORT))
        self.add_flow(datapath, 100, match, actions)
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_dst=int(mqtt.TCP_SERVER_PORT))
        self.add_flow(datapath, 100, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocols(ethernet.ethernet)[0]

        if pkt_ethernet.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        #######################
        # Handling ARP messages sent to the SDN-based MQTT broker APP
        #######################
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp and pkt_arp.dst_ip == self.ip_addr:
            self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp)
            return

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        ###############
        # Handling ICMP implementing a PING responder (not needed, but useful for testing)
        ###############
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp and pkt_ipv4.dst == self.ip_addr:
            self._handle_icmp(datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp)
            return

        ##############
        # Checking TCP packets (over IP)
        ##############
        if pkt_ipv4:
            if pkt_ipv4.proto == in_proto.IPPROTO_TCP:
                pkt_tcp = pkt.get_protocol(tcp.tcp)

                if pkt_tcp and pkt_ipv4.dst == self.ip_addr:
                    if pkt_tcp.src_port == mqtt.TCP_SERVER_PORT or pkt_tcp.dst_port == mqtt.TCP_SERVER_PORT:

                        data = msg.data
                        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
                        #self.logger.debug("##### %s > Full message: %s", now, data)
                        self.logger.debug("##### %s > pkt.protocols: %s", now, pkt.protocols)
                        #self.logger.debug("##### %s > TCP packet: %s", now, pkt_tcp)

                        #######################
                        # Handling TCP messages sent to the SDN-based MQTT broker APP (for TCP SYN and TCP FIN messages)
                        #######################
                        self._handle_tcp(datapath, in_port, msg.data, pkt_ethernet, pkt_ipv4, pkt_tcp)

                        ########################
                        # Handling MQTT messages
                        ########################
                        pkt_mqtt = pkt.get_protocol(mqtt.mqtt)
                        # Handshake messages (TCP SYN, TCP FIN, ...) do not have an MQTT payload, so pkt_mqtt is None in those cases.
                        if pkt_mqtt is not None:
                            self._handle_mqtt(datapath, in_port, msg.data, pkt_ethernet, pkt_ipv4, pkt_tcp, pkt_mqtt)

                    return

                else:
                    # Checking other MQTT messages (to other brokers) just for testing...
                    if pkt_tcp.src_port == mqtt.TCP_SERVER_PORT or pkt_tcp.dst_port == mqtt.TCP_SERVER_PORT:
                        pkt_mqtt = pkt.get_protocol(mqtt.mqtt)


        # The previous handlers (for ARP, TCP, MQTT...) will exit this function if required.
        # If not, the learning switch has to be executed for the current packet.


        ###################
	### Learning switch
        ###################
        dst = pkt_ethernet.dst
        src = pkt_ethernet.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

#        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port) # Used for learning switch

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


    ############################
    ### ARP handler function ###
    ############################
    # Based on information from https://github.com/osrg/ryu-book/blob/master/sources/ping_responder.py
    #
    # If an ARP request is received asking for the MAC address of the MQTT broker IP address,
    # an ARP reply with that information is sent.
    def _handle_arp(self, datapath, in_port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
           return

        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        self.logger.info("### %s > ARP packet request received from %s", now, pkt_arp.src_ip)

        if pkt_arp.dst_ip == self.ip_addr:
            pkt = packet.Packet()

            # Add Ethernet header
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=self.mac_addr))
            # Add ARP header
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.mac_addr, src_ip=self.ip_addr, dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip))

            # Send packet
            now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
            self.logger.info("### %s > ARP packet reply sent to %s", now, pkt_arp.src_ip)
            self._send_packet(datapath, in_port, pkt)


    #############################
    ### ICMP handler function ###
    #############################
    # Based on information from https://github.com/osrg/ryu-book/blob/master/sources/ping_responder.py
    #
    # If an echo-request is received asking for the MQTT broker IP address,
    # an echo-reply is sent.
    def _handle_icmp(self, datapath, in_port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return

        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        self.logger.info("### %s > ICMP echo-request received from %s", now, pkt_ipv4.src)

        if pkt_ipv4.dst == self.ip_addr:
            pkt = packet.Packet()

            # Add Ethernet header
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=self.mac_addr))
            # Add IPv4 header
            pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src, src=self.ip_addr, proto=pkt_ipv4.proto))

            # Add ICMP header and data
            pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=pkt_icmp.data))

            # Send packet
            now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
            self.logger.info("### %s > ICMP echo-reply sent to %s", now, pkt_ipv4.src)
            self._send_packet(datapath, in_port, pkt)


    ######################
    ### TCP connection ###
    ######################
    # Generate TCP ACK (with SYN or FIN if required)
    def generate_tcp_ack(self, datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_tcp):

        # Compute seq and ack for the different type of TCP packets
        flagsTCP = pkt_tcp.bits
        if flagsTCP & tcp.TCP_SYN:
            # TCP SYN received
                # Flags for the new packet (SYN + ACK)
            bits=(tcp.TCP_SYN | tcp.TCP_ACK)

                # TCP seq and ack for SYN + ACK packet
            seq=random.getrandbits(32) # Random number of 32 bits
            ack=pkt_tcp.seq+1

                # IP address to MAC address (for PUBLISH)
            self.ipToMAC[pkt_ipv4.src] = pkt_ethernet.src

        elif flagsTCP & tcp.TCP_FIN:
            # TCP FIN received
                # Flags for the new packet (FIN + ACK)
            bits=(tcp.TCP_FIN | tcp.TCP_ACK)

                # TCP seq and ack for FIN + ACK packet
            pkt_len = len(data)
            header_size = len(pkt_ethernet) + len(pkt_ipv4) + len(pkt_tcp)
            tcpPayloadSize = pkt_len - header_size

            seq=pkt_tcp.ack
            ack=pkt_tcp.seq+1 + tcpPayloadSize # Add TCP payload size because some TCP FIN messages also include data, which increases the ack number.

        else:
            # TCP payload size required for TCP ACK
            pkt_len = len(data)
            header_size = len(pkt_ethernet) + len(pkt_ipv4) + len(pkt_tcp)
            tcpPayloadSize = pkt_len - header_size
            tcpPayload = data[header_size:]

                # TCP seq and ack for normal TCP packet
            seq=pkt_tcp.ack
            ack=pkt_tcp.seq + tcpPayloadSize

        # New TCP packet with ACK and required flags
        pkt = packet.Packet()
            # Add Ethernet header
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=self.mac_addr))
            # Add IP header
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src, src=self.ip_addr, proto=pkt_ipv4.proto))
            # Add TCP header (see https://sourceforge.net/p/ryu/mailman/message/34718081/)

        tcpOptions = []
        for op in pkt_tcp.option:
            # See options in lib/packet/tcp.py
            if op.kind == tcp.TCP_OPTION_KIND_NO_OPERATION:
                tcpOptions.append(tcp.TCPOptionNoOperation())
                #self.logger.debug("    TCP NO OPERATION")
            elif op.kind == tcp.TCP_OPTION_KIND_MAXIMUM_SEGMENT_SIZE:
                max_seg_size = op.max_seg_size
                tcpOptions.append(tcp.TCPOptionMaximumSegmentSize(max_seg_size=max_seg_size))
                #self.logger.debug("    TCP MAXIMUM_SEGMENT_SIZE: max_seg_size=%s", max_seg_size)
            elif op.kind == tcp.TCP_OPTION_KIND_SACK_PERMITTED:
                tcpOptions.append(tcp.TCPOptionSACKPermitted())
                #self.logger.debug("    TCP SACK PERMITTED")
            elif op.kind == tcp.TCP_OPTION_KIND_WINDOW_SCALE:
                shift_cnt = op.shift_cnt
                tcpOptions.append(tcp.TCPOptionWindowScale(shift_cnt=shift_cnt))
                #self.logger.debug("    TCP WINDOW SCALE: shift_cnt=%s", shift_cnt)
            elif op.kind == tcp.TCP_OPTION_KIND_TIMESTAMPS:
                ts_val = op.ts_val
                ts_ecr = op.ts_ecr
                #self.logger.debug("    TCP TIMESTAMPS: ts_val=%s, ts_ecr=%s", ts_val, ts_ecr)
                # 'ts_val' of the new packet should be a random number. Set to ts_val+1 for simplicity.
                tcpOptions.append(tcp.TCPOptionTimestamps(ts_val=ts_val+1, ts_ecr=ts_val))

        # The flags are the same than in the previous message + ACK
        newFlagsTCP = flagsTCP | tcp.TCP_ACK
        pkt.add_protocol(tcp.tcp(src_port=pkt_tcp.dst_port, dst_port=pkt_tcp.src_port, seq=seq, ack=ack, offset=pkt_tcp.offset, bits=newFlagsTCP, window_size=pkt_tcp.window_size, csum=0, urgent=pkt_tcp.urgent, option=tcpOptions))

        return pkt

    # Based on information from http://osrg.github.io/ryu-book/en/html/packet_lib.html#analysis-of-packet-parse
    #
    # If a TCP SYN message is received (sent to the MQTT broker IP address),
    # a TCP SYN+ACK message is sent.
    # Similarly, if a TCP FIN message is received, a TCP FIN+ACK message is sent.
    def _handle_tcp(self, datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_tcp):
        # TCP flags (see RFC 793): URG, ACK, PUSH, RESET, SYN, FIN
        flagsTCP = pkt_tcp.bits
        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        
        if (flagsTCP & tcp.TCP_SYN) or (flagsTCP & tcp.TCP_FIN):
            if flagsTCP & tcp.TCP_SYN:
                # TCP SYN received
                self.logger.info("### %s > TCP SYN received by the MQTT broker APP from %s", now, pkt_ipv4.src)

            if flagsTCP & tcp.TCP_FIN:
                # TCP FIN received
                self.logger.info("### %s > TCP FIN received by the MQTT broker APP from %s", now, pkt_ipv4.src)

                # Remove the topic and the subscriber (IP address + TCP port) from topicsSubscribers, subscribersTopics and subscribersTCPInfo
                subscriberStr = pkt_ipv4.src + "-" + str(pkt_tcp.src_port)
                if subscriberStr in self.subscribersTopics:
                    topics = self.subscribersTopics[subscriberStr]                               # List of lists (subscriber (IP address + TCP port) + MQTT QoS)
                    for topic in topics:
                        subscribersList = self.topicsSubscribers[topic]
                        subscribersList = [x for x in subscribersList if x[0] != subscriberStr] # Removing based on the content of the first element. 
                                                                                                # Maybe list comprehension is not the best for performance, but it works...
                        self.topicsSubscribers[topic] = subscribersList                         # Required since subscribersList is now a different object
                        # If this key has no content, remove it from the dictionary
                        if not self.topicsSubscribers[topic]:
                            del self.topicsSubscribers[topic]

                if subscriberStr in self.subscribersTopics:
                    self.subscribersTopics.pop(subscriberStr)

                if subscriberStr in self.subscribersTCPInfo:
                    self.subscribersTCPInfo.pop(subscriberStr)

                self.logger.debug("######### topicsSubscribers:  %s", self.topicsSubscribers)
                self.logger.debug("######### subscribersTopics:  %s", self.subscribersTopics)
                self.logger.debug("######### subscribersTCPInfo: %s", self.subscribersTCPInfo)

            # Generate SYN+ACK or FIN+ACK
            ackPkt = self.generate_tcp_ack(datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_tcp)

            # Send packet
            now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
            if flagsTCP & tcp.TCP_SYN:
                self.logger.info("### %s > TCP SYN+ACK sent to %s", now, pkt_ipv4.src)
            if flagsTCP & tcp.TCP_FIN:
                self.logger.info("### %s > TCP FIN+ACK sent to %s", now, pkt_ipv4.src)

            self._send_packet(datapath, in_port, ackPkt)
            return

        else:
            # Other TCP messages, e.g. ACK
            # If the host was subscribed (and therefore its MQTT/TCP parameters are stored in the corresponding lists), TCP seq and ack shall be updated each time a TCP packet is received
            subscriberStr = pkt_ipv4.src + "-" + str(pkt_tcp.src_port)
            if subscriberStr in self.subscribersTCPInfo:
                # Get TCP payload size
                pkt_len = len(data)
                header_size = len(pkt_ethernet) + len(pkt_ipv4) + len(pkt_tcp)
                tcpPayloadSize = pkt_len - header_size

                # Get TCP ts_val (within the timestamps option)
                if pkt_tcp.option:
                    timestamps = [op for op in pkt_tcp.option if op.kind == tcp.TCP_OPTION_KIND_TIMESTAMPS][0]

                self.subscribersTCPInfo[subscriberStr] = [pkt_tcp.ack, pkt_tcp.seq + tcpPayloadSize, timestamps.ts_val]
                self.logger.debug("######### subscribersTCPInfo updated for %s: %s", subscriberStr, self.subscribersTCPInfo[subscriberStr])


    #############################
    ### MQTT handler function ###
    #############################
    def _handle_mqtt(self, datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_tcp, pkt_mqtt):
        tcpPayloadType = pkt_tcp.get_payload_type(pkt_tcp.src_port, pkt_tcp.dst_port)
        now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
        mqttPacketType = pkt_mqtt.mqttControlPacketType

        # TCP payload size required for TCP ack
        pkt_len = len(data)
        header_size = len(pkt_ethernet) + len(pkt_ipv4) + len(pkt_tcp)
        tcpPayloadSize = pkt_len - header_size
        tcpPayload = data[header_size:]

        self.logger.debug("##### %s > Received TCP packet (seq=%d, ack=%d), payload type: %s, MQTT packet: %s, MQTT packet type: %d (%s), MQTT packet content (%d bytes): %s", now, pkt_tcp.seq, pkt_tcp.ack, tcpPayloadType, pkt_mqtt, mqttPacketType, pkt_mqtt.mqttPacketControlTypeStr[mqttPacketType], tcpPayloadSize, tcpPayload)

        if mqttPacketType == 1 or mqttPacketType == 8 or mqttPacketType == 12:
            # MQTT CONNECT, SUBSCRIBE or PING REQUEST, i.e. messages that will send one (or several) response message (CONNACK, SUBACK, PING RESPONSE)
            pkt = packet.Packet()
                # Add Ethernet header
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=pkt_ethernet.src, src=self.mac_addr))
                # Add IP header
            pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src, src=self.ip_addr, proto=pkt_ipv4.proto))
                # Add TCP header (see https://sourceforge.net/p/ryu/mailman/message/34718081/)
            tcpOptions = []
            for op in pkt_tcp.option:
                # See options in lib/packet/tcp.py
                if op.kind == tcp.TCP_OPTION_KIND_NO_OPERATION:
                    tcpOptions.append(tcp.TCPOptionNoOperation())
                elif op.kind == tcp.TCP_OPTION_KIND_MAXIMUM_SEGMENT_SIZE:
                    max_seg_size = op.max_seg_size
                    tcpOptions.append(tcp.TCPOptionMaximumSegmentSize(max_seg_size=max_seg_size))
                elif op.kind == tcp.TCP_OPTION_KIND_SACK_PERMITTED:
                    tcpOptions.append(tcp.TCPOptionSACKPermitted())
                elif op.kind == tcp.TCP_OPTION_KIND_WINDOW_SCALE:
                    shift_cnt = op.shift_cnt
                    tcpOptions.append(tcp.TCPOptionWindowScale(shift_cnt=shift_cnt))
                elif op.kind == tcp.TCP_OPTION_KIND_TIMESTAMPS:
                    ts_val = op.ts_val
                    ts_ecr = op.ts_ecr
                    # 'ts_val' of the new packet should be a random number. Set to ts_val+1 for simplicity.
                    tcpOptions.append(tcp.TCPOptionTimestamps(ts_val=ts_val+1, ts_ecr=ts_val))

            # Increase SEQ (with respect to ACK from previous message)
            # The flags are the same than in the previous message (PSH, ACK)
            pkt.add_protocol(tcp.tcp(src_port=pkt_tcp.dst_port, dst_port=pkt_tcp.src_port, seq=pkt_tcp.ack, ack=pkt_tcp.seq + tcpPayloadSize, offset=pkt_tcp.offset, bits=pkt_tcp.bits, window_size=pkt_tcp.window_size, csum=0, urgent=pkt_tcp.urgent, option=tcpOptions))

            now = datetime.now().strftime('%Y/%m/%d %H:%M:%S.%f')
            if mqttPacketType == 1:
                # MQTT CONNECT received, sending MQTT CONNACK (mqttControlPacketType=2, mqttRemainingLength=2)
                # returnCode=0 if password matches, returnCode=5 otherwise
                # See https://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html#connack for all the return codes
                self.logger.info("### %s > MQTT CONNECT (protocolName=%s, version=%s, connectionFlags=%s, keepAlive=%d, clientID=%s, willTopic=%s, willMessage=%s, userName=%s, password=%s) received from %s", now, pkt_mqtt.protocolName, pkt_mqtt.version, format(pkt_mqtt.connectionFlags, '08b'), pkt_mqtt.keepAlive, pkt_mqtt.clientID, pkt_mqtt.willTopic, pkt_mqtt.willMessage, pkt_mqtt.userName, pkt_mqtt.password, pkt_ipv4.src)

                returnCode=5 # Not authorized (wrong username or password)
                if pkt_mqtt.userName.decode("utf-8") == self.mqtt_user and pkt_mqtt.password.decode("utf-8") == self.mqtt_pass:
                    returnCode=0

                pkt.add_protocol(mqtt.mqtt(2, 2, returnCode=returnCode, messageID=None, qos=None, topic=None, message=None))
                self.logger.info("### %s > MQTT CONNACK (returnCode=%d) sent to %s", now, returnCode, pkt_ipv4.src)

            elif mqttPacketType == 8:
                # MQTT SUBSCRIBE received, sending MQTT SUBACK (mqttControlPacketType=9, mqttRemainingLength=3, messageID, qos)
                # Include the subscriber (IP address + TCP port) to the topic along with its MQTT QoS ('topicsSubscribers' dictionary)
                if pkt_mqtt.topic in self.topicsSubscribers:
                    subscribersList = self.topicsSubscribers[pkt_mqtt.topic] # List of lists, i.e. list of subscribers' info (each subscriber info is also a list)
                    subscribersList.append([pkt_ipv4.src + "-" + str(pkt_tcp.src_port), pkt_mqtt.qos])
                else:
                    self.topicsSubscribers[pkt_mqtt.topic] = [[pkt_ipv4.src + "-" + str(pkt_tcp.src_port), pkt_mqtt.qos]]

                # Include the topic to the subscriber
                subscriberStr = pkt_ipv4.src + "-" + str(pkt_tcp.src_port)
                if subscriberStr in self.subscribersTopics:
                    subscriberInfo = self.subscribersTopics[subscriberStr]
                    subscriberInfo.append(pkt_mqtt.topic)
                else:
                    self.subscribersTopics[subscriberStr] = [pkt_mqtt.topic]

                # Once the host is subscribed, include the TCP required fields to the subscriber ('subscriber' dictionary)
                    # Get TCP ts_val (within the timestamps option)
                if pkt_tcp.option:
                    timestamps = [op for op in pkt_tcp.option if op.kind == tcp.TCP_OPTION_KIND_TIMESTAMPS][0]

                subscriberStr = pkt_ipv4.src + "-" + str(pkt_tcp.src_port)
                self.subscribersTCPInfo[subscriberStr] = [pkt_tcp.ack, pkt_tcp.seq + tcpPayloadSize, timestamps.ts_val]

                self.logger.info("### %s > MQTT SUBSCRIBE (grantedQoS=%d, messageID=%d, topic=%s) received from %s", now, pkt_mqtt.qos, pkt_mqtt.messageID, pkt_ipv4.src, pkt_mqtt.topic)
                self.logger.debug("######### topicsSubscribers:  %s", self.topicsSubscribers)
                self.logger.debug("######### subscribersTopics:  %s", self.subscribersTopics)
                self.logger.debug("######### subscribersTCPInfo: %s", self.subscribersTCPInfo)
                grantedQoS = pkt_mqtt.qos
                messageID = pkt_mqtt.messageID
                pkt.add_protocol(mqtt.mqtt(9, 3, returnCode=None, messageID=messageID, qos=grantedQoS, topic=None, message=None))
                self.logger.info("### %s > MQTT SUBACK (grantedQoS=%d, messageID=%d) sent to %s", now, grantedQoS, messageID, pkt_ipv4.src)

            elif mqttPacketType == 12:
                # PING REQUEST
                self.logger.info("### %s > MQTT PING REQUEST received from %s, sending TCP ACK...", now, pkt_ipv4.src)

                # New packet to be sent (TCP ACK)
                ackPkt = self.generate_tcp_ack(datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_tcp)

                # Send packet
                self.logger.info("### %s > TCP ACK sent to %s", now, pkt_ipv4.src)

                self._send_packet(datapath, in_port, ackPkt)

                # Send PING RESPONSE
                pkt.add_protocol(mqtt.mqtt(13, 0, returnCode=None, messageID=None, qos=None, topic=None, message=None))
                self.logger.info("### %s > MQTT PING RESPONSE sent to %s", now, pkt_ipv4.src)

            # Send packet
            self._send_packet(datapath, in_port, pkt)
            return

        elif mqttPacketType == 3:
            # PUBLISH
            self.logger.info("### %s > MQTT PUBLISH (topic=%s, message=%s) received from %s, sending TCP ACK...", now, pkt_mqtt.topic, pkt_mqtt.message, pkt_ipv4.src)

            # New packet to be sent (TCP ACK)
            ackPkt = self.generate_tcp_ack(datapath, in_port, data, pkt_ethernet, pkt_ipv4, pkt_tcp)

            # Send packet
            self.logger.info("### %s > TCP ACK sent to %s", now, pkt_ipv4.src)

            self._send_packet(datapath, in_port, ackPkt)

            # *** TO BE DONE: FORWARD TO SUBSCRIBERS ***
            if pkt_mqtt.topic in self.topicsSubscribers:
                subscribersList = self.topicsSubscribers[pkt_mqtt.topic]
                # Loop for all subscribers for this topic
                for x in subscribersList:
                    # Selected subscriber x
                    qos = x[1]
                    subscriberStr = x[0] # IP address + "-" + TCP port
                    [subscriberIpStr, subscriberTCPPortStr] = subscriberStr.split("-")
                    macDstAddr = self.ipToMAC[subscriberIpStr]
                    if subscriberStr in self.subscribersTCPInfo:
                        subscriberTcpInfo = self.subscribersTCPInfo[subscriberStr]
                        subscriberSeq = subscriberTcpInfo[0]
                        subscriberAck = subscriberTcpInfo[1]
                        subscriberTS = subscriberTcpInfo[2]

                        if datapath.id not in self.mac_to_port:
                            self.logger.info("### %s > CANNOT FORWARD MQTT PUBLISH since switch is not included in the MAC table. Restart mininet and perform a pingall!!!", now)
                            return
                        else:
                            if macDstAddr not in self.mac_to_port[datapath.id]:
                                self.logger.info("### %s > CANNOT FORWARD MQTT PUBLISH since the MAC address is not included in the MAC table of switch %s. Try to perform a pingall. If it does not work, restart mininet!!!", now, datapath.id)
                                return

                        self.logger.info("### %s > forward MQTT PUBLISH (topic=%s, message=%s) to %s (MAC=%s, TCP port=%s, seq=%d, ack=%d, ts_val=%d)", now, pkt_mqtt.topic, pkt_mqtt.message, subscriberIpStr, macDstAddr, subscriberTCPPortStr, subscriberSeq, subscriberAck, subscriberTS)

                        # New packet to forward PUBLISH to the selected subscriber
                        pkt = packet.Packet()
                            # Add Ethernet header
                        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype, dst=macDstAddr, src=self.mac_addr))
                            # Add IP header
                        pkt.add_protocol(ipv4.ipv4(dst=subscriberIpStr, src=self.ip_addr, proto=pkt_ipv4.proto))
                            # Add TCP header (see https://sourceforge.net/p/ryu/mailman/message/34718081/)
                        tcpOptions = []
                        for op in pkt_tcp.option:
                            # See options in lib/packet/tcp.py
                            if op.kind == tcp.TCP_OPTION_KIND_NO_OPERATION:
                                tcpOptions.append(tcp.TCPOptionNoOperation())
                            elif op.kind == tcp.TCP_OPTION_KIND_MAXIMUM_SEGMENT_SIZE:
                                max_seg_size = op.max_seg_size
                                tcpOptions.append(tcp.TCPOptionMaximumSegmentSize(max_seg_size=max_seg_size))
                            elif op.kind == tcp.TCP_OPTION_KIND_SACK_PERMITTED:
                                tcpOptions.append(tcp.TCPOptionSACKPermitted())
                            elif op.kind == tcp.TCP_OPTION_KIND_WINDOW_SCALE:
                                shift_cnt = op.shift_cnt
                                tcpOptions.append(tcp.TCPOptionWindowScale(shift_cnt=shift_cnt))
                            elif op.kind == tcp.TCP_OPTION_KIND_TIMESTAMPS:
                                ts_val = op.ts_val
                                ts_ecr = op.ts_ecr
                                # 'ts_val' of the new packet should be a random number. Set to ts_val+1 for simplicity.
                                tcpOptions.append(tcp.TCPOptionTimestamps(ts_val=subscriberTS+1, ts_ecr=subscriberTS))

                        # Increase SEQ (with respect to ACK from previous message)
                        # The flags are the same than in the previous message (PSH, ACK)
                        pkt.add_protocol(tcp.tcp(src_port=mqtt.TCP_SERVER_PORT, dst_port=int(subscriberTCPPortStr), seq=subscriberSeq, ack=subscriberAck, offset=pkt_tcp.offset, bits=pkt_tcp.bits, window_size=pkt_tcp.window_size, csum=0, urgent=pkt_tcp.urgent, option=tcpOptions))

                        pkt.add_protocol(mqtt.mqtt(3, pkt_mqtt.mqttRemainingLength, returnCode=None, messageID=None, qos=None, topic=str(pkt_mqtt.topic.decode()), message=str(pkt_mqtt.message.decode())))
                        self.logger.debug("MAC table=%s", self.mac_to_port)
                        self.logger.debug("datapath.id=%s", datapath.id)
                        self.logger.debug("MAC addr=%s", macDstAddr)
                        self.logger.debug("MAC table=%s, MAC addr=%s", self.mac_to_port[datapath.id], macDstAddr)
                        self.logger.debug("### %s >>>>> MQTT PUBLISH message: %s (datapath=%s, port=%s)", now, pkt, datapath.id, self.mac_to_port[datapath.id][macDstAddr])

                        self._send_packet(datapath, self.mac_to_port[datapath.id][self.ipToMAC[subscriberIpStr]], pkt)
            return

        elif mqttPacketType == 14:
            # DISCONNECT (includes TCP FIN, which will be handled by the _handle_tcp() function - nothing to do here)
            self.logger.info("### %s > MQTT DISCONNECT received from %s", now, pkt_ipv4.src)

        # *** ADD OTHER MQTT MESSAGES TO BE RECEIVED HERE ***

        else:
            # Packet type not handled yet
            self.logger.info("### %s > MQTT message with Packet Type=%d received from %s, NOT SUPPORTED YET!", now, mqttPacketType, pkt_ipv4.src)


    def _send_packet(self, datapath, port, pkt):
        # Update TCP seq and ack if stored
        pkt_ethernet = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            if pkt_tcp:
                subscriberStr = pkt_ipv4.dst + "-" + str(pkt_tcp.dst_port)
                self.logger.debug("######### subscriber: %s, subscribersTCPInfo=%s", subscriberStr, self.subscribersTCPInfo)
                if subscriberStr in self.subscribersTCPInfo:
                    tcpPayloadSize=0
                    if len(pkt.protocols) == 4:
                        # pkt.protocols = [Ethernet, IP, TCP, APP] -> 4 means there is TCP payload (APP layer)
                        tcpPayload = pkt.protocols[-1]
                        tcpPayloadSize = len(tcpPayload)

                        # Get TCP ts_val (within the timestamps option)
                    if pkt_tcp.option:
                        timestamps = [op for op in pkt_tcp.option if op.kind == tcp.TCP_OPTION_KIND_TIMESTAMPS][0]

                    self.subscribersTCPInfo[subscriberStr] = [pkt_tcp.seq + tcpPayloadSize, pkt_tcp.ack, timestamps.ts_ecr]
                    self.logger.debug("######### subscribersTCPInfo updated for %s (TCP payload size=%d): %s", subscriberStr, tcpPayloadSize, self.subscribersTCPInfo[subscriberStr])

        # Send packet
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

