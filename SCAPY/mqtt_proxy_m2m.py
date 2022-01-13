#!/usr/bin/env python3
#
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021
#

from scapy.all import *
from threading import Thread, Lock, Timer

from scapy.contrib.mqtt import *

import socket, struct

import random
import sys, getopt
import pdb

import binascii
import time
from datetime import datetime

DEBUG=False

# Dictionary of subscribers: each entry has the topic as key and a list of lists ({IP address, TCP port, QoS}) of the subscribers for that topic
subscribersForTopic = {}
subscribersForTopic_lock = Lock() # To avoid concurrent access
# Dictionary of TCP connections (key = tuple([IP address, TCP port]) (IP address and TCP port from destination), value = seq or ack (from the MQTT proxy point of view))
tcpSeqList = {}
tcpAckList = {}
tcpInitSeqList = {}
tcpInitAckList = {}
# Dictionary of forwarders that should receive a given topic (i.e. an MQTT SUBSCRIBE message has been received from them, and no MQTT UNSUBSCRIBE has been sent by them)
forwardersForTopic = {}
forwardersForTopic_lock = Lock() # To avoid concurrent access

# Dictionary of topic to multicast IP address, and transactionID to topic
topicToMulticast = {}
topicToMulticastBackup = {} # Backup not deleted when there are no subscribers for this topic. Intended for publishers, so the MQTT proxy can multicast their messages.
transactionIDToTopic = {}
lastTimePublishMessageInTopic = {}
maxTimeBetweenPublishMessageInTopic = 3540 # 3600 is the default idle timeout of the SDN switches flow entries, so a slightly smaller value

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

class MQTTProxy:

   def __init__(self, tcpport, username, password, forwarders=None, udpport=None, mqtt2multicast_ip_addr_server=None, mqtt2multicast_udp_port_server=None, mqtt2multicast_udp_port_client=None):
      self.tcpport = tcpport
      self.username = username
      self.password = password
      self.forwarders = forwarders # List of forwarders 
      self.udpport = udpport
      self.mqtt2multicast_ip_addr_server = mqtt2multicast_ip_addr_server
      self.mqtt2multicast_udp_port_server = mqtt2multicast_udp_port_server
      self.mqtt2multicast_udp_port_client = mqtt2multicast_udp_port_client

      self._timeout = 1
      self._noClients = 0

   def _ack(self, p):
      index = tuple([p[IP].src,p[TCP].sport])

      ip = IP(src=p[IP].dst, dst=p[IP].src)
      ackPacket = ip/TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
      send(ackPacket, verbose=False)

      threadName = threading.currentThread().getName()
      if DEBUG: print ("[%s] %s TCP ACK sent! (seq=%d, ack=%d)" % (threadName, index, ackPacket[TCP].seq - tcpInitSeqList[index], ackPacket[TCP].ack - tcpInitAckList[index]))

   def _disconnect(self, dstIPAddress, srcIPAddress, tcpPort, connected):
      connected = False

      # Check if this IP address and TCP port is a subscriber, and remove from the list
      with subscribersForTopic_lock:
          for topic in subscribersForTopic.copy():
              subscribersList = subscribersForTopic[topic]
#              pdb.set_trace()
              subscribersList = [x for x in subscribersList if not(x[0] == srcIPAddress and x[1] == tcpPort)] # Removing based on the content of the first element. 
                                                                                                              # Maybe list comprehension is not the best for performance, but it works...
              subscribersForTopic[topic] = subscribersList                                                    # Required since subscribersList is now a different object
              # If this key has no content, remove it from the dictionary
              if not subscribersForTopic[topic]:
                  del subscribersForTopic[topic]

                  if self.mqtt2multicast_ip_addr_server:
                      self._unsubscribeFromTopicMQTT2MULTICAST(dstIPAddress, topic)

                  if self.forwarders:
                      # Sending MQTT UNSUBSCRIBE to forwarders using UDP
                      for i in range(len(self.forwarders)):
#                          pdb.set_trace()
                          forwarder = self.forwarders[i]
                          ipF = IP(src=dstIPAddress, dst=forwarder)
                          udpF = UDP(sport=self.udpport, dport=self.udpport)
                          # NOTE: if the length of the whole MQTT packet (4+len(topic)) is not set, the packet includes an extra byte (00) which makes the packet malformed. 
                          # Maybe related to QOS in SUBSCRIBE messages, which is not included in UNSUBSCRIBE?
                          mqttF = MQTT(type=11, len=4+len(topic))/MQTTUnsubscribe(msgid=1, topics=[MQTTTopicQOS(topic=topic, length=len(topic))])
                          send(ipF/udpF/mqttF, verbose=False)


      if DEBUG: print("[%s] %s (TCP port %d) disconnected. TOPICS-SUBSCRIBERS list: %s" % (threading.currentThread().getName(), srcIPAddress, tcpPort, subscribersForTopic))

   def _timerExpiration(self, p, connected):
       if DEBUG: print("[%s] Keep alive (MQTT PING REQUEST) timeout!!!" % (threading.currentThread().getName()))
       self._disconnect(p[IP].dst, p[IP].src, p[TCP].sport, connected)

   def _ack_rclose(self, p, connected):
      # Finish connection
      connected = False

      # The following line is commented to avoid forwarding two DISCONNECT REQ message when e.g. PUBLISHing a message
      # (the first one due to the DISCONNECT REQ, the second one due to the TCP FIN packet)
      # In the case of closing with ctrl+C a subscriber, the DISCONNECT REQ message will be forwarded when
      # the corresponding timer (for PING REQ) expires.

      self._disconnect(p[IP].dst, p[IP].src, p[TCP].sport, connected)

      # Send FIN + ACK
      index = tuple([p[IP].src,p[TCP].sport])

      ip = IP(src=p[IP].dst, dst=p[IP].src)
      finAckPacket = ip/TCP(sport=self.tcpport, dport=p[TCP].sport, flags='FA', seq=tcpSeqList[index], ack=tcpAckList[index])
      send(finAckPacket, verbose=False)

      threadName = threading.currentThread().getName()
      if DEBUG: print ("[%s] %s TCP FIN + ACK sent! (seq=%d, ack=%d)" % (threadName, index, finAckPacket[TCP].seq - tcpInitSeqList[index], finAckPacket[TCP].ack - tcpInitAckList[index]))

      tcpSeqList[index] = tcpSeqList[index] + 1

#      assert ackPacket.haslayer(TCP), 'TCP layer missing'
#      assert ackPacket[TCP].flags & 0x10 == 0x10 , 'No ACK flag'
#      assert ackPacket[TCP].ack == seq , 'Acknowledgment number error'

   def _sendAckIfNeeded(self, p, connected):
      # Send ACK
      if not p[TCP].flags & 0x01 == 0x01:
          # Normal ACK
          self._ack(p)
      else:
          # FIN received in this MQTT message, sending FIN+ACK (this happens with the MQTT DISCONNECT message, which does not require an MQTT response)
          connected = False
          threadName = threading.currentThread().getName()
          index = tuple([p[IP].src,p[TCP].sport])
          if DEBUG: print("[%s] FIN received within this MQTT message (seq=%d, ack=%d, len=%d), tcpAckList: %s" % (threadName, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT]), tcpAckList))
          tcpAckList[index] = tcpAckList[index] + 1
          self._ack_rclose(p, connected)

   def _broadcastMessageForTopic(self, p, topic, message):
      with subscribersForTopic_lock:
          if topic in subscribersForTopic:
              subscribersList = subscribersForTopic[topic]
              for x in subscribersList:
                  ipAddress = x[0]
                  tcpPort = x[1]
                  QOS = x[2]
                  print("Broadcasting MQTT PUBLISH - sending message %s to %s (TCP port %d) with topic %s and QoS %d" % (message, ipAddress, tcpPort, topic, QOS))

                  index = tuple([ipAddress,tcpPort])
                  #ipB = IP(src=p[IP].dst, dst=ipAddress) # Avoid specifying the source address, since it will be incorrect for received multicast messages
                  ipB = IP(dst=ipAddress)
                  tcpB = TCP(sport=self.tcpport, dport=tcpPort, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                  mqttB = MQTT()/MQTTPublish(topic=topic,value=message)
#                  pdb.set_trace()
                  send(ipB/tcpB/mqttB)#, verbose=False)
                  threadName = threading.currentThread().getName()
                  if DEBUG: print("[%s] %s MQTT PUBLISH sent! (src=%s, dst=%s, seq=%d, ack=%d, len=%d)" % (threadName, index, p[IP].dst, ipAddress, tcpB.seq - tcpInitSeqList[index], tcpB.ack - tcpInitAckList[index], len(mqttB)))
                  tcpSeqList[index] = tcpSeqList[index] + len(mqttB)
          else:
              print("Broadcasting MQTT PUBLISH - no one subscribed to topic %s" % (topic))

   def _checkIfTopicIsNewMQTT2MULTICAST(self, dstIPAddress, topic, flags, force):
      # If it is a new topic, send a MQTT2MULTICAST REQUEST message to the MQTT2MULTICAST server (SDN controller)
      if (topic.decode() in topicToMulticast) and (not force):
          # Existing topic
          multicastIPAddress = topicToMulticast[topic.decode()]
          if DEBUG: print("[%s] MQTT2MULTICAST - existing topic=%s, multicast IP address=%s" % (threading.currentThread().getName(), topic, multicastIPAddress))

      else:
          # New topic
          ipM2M = IP(src=dstIPAddress, dst=self.mqtt2multicast_ip_addr_server)
          udpM2M = UDP(sport=self.mqtt2multicast_udp_port_client, dport=self.mqtt2multicast_udp_port_server)

          packetType=1
          transactionID=random.getrandbits(32)
          topicLength = len(topic)
          #flags = 1
          M2MContent = bytearray(struct.pack('!BIBH', packetType, transactionID, flags, topicLength))
          #M2MContent.extend(bytearray(topic.encode()))
          M2MContent.extend(topic)

          print("[%s] MQTT2MULTICAST REQUEST sent, topic=%s, transactionID=%d, flags=%d" % (threading.currentThread().getName(), topic, transactionID, flags))
          transactionIDToTopic[transactionID] = topic

          send(ipM2M/udpM2M/Raw(load=M2MContent), verbose=False)
          # The multicastIPAddress will be included as soon as the MQTT2MULTICAST REPLY message is received from the MQTT2MULTICAST server (SDN controller)

   def _unsubscribeFromTopicMQTT2MULTICAST(self, dstIPAddress, topic):
          ipM2M = IP(src=dstIPAddress, dst=self.mqtt2multicast_ip_addr_server)
          udpM2M = UDP(sport=self.mqtt2multicast_udp_port_client, dport=self.mqtt2multicast_udp_port_server)

          packetType=1
          transactionID=random.getrandbits(32)
          topicLength = len(topic)
          flags = 2
          M2MContent = bytearray(struct.pack('!BIBH', packetType, transactionID, flags, topicLength))
          #print("### Topic: %s" % (topic))
          M2MContent.extend(bytearray(topic.encode()))
          #M2MContent.extend(topic)

          print("[%s] MQTT2MULTICAST REQUEST sent (unsubscribe), topic=%s, transactionID=%d, flags=%d" % (threading.currentThread().getName(), topic, transactionID, flags))
          transactionIDToTopic[transactionID] = topic

          send(ipM2M/udpM2M/Raw(load=M2MContent), verbose=False)
          # The multicastIPAddress will be included as soon as the MQTT2MULTICAST REPLY message is received from the MQTT2MULTICAST server (SDN controller)

          if topic in topicToMulticast:
              del topicToMulticast[topic]
          if DEBUG: print("[%s] MQTT2MULTICAST - topicToMulticast: %s" % (threading.currentThread().getName(), topicToMulticast))
          

   def _mqttProxy(self, clientIPAddress, clientTCPPort):
      connected = True
      keepAlive = 60 # Default value, sent on MQTT CONNECT
      threadName = threading.currentThread().getName()

      if DEBUG: print("[%s] NEW THREAD for client %s (TCP port %s)" % (threadName, clientIPAddress, clientTCPPort))

# IMPORTANT: L3RawSocket filters DO NOW WORK (or I am not able to get them working!), so finally I have used the sniff() function (in which filters do work)
#      s = L3RawSocket(filter='host ' + str(clientIPAddress) + ' and tcp and tcp port ' + str(clientTCPPort))

      interfacesList = get_if_list()#[1:]
      if DEBUG: print("[%s] MQTT proxy - interfaces to sniff: %s (all interfaces: %s)" % (threadName, interfacesList, get_if_list()))
      while connected:
#         p = s.recv(MTU)

         p = sniff(count=1, iface=interfacesList, filter='host ' + str(clientIPAddress) + ' and tcp and tcp port ' + str(clientTCPPort))[0]

         # MQTT message received
         if p.haslayer(TCP) and p.haslayer(MQTT) and p[TCP].dport == self.tcpport:
            index = tuple([p[IP].src,p[TCP].sport])
#            if DEBUG: print("[%s] %s MQTT packet type: %d" % (threadName, index, p[MQTT].type))
#            if DEBUG: print("[%s] tcpAckList: %s" % (threadName, tcpAckList))
            if p[TCP].seq >= tcpAckList[index]:
               tcpAckList[index] = tcpAckList[index] + len(p[MQTT])
#               if DEBUG: print("[%s] tcpAckList[%s]: %d, p[TCP].seq: %d" % (threadName, index, tcpAckList[index] - tcpInitAckList[index], p[TCP].seq - tcpInitAckList[index]))
            else:
               print("[%s] DUPLICATED!!! - tcpAckList[%s]: %d, p[TCP].seq: %d" % (threadName, index, tcpAckList[index] - tcpInitAckList[index], p[TCP].seq - tcpInitAckList[index]))
               continue

            if p[MQTT].type == 1:
                # MQTT CONNECT received, sending MQTT CONNACK
#                pdb.set_trace()
                keepAlive = p[MQTT].klive
                ip = IP(src=p[IP].dst, dst=p[IP].src)
                tcp = TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                if p[MQTT].username.decode() == self.username and p[MQTT].password.decode() == self.password:
                    mqtt = MQTT()/MQTTConnack(sessPresentFlag=1,retcode=0)
                    print("[%s] %s MQTT CONNECT received (seq=%d, ack=%d, len=%d), correct user/password, keepAlive=%d" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT]), keepAlive))
                else:
                    mqtt = MQTT()/MQTTConnack(sessPresentFlag=1,retcode=5)
                    print("[%s] %s MQTT CONNECT received (seq=%d, ack=%d, len=%d), wrong user/password" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT])))

                self._sendAckIfNeeded(p, connected)
                send(ip/tcp/mqtt, verbose=False)
                if DEBUG: print ("[%s] %s MQTT CONNACK sent! (seq=%d, ack=%d, len=%d)" % (threadName, index, tcp.seq - tcpInitSeqList[index], tcp.ack - tcpInitAckList[index], len(mqtt)))
                tcpSeqList[index] = tcpSeqList[index] + len(mqtt)

            elif p[MQTT].type == 3:
                # MQTT PUBLISH received
                topic=p[MQTT][1].topic
                message=p[MQTT][1].value
#                pdb.set_trace()
                print("[%s] %s MQTT PUBLISH received (seq=%d, ack=%d, len=%d), topic=%s, message=%s" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT]), topic, message))

                self._sendAckIfNeeded(p, connected)

                # If an MQTT2MULTICAST server is configured
                if self.mqtt2multicast_ip_addr_server:

                    now = datetime.now()
                    if topic.decode() in lastTimePublishMessageInTopic:
                        timeBetweenPublishMessages = (now - lastTimePublishMessageInTopic[topic.decode()]).total_seconds()
                        lastTimePublishMessageInTopic[topic.decode()] = now
                        if timeBetweenPublishMessages >= maxTimeBetweenPublishMessageInTopic:
                            # If the last publish message for this topic was too long ago, refresh the MQTT2MULTICAST messages
                            self._checkIfTopicIsNewMQTT2MULTICAST(p[IP].dst, topic, 0, True)
                    else:
                        lastTimePublishMessageInTopic[topic.decode()] = now
                        if not topic.decode() in topicToMulticastBackup:
                            self._checkIfTopicIsNewMQTT2MULTICAST(p[IP].dst, topic, 0, False)

                # Broadcast MQTT PUBLISH to subscribers connected to this proxy
                self._broadcastMessageForTopic(p, topic.decode(), message.decode())

                # Send to the multicast address assigned to this topic
                if self.mqtt2multicast_ip_addr_server:
                    if DEBUG: print("[%s] topicToMulticastBackup: %s, topic=%s" % (threadName, topicToMulticastBackup, topic.decode()))

                    if topic.decode() in topicToMulticastBackup:
                        # Existing topic
                        multicastIPAddress = topicToMulticastBackup[topic.decode()]
                        print("[%s] Multicasting the received MQTT PUBLISH message, src=%s, multicast IP address=%s, topic=%s, message=%s" % (threadName, p[IP].dst, multicastIPAddress, topic.decode(), message.decode()))
                        ethM = Ether(dst="FF:FF:FF:FF:FF:FF", src=p[Ether].dst) # Multicast not working if ethernet layer is not included in the packet
                        ipM = IP(src=p[IP].dst, dst=multicastIPAddress, ttl=1)  # TTL=1 to avoid flooding packets beyond this network
                        udpM = UDP(sport=self.udpport, dport=self.udpport)
                        mqttM = p[MQTT]
#                        pdb.set_trace()
                        sendp(ethM/ipM/udpM/mqttM, verbose=False)

                    else:
                        print("[%s] ERROR!!!! Trying to multicast the received MQTT PUBLISH message, but no nulticast IP address was found for topic=%s. Wait 10s for a MQTT2MULTICAST REPLY message." % (threadName, topic.decode()))
                        waiting = True
                        i=0
                        # Typically only one second (one attempt) has to be wait if everything is ok
                        while waiting:
                            time.sleep(1.0)
                            i = i + 1
                            print("[%s] Wait %d seconds" % (threadName, i))

                            if topic.decode() in topicToMulticastBackup:
                                waiting = False
                                multicastIPAddress = topicToMulticastBackup[topic.decode()]
                                print("[%s] Multicasting the received MQTT PUBLISH message, src=%s, multicast IP address=%s, topic=%s, message=%s" % (threadName, p[IP].dst, multicastIPAddress, topic.decode(), message.decode()))
                                ethM = Ether(dst="FF:FF:FF:FF:FF:FF", src=p[Ether].dst) # Multicast not working if ethernet layer is not included in the packet
                                ipM = IP(src=p[IP].dst, dst=multicastIPAddress, ttl=1)  # TTL=1 to avoid flooding packets beyond this network
                                udpM = UDP(sport=self.udpport, dport=self.udpport)
                                mqttM = p[MQTT]
#                                pdb.set_trace()
                                sendp(ethM/ipM/udpM/mqttM, verbose=False)

                            elif i >= 10:
                                waiting = False
                                print("[%s] No MQTT2MULTICAST REPLY message received, discarding MQTT PUBLISH message (topic=%s, message=%s)" % (threadName, multicastIPAddress, topic.decode(), message.decode()))

                        # If there is no subscriber, the topic is removed from topicToMulticast
                        if not topic.decode() in subscribersForTopic:
                            if topic.decode() in topicToMulticast:
                                del topicToMulticast[topic.decode()]

                # Forward MQTT PUBLISH to forwarder using UDP
                if self.forwarders:
                    if topic.decode() in forwardersForTopic:
                        forwardersForThisTopic = forwardersForTopic[topic.decode()]
#                        pdb.set_trace()
                        for i in range(len(forwardersForThisTopic[0])):
                            forwarder = forwardersForThisTopic[0][i]
                            ipF = IP(src=p[IP].dst, dst=forwarder)
                            udpF = UDP(sport=self.udpport, dport=self.udpport)
                            mqttF = p[MQTT]
#                            pdb.set_trace()
                            send(ipF/udpF/mqttF, verbose=False)

            elif p[MQTT].type == 8:
                # MQTT SUBSCRIBE received, sending MQTT SUBACK
#                pdb.set_trace()
                topic = p[MQTT][2].topic
                QOS = p[MQTT][2].QOS
                ipAddress = p[IP].src
                tcpPort = p[TCP].sport
                print("[%s] %s MQTT SUBSCRIBE received (seq=%d, ack=%d, len=%d), topic=%s, QoS=%d" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT]), topic, QOS))

                # If an MQTT2MULTICAST server is configured
                if self.mqtt2multicast_ip_addr_server:
                    self._checkIfTopicIsNewMQTT2MULTICAST(p[IP].dst, topic, 1, False)

                # Add subscriber to the list of topics (list of lists)
                with subscribersForTopic_lock:
                    if topic.decode() in subscribersForTopic:
                        # Existing topic
                        subscribersForThisTopic = subscribersForTopic[topic.decode()]
                        subscribersForThisTopic.append([ipAddress, tcpPort, QOS])
                    else:
                        # New topic
                        subscribersForTopic[topic.decode()] = [[ipAddress, tcpPort, QOS]]

                        # If the topic is new, forward MQTT SUBSCRIBE to forwarder using UDP
                        if self.forwarders:
                            for i in range(len(self.forwarders)):
                                forwarder = self.forwarders[i]
                                ipF = IP(src=p[IP].dst, dst=forwarder)
                                udpF = UDP(sport=self.udpport, dport=self.udpport)
                                mqttF = p[MQTT]
                                send(ipF/udpF/mqttF, verbose=False)

                if DEBUG: print("[%s] %s Subscribers list for this topic: %s" % (threadName, index, subscribersForTopic[topic.decode()]))
                if DEBUG: print("[%s] %s TOPICS-SUBSCRIBERS list:         %s" % (threadName, index, subscribersForTopic))

                ip = IP(src=p[IP].dst, dst=p[IP].src)
                tcp = TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                mqtt = MQTT()/MQTTSuback(msgid=p[MQTT].msgid, retcode=QOS) # 'retcode' in MQTT SUBACK is really granted QoS
                self._sendAckIfNeeded(p, connected)
                send(ip/tcp/mqtt, verbose=False)
                if DEBUG: print ("[%s] %s MQTT SUBACK sent! (seq=%d, ack=%d, len=%d)" % (threadName, index, tcp.seq - tcpInitSeqList[index], tcp.ack - tcpInitAckList[index], len(mqtt)))
                tcpSeqList[index] = tcpSeqList[index] + len(mqtt)

                # Create a timer. If there is a timeout (PING REQUEST not received), the client is assumed to be disconnected.
                if DEBUG: print("[%s] %s KEEP ALIVE timer started!!!" % (threadName, index))
                t = Timer(keepAlive+10, self._timerExpiration, args=(p, connected,))
                t.start()

            elif p[MQTT].type == 12:
                # PING REQUEST received, sending MQTT PING RESPONSE
#                pdb.set_trace()
                if DEBUG: print("[%s] %s MQTT PING REQUEST received (seq=%d, ack=%d, len=%d)" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT])))
                ip = IP(src=p[IP].dst, dst=p[IP].src)
                tcp = TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                mqtt = MQTT(type=13,len=0)
                self._sendAckIfNeeded(p, connected)
                send(ip/tcp/mqtt, verbose=False)
                if DEBUG: print ("[%s] %s MQTT PING RESPONSE sent! (seq=%d, ack=%d, len=%d)" % (threadName, index, tcp.seq - tcpInitSeqList[index], tcp.ack - tcpInitAckList[index], len(mqtt)))
                tcpSeqList[index] = tcpSeqList[index] + len(mqtt)

                # Restart timer
                if DEBUG: print("[%s] %s Keep alive timer restarted!!!" % (threadName, index))
                t.cancel()
                t = Timer(keepAlive+10, self._timerExpiration, args=(p, connected,))
                t.start()

            elif p[MQTT].type == 14:
                # MQTT DISCONNECT REQ received
#                pdb.set_trace()                
                print("[%s] %s MQTT DISCONNECT REQ received (seq=%d, ack=%d, len=%d)" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index], len(p[MQTT])))
                self._sendAckIfNeeded(p, connected)
                self._disconnect(p[IP].dst, p[IP].src, p[TCP].sport, connected)

            # ADD OTHER MQTT MESSAGES HERE


         # TCP FIN received, sending TCP FIN+ACK
         elif p.haslayer(TCP) and p[TCP].dport == self.tcpport and p[TCP].flags & FIN:
            index = tuple([p[IP].src,p[TCP].sport])
            if DEBUG: print ("[%s] %s TCP FIN received (seq=%d, ack=%d)" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index]))

            connected = False
            if DEBUG: print("[%s] tcpAckList: %s" % (threadName, tcpAckList))
            tcpAckList[index] = tcpAckList[index] + 1
#            pdb.set_trace()
            self._ack_rclose(p, connected)

         # TCP ACK received
         elif p.haslayer(TCP) and p[TCP].dport == self.tcpport and p[TCP].flags & ACK:
            index = tuple([p[IP].src,p[TCP].sport])
            if DEBUG: print ("[%s] %s TCP ACK received! (seq=%d, ack=%d)" % (threadName, index, p[TCP].seq - tcpInitAckList[index], p[TCP].ack - tcpInitSeqList[index])) # Do nothing

#      s.close()
      self._mqttServerThread = None
      print('[%s] MQTT server thread stopped' % (threadName))

   def _start_mqttServerForThisClientThread(self, clientIPAddress, clientTCPPort):
      self._noClients = self._noClients + 1
      print("[MAIN] STARTING THREAD for serving MQTT client no. %s (name=%s) ..." % (str(self._noClients), threading.currentThread().getName()))
      mqttServerForThisClientThread = Thread(name='MQTTServerThread'+str(self._noClients), target=self._mqttProxy, args=(clientIPAddress, clientTCPPort))
      mqttServerForThisClientThread.start()

   def waitForConnections(self):

      # Infinite loop for clients      
      while True:
         print("[MAIN] Waiting for a new connection on port " + str(self.tcpport) + "...")
         # Wait for a new connection (TCP SYN on server's port)
         interfacesList = get_if_list()#[1:]
         if DEBUG: print("[MAIN] Interfaces to sniff: %s (all interfaces: %s)" % (interfacesList, get_if_list()))
         synPacket = sniff(count=1, iface=interfacesList, filter='tcp and port ' + str(self.tcpport) + ' and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0')[0]
         if DEBUG: print ("[MAIN] NEW CONNECTION: Received TCP SYN from %s (TCP port %s) (seq=0, ack=0)" % (synPacket[IP].src, synPacket[TCP].sport))
         # Create TCP SYN+ACK packet
         sport = synPacket[TCP].sport
         index = tuple([synPacket[IP].src,synPacket[TCP].sport])
         tcpInitSeqList[index] = random.getrandbits(32) # Random number of 32 bits
         tcpSeqList[index] = tcpInitSeqList[index]
         tcpInitAckList[index] = synPacket[TCP].seq
         tcpAckList[index] = tcpInitAckList[index] + 1 # SYN+ACK
#         if DEBUG: print("[MAIN] tcpAckList: %s" % (tcpAckList))

         # Generating the IP layer
         ip = IP(src=synPacket[IP].dst, dst=synPacket[IP].src)
         # Generating the TCP layer
         tcpSynAck = TCP(sport=self.tcpport, dport=sport, flags="SA", seq=tcpSeqList[index], ack=tcpAckList[index], options=[('MSS', 1460)])
         # Start new thread for this connection
         self._start_mqttServerForThisClientThread(synPacket[IP].src, synPacket[TCP].sport)
         # Send SYN+ACK and receive ACK
         tcpSeqList[index] = tcpSeqList[index] + 1
         send(ip/tcpSynAck, verbose=False)
         if DEBUG: print ("[MAIN] %s TCP SYN+ACK sent! (seq=%d, ack=%d)" % (index, tcpSynAck.seq - tcpInitSeqList[index], tcpSynAck.ack - tcpInitAckList[index]))

   def _udpForwarder(self):
      # Infinite loop to handle UDP messages from other MQTT proxies
      # Wait for a new UDP (MQTT) packet from the corresponding port
      interfacesList = get_if_list()#[1:]
      if DEBUG: print("[%s] UDP forwarder - interfaces to sniff: %s (all interfaces: %s)" % (threading.currentThread().getName(), interfacesList, get_if_list()))

      while True:
         p = sniff(count=1, iface=interfacesList, filter='inbound and udp and port ' + str(self.udpport))[0] 
         if DEBUG: print ("[%s] FORWARDER received packet %s from %s (UDP port %d)" % (threading.currentThread().getName(), p, p[IP].src, p[UDP].sport))
#         pdb.set_trace()

         if p.haslayer(MQTT):
             if p[MQTT].type == 8:
                 # SUBSCRIBE
                 # Create a dictionary of topics and forwarders subscribed to the topic
                 topic = p[MQTT][2].topic
                 forwarderIPAddress = p[IP].src
                 print("[FORWARDER] MQTT SUBSCRIBE received, topic=%s" % (topic))

                 # Add subscriber to the list of topics (list of lists)
                 with forwardersForTopic_lock:
                     if topic.decode() in forwardersForTopic:
                         # Existing topic
                         forwardersForThisTopic = forwardersForTopic[topic.decode()]
                         forwardersForThisTopic.append([forwarderIPAddress])
                     else:
                         # New topic
                         forwardersForTopic[topic.decode()] = [[forwarderIPAddress]]
                     if DEBUG: print("[FORWARDER] forwardersForTopic: %s" % (forwardersForTopic))

             elif p[MQTT].type == 11:
                 # UNSUBSCRIBE
                 # Remove this forwarder from the dictionary of topics
#                 pdb.set_trace()
                 #topic = p[MQTT][2].topic
                 topic = p[MQTT][2].load[:p[MQTT][2].len]
                 print("[FORWARDER] MQTT UNSUBSCRIBE received") #, topic=%s" % (topic))
                 forwarderIPAddress = p[IP].src
                 with forwardersForTopic_lock:
                     for topic in forwardersForTopic.copy():
                         forwardersList = forwardersForTopic[topic]
                         forwardersList = [x for x in forwardersList if not(x[0] == forwarderIPAddress)] # Removing based on the content of the first element. 
                                                                                                         # Maybe list comprehension is not the best for performance, but it works...
                     forwardersForTopic[topic] = forwardersList                                          # Required since forwardersList is now a different object
                     # If this key has no content, remove it from the dictionary
                     if not forwardersForTopic[topic]:
                         del forwardersForTopic[topic]
                     if DEBUG: print("[FORWARDER] forwardersForTopic: %s" % (forwardersForTopic))

             elif p[MQTT].type == 3:
                 # PUBLISH: forward this MQTT message to the forwarders subscribed on this proxy
                 topic=p[MQTT][1].topic
                 message=p[MQTT][1].value
                 print("[FORWARDER] MQTT PUBLISH received, topic=%s, message=%s" % (topic, message))
                 # Broadcast MQTT PUBLISH to subscribers connected to this proxy
                 self._broadcastMessageForTopic(p, topic.decode(), message.decode())

   def _start_udpForwarderThread(self):
      print ("Starting thread UDPForwarderThread to forward MQTT using UDP...")
      udpForwarderThread = Thread(name='UDPForwarderThread', target=self._udpForwarder)
      udpForwarderThread.start()

   def _mqtt2Multicast(self):
      # Infinite loop to handle MQTT2MULTICAST messages from the MQTT2MULTICAST server
      # Wait for a new UDP (MQTT2MULTICAST) packet from the corresponding port
      interfacesList = get_if_list()#[1:]
      if DEBUG: print("[%s] MQTT2MULTICAST listeners - interfaces to sniff: %s (all interfaces: %s)" % (threading.currentThread().getName(), interfacesList, get_if_list()))

      while True:
         p = sniff(count=1, iface=interfacesList, filter='inbound and udp and port ' + str(self.mqtt2multicast_udp_port_client))[0] 
#         pdb.set_trace()

         if DEBUG: print("[%s] MQTT2MULTICAST message received!!!" % (threading.currentThread().getName()))

         if p.haslayer(UDP):
            hexStr=binascii.hexlify(bytes(p[UDP].payload))
            if DEBUG: print("[%s] MQTT2MULTICAST listener received from %s (UDP port %d) packet with payload: 0x%s" % (threading.currentThread().getName(), p[IP].src, p[UDP].sport, hexStr.decode()))

         tmpBuffer = bytes(p[UDP].payload)
         _MQTT2MULTICAST_PACK_STR='!BIB'
         _MIN_LEN = struct.calcsize(_MQTT2MULTICAST_PACK_STR)
         (mqtt2multicastPacketType, mqtt2multicastTransactionID, mqtt2multicastFlags) = struct.unpack_from(_MQTT2MULTICAST_PACK_STR, tmpBuffer)

         if mqtt2multicastPacketType == 2:
             # If a MQTT2MULTICAST REPLY packet is received, store the multicast IP address for the corresponding topic (using the matching transaction ID)
             tmpBuffer=tmpBuffer[_MIN_LEN:]
             (mqtt2multicastIPAddress, ) = struct.unpack_from('!I', tmpBuffer)
             mqtt2multicastIPAddressStr = socket.inet_ntoa(mqtt2multicastIPAddress.to_bytes(4, 'big'))
             topic = transactionIDToTopic[mqtt2multicastTransactionID]
             print("[%s] MQTT2MULTICAST listener - received MQTT2MULTICAST IP Address (transaction ID: %d, topic:%s, flags=%d): %s" % (threading.currentThread().getName(), mqtt2multicastTransactionID, topic.decode(), int(mqtt2multicastFlags), mqtt2multicastIPAddressStr))
             topicToMulticast[topic.decode()] = mqtt2multicastIPAddressStr
             topicToMulticastBackup[topic.decode()] = mqtt2multicastIPAddressStr

   def _start_mqtt2MulticastThread(self):
      print ("Starting thread mqtt2MulticastThread to receive MQTT2MULTICAST REPLY messages...")
      mqtt2MulticastThread = Thread(name='mqtt2MulticastThread', target=self._mqtt2Multicast)
      mqtt2MulticastThread.start()


def main():
    # Initialization
    forwarders = list()
    udpport = 0
    mqtt2multicast_ip_addr_server = None
    mqtt2multicast_udp_port_server = 0
    mqtt2multicast_udp_port_client = 0

    # Required to interprete UDP packets on port 1883 as MQTT
    bind_layers(UDP, MQTT, sport=1883)
    bind_layers(UDP, MQTT, dport=1883)

    # Command-line arguments
    print("Arguments: %s" % (sys.argv))

    # Take arguments from command line (getopt)
    try:
        opts, args = getopt.getopt(sys.argv[1:],"ht:u:p:F:U:s:S:C:",["tcpport=","username=","password=","forwarder=","udpport="])
    except getopt.GetoptError:
        print ("%s -t <TCP port> -u <username> -p <password> -F <IP address of UDP MQTT forwarder #1> -F <IP address of UDP MQTT forwarder #2> [...] -U <UDP port> [-s <MQTT2MULTICAST server IP address>] [-S <MQTT2MULTICAST server port>] [-C <MQTT2MULTICAST client port>]" % (sys.argv[0]))
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ("%s -t <TCP port> -u <username> -p <password> -F <IP address of UDP MQTT forwarder #1> -F <IP address of UDP MQTT forwarder #2> [...] -U <UDP port> [-s <MQTT2MULTICAST server IP address>] [-S <MQTT2MULTICAST server port>] [-C <MQTT2MULTICAST client port>]" % (sys.argv[0]))
            sys.exit()
        elif opt in ("-t", "--tcpport"):
            tcpport = int(arg)
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-F", "--forwarder"):
            forwarders.append(arg)
        elif opt in ("-U", "--udpport"):
            udpport = int(arg)
        elif opt in ("-s", "--server"):
            mqtt2multicast_ip_addr_server = arg
        elif opt in ("-S", "--server-port"):
            mqtt2multicast_udp_port_server = int(arg)
        elif opt in ("-C", "--client-port"):
            mqtt2multicast_udp_port_client = int(arg)

    print("MQTT credentials: username=%s, password=%s" % (username, password))

    # Create an MQTTProxy object
    proxy = MQTTProxy(tcpport, username, password, forwarders, udpport, mqtt2multicast_ip_addr_server, mqtt2multicast_udp_port_server, mqtt2multicast_udp_port_client)

    # Execute a UDP forwarder thread (if any forwarder has been configured from command line parameters)
    if forwarders:
        print("Listening MQTT on TCP port %d and forwarding MQTT messages to %s (UDP port %d)" % (tcpport, forwarders, udpport))
        proxy._start_udpForwarderThread()
    else:
        print("Listening MQTT on TCP port %d with no MQTT forwarding" % (tcpport))

    # Execute an MQTT2MULTICAST thread (if an MQTT2MULTICAST server has been configured)
    if mqtt2multicast_ip_addr_server:
        # Execute MQTT2MULTICAST listener (to receive MQTT2MULTICAST REPLY messages)
        proxy._start_mqtt2MulticastThread()


    # Execute the MQTTProxy infinite loop waiting for MQTT connections
    proxy.waitForConnections()


if __name__ == "__main__":
    main()

