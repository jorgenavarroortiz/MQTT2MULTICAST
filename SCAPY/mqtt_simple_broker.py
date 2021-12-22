#!/usr/bin/env python3
#
# Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada
#

from scapy.all import *
from threading import Thread, Lock, Timer

from scapy.contrib.mqtt import *

import random
import sys, getopt
import pdb

# Dictionary of subscribers: each entry has the topic as key and a list of lists ({IP address, TCP port, QoS}) of the subscribers for that topic
subscribersForTopic = {}
subscribersForTopic_lock = Lock() # To avoid concurrent access
# Dictionary of TCP connections (key = tuple([IP address, TCP port]) (IP address and TCP port from destination), value = seq or ack (from the MQTT broker point of view))
tcpSeqList = {}
tcpAckList = {}

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

class MQTTBroker:

   def __init__(self, iface, tcpport, username, password):
      self.iface = iface
      self.tcpport = tcpport
      self.username = username
      self.password = password

      self._timeout = 1

      self._noClients = 0

   def _ack(self, p):
      index = tuple([p[IP].src,p[TCP].sport])

      ip = IP(src=p[IP].dst, dst=p[IP].src)
      ackPacket = ip/TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
      send(ackPacket, verbose=False)

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

      print("[%s] %s (TCP port %d) disconnected. TOPICS-SUBSCRIBERS list:         %s" % (threading.currentThread().getName(), srcIPAddress, tcpPort, subscribersForTopic))

   def _timerExpiration(self, p, connected):
       print("[%s] Keep alive (MQTT PING REQUEST) timeout!!!" % (threading.currentThread().getName()))
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
      tcpSeqList[index] = tcpSeqList[index] + 1

#      assert ackPacket.haslayer(TCP), 'TCP layer missing'
#      assert ackPacket[TCP].flags & 0x10 == 0x10 , 'No ACK flag'
#      assert ackPacket[TCP].ack == seq , 'Acknowledgment number error'

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
                  ipB = IP(src=p[IP].dst, dst=ipAddress)
                  tcpB = TCP(sport=self.tcpport, dport=tcpPort, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                  mqttB = MQTT()/MQTTPublish(topic=topic,value=message)
#                  pdb.set_trace()
                  send(ipB/tcpB/mqttB)#, verbose=False)
                  tcpSeqList[index] = tcpSeqList[index] + len(mqttB)
          else:
              print("Broadcasting MQTT PUBLISH - no one subscribed to topic %s" % (topic))

   def _mqttBroker(self, clientIPAddress, clientTCPPort):
      connected = True
      keepAlive = 60 # Default value, sent on MQTT CONNECT
      threadName = threading.currentThread().getName()

      print("[%s] NEW THREAD for client %s (TCP port %s)" % (threadName, clientIPAddress, clientTCPPort))

# IMPORTANT: L3RawSocket filters DO NOW WORK (or I am not able to get them working!), so finally I have used the sniff() function (in which filters do work)
#      s = L3RawSocket(filter='host ' + str(clientIPAddress) + ' and tcp and tcp port ' + str(clientTCPPort))

      interfacesList = get_if_list()[1:]
      while connected:
#         p = s.recv(MTU)

         p = sniff(count=1, iface=interfacesList, filter='host ' + str(clientIPAddress) + ' and tcp and tcp port ' + str(clientTCPPort))[0]

         # MQTT message received
         if p.haslayer(TCP) and p.haslayer(MQTT) and p[TCP].dport == self.tcpport:
            index = tuple([p[IP].src,p[TCP].sport])
            print("[%s] %s MQTT packet type: %d" % (threadName, index, p[MQTT].type))
            print("[%s] tcpAckList: %s" % (threadName, tcpAckList))
            tcpAckList[index] = tcpAckList[index] + len(p[MQTT])

            # Send ACK
            if not p[TCP].flags & 0x01 == 0x01:
                # Normal ACK
                self._ack(p)
            else:
                # FIN received, sending FIN+ACK (this happens with the MQTT DISCONNECT message, which does not require an MQTT response)
                connected = False
                print("[%s] tcpAckList: %s" % (threadName, tcpAckList))
                tcpAckList[index] = tcpAckList[index] + 1
                self._ack_rclose(p, connected)

            if p[MQTT].type == 1:
                # MQTT CONNECT received, sending MQTT CONNACK
#                pdb.set_trace()
                keepAlive = p[MQTT].klive
                ip = IP(src=p[IP].dst, dst=p[IP].src)
                tcp = TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                if p[MQTT].username.decode('utf-8') == self.username and p[MQTT].password.decode('utf-8') == self.password:
                    mqtt = MQTT()/MQTTConnack(sessPresentFlag=1,retcode=0)
                    print("[%s] %s MQTT CONNECT received, correct user/password, keepAlive=%d" % (threadName, index, keepAlive))
                else:
                    mqtt = MQTT()/MQTTConnack(sessPresentFlag=1,retcode=5)
                    print("[%s] %s MQTT CONNECT received, wrong user/password" % (threadName, index))
                send(ip/tcp/mqtt, verbose=False)
                tcpSeqList[index] = tcpSeqList[index] + len(mqtt)

            elif p[MQTT].type == 3:
                # MQTT PUBLISH received
                topic=p[MQTT][1].topic
                message=p[MQTT][1].value
#                pdb.set_trace()
                print("[%s] %s MQTT PUBLISH received, topic=%s, message=%s" % (threadName, index, topic, message))

                # Broadcast MQTT PUBLISH to subscribers connected to this proxy
                self._broadcastMessageForTopic(p, topic.decode('utf-8'), message.decode('utf-8'))

            elif p[MQTT].type == 8:
                # MQTT SUBSCRIBE received, sending MQTT SUBACK
#                pdb.set_trace()
                topic = p[MQTT][2].topic
                QOS = p[MQTT][2].QOS
                ipAddress = p[IP].src
                tcpPort = p[TCP].sport
                print("[%s] %s MQTT SUBSCRIBE received, topic=%s, QoS=%d" % (threadName, index, topic, QOS))

                # Add subscriber to the list of topics (list of lists)
                with subscribersForTopic_lock:
                    if topic.decode('utf-8') in subscribersForTopic:
                        subscribersForThisTopic = subscribersForTopic[topic.decode('utf-8')]
                        subscribersForThisTopic.append([ipAddress, tcpPort, QOS])
                    else:
                        subscribersForTopic[topic.decode('utf-8')] = [[ipAddress, tcpPort, QOS]]
                print("[%s] %s Subscribers list for this topic: %s" % (threadName, index, subscribersForTopic[topic.decode('utf-8')]))
                print("[%s] %s TOPICS-SUBSCRIBERS list:         %s" % (threadName, index, subscribersForTopic))

                ip = IP(src=p[IP].dst, dst=p[IP].src)
                tcp = TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                mqtt = MQTT()/MQTTSuback(msgid=p[MQTT].msgid, retcode=QOS) # 'retcode' in MQTT SUBACK is really granted QoS
                send(ip/tcp/mqtt, verbose=False)
                tcpSeqList[index] = tcpSeqList[index] + len(mqtt)

                # Create a timer. If there is a timeout (PING REQUEST not received), the client is assumed to be disconnected.
                print("[%s] %s KEEP ALIVE timer started!!!" % (threadName, index))
                t = Timer(keepAlive+10, self._timerExpiration, args=(p, connected,))
                t.start()

            elif p[MQTT].type == 12:
                # PING REQUEST received, sending MQTT PING RESPONSE
#                pdb.set_trace()
                ip = IP(src=p[IP].dst, dst=p[IP].src)
                tcp = TCP(sport=self.tcpport, dport=p[TCP].sport, flags='A', seq=tcpSeqList[index], ack=tcpAckList[index])
                mqtt = MQTT(type=13,len=0)
                send(ip/tcp/mqtt, verbose=False)
                tcpSeqList[index] = tcpSeqList[index] + len(mqtt)

                # Restart timer
                print("[%s] %s Keep alive timer restarted!!!" % (threadName, index))
                t.cancel()
                t = Timer(keepAlive+10, self._timerExpiration, args=(p, connected,))
                t.start()

            elif p[MQTT].type == 14:
                # MQTT DISCONNECT REQ received
#                pdb.set_trace()                
                print("[%s] %s MQTT DISCONNECT REQ received" % (threadName, index))
                self._disconnect(p[IP].dst, p[IP].src, p[TCP].sport, connected)

            # *** ADD OTHER MQTT MESSAGES HERE ***


         # TCP FIN received, sending TCP FIN+ACK
         elif p.haslayer(TCP) and p[TCP].dport == self.tcpport and p[TCP].flags & FIN:
            index = tuple([p[IP].src,p[TCP].sport])
            print ("[%s] %s TCP FIN received" % (threadName, index))

            connected = False
            print("[%s] tcpAckList: %s" % (threadName, tcpAckList))
            tcpAckList[index] = tcpAckList[index] + 1
#            pdb.set_trace()
            self._ack_rclose(p, connected)

         # TCP ACK received
         elif p.haslayer(TCP) and p[TCP].dport == self.tcpport and p[TCP].flags & ACK:
            index = tuple([p[IP].src,p[TCP].sport])
            print ("[%s] %s TCP ACK received!" % (threadName, index)) # Do nothing

#      s.close()
      self._mqttServerThread = None
      print('[%s] MQTT server thread stopped' % (threadName))

   def _start_mqttServerForThisClientThread(self, clientIPAddress, clientTCPPort):
      self._noClients = self._noClients + 1
      print("[MAIN] STARTING THREAD for serving MQTT client no. %s (name=%s) ..." % (str(self._noClients), threading.currentThread().getName()))
      mqttServerForThisClientThread = Thread(name='MQTTServerThread'+str(self._noClients), target=self._mqttBroker, args=(clientIPAddress, clientTCPPort))
      mqttServerForThisClientThread.start()

   def waitForConnections(self):

      # Infinite loop for clients      
      while True:
         print("[MAIN] Waiting for a new connection on port " + str(self.tcpport) + "...")
         # Wait for a new connection (TCP SYN on server's port)
         synPacket = sniff(count=1, iface=self.iface, filter='tcp and port ' + str(self.tcpport) + ' and tcp[tcpflags] & tcp-syn != 0')[0]
         print ("[MAIN] NEW CONNECTION: Received TCP SYN from %s (TCP port %s)" % (synPacket[IP].src, synPacket[TCP].sport))
         # Create TCP SYN+ACK packet
         sport = synPacket[TCP].sport
         index = tuple([synPacket[IP].src,synPacket[TCP].sport])
         tcpSeqList[index] = random.getrandbits(32) # Random number of 32 bits
         tcpAckList[index] = synPacket[TCP].seq + 1 # SYN+ACK
         print("[MAIN] tcpAckList: %s" % (tcpAckList))

         # Generating the IP layer
         ip = IP(src=synPacket[IP].dst, dst=synPacket[IP].src)
         # Generating the TCP layer
         tcpSynAck = TCP(sport=self.tcpport, dport=sport, flags="SA", seq=tcpSeqList[index], ack=tcpAckList[index], options=[('MSS', 1460)])
         # Start new thread for this connection
         self._start_mqttServerForThisClientThread(synPacket[IP].src, synPacket[TCP].sport)
         # Send SYN+ACK and receive ACK
         tcpSeqList[index] = tcpSeqList[index] + 1
         send(ip/tcpSynAck, verbose=False)


def main():

    print("Arguments: %s" % (sys.argv))

    # Take arguments from command line (getopt)
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hi:t:u:p:",["interface=","tcpport=","username=","password="])
    except getopt.GetoptError:
        print ("%s -i <interface> -t <TCP port> -u <username> -p <password>" % (sys.argv[0]))
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ("%s -i <interface> -t <TCP port> -u <username> -p <password>" % (sys.argv[0]))
            sys.exit()
        elif opt in ("-i", "--interface"):
            interface = arg
        elif opt in ("-t", "--tcpport"):
            tcpport = int(arg)
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg

    print("Listening MQTT on interface %s (TCP port %d)" % (interface, tcpport))
    print("MQTT credentials: username=%s, password=%s" % (username, password))

    # Execute MQTT broker
    broker = MQTTBroker(interface, tcpport, username, password)
    broker.waitForConnections()


if __name__ == "__main__":
    main()

