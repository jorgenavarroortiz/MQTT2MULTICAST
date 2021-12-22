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

# "Registered" in ryu/lib/packets/udp.py (see get_payload_type())

import struct
import logging

import six

from ryu.lib import addrconv
from ryu.lib import stringify
from . import packet_base
from . import packet_utils

LOG = logging.getLogger(__name__)

UDP_SERVER_PORT = 11883
UDP_CLIENT_PORT = 11882

# PACKET CONTROL TYPE
MQTT2MULTICAST_REQUEST=1
MQTT2MULTICAST_REPLY=2

class mqtt2multicast(packet_base.PacketBase):
    """An MQTT2MULTICAST packet consists of two parts in the following order: 
           + Packet type (1 byte)
           + Payload

       Packet type (1 byte):
               1 ..... REQUEST
               2 ..... REPLY

       Payload: it depends on the packet type

               If packet type == 1:
                       Transaction ID: 4 bytes
                       Topic size: 2 bytes
                       Topic: variable length field

               If packet type == 2:
                       Transaction ID: 4 bytes
                       Multicast IP address
    """

    _MQTT2MULTICAST_PACK_STR='!BI'
    _MIN_LEN = struct.calcsize(_MQTT2MULTICAST_PACK_STR)

    mqtt2multicastPacketTypeStr = {
        1: "REQUEST",
        2: "REPLY",
    }

    def __init__(self, mqtt2multicastPacketType, mqtt2multicastTransactionID, mqtt2multicastTopicSize=None, mqtt2multicastTopic=None, mqtt2multicastIPAddress=None):
        LOG.debug("######### MQTT2MULTICAST INIT (mqtt2multicastPacketType=%d, mqtt2multicastTransactionID=%d) #########", mqtt2multicastPacketType, mqtt2multicastTransactionID)
        super(mqtt2multicast, self).__init__()

        # Required for all packet types: mqtt2multicastPacketType and mqtt2multicastTransactionID
        self.mqtt2multicastPacketType = mqtt2multicastPacketType
        self.mqtt2multicastTransactionID = mqtt2multicastTransactionID

        # Required for other messages
        self.mqtt2multicastTopicSize = mqtt2multicastTopicSize
        self.mqtt2multicastTopic = mqtt2multicastTopic
        self.mqtt2multicastIPAddress = mqtt2multicastIPAddress

    @classmethod
    def parser(cls, buf):
        LOG.debug("######### MQTT2MULTICAST PARSER #########")
        tmpBuffer = buf

        # Not all the fields are present in all the messages, so they are initialized to None
        cls.mqtt2multicastPacketType = None
        cls.mqtt2multicastTransactionID = None
        cls.mqtt2multicastTopicSize = None
        cls.mqtt2multicastTopic = None
        cls.mqtt2multicastIPAddress = None

        # MQTT Control Packet Type (first 4 bits on the first byte of the MQTT header) and MQTT flags (last 4 bits on the first byte of the MQTT header)
        (cls.mqtt2multicastPacketType, cls.mqtt2multicastTransactionID) = struct.unpack_from(cls._MQTT2MULTICAST_PACK_STR, tmpBuffer)
        LOG.debug("      MQTT2MULTICAST Packet Type:    %s (%d)", cls.mqtt2multicastPacketTypeStr[cls.mqtt2multicastPacketType], cls.mqtt2multicastPacketType)
        LOG.debug("      MQTT2MULTICAST Transaction ID: %d", cls.mqtt2multicastTransactionID)

        tmpBuffer=tmpBuffer[cls._MIN_LEN:]

        if cls.mqtt2multicastPacketType == 1:
            # REQUEST

            (cls.mqtt2multicastTopicSize, ) = struct.unpack_from('!H', tmpBuffer)
            LOG.debug("      MQTT2MULTICAST Topic Size:     %d", cls.mqtt2multicastTopicSize)
            cls.mqtt2multicastTopic = tmpBuffer[2:cls.mqtt2multicastTopicSize+2]
            LOG.debug("      MQTT2MULTICAST Topic:          %s", cls.mqtt2multicastTopic)

        elif cls.mqtt2multicastPacketType == 2:
            # REPLY

            (cls.mqtt2multicastIPAddress, ) = struct.unpack_from('!I', tmpBuffer)
            LOG.debug("      MQTT2MULTICAST IP Address: %d", addrconv.ipv4.bin_to_text(cls.mqtt2multicastIPAddress))

        # *** INCLUDE HERE FUTURE MQTT2MULTICAST MESSAGES TO BE DECODED ***


        # From packet_base.py. The parser(cls, buf) function is used when decoding a packet. It shall return:
        # * An object to describe the decoded header.
        # * A packet_base.PacketBase subclass appropriate for the rest of the packet. None when the rest of the packet should be considered as raw payload.
        # * The rest of packet.
        # JNa: This (cls(...)) calls the __init__ function, which stores values in the object variables (and therefore we should not store them in this function)
        return (cls(cls.mqtt2multicastPacketType, cls.mqtt2multicastTransactionID, cls.mqtt2multicastTopicSize, cls.mqtt2multicastTopic, cls.mqtt2multicastIPAddress), None, None)


    def serialize(self, _payload, _prev):
        LOG.debug("######### MQTT2MULTICAST SERIALIZE #########")

        # From packet_base.py. The serialize(self, payload, prev) function is used when encoding a packet.
        # Returns a bytearray which contains the header (and the payload if it is an application layer protocol, which is the case of MQTT2MULTICAST).

        fixedHeader = bytearray(struct.pack('!BI', self.mqtt2multicastPacketType, self.mqtt2multicastTransactionID))
        if self.mqtt2multicastPacketType == 1:
            # REQUEST
            variableHeader = bytearray(struct.pack('!H', self.mqtt2multicastTopicSize))
            variableHeader.extend(bytearray(self.mqtt2multicastTopic.encode()))

        elif self.mqtt2multicastPacketType == 2:
            # REPLY
            #variableHeader = bytearray(struct.pack('!I', self.mqtt2multicastIPAddress))
            variableHeader = bytearray(self.mqtt2multicastIPAddress)

        # *** INCLUDE HERE FUTURE MQTT2MULTICAST MESSAGES TO BE ENCODED ***


        return six.binary_type(fixedHeader + variableHeader)


    def mqtt2multicastPacketType(self):
        return self.mqtt2multicastPacketType

