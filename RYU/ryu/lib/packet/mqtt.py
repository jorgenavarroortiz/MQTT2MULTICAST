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

# "Registered" in ryu/lib/packets/tcp.py (see get_payload_type())

import struct
import logging

import six

from ryu.lib import addrconv
from ryu.lib import stringify
from . import packet_base
from . import packet_utils

LOG = logging.getLogger(__name__)


TCP_SERVER_PORT = 1883

# PACKET CONTROL TYPE
MQTT_PACKET_CONTROL_TYPE_CONNECT=1
MQTT_PACKET_CONTROL_TYPE_CONNACK=2
MQTT_PACKET_CONTROL_TYPE_PUBLISH=3
MQTT_PACKET_CONTROL_TYPE_PUBACK=4
MQTT_PACKET_CONTROL_TYPE_PUBREC=5
MQTT_PACKET_CONTROL_TYPE_PUBREL=6
MQTT_PACKET_CONTROL_TYPE_PUBCOMP=7
MQTT_PACKET_CONTROL_TYPE_SUBSCRIBE=8
MQTT_PACKET_CONTROL_TYPE_SUBACK=9
MQTT_PACKET_CONTROL_TYPE_UNSUBSCRIBE=10
MQTT_PACKET_CONTROL_TYPE_UNSUBACK=11
MQTT_PACKET_CONTROL_TYPE_PINGREQ=12
MQTT_PACKET_CONTROL_TYPE_PINGRESP=13
MQTT_PACKET_CONTROL_TYPE_DISCONNECT=14

class mqtt(packet_base.PacketBase):
    """MQTT Version 3.1 (http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf) header encoder/decoder class.
       *** FOR FURTHER STUDY, check the posible differences with MQTT v3.1.1 (http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf). At least the 'protocol name' is different ('MQIsdp' for v3.1 and 'MQTT' for v3.1.1).

       An MQTT Control Packet consists of up to three parts, always in the following order: 
           + Fixed header (present in all MQTT Control Packets)
           + Variable header (present in some MQTT Control Packets)
           + Payload (present in some MQTT Control Packets)

       Fixed header:
           + Byte 1: MQTT Control Packet type (most significant 4 bits), flags (less significant 4 bits)
              MQTT Control Packet type - Flags (bits 3, 2, 1, 0)
               0 ..... Reserved
               1 ..... CONNECT         - 0   0   0   0
               2 ..... CONNACK         - 0   0   0   0
               3 ..... PUBLISH         - DUP QoS QoS RETAIN
               4 ..... PUBACK          - 0   0   0   0
               5 ..... PUBREC          - 0   0   0   0
               6 ..... PUBREL          - 0   0   1   0
               7 ..... PUBCOMP         - 0   0   0   0
               8 ..... SUBSCRIBE       - 0   0   1   0
               9 ..... SUBACK          - 0   0   0   0
              10 ..... UNSUBSCRIBE     - 0   0   1   0
              11 ..... UNSUBACK        - 0   0   0   0
              12 ..... PINGREQ         - 0   0   0   0
              13 ..... PINGRESP        - 0   0   0   0
              14 ..... DISCONNECT      - 0   0   0   0
              15 ..... Reserved

              DUP    = Duplicate delivery of a PUBLISH Control Packet
              QoS    = PUBLISH Quality of Service
              RETAIN = PUBLISH Retain flag

           + Byte 2...: Remaining Length
              Number of bytes remaining within the current packet, including data in the variable header and the payload. RL does not include the bytes used to encode the RL. Values lower than 127 are encoded in one byte. Larger values use the most significant bit to indicate that there are following bytes in the representation. The least significant bits encode the data. The first byte is the least significant, and the last byte is the most significant.

       Variable header:
           + Byte 1: Packet Identifier MSB
           + Byte 2: Packet Identifier LSB

           SUBSCRIBE, UNSUBSCRIBE, and PUBLISH (if QoS > 0) Control Packets MUST contain a non-zero 16-bit Packet Identifier. Each time a client sends a new packet of one of these types it MUST assign it a currently unused Packet Identifier.
           (...) 
           A PUBLISH Packet MUST NOT contain a Packet Identifier if its QoS value is set to 0. 
           A PUBACK, PUBREC or PUBREL Packet MUST contain the same Packet Identifier as the PUBLISH Packet that was originally sent. Similarly SUBACK and UNSUBACK MUST contain the Packet Identifier that was used in the corresponding SUBSCRIBE and UNSUBSCRIBE Packet respectively.

       Payload:
           Some MQTT Control Packets contain a payload as the final part of the packet. In the case of the PUBLISH packet this is the Application Message. Control Packets that require payload: CONNECT, PUBLISH (optional), SUBSCRIBE, SUBACK, and UNSUBSCRIBE.
    """

    _MQTT_PACK_STR='!BB'
    _MIN_LEN = struct.calcsize(_MQTT_PACK_STR)

    mqttPacketControlTypeStr = {
        0: "Reserved",
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        5: "PUBREC",
        6: "PUBREL",
        7: "PUBCOMP",
        8: "SUBSCRIBE",
        9: "SUBACK",
        10: "UNSUBSCRIBE",
        11: "UNSUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
        15: "Reserved",
    }

    def __init__(self, mqttControlPacketType, mqttRemainingLength, returnCode=None, messageID=None, qos=None, topic=None, message=None):
        LOG.debug("######### MQTT INIT (mqttControlPacketType=%d, mqttRemainingLength=%d, returnCode=%s, messageID=%s, qos=%s, topic=%s, message=%s) #########", mqttControlPacketType, mqttRemainingLength, str(returnCode or 'None'), str(messageID or 'None'), str(qos or 'None'), str(topic or 'None'), str(message or 'None'))
        super(mqtt, self).__init__()

        # Required for all packet types: mqttControlPacketType and mqttRemainingLength
        self.mqttControlPacketType = mqttControlPacketType
        self.mqttRemainingLength = mqttRemainingLength

        # Required for other messages
        self.returnCode = returnCode
        self.messageID = messageID
        self.qos = qos
        self.topic = topic
        self.message = message

    @classmethod
    def parser(cls, buf):
        LOG.debug("######### MQTT PARSER #########")
        tmpBuffer = buf

        # Not all the fields are present in all the messages, so they are initialized to None
        cls.protocolName = None
        cls.version = None
        cls.connectionFlags = None
        cls.keepAlive = None
        cls.clientID = None
        cls.willTopic = None
        cls.willMessage = None
        cls.userName = None
        cls.password = None
        cls.returnCode = None
        cls.messageID = None
        cls.topic = None
        cls.qos = None
        cls.message = None

        # MQTT Control Packet Type (first 4 bits on the first byte of the MQTT header) and MQTT flags (last 4 bits on the first byte of the MQTT header)
        (mqttByte1, mqttRLByte1) = struct.unpack_from(cls._MQTT_PACK_STR, tmpBuffer)
        mqttControlPacketType = mqttByte1 >> 4
        mqttFlags = mqttByte1 & 15
        mqttFlagDUP = (mqttFlags & 8) >> 2
        mqttFlagQoS = (mqttFlags & 7) >> 1
        mqttFlagRET = (mqttFlags & 1)
        LOG.debug("      MQTT Control Packet Type:  %s (%d)", cls.mqttPacketControlTypeStr[mqttControlPacketType], mqttControlPacketType)
        LOG.debug("      MQTT Flags:                %d (DUP=%d, QoS=%d, RET=%d)", mqttFlags, mqttFlagDUP, mqttFlagQoS, mqttFlagRET)

        # MQTT Remaining Length (reverse order, first bit of each byte is a flag, a "continuation" bit that indicates whether next byte is used for this field
        #(mqttRLByte1, ) = struct.unpack_from('!B', tmpBuffer[1])
        continuationBit = (mqttRLByte1 & 128) >> 7
        extraLengthRL = 0
        mqttRLByte2=0
        mqttRLByte3=0
        mqttRLByte4=0
        if continuationBit == 1:
            extraLengthRL = extraLengthRL + 1
            (mqttRLByte2, ) = struct.unpack_from('!B', tmpBuffer[2])
            continuationBit = (mqttRLByte2 & 128) >> 7
            if continuationBit == 1:
                extraLengthRL = extraLengthRL + 1
                (mqttRLByte3, ) = struct.unpack_from('!B', tmpBuffer[3])
                continuationBit = (mqttRLByte3 & 128) >> 7
                if continuationBit == 1:
                    extraLengthRL = extraLengthRL + 1
                    (mqttRLByte4, ) = struct.unpack_from('!B', tmpBuffer[4])
                    continuationBit = (mqttRLByte4 & 128) >> 7

        # NOTE: 128^2 in the next command would be treated as the XOR operand, since these are bitwise operations
        mqttRemainingLength = (mqttRLByte1 & 127) + (mqttRLByte2 & 127)*128 + (mqttRLByte3 & 127)*128*128 + (mqttRLByte4 & 127)*128*128*128
        LOG.debug("      MQTT Remaining Length:     %d", mqttRemainingLength)
        LOG.debug("      MQTT RL bytes:             %d, %d, %d, %d", mqttRLByte1, mqttRLByte2, mqttRLByte3, mqttRLByte4)

        if mqttRLByte2 == 0:
            mqttRLByte2 = None
        if mqttRLByte3 == 0:
            mqttRLByte3 = None
        if mqttRLByte4 == 0:
            mqttRLByte4 = None

        tmpBuffer=tmpBuffer[(cls._MIN_LEN+extraLengthRL):]

        if mqttControlPacketType == 1:
            # CONNECT

            (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
            LOG.debug("      MQTT Protocol Name Length: %d", fieldLength)
            cls.protocolName = tmpBuffer[2:fieldLength+2]
            LOG.debug("      MQTT Protocol Name:        %s", cls. protocolName)
            if cls.protocolName == b'MQIsdp':
                LOG.debug("      MQTT version:              3.1 (from protocol name)")
            tmpBuffer=tmpBuffer[fieldLength+2:]

            (cls.version, cls.connectionFlags, cls.keepAlive, clientIDLength) = struct.unpack_from('!BBHH', tmpBuffer)
            versionStr=""
            if cls.version == 3:
                versionStr="3.1"
            LOG.debug("      MQTT version:              %s (%d)", versionStr, cls.version)
            userNameFlag=(cls.connectionFlags & 128) >> 7
            passwordFlag=(cls.connectionFlags & 64) >> 6
            willRetainFlag=(cls.connectionFlags & 32) >> 5
            QoSlevelFlag=(cls.connectionFlags & 24) >> 3
            willFlag=(cls.connectionFlags & 4) >> 2
            cleanSessionFlag=(cls.connectionFlags & 2) >> 1
            LOG.debug("      MQTT connection flags:     userNameFlag=%d, passwordFlag=%d, willRetainFlag=%d, QoSlevelFlag=%d, willFlag=%d, cleanSessionFlag=%d", userNameFlag, passwordFlag, willRetainFlag, QoSlevelFlag, willFlag, cleanSessionFlag)
            LOG.debug("      MQTT Keep Alive timer:     %d", cls.keepAlive)
            LOG.debug("      MQTT Client ID length:     %d", clientIDLength)
            tmpBuffer=tmpBuffer[6:]

            cls.clientID = tmpBuffer[:clientIDLength]
            LOG.debug("      MQTT Client ID:            %s", cls.clientID)
            tmpBuffer=tmpBuffer[clientIDLength:]

            if willFlag:
                # (MQTT 1.3) If the Will Flag is set, this is the next UTF-8 encoded string
                (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
                LOG.debug("      MQTT Will Topic Length:     %d", fieldLength)
                cls.willTopic = tmpBuffer[2:fieldLength+2]
                LOG.debug("      MQTT Will Topic:            %s", cls.willTopic)
                tmpBuffer=tmpBuffer[fieldLength+2:]
                # (MQTT 1.3) If the Will Flag is set, this is the next UTF-8 encoded string
                (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
                LOG.debug("      MQTT Will Message Length:     %d", fieldLength)
                cls.willMessage = tmpBuffer[2:fieldLength+2]
                LOG.debug("      MQTT Will Topic:            %s", cls.willMessage)
                tmpBuffer=tmpBuffer[fieldLength+2:]

                LOG.debug("      MQTT Will ***NOT IMPLEMENTED YET***") # Not required for testing typical configuration

            if userNameFlag:
                (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
                LOG.debug("      MQTT User Name Length:     %d", fieldLength)
                cls.userName = tmpBuffer[2:fieldLength+2]
                LOG.debug("      MQTT User Name:            %s", cls.userName)
                tmpBuffer=tmpBuffer[fieldLength+2:]

            if passwordFlag:
                (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
                LOG.debug("      MQTT Password Length:      %d", fieldLength)
                cls.password = tmpBuffer[2:fieldLength+2]
                LOG.debug("      MQTT Password:             %s", cls.password)
                tmpBuffer=tmpBuffer[fieldLength+2:]

        elif mqttControlPacketType == 2:
            # CONNACK

            tmpBuffer=tmpBuffer[1:]
            (cls.returnCode, ) = struct.unpack_from('!B', tmpBuffer)
            LOG.debug("      MQTT Return Code:          %d", cls.returnCode)

        elif mqttControlPacketType == 3:
            # PUBLISH

            (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
            LOG.debug("      MQTT Topic Length:         %d", fieldLength)
            cls.topic = tmpBuffer[2:fieldLength+2]
            LOG.debug("      MQTT Topic:                %s", cls.topic)
            tmpBuffer=tmpBuffer[fieldLength+2:]

            cls.message = tmpBuffer[:]
            LOG.debug("      MQTT Message:              %s", cls.message)

        elif mqttControlPacketType == 8:
            # SUBSCRIBE

            (cls.messageID, ) = struct.unpack_from('!H', tmpBuffer)
            LOG.debug("      MQTT Message Identifier:   %d", cls.messageID)
            tmpBuffer=tmpBuffer[2:]

            (fieldLength, ) = struct.unpack_from('!H', tmpBuffer)
            LOG.debug("      MQTT Topic Length:         %d", fieldLength)
            cls.topic = tmpBuffer[2:fieldLength+2]
            LOG.debug("      MQTT Topic:                %s", cls.topic)
            tmpBuffer=tmpBuffer[fieldLength+2:]

            (cls.qos, ) = struct.unpack_from('!B', tmpBuffer)
            LOG.debug("      MQTT Requested QoS:        %s", cls.qos)

        elif mqttControlPacketType == 9:
            # SUBACK

            (cls.messageID, ) = struct.unpack_from('!H', tmpBuffer)
            LOG.debug("      MQTT Message Identifier:   %d", cls.messageID)
            tmpBuffer=tmpBuffer[2:]

            (cls.qos, ) = struct.unpack_from('!B', tmpBuffer)
            LOG.debug("      MQTT Granted QoS:        %s", cls.qos)

        elif mqttControlPacketType == 12:
            # PING REQUEST -> not included here since it has no body (type and flags already decoded at the beginning of this function)
            LOG.debug("      MQTT body empty")

        elif mqttControlPacketType == 13:
            # PING RESPONSE -> not included here since it has no body (type and flags already decoded at the beginning of this function)
            LOG.debug("      MQTT body empty")

        elif mqttControlPacketType == 14:
            # DISCONNECT -> not included here since it has no body (type and flags already decoded at the beginning of this function)
            LOG.debug("      MQTT body empty")

        # *** INCLUDE HERE OTHER MQTT MESSAGES TO BE DECODED ***


        # From packet_base.py. The parser(cls, buf) function is used when decoding a packet. It shall return:
        # * An object to describe the decoded header.
        # * A packet_base.PacketBase subclass appropriate for the rest of the packet. None when the rest of the packet should be considered as raw payload.
        # * The rest of packet.
        # JNa: This (cls(...)) calls the __init__ function, which stores values in the object variables (and therefore we should not store them in this function)
        return (cls(mqttControlPacketType, mqttRemainingLength, cls.returnCode, cls.messageID, cls.qos, cls.topic, cls.message), None, buf[(cls._MIN_LEN+extraLengthRL):])


    def serialize(self, _payload, _prev):
        LOG.debug("######### MQTT SERIALIZE #########")

        # From packet_base.py. The serialize(self, payload, prev) function is used when encoding a packet.
        # Returns a bytearray which contains the header (and the payload if it is an application layer protocol, which is the case of MQTT).

        mqttByte1 = self.mqttControlPacketType << 4

        mqttRLByte2 = None
        mqttRLByte3 = None
        mqttRLByte4 = None

        tmpMqttRemainingLength = self.mqttRemainingLength
        mqttRLByte1 = tmpMqttRemainingLength % 128
        tmpMqttRemainingLength = (tmpMqttRemainingLength - mqttRLByte1) / 128
        if tmpMqttRemainingLength > 128:
            mqttRLByte2 = tmpMqttRemainingLength % 128
            tmpMqttRemainingLength = (tmpMqttRemainingLength - mqttRLByte2) / 128
            if tmpMqttRemainingLength > 128:
                mqttRLByte3 = tmpMqttRemainingLength % 128
                tmpMqttRemainingLength = (tmpMqttRemainingLength - mqttRLByte3) / 128
                if tmpMqttRemainingLength > 128:
                    mqttRLByte4 = tmpMqttRemainingLength

        fixedHeader = bytearray(struct.pack('!B', mqttByte1))
        if mqttRLByte4 is not None:
            fixedHeader.extend(struct.pack('!BBBB', mqttRLByte1, mqttRLByte2, mqttRLByte3, mqttRLByte4))
            LOG.debug("######### MQTT SERIALIZE HEADER (mqttByte1=%d, mqttRLByte1=%d, mqttRLByte2=%d, mqttRLByte3=%d, mqttRLByte4=%d) #########", mqttByte1, mqttRLByte1, mqttRLByte2, mqttRLByte3, mqttRLByte4)
        elif mqttRLByte3 is not None:
            fixedHeader.extend(struct.pack('!BBB', mqttRLByte1, mqttRLByte2, mqttRLByte3))
            LOG.debug("######### MQTT SERIALIZE HEADER (mqttByte1=%d, mqttRLByte1=%d, mqttRLByte2=%d, mqttRLByte3=%d) #########", mqttByte1, mqttRLByte1, mqttRLByte2, mqttRLByte3)
        elif mqttRLByte2 is not None:
            fixedHeader.extend(struct.pack('!BB', mqttRLByte1, mqttRLByte2))
            LOG.debug("######### MQTT SERIALIZE HEADER (mqttByte1=%d, mqttRLByte1=%d, mqttRLByte2=%d) #########", mqttByte1, mqttRLByte1, mqttRLByte2)
        else:
            fixedHeader.extend(struct.pack('!B', mqttRLByte1))
            LOG.debug("######### MQTT SERIALIZE HEADER (mqttByte1=%d, mqttRLByte1=%d) #########", mqttByte1, mqttRLByte1)

        variableHeader=bytearray()
        # Packets required to be sent for MQTT broker-like APP are included. Other packets are also included for completeness (so they can be used with other apps).
        if self.mqttControlPacketType == 1:
            # CONNECT *** TO BE DONE ***
            LOG.debug("######### MQTT SERIALIZE CONNECT *** TO BE DONE ***")

        elif self.mqttControlPacketType == 2:
            # CONNACK
            topicNameCompressionResponse = 0 # Reserved in MQTT v3.1 and v3.1.1
            variableHeader = bytearray(struct.pack('!B', topicNameCompressionResponse))
            returnCode = self.returnCode # 0 for 'Connection Accepted'; 5 for 'Connection Refused: not authorized', when the user name and password do not match
            variableHeader.extend(struct.pack('!B', returnCode))
            LOG.debug("######### MQTT SERIALIZE CONNACK (mqttControlPacketType=%d, returnCode=%d) #########", self.mqttControlPacketType, self.returnCode)

        elif self.mqttControlPacketType == 3:
            # PUBLISH
            topicLength = len(self.topic)
            variableHeader = bytearray(struct.pack('!H', topicLength))
            variableHeader.extend(bytearray(self.topic.encode()))
            variableHeader.extend(bytearray(self.message.encode()))
            LOG.debug("######### MQTT SERIALIZE PUBLISH (mqttControlPacketType=%d, topic=%s, message=%s) #########", self.mqttControlPacketType, self.topic, self.message)
            # *** TO BE TESTED (IT SHOULD WORK) ***

        elif self.mqttControlPacketType == 8:
            # SUBSCRIBE
            topicLength = len(self.topic)
            variableHeader = bytearray(struct.pack('!HH', self.messageID, topicLength))
            variableHeader.extend(bytearray(self.topic.encode()))
            variableHeader.extend(struct.pack('!B', self.qos))
            LOG.debug("######### MQTT SERIALIZE SUBSCRIBE (mqttControlPacketType=%d, messageID=%d, topic=%s, requestedQoS=%d) #########", self.mqttControlPacketType, self.messageID, self.topic, self.qos)
            # *** TO BE TESTED (IT SHOULD WORK) ***

        elif self.mqttControlPacketType == 9:
            # SUBACK
            variableHeader = bytearray(struct.pack('!HB', self.messageID, self.qos))
            LOG.debug("######### MQTT SERIALIZE SUBACK (mqttControlPacketType=%d, messageID=%d, grantedQoS=%d) #########", self.mqttControlPacketType, self.messageID, self.qos)

        elif self.mqttControlPacketType == 12:
            # PING REQUEST -> it has no body (type and flags already encoded at the beginning of this function), so there is no variable header
            LOG.debug("######### MQTT SERIALIZE PING REQUEST (mqttControlPacketType=%d) #########", self.mqttControlPacketType)

        elif self.mqttControlPacketType == 13:
            # PING RESPONSE -> it has no body (type and flags already encoded at the beginning of this function), so there is no variable header
            LOG.debug("######### MQTT SERIALIZE PING RESPONSE (mqttControlPacketType=%d) #########", self.mqttControlPacketType)
            # *** TO BE TESTED (IT SHOULD WORK) ***

        elif self.mqttControlPacketType == 14:
            # DISCONNECT -> it has no body (type and flags already encoded at the beginning of this function), so there is no variable header
            LOG.debug("######### MQTT SERIALIZE DISCONNECT (mqttControlPacketType=%d) #########", self.mqttControlPacketType)
            # *** TO BE TESTED (IT SHOULD WORK) ***


        # *** INCLUDE HERE OTHER MQTT MESSAGES TO BE ENCODED ***

            
        return six.binary_type(fixedHeader + variableHeader)

