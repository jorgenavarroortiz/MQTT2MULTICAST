# MQTT to multicast

© Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada, 2021

This repository is composed of two parts:

- An MQTT proxy created with SCAPY (tested with Scapy 2.4.4).
- An MQTT2MULTICAST server, implemented as a SDN application at the RYU controller.

This implementation has two objectives:

1) The MQTT proxy is intended to split the TCP connection within an SDN scenario, using MQTT proxies at the edge switches. These proxies:
- Act as a broker from the subscriber/publisher perspective connected to that SDN switch.
- Forward MQTT messages to forwarders (which may be another MQTT proxy) over UDP. 

2) Leverage MQTT over UDP to employ multicast within the SDN network to forward `MQTT PUBLISH` messages.

The forwarders may use UDP or multicast:
- When using UDP, the MQTT proxy will send an `MQTT SUBSCRIBE` message to the other proxies as soon as the first MQTT client subscribes to a new topic. When the last of the subscribers for that topic is disconnected, an `MQTT UNSUBSCRIBE` message is sent to the other proxies. `MQTT PUBLISH` messages are forwarded only to other proxies that have at least one subscriber for that specific topic (not forwarded otherwise).
- When using multicast, the forwarders will ask the MQTT2MULTICAST server which multicast IP address (starting e.g. from 225.0.0.0) is assigned to this specific topic using an `MQTT2MULTICAST REQUEST` message. The MQTT2MULTICAST server will assign multicast IP addresses to topics by following the order of the requests, and will respond with an `MQTT2MULTICAST REPLY` message. The MQTT2MULTICAST server will store the IP addresses of the MQTT proxies that are subscribed to specific topics, so this may be used to create a multicast tree for routing the multicast messages based on their destination multicast IP address. 

**MULTICAST ROUTING** based on this information is also implemented

In order to implement multicast routing, the RYU application `simple_switch_13_MQTT2MULTICAST.py` has the following variables: `multicastReceiverForTopic`, which includes a list of subscribers (IP addresses) for a specific topic, `multicastTransmittersForTopic`, which includes a list of publishers (IP addresses) for a specific topic,  and `topicToMulticast`, which translates between the topic space and the multicast IP addresses space. Thus, with these variables, we generate, on the RYU application, the corresponding group table and flow rules for the switches to transmit the multicast messages to their corresponding receivers, i.e. create a multicast tree for each pair of topic/multicast IP address and transmitter. These multicast trees have been computed using the shortest paths (Dijkstra's algorithm, implemented in the `networkx` library).

**MQTT2MULTICAST protocol**

This protocol allows an MQTT proxy to translate a specific topic to a multicast IP address. An MQTT2MULTICAST packet consists of two parts in the following order:
- `Packet type` (1 byte)
- Payload
The `packet type` can be 1 (`MQTT2MULTICAST REQUEST`) or 2 (`MQTT2MULTICAST REPLY`). The payload depends on the packet type:
- If `packet type` is 1 (`MQTT2MULTICAST REQUEST`), the payload is composed of a `transaction ID` (4 bytes), a `flags` field (1 byte), the `topic size` (2 bytes) and the `topic` (variable length). If `flags` is 0, it means that the MQTT proxy is asking because a publisher will send an `MQTT PUBLISH` message. If `flags` is 1, it means that the MQTT proxy is asking because a subscriber will subscribe to that specific topic. If `flags` is 2, the subscriber will unsubscribe from that topic. If `flags` is 0 or 1, the MQTT2MULTICAST server will respond with an `MQTT2MULTICAST REPLY`, informing about the multicast IP address associated to the `topic`. If `flags` is 2, no response is required.
- If `packet type` is 2 (`MQTT2MULTICAST REPLY`), the payload is composed of a `transaction ID` (4 bytes) (which shall match the `transaction ID` of the `MQTT2MULTICAST REQUEST`), a `flags`field (1 byte) (always 0 for `MQTT2MULTICAST REPLY`, reserved for future uses) and a `multicast IP address` (4 bytes) associated with the topic in the `MQTT2MULTICAST REQUEST` message.

**Other implementation details**

- Please make sure that you **use Scapy 2.4.4** (``pip install scapy==2.4.4``). The ``sniff()`` function does not work with a list of network interfaces in version 2.4.5. Tested with ``mosquitto_sub`` and ``mosquitto_pub`` tools (see the examples below).

- Please make sure that you have installed the `networkx` package (Python package for the creation, manipulation, and study of the structure, dynamics, and functions of complex networks). You can execute `python3 -m pip install networkx` for that purpose.

- IPv6 has been disabled in hosts and switches to avoid too many messages in RYU's log.

- You can select `learning switch` or `shortest path` for L2 routing in the script `~/RYU/ryu/app/simple_switch_13_MQTT2MULTICAST.py`. Please change the line `LEARNING_SWITCH = True` accordingly.

- To avoid the kernel resetting the TCP connection (since there is no socket open from the kernel's point of view), we have to avoid sending TCP RESET packets to the publisher/subscriber using e.g. ``iptables``. Similarly to avoid ICMP destination unreachable because there is no application receiving the UDP packets. In order to simplify this (and to include the arguments required for the Python script), we have created Bash scripts (``mqtt_proxyX.sh``).

- If no UDP forwarders are configured nor MQTT2MULTICAST server is configured, the program will act as a simple MQTT broker supporting QoS=0.

- The `topo_mqtt_lora_VM_bridged.py` script in the `~/MQTT2MULTICAST/mininet` directory:
  - creates a tree topology specifying the fanout of the switches on each level (e.g. with `-f 2 -f 2`, please check the syntax with `-h`)
  - allows to add delay in the links between switches (e.g. with `-D 10ms`) and in the links between switches and hosts (e.g. with `-d 20ms`)
  - allows connecting a real network interface to a specific host (e.g. with `-r enp0s8 -R h1`)

See the launch scripts (``mqtt_proxy1.sh`` and similar) to get examples. You can also use the help (argument ``-h``) to see the syntax.

## Experiment using UDP to forward MQTT messages within the SDN network

In this example, `MQTT PUBLISH` messages will be forwarded between two MQTT proxies. Only the first `MQTT SUBSCRIBE` message for a specific topic will be forwarded to the other MQTT proxy, so it will know that MQTT publish messages for that topic have to be forwarded. Only the `MQTT UNSUBSCRIBE` message for the last subscriber connected to a MQTT proxy will be forwarded to the other MQTT proxy, so it will know that it will not have to forward `MQTT PUBLISH` messages to that proxy.

This experiment uses `mininet` with a tree topology with a 3 switches (one root, `s1`, and two leaves, `s2` and `s3`) which connect two hosts to each leaf (`h1` and `h2` to `s2` and `h3` and `h4` to `s3`). `h1` and `h4` will act as MQTT proxies. `h2` will be an MQTT subscriber, subscribed to topic `topic1`, whereas `h3` will be an MQTT publisher, which will publish a message on that topic.

Steps to execute the experiment:
- Clone this repository:
```
cd $HOME
git clone https://github.com/jorgenavarroortiz/MQTT2MULTICAST.git
```
- Open a terminal to execute RYU:
```
cd ~/MQTT2MULTICAST/RYU
python3 ./bin/ryu-manager --verbose ryu/app/simple_switch_13_MQTT2MULTICAST.py 2>&1 | tee ryu.log
```
- Open a terminal to execute mininet (you can change `halfrtt` and `use_real_interface`, as required for the particular experiment, in the Python script for the topology):
```
cd ~/MQTT2MULTICAST
sudo python ./mininet/topo_mqtt_lora_VM_bridged.py -v -f 2 -f 2
```
- Open a terminal on `h1` (`xterm h1`, IP address 192.168.1.101) to execute the first MQTT proxy, which is configured to forward MQTT traffic to `h4` (IP address 192.168.1.104):
```
cd ~/MQTT2MULTICAST/SCAPY
./mqtt_proxy1.sh
```
- Repeat on `h4` (`xterm h4`, IP address 192.168.1.104), so it will also forward MQTT traffic to `h1` (IP address 192.168.1.101):
```
cd ~/MQTT2MULTICAST/SCAPY
./mqtt_proxy2.sh
```

Test that MQTT messages are being forwarded:
- Execute a subscriber on `h2`:
```
mosquitto_sub -h 192.168.1.101 -t "topic1" -u "jorge" -P "pasaswd"
```
- Execute a publisher on `h3`:
```
mosquitto_pub -h 192.168.1.104 -t "topic1" -u "jorge" -P "passwd" -m "message1"
```
- `h3` can also publish connected to `h1` (i.e. both `h2` and `h3` connected to the same MQTT proxy):
```
mosquitto_pub -h 192.168.1.101 -t "topic1" -u "jorge" -P "passwd" -m "message1"
```

The following picture shows two MQTT proxies (hosts `h1` and `h4`) which forward the PUBLISH messages from one publisher (host `h3`) to one subscriber (host `h2`).

![image](https://user-images.githubusercontent.com/17797704/147362234-07a4e7ab-5b6c-417c-a49c-2e8a3ebd6a18.png)

## Experiment using multicast to forward MQTT messages within the SDN network

In this example, `MQTT PUBLISH` messages will be forwarded using multicast IP addresses between any MQTT proxy connected to the SDN network with at least one subscriber subscribed to that topic.

This experiment uses `mininet` with a tree topology with a 3 switches (one root, `s1`, and two leaves, `s2` and `s3`) which connect two hosts to each leaf (`h1` and `h2` to `s2` and `h3` and `h4` to `s3`). `h1` and `h4` will act as MQTT proxies. `h2` will be an MQTT subscriber, subscribed to topic `topic1`, whereas `h3` will be an MQTT publisher, which will publish a message on that topic.

Steps to execute the experiment:
- Clone this repository:
```
cd $HOME
git clone https://github.com/jorgenavarroortiz/MQTT2MULTICAST.git
```
- Open a terminal to execute RYU with the MQTT2MULTICAST server app:
```
cd ~/MQTT2MULTICAST/RYU
python3 ./bin/ryu-manager --observe-links --verbose ryu/app/simple_switch_13_MQTT2MULTICAST.py 2>&1 | tee ryu.log
```
- Open a terminal to execute mininet (you can change `halfrtt` and `use_real_interface`, as required for the particular experiment, in the Python script for the topology):
```
cd ~/MQTT2MULTICAST
sudo python ./mininet/topo_mqtt_lora_VM_bridged.py -v -f 2 -f 2
```
- Open a terminal on `h1` (`xterm h1`, IP address 192.168.1.101) to execute the first MQTT proxy, which is configured to forward MQTT traffic to `h4` (IP address 192.168.1.104):
```
cd ~/MQTT2MULTICAST/SCAPY
./mqtt_proxy1_m2m.sh
```
- Repeat on `h4` (`xterm h4`, IP address 192.168.1.104), so it will also forward MQTT traffic to `h1` (IP address 192.168.1.101):
```
cd ~/MQTT2MULTICAST/SCAPY
./mqtt_proxy2_m2m.sh
```

Test that MQTT messages are being forwarded:
- Execute a subscriber on `h2`:
```
mosquitto_sub -h 192.168.1.101 -t "topic1" -u "jorge" -P "pasaswd"
```
- Execute a publisher on `h3`:
```
mosquitto_pub -h 192.168.1.104 -t "topic1" -u "jorge" -P "passwd" -m "message1"
```
- `h3` can also publish connected to `h1` (i.e. both `h2` and `h3` connected to the same MQTT proxy):
```
mosquitto_pub -h 192.168.1.101 -t "topic1" -u "jorge" -P "passwd" -m "message1"
```

The following picture shows two MQTT proxies (hosts `h1` and `h4`) which forward the PUBLISH messages from one publisher (host `h3`) to one subscriber (host `h2`) using multicast.

![image](https://user-images.githubusercontent.com/17797704/147364627-2c40656d-000c-47bb-b002-cf6213739473.png)

## Experiment using multicast with Shortest Path First routing to forward MQTT messages within the SDN network


