# MQTT proxy using SCAPY

© Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada

MQTT proxy created with SCAPY (tested with Scapy 2.4.4). **NOTE**: Please make sure that you **use Scapy 2.4.4** (``pip install scapy==2.4.4``). The ``sniff()`` function does not work with a list of network interfaces in version 2.4.5. Tested with ``mosquitto_sub`` and ``mosquitto_pub`` tools (see example in the picture below).

The intention is to split the TCP connection within an SDN scenario, using MQTT proxies at the edge switches. These proxies:

- Act as a broker from the subscriber/publisher perspective connected to that SDN switch
- Forward MQTT messages to forwarders (which may be another MQTT proxy or an SDN application e.g. using RYU) over UDP. As long as the MQTT proxy has the first subscriber for one topic, it will send an MQTT SUBSCRIBE message to the other proxy. When the last of the subscribers for that topic is disconnected, an MQTT UNSUBSCRIBE message is sent to the other proxy. MQTT PUBLISH messages are forwarded only if the other proxy has at least one subscriber for that specific topic (not forwarded otherwise).

To avoid the kernel resetting the TCP connection (since there is no socket open from the kernel's point of view), we have to avoid sending TCP RESET packets to the publisher/subscriber using e.g. ``iptables``. Similarly to avoid ICMP destination unreachable because there is no application receiving the UDP packets. In order to simplify this (and to include the arguments required for the Python script), we have created Bash scripts (``mqtt_proxyX.sh``).

See the launch scripts (``mqtt_proxy1.sh`` and similar) to get examples. You can also use the help (argument ``-h``) to see the syntax.

If no UDP forwarders are configured, the program will act as a simple MQTT broker supporting QoS=0.

The following picture shows two MQTT proxies (hosts H1 and H4) which forwards the PUBLISH messages from one publisher (host H3, connected to H4) to one subscriber (host H2, connected to H1).

<img src="https://github.com/jorgenavarroortiz/MQTT-proxy-SCAPY/raw/main/img/scapy-mqtt-proxy.png" width="800">

----------

The following steps assume that the cloned directory is moved to `~/SCAPPY_MQTT`.

Steps for a simple experiment:
- Clone this repository:
```
cd $HOME
https://github.com/jorgenavarroortiz/MQTT-proxy-SCAPY.git
```
- Open a terminal to execute RYU:
```
cd ~/RYU
python3 ./bin/ryu-manager --verbose ryu/app/simple_switch_13.py
```
- Open a terminal to execute mininet (you can change `halfrtt` and `use_real_interface` as required for the particular experiment):
```
cd ~/MQTT-proxy-SCAPY
sudo python ./mininet/topo_mqtt_lora_VM_bridged.py
```
- Open a terminal on h1 (`xterm h1`, IP address 192.168.1.101) to execute the first MQTT proxy, which is configured to forward MQTT traffic to h4 (IP address 192.168.1.104):
```
cd ~/MQTT-proxy-SCAPY
./mqtt_proxy1.sh
```
- Repeat on h4 (`xterm h4`, IP address 192.168.1.104), so it will also forward MQTT traffic to h1 (IP address 192.168.1.101):
```
cd ~/MQTT-proxy-SCAPY
./mqtt_proxy2.sh
```

Test that MQTT messages are being forwarded:
- Execute a subscriber on h2:
```
mosquitto_sub -h 192.168.1.101 -t "topic1" -u "jorge" -P "passwd"
```
- Execute a publisher on h3:
```
mosquitto_pub -h 192.168.1.104 -t "topic1" -u "jorge" -P "passwd" -m "message1"
```
- h3 can also publish connected to h1 (i.e. both h2 and h3 connected to the same MQTT proxy):
```
mosquitto_pub -h 192.168.1.101 -t "topic1" -u "jorge" -P "passwd" -m "message1"
```
