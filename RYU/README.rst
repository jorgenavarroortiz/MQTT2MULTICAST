© Jorge Navarro-Ortiz (jorgenavarro@ugr.es), University of Granada (for the MQTT part)

This repo contains the Ryu SDN controller (version 4.34) with MQTT support (parsing/encoding MQTT messages, initial MQTT broker app). Currently, only QoS=0 is supported for MQTT v3.1.

- To compile all (including libraries, especially for ryu/lib/packet/mqtt.py and related): ``sudo python3 ./setup.py install``
- To run the MQTT broker application: ``ryu-manager --verbose ryu/app/mqttbroker.py``. This will create a MQTT broker application in the SDN controller, which is accessible at IP 192.168.1.100 (modifiable in mqtt_13.py).
- Remember to start the mininet topology after starting RYU. Also, perform a ``pingall`` so that the MAC table (for the learning switch) is populated.
- You can check that you can subscribe using ``mosquitto_sub -h 192.168.1.100 -t "topic" -u "jorge" -P "passwd"`` within one host (e.g. using a Mininet topology with several switches and hosts). You can also check one host subscribing to several topics using ``-t`` repeteadly on the same command, so they share the same TCP port.
- You can also check that you can publish using ``mosquitto_pub -h 192.168.1.100 -t "topic" -u "jorge" -P "passwd" -m "message"`` within another host.

**NOTE**: The application ``mqttbroker.py`` also includes the learning switch, so all hosts should be able to connect each other.


------------------

What's Ryu
==========
Ryu is a component-based software defined networking framework.

Ryu provides software components with well defined API's that make it
easy for developers to create new network management and control
applications. Ryu supports various protocols for managing network
devices, such as OpenFlow, Netconf, OF-config, etc. About OpenFlow,
Ryu supports fully 1.0, 1.2, 1.3, 1.4, 1.5 and Nicira Extensions.

All of the code is freely available under the Apache 2.0 license. Ryu
is fully written in Python.


Quick Start
===========
Installing Ryu is quite easy::

   % pip install ryu

If you prefer to install Ryu from the source code::

   % git clone git://github.com/osrg/ryu.git
   % cd ryu; pip install .

If you want to write your Ryu application, have a look at
`Writing ryu application <http://ryu.readthedocs.io/en/latest/writing_ryu_app.html>`_ document.
After writing your application, just type::

   % ryu-manager yourapp.py


Optional Requirements
=====================

Some functions of ryu require extra packages:

- OF-Config requires lxml and ncclient
- NETCONF requires paramiko
- BGP speaker (SSH console) requires paramiko
- Zebra protocol service (database) requires SQLAlchemy

If you want to use these functions, please install the requirements::

    % pip install -r tools/optional-requires

Please refer to tools/optional-requires for details.


Prerequisites
=============
If you got some error messages at the installation stage, please confirm
dependencies for building the required Python packages.

On Ubuntu(16.04 LTS or later)::

  % apt install gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev


Support
=======
Ryu Official site is `<http://osrg.github.io/ryu/>`_.

If you have any
questions, suggestions, and patches, the mailing list is available at
`ryu-devel ML
<https://lists.sourceforge.net/lists/listinfo/ryu-devel>`_.
`The ML archive at Gmane <http://dir.gmane.org/gmane.network.ryu.devel>`_
is also available.
