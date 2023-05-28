# -*- coding: utf-8 -*-
&quot;&quot;&quot;
Created on Wed Feb 15 11:51:01 2023
@author: exam
&quot;&quot;&quot;
from scapy.all import *
def handler(packet):
print(packet.summary())
sniff(iface=&quot;wlp1s0&quot;, prn=handler, store=0)
# Run with following command
# sudo python3 sniffer.py
# You can change last network id -&gt; wlp1s0as