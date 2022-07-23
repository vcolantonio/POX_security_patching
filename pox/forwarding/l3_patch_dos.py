
# Copyright 2012-2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A stupid L3 switch
For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import time
import threading

# Timeout for flows
FLOW_IDLE_TIMEOUT = 10

# Timeout for ARP entries
ARP_TIMEOUT = 60 * 2

# Maximum number of packet to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 5



class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


class l3_switch (EventMixin):

  ip_numPacchetti = dict()
  rilevazioni_thread = dict() #key =ip - value=counter
  MAX_BLACKLIST = 3
  TEMPORARY_RULE_TIME = 30
  TIME_TO_SLEEP = 5
  lock_strutture = threading.Lock()
  rule_present = dict()
  tempi_rilevazioni = dict()

  def __init__ (self, fakeways = [], arp_for_unknowns = False, wide = False):

    #--------------------THREAD DDOS-----------------------------

    t = threading.Thread(target=l3_switch.checkDDOS)
    t.start()

    #-------------------THREAD DDOS-------------------------------

    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If True, we create "wide" matches.  Otherwise, we create "narrow"
    # (exact) matches.
    self.wide = wide

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> expire_time
    # We use this to keep from spamming ARPs
    self.outstanding_arps = {}

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we map IP addresses to Entries
    self.arpTable = {}

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    core.listen_to_dependencies(self)

  def checkDDOS():

    soglia = 500

    while True:

      time.sleep(l3_switch.TIME_TO_SLEEP)
      #global ip_numPacchetti
      with l3_switch.lock_strutture:
        for ip in l3_switch.ip_numPacchetti.keys():
          if l3_switch.ip_numPacchetti[ip] >= soglia:
            print("SOGLIA SUPERATA per l'ip: {}".format(ip))
            #print(l3_switch.rilevazioni_thread)
            if ip in l3_switch.rilevazioni_thread.keys():
              print("Incremento le rilevazioni per l'ip: {}".format(ip))
              l3_switch.rilevazioni_thread[ip]+=1
              l3_switch.tempi_rilevazioni[ip] = time.time()
            else:
              l3_switch.rilevazioni_thread[ip] = 1
              l3_switch.tempi_rilevazioni[ip] = time.time()

          else:
            #num pacchetti non supera la soglia
            print("SOGLIA NON SUPERATA per l'ip: {}".format(ip))
            #print(l3_switch.ip_numPacchetti[ip])
            if ip in l3_switch.rilevazioni_thread.keys():
              if (time.time() - l3_switch.rule_present[ip]) > l3_switch.TEMPORARY_RULE_TIME:
                print("RIMUOVO HOST NON PIU` MALEVOLO: {}".format(ip))
                del l3_switch.rilevazioni_thread[ip]
        l3_switch.ip_numPacchetti = dict()

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.items():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_openflow_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    #--------------------------DDOS-----------------------------

    src_ip = None


    if isinstance(packet.next, ipv4):

        with l3_switch.lock_strutture:

          dstaddr = packet.next.dstip
          src_ip = packet.next.srcip

          if str(src_ip) not in l3_switch.ip_numPacchetti.keys():
              l3_switch.ip_numPacchetti[str(src_ip)] = 1
          else:
              l3_switch.ip_numPacchetti[str(src_ip)] += 1

          actions = []

          if self.wide:
              match = of.ofp_match(dl_type = packet.type, nw_dst = dstaddr)
          else:
              match = of.ofp_match.from_packet(packet, inport)

          match = of.ofp_match(dl_type = packet.type, nw_src = src_ip)

          if str(src_ip) in l3_switch.rilevazioni_thread.keys():
              if l3_switch.rilevazioni_thread[str(src_ip)] >= l3_switch.MAX_BLACKLIST:

                msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                        idle_timeout=of.OFP_FLOW_PERMANENT,
                                        hard_timeout=of.OFP_FLOW_PERMANENT,
                                        buffer_id=event.ofp.buffer_id,
                                        actions=actions,
                                        match=match)
                event.connection.send(msg.pack())
                print('#-------------------DDOS DETECTED: PERMANENT RULE per host: {} -----------------'.format(str(src_ip)))
                del l3_switch.rilevazioni_thread[str(src_ip)]

              else:
                if str(src_ip) in l3_switch.rule_present.keys(): #non e` la prima regola che installo
                  if (time.time() - l3_switch.rule_present[str(src_ip)]) > l3_switch.TEMPORARY_RULE_TIME: #regola scaduta
                    #check sui tempi
                    tempo = time.time()
                    if tempo - l3_switch.tempi_rilevazioni[str(src_ip)] > l3_switch.TIME_TO_SLEEP: #rilevazione vecchia
                      return
                    else:
                      #print(l3_switch.rilevazioni_thread)
                      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                              idle_timeout=l3_switch.TEMPORARY_RULE_TIME, #drop per 3 min
                                              hard_timeout=l3_switch.TEMPORARY_RULE_TIME,
                                              buffer_id=event.ofp.buffer_id,
                                              actions=actions,
                                              match=match)
                      event.connection.send(msg.pack())
                      l3_switch.rule_present[str(src_ip)] = time.time()
                      print('#------------------DDOS DETECTED: TEMPORARY RULE per host: {} -----------------'.format(str(src_ip)))

                else:

                  #print(l3_switch.rilevazioni_thread)
                  msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                          idle_timeout=l3_switch.TEMPORARY_RULE_TIME, #drop per 3 min
                                          hard_timeout=l3_switch.TEMPORARY_RULE_TIME,
                                          buffer_id=event.ofp.buffer_id,
                                          actions=actions,
                                          match=match)
                  event.connection.send(msg.pack())
                  l3_switch.rule_present[str(src_ip)] = time.time()
                  print('#------------------DDOS DETECTED: TEMPORARY RULE per host: {} -----------------'.format(str(src_ip)))

              return


    #--------------------------DDOS-----------------------------

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Learn or update port/MAC info
      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
          if self.wide:
            # Make sure we don't have any entries with the old info...
            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            msg.match.nw_dst = packet.next.srcip
            msg.match.dl_type = ethernet.IP_TYPE
            event.connection.send(msg)
      else:
        log.debug("%i %i learned %s", dpid,inport,packet.next.srcip)
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      # Try to forward
      dstaddr = packet.next.dstip
      if dstaddr in self.arpTable[dpid]:
        # We have info about what port to send it out on...

        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the "
                      "input port" % (dpid, inport, dstaddr))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          if self.wide:
            match = of.ofp_match(dl_type = packet.type, nw_dst = dstaddr)
          else:
            match = of.ofp_match.from_packet(packet, inport)

          if str(src_ip) not in l3_switch.rilevazioni_thread.keys():
            # l'ip non è mai stato segnalato sino ad ora
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=10,
                                hard_timeout=10,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=match)
            event.connection.send(msg.pack())
          else:
            #non installo regole per ip già segnalati come attaccanti
            #questo mi permette di controllare meglio il flusso di pacchetti ricevuti
            return

      elif self.arp_for_unknowns:
        # We don't know this destination.
        # First, we track this buffer so that we can try to resend it later
        # if we learn the destination, second we ARP for the destination,
        # which should ultimately result in it responding and us learning
        # where it is

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        # Expire things from our outstanding ARP list...
        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.items() if v > time.time()}

        # Check if we've already ARPed recently
        if (dpid,dstaddr) in self.outstanding_arps:
          # Oop, we've already done this one recently.
          return

        # And ARP...
        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst)

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            # Learn or update port/MAC info
            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,a.protosrc)
                if self.wide:
                  # Make sure we don't have any entries with the old info...
                  msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                  msg.match.dl_type = ethernet.IP_TYPE
                  msg.match.nw_dst = a.protosrc
                  event.connection.send(msg)
            else:
              log.debug("%i %i learned %s", dpid,inport,a.protosrc)
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            # Send any waiting packets...
            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:
              # Maybe we can answer

              if a.protodst in self.arpTable[dpid]:
                # We have an answer...

                if not self.arpTable[dpid][a.protodst].isExpired():
                  # .. and it's relatively current, so we'll reply ourselves

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   r.protosrc))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      # Didn't know how to answer or otherwise handle this ARP, so just flood it
      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)


def launch (fakeways="", arp_for_unknowns=None, wide=False):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns, wide)
