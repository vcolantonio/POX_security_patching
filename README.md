# Pox_security_patching
 
In this repository, you'll find a patched version of POX controller for SDN (https://github.com/noxrepo/pox), against these types of attacks: 
- DDOS
- ARP poisoning
- LLDP injection
- attacks against Host Tracker service

The source code of the attacks is in the `attacchi` directory, while the patched versions of POX modules are respectively:
- `/pox/forwarding/l3_patch_dos.py`
- `/pox/forwarding/l3_patch_ARP.py`
- `/pox/openflow/discovery_patch_lldpinj.py`
- `/pox/host_tracker/host_patch.py`

This project was realized for "Network Security" course (in group).
