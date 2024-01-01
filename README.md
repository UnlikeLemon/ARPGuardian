# ARPGuardian
---

## What is this?
It's a simple IDS I made in Python using `scapy` library. It has 2 functions, offline and live scanning. 

Offline mode: Simply scans a .pcap(ng) file and looks for possible patterns matching an ARP Spoofing/Poisoning attack. If it does find anything it prints outs the results, mostly which clients (Client's MAC), the amount of packets sent along with timestamps and the duration of the attack.

Live scanning: Running on given interface, it will scan each ARP packet sniffed and also try to match any pattern that looks like an ARP Spoofing/Poisoning attack. For now it simply prints out which user sent a malicious packet, but in newer versions i'll add an aggressive mode, where if activated the attacker gets kicked off the network.


## How it works?
---

Its relatively simple. All we have to do is look at packets containing `op-code: is-at`. Not going to get technical but let's look at a normal packet and a maliciously crafted one and try to spot the difference.

```Malicious packet
###[ Ethernet ]### 
  dst       = 08:00:27:b8:b7:58
  src       = 08:00:27:2d:f8:5a
  type      = ARP
###[ ARP ]### 
     hwtype    = 0x1
     ptype     = IPv4
     hwlen     = 6
     plen      = 4
     op        = is-at
     hwsrc     = 08:00:27:2d:f8:5a
     psrc      = 192.168.1.1
     hwdst     = 08:00:27:b8:b7:58
     pdst      = 192.168.1.104

```
```Legitimate
###[ Ethernet ]### 
  dst       = 08:00:27:b8:b7:58
  src       = 08:00:27:2d:f8:5a
  type      = ARP
###[ ARP ]### 
     hwtype    = 0x1
     ptype     = IPv4
     hwlen     = 6
     plen      = 4
     op        = is-at
     hwsrc     = 08:00:27:2d:f8:5a
     psrc      = 192.168.1.105
     hwdst     = 08:00:27:b8:b7:58
     pdst      = 192.168.1.104

```

As we can see the difference is in the ARP layer, where the `psrc` is different.
In the legitimate request the client with MAC address `08:00:27:2d:f8:5a` sent a packet to client `08:00:27:b8:b7:58` with the actual IP, `192.168.1.105`. But in the malicious one, the `psrc` value is set to `192.168.1.1`, basically saying "Hey client `08:00:27:b8:b7:58`, im client `08:00:27:2d:f8:5a` and im the gateway, forward all your traffic to me!". Now obviously we don't want any intruders snooping around our network and sniffing our traffic. This is where my script comes in, finding any intrusions in a netwrork or if it happened from .pcap(ng) logs.


## Does it actually work?

---

Well yes, and no. It still in its early stages, and its relying on this one missmatch in the packets. Obviously someone skilled enough could work around it and avoid any detection. But keep in mind this program was made by an 18 year old university student experimenting with Network Security. I will be adding new features soon.