# pa2a-starter

## Info

Name: Bryce Pollack

PID: A16657276

Email: bpollack@ucsd.edu

## Description and Overview
Describe in brief what files you changed and what they should do.

sr_router.c: This is the file with the core implementation of the router. Incoming packets are fed into sr_handlepacket(), which processes packets according to their headers. If they are IP packets, then they will be acknowledged with an ICMP echo reply if they are destined for one of the router's interfaces or forwarded to the next-hop router if they are not. If it is an ARP request, an ARP reply will be sent back to the sender. If it is an ARP reply, all packets waiting on that ARP reply will be forwarded.

    sr_handlepacket: Determines if the incoming packet is an IP packet or an ARP packet and then delegates to the respective handle functions.

    sr_handleippacket: Determines if the incoming IP packet is destined towards this router's interfaces or not. If it is, then checks if it is an ICMP packet and delegates to sr_handleicmppacket if so. If it is not, then decrements TTL by 1 and broadcasts ARP request for the next-hop router. If TTL is 0 or no next-hop router can be found, sends an ICMP error.

    sr_handleicmppacket: Determines if the incoming ICMP packet is an echo request. If so, sends an ICMP echo reply. 

    sr_handlearppacket: Determines if the incoming ARP packet is an ARP request or ARP reply. If it is an ARP request, then send an ARP reply if the interface it is arriving on matches the target IP. If it is an ARP reply, iterate over the packets attached to the corresponding ARP request object and forward each one.

    sr_sendicmppacket: Sends either an echo reply or an ICMP error. If it is an echo reply, modify the incoming echo request to become an echo reply and send back to the original sender. If it is an ICMP error, construct a new packet to the error specifications and send back to the original sender.

    sr_sendarppacket: Sends either an ARP request or ARP reply. If it is an ARP request, construct a new packet to the ARP request specifications and flood to all local links. If it is an ARP reply, modify the incoming ARP request to become an ARP reply and send back to the original sender.

sr_arpcache.c: This file is responsible for the initialization and methods associated with the ARP cache object. 

    sr_arpcache_sweepreqs: Iterates over all ARP requests in the ARP cache and delegates handling them to sr_handlearpreq

    sr_handlearpreq: For the ARP request in question, determine if it has been 1 second since the request was last sent out. If so, then check if the request has been sent 5 times. If so, then send an ICMP error to each host waiting on this ARP request and clear it from the cache. If not, then retransmit this ARP request. 
