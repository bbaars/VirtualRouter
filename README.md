# CIS 457 Virtual Router Project (Cpp) #

### Objective: ###
Learn about the function of a router through implementing a simplified version in software.

## Part One ##

For part one, your router must correctly deal with arp requests and ICMP echo requests. When your router gets an ARP request for one of its IP addresses, it must send out an ARP response on the same socket, back to the sender of the ARP request. The MAC address indicated in the ARP reply should be one for the same interface as the IP address indicated in the request. ARP packets consist of an Ethernet header and an ARP header. No IP header is used.

Additionally for part one, your router must correctly respond to ICMP echo request packets with any of its own IP addresses as the destination. The correct action to take when recieving an ICMP echo request is to send an ICMP echo reply with the same ID, sequence number, and data as the response. You must correctly construct the Ethernet, IP, and ICMP headers.

The above behavior should work for all Ethernet interfaces of your virtual router.

Once these two steps are completed, a host should be able to successfully ping the router interface it is connected to. If ARP is working but not ICMP, ping on the host should be sending ICMP echo requets, and they should be seen on the router. If ARP is not working, the ICMP echo requests will not be sent. If your ARP implementation is not yet correctly working, you may test ICMP by re-enabling the operating system's ARP responses which we have disabled for this project.

## Part Two ##

For part three, your router must forward packets towards their destination. This primarily consists of two tasks:

Look up the destination address in the forwarding table, to get the IP address of the next hop.
Find the MAC address corresponding to this IP address through using ARP.
Construct a new Ethernet header, attach it to the packet, and sent it out the correct socket
For the forwarding table lookup, you must match the destination address in your packet against the entries in the table. In this project we will only use very simple forwarding tables, where there is at most one match for any address. All prefixes in the table will be either 16 or 24 bits. Although these are not generally true for real forwarding tables, your code for this project may assume these to be true. You are not required to implement the lookup in an efficient manner. At this point, if there is no match, you can ignore any further action for this packet (we will implement the correct behavior here in part 3)

After finding the next hop IP address, you must construct the ARP packet to find the MAC address corresponding to the next hop IP address, and send it. Send this request out only on the correct interface from the previous step, and receive the reply. You may use a cache to bypass this step, although you are not required to. If there is no response, for now you can ignore any further action on this packet (we will implement the correct behavior here in part 3)

Upon receiving the ARP response, change construct the new ethernet header on the packet to be forwarded. Your routers MAC address, on the interface that is sending the packet out, should be the source. The MAC address you learned though ARP should be the destination.


### Part Three ###
In part 3, we will add the last bits of functionality to our routers. By the end of part 2, they should have been forwarding packets, but not necessarily with the correct changes to TTL and checksum, or with the correct behavior in the case of errors. By part 3, the following behavior is expected (this description includes steps from part 2 as well for clarity):

Upon receiving an IPv4 packet where the router itself is not the destination, the following steps should be taken:

Verify the IP checksum in the received packet. If incorrect, drop the packet.
Decrement the TTL. If the TTL becomes zero, due to this operation, send back a ICMP time exceeded (TTL exceeded) message and drop the original packet. Otherwise, you must recompute the IP checksum due to the changed TTL.
Find an entry in the routing table, with prefix matching the destination IP address in the packet. If no such entry exists, send back an ICMP destination unreachable (network unreachable) message.
Using the routing table entry found, determine the interface and next hop IP address. The next hop IP address is only used in ARP, we do not put this address into the packet being forwarded in any way.
Construct an ARP request, to find the ethernet address corresponding to the next hop IP address. Send this request out on the correct interface from the previous step, and receive the reply. You may use a cache to bypass this step, although you are not required to. If there is no ARP response, send back and ICMP destination unreachable (host unreachable) message.
Using the ethernet address found through arp as the destination, and the ethernet address of the interface you are sending on as the source, construct a new ethernet header for the packet being forwarded.
Finally, send out the packet on the appropriate interface (packet socket).
