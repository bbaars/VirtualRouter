/*
 * @authors: Brandon Baars, Mike Ford, Isaac Benson
 * @date: 02/13/2018
 * @description: CIS 457 Project 2: Forwarding (Virtual Router)
 *
 */

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <map>
#include <sstream>
#include <fstream>
#include <vector>

#define ARP_PACK 0x0806
#define IP_PACK 0x0800

#define ARP_REQUEST 0x1
#define ARP_RESPONSE 0x2

// ARP Struct
// Ether Header -> Arp Header (request or reply)
typedef struct arpheader {

        u_int16_t htype; // hardware type
        u_int16_t ptype; // protocol type
        u_char hlen; // hardware addr length
        u_char plen; // protocol addr length
        u_int16_t oper; // operation code
        u_char sha[6]; // sender hardware addr
        u_char spa[4]; // sender IP addr
        u_char tha[6]; // target hardware addr
        u_char tpa[4]; // target IP addr

} arpheader_t;

typedef struct datacache {

        std::string eth_iface; // network interface it needs to go out on
        char buff[5000]; // the packet it received that will be cached
        int bytes; //how many bytes are in the cached packet

} datacache_t;



// FUNCTION DECLARATIONS
std::vector<std::string> split(const std::string &str, char delim);
bool addr_in_range(std::string ipaddr, std::string prefix);
uint32_t convert_addr_to_uint32(u_char addr[]);
std::string get_eth_interface(uint32_t ipaddr);
arpheader_t construct_arp_packet(const bool arp_reply, const u_char src_mac[], const u_char dst_mac[], const u_char src_ip[], const u_char dst_ip[]);
ether_header construct_eth_header(ether_header original, u_char dhost[], u_char shost[], uint16_t type);
iphdr construct_ip_header(uint32_t src_ip, uint32_t dst_ip);
void convert_addr_to_char_array(u_char (&arr)[4], uint32_t addr);

// holds all the IP address of the router to check if the destination IP is
// for us or not.
std::vector<uint32_t> router_ipaddrs;

std::string router2_ip = "10.0.0.2";
std::string router1_ip = "10.0.0.1";

bool isR1 = false;
std::string file_name;

/*
 * Checks whether the IP Address falls within the CIDR range of IPAddrs
 * @arg ipaddr is the IP Address you wish to check
 * @arg prefix is the CIDR prefix you wish to use to check the IP addr
 *
 * @return returns a 1 if it is within the range, 0 otherwise.
 *
 * @example True = inet_cidr_to_addr("10.0.0.1", "10.0.0.0/16")
 */
bool addr_in_range(std::string ipaddr, std::string prefix) {

        std::stringstream ip_stream(ipaddr);
        std::stringstream prefix_stream(prefix);

        int x1, x2, x3, x4;
        int y1, y2, y3, y4, range;
        char ch;

        // extract the individual integers of the octets from the IP Addr and Prefix
        ip_stream >> x1 >> ch >> x2 >> ch >> x3 >> ch >> x4;
        prefix_stream >> y1 >> ch >> y2 >> ch >> y3 >> ch >> y4 >> ch >> range;

        // convert our individual integers to a 32 bit unsigned int
        uint32_t ip_addr_t = (x1 << 24) + (x2 << 16) + (x3 << 8) + x4;
        uint32_t prefix_t = (y1 << 24) + (y2 << 16) + (y3 << 8) + y4;
        uint32_t mask = (~uint32_t(0) << (32-range));

        return (ip_addr_t & mask) == (prefix_t & mask);
}


/*
 * checks the routing table file to see if the ipaddr is within any of the
 * interfaces, (i.e eth0, eth1, eth2, etc.)
 *
 * @arg ipaddr is the uint32_t ip address of the host the packet was received from
 *
 * @return returns a string of the interface it was found on. NULL if not found.
 */
std::string get_eth_interface(uint32_t ipaddr) {

        std::ifstream file;

        if (isR1)
                file.open("r1-table.txt");
        else
                file.open("r2-table.txt");

        std::string line, ip_string;
        std::vector<std::string> interfaces;

        // convert our passed IP Address to a string to use later on
        ip_string = inet_ntoa(*(struct in_addr *)&ipaddr);

        if(file.is_open()) {

                while(getline(file, line)) {
                        interfaces = split(line, ':');

                        if(addr_in_range(ip_string, interfaces[0])) {
                                if (interfaces.size() < 3)
                                        return interfaces[1];
                                else
                                        return interfaces[2];
                        }
                }

                file.close();
        }
}

/*
 * Parses the past line for the delimeter, returns an array of the newly split line
 */
std::vector<std::string> split(const std::string &str, char delim) {

        std::stringstream stream(str);
        std::string word;
        std::vector<std::string> token;

        while(getline(stream, word, delim)) {
                token.push_back(word);
        }

        return token;
}

/*
 * Convert a character byte array to a uint32_t
 */
uint32_t convert_addr_to_uint32(u_char addr[]) {
        return (addr[3] << 24) + (addr[2] << 16) + (addr[1] << 8) + addr[0];
}

/*
 * Converst the uint32_t to a char array
 * Must pass the char array as a parameter
 */
void convert_addr_to_char_array(u_char (&arr)[4], uint32_t addr) {

        arr[3] = (addr >> 24);
        arr[2] = (addr >> 16);
        arr[1] = (addr >> 8);
        arr[0] = (addr);
}


/*
 * Constructs and arp packet and returns the packet with given parameters
 *
 * @return arpheader_t the packet
 */
arpheader_t construct_arp_packet(const bool arp_reply, const u_char src_mac[], const u_char dst_mac[], const u_char src_ip[], const u_char dst_ip[]) {

        arpheader_t arp_req;

        // specify we want hardware type 1 (Ethernet)
        arp_req.htype = htons(1);

        // specify IPv4 Paket type
        arp_req.ptype = htons(IP_PACK);

        // size of 6 for ethernet address size (MAC Size of 6 bytes)
        arp_req.hlen = 6;
        arp_req.plen = 4;

        if (arp_reply) {
                memcpy(arp_req.tha, dst_mac, 6);
                arp_req.oper = htons(ARP_RESPONSE);
        } else {
                memset(arp_req.tha, 0, 6);
                arp_req.oper = htons(ARP_REQUEST);
        }

        // Specify the src hardware, dst hardware, src IP, and dst IP
        memcpy(arp_req.sha, src_mac, 6);
        memcpy(arp_req.spa, src_ip, 4);
        memcpy(arp_req.tpa, dst_ip, 4);

        /*
           std::cout << "Source MAC " << ether_ntoa((struct ether_addr*)arp_req.sha) << std::endl;
           std::cout << "Source IP Address: " << inet_ntoa(*(struct in_addr*)arp_req.spa) << std::endl;
           std::cout << "Target MAC " << ether_ntoa((struct ether_addr*)arp_req.tha) << std::endl;
           std::cout << "Target IP Address: " << inet_ntoa(*(struct in_addr*)arp_req.tpa) << std::endl;
         */

        return arp_req;
}

/*
 * Constructs and returns and Ethernet Header
 */
ether_header construct_eth_header(ether_header original, u_char dhost[], u_char shost[], uint16_t type) {

        struct ether_header eh;

        memcpy(original.ether_shost, shost, 6);

        memcpy(original.ether_dhost, dhost, 6);

        original.ether_type = type;

        return original;
}


/*
 * Constrcuts and returns an IP Header Packet
 */
iphdr construct_ip_header(uint32_t src_ip, uint32_t dst_ip) {

        struct iphdr ip;

        ip.version = 4;
        ip.frag_off = 0;
        ip.ihl = 5;
        ip.tot_len = htons(sizeof(struct iphdr));
        ip.id = 0;
        ip.ttl = 64;
        ip.protocol = IPPROTO_ICMP;
        ip.saddr = src_ip;
        ip.daddr = dst_ip;
        ip.check = 0;

        return ip;
}


int main(int argc, char** argv) {

        int packetSocket;

        if(*argv[1] == '1') {
                isR1 = true;
                file_name = "r1-table.txt";
                std::cout << "Starting Router 1" << std::endl;
        } else {
                file_name = "r2-table.txt";
                std::cout << "Starting Router 2" << std::endl;
        }

        // create a file descriptor set
        fd_set sockets;
        FD_ZERO(&sockets);

        // obtain a list of interfaces
        struct ifaddrs *ifaddr, *tmp;

        // map of (IP, MAC)
        std::map<int, struct sockaddr_ll> sockAddrMap;

        // map of ("r1-eth1, "10.1.0.1")
        std::map<std::string, uint32_t> name_to_ip_map;

        // map of ("10.1.0.1", "r1-eth1"):
        // used for when we receive an arp response, we can
        // get the interface name to add to our cache.
        std::map<uint32_t, std::string> ip_to_name_map;

        // mapr of ("r1-eth1, "socket")
        std::map<std::string, int> name_to_socket_map;

        // map of ("r1-eth1, "ae:25:e4:b4:12:ed");
        std::map<std::string, struct sockaddr_ll> name_to_mac_map;

        // map of ("r1-eth1, "bc:23:4d:12:b3:ty");
        // this caches the hosts' MAC attached to the routers interface name
        std::map<std::string, struct sockaddr_ll> cached_mac_map;

        // vector of all the packets that are cached
        std::vector<datacache_t> data_cache;

        if(getifaddrs(&ifaddr) == -1) {
                std::cerr << "Error with getifaddrs";
                return 1;
        }

        // loop through all the network interfaces
        for(tmp = ifaddr; tmp != NULL; tmp = tmp->ifa_next) {

                // check if this is a packet address.
                if(tmp->ifa_addr->sa_family == AF_PACKET) {
                        printf("Interface: %s\n", tmp->ifa_name);

                        // ignore the 'lo' interface, create a socket on all the others
                        if(strcmp(tmp->ifa_name, "lo")) {
                                // if(!strncmp(&(tmp->ifa_name[3]), "eth1", 4)) {
                                std::cout << "Creating socket interface " << tmp->ifa_name << std::endl;

                                // Create a packet socket
                                // AF_PACKET makes it a packet socket
                                // SOCK_RAW makes it so we get the entire packet
                                // ETH_P_ALL indicates we want all (upper layer) protocols
                                packetSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

                                if(packetSocket < 0) {
                                        std::cerr << "Error creating socket on interface " << tmp->ifa_name << std::endl;
                                        return 2;
                                }

                                // once the socket is created, add it to our file desc. list
                                FD_SET(packetSocket, &sockets);


                                // add the IP Address and MAC address to a MAP.
                                // cast our Addr to a lower level sock address.
                                struct sockaddr_ll *s = (struct sockaddr_ll *)tmp->ifa_addr;
                                unsigned char macaddr[8];
                                memcpy(macaddr, &s->sll_addr[0], 8);

                                sockAddrMap[packetSocket] = *s;

                                // convert our char * to string to add to our map
                                // (easier than using char * as key)
                                std::string name(tmp->ifa_name);
                                name_to_mac_map[name] = *s;

                                name_to_socket_map[tmp->ifa_name] = packetSocket;

                                // bind the socket to the address
                                if(bind(packetSocket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1) {
                                        std::cerr << "Error binding socket to interface " << tmp->ifa_name << std::endl;
                                }
                        }
                }

                // use the AF_INET to get the IP Addresses of our router
                else if (tmp->ifa_addr->sa_family = AF_INET && tmp->ifa_addr) {

                        // ignore the 'lo' interface
                        if(strcmp(tmp->ifa_name, "lo")) {

                                struct sockaddr_in *sa;
                                sa = (struct sockaddr_in *)tmp->ifa_addr;

                                // Pull the IP Address from the (sockaddr_in) structure
                                uint32_t ipaddr = sa->sin_addr.s_addr;
                                router_ipaddrs.push_back(ipaddr);
                                std::cout << "IP ADDR: " << inet_ntoa(sa->sin_addr) << std::endl;

                                // convert our char * to string to add to our map
                                // (easier than using char * as key)
                                std::string name(tmp->ifa_name);
                                name_to_ip_map[name] = ipaddr;
                                ip_to_name_map[ipaddr] = name;
                        }
                }
        }

        // free the interface list, we don't need it anymore
        freeifaddrs(ifaddr);

        std::cout << "Getting ready to start receiving on all interfaces" << std::endl;

        while(1) {

                char buff[5000];

                struct sockaddr_ll recvaddr;
                int recvAddrLen = sizeof(recvaddr);
                int rec;

                // create a temp variable for our destructive actions
                fd_set tmpSet = sockets;

                select(FD_SETSIZE, &tmpSet, NULL, NULL, NULL);

                int i = 0;
                for(; i < FD_SETSIZE; i++) {

                        // check if the socket is available
                        if(FD_ISSET(i, &tmpSet)) {

                                // receive from the interface
                                rec = recvfrom(i, buff, 5000, 0, (struct sockaddr*)&recvaddr, (socklen_t*)&recvAddrLen);

                                if(recvaddr.sll_pkttype == PACKET_OUTGOING) {
                                        continue;
                                }

                                if(recvaddr.sll_pkttype != PACKET_OUTGOING) {

                                        std::cout << "Got a " << rec << " byte packet" << std::endl;
                                        struct ether_header eh;
                                        struct iphdr ipheader;
                                        memcpy(&eh, &buff[0], 14);
                                        //printf("Destination %s\n", ether_ntoa((struct ether_addr*)&eh.ether_dhost));
                                        //printf("Source %s\n", ether_ntoa((struct ether_addr*)&eh.ether_shost));
                                        short type = ntohs(eh.ether_type);

                                        bool isMeantForUs = false;
                                        uint32_t source_ip;

                                        // ICMP Request
                                        if(type == IP_PACK) {

                                                //copy IP header
                                                memcpy(&ipheader, &buff[14], 20);

                                                //Print out packet type
                                                if(ipheader.protocol == 1)
                                                        std::cout << "ICMP Packet." << '\n';
                                                else if(ipheader.protocol == 6)
                                                        std::cout << "TCP Packet" << '\n';
                                                else if(ipheader.protocol == 17)
                                                        std::cout << "UDP Packet." << '\n';
                                                int j = 0;

                                                // check all of the routers IP Address to see if the
                                                // packet was meant for us
                                                for(j = 0; j < router_ipaddrs.size(); j++) {

                                                        if (ipheader.daddr == router_ipaddrs[j]) {

                                                                // This is the destination of the packet
                                                                // Do something if the destination is the router
                                                                std::cout << "From IP Address: " << inet_ntoa(*(struct in_addr*)&router_ipaddrs[j]) << std::endl;
                                                                std::cout << "From ETH Interface: " << get_eth_interface(router_ipaddrs[j]) << std::endl;

                                                                // create a sockaddr_ll just to hold our mac address
                                                                struct sockaddr_ll mac;
                                                                memcpy(mac.sll_addr, eh.ether_shost, 6);

                                                                // Get the ETH Interface for what we recieved the packet on
                                                                // cache the MAC Address
                                                                uint32_t router_ip = router_ipaddrs[j];
                                                                std::string eth_iface = ip_to_name_map[router_ip];

                                                                cached_mac_map[eth_iface] = mac;

                                                                std::cout << "Cached MAC Addr: " << ether_ntoa((struct ether_addr*)mac.sll_addr) << " from interface: " << eth_iface << std::endl;

                                                                isMeantForUs = true;
                                                                break;
                                                        }
                                                }

                                                // if the ICMP dst IP is one of our routers
                                                if (isMeantForUs) {

                                                        //swap source and destination of eth header
                                                        std::swap(eh.ether_shost, eh.ether_dhost);
                                                        //overwrite eth header
                                                        memcpy(&buff[0], &eh, 14);
                                                        //swap source and destination of IP header
                                                        std::swap(ipheader.saddr,ipheader.daddr);
                                                        //overwrite ip header
                                                        memcpy(&buff[14], &ipheader, 20);

                                                        //if packet is echo request, change type to reply
                                                        if((unsigned int)buff[34] == 8) {
                                                                std::cout << "Echo request received." << std::endl;
                                                                buff[34] = 0;
                                                        }

                                                        //send packet
                                                        send(i,buff, rec, 0);

                                                        memset(&buff[0], 0, sizeof(buff));

                                                        // if the ICMP dst IP was not meant for us.
                                                        // construct the appropriate packet
                                                        // to forward onward
                                                } else {

                                                        std::cout << "This packet is meant for: " << inet_ntoa(*(struct in_addr *)&ipheader.daddr) << std::endl;

                                                        // Find the Interface this packet was meant for
                                                        std::string eth_iface = get_eth_interface(ipheader.daddr);

                                                        std::cout << "ETH Interface: " << eth_iface << std::endl;
                                                        uint32_t router_forward_ip = name_to_ip_map[eth_iface];

                                                        // Check to see if we've cached the MAC Addr
                                                        // if we have, forward on the packet with the cached MAC Addr.
                                                        if(cached_mac_map.find(eth_iface) != cached_mac_map.end()) {

                                                                // The cache was found, we can forward our packet with the correct MAC
                                                                std::cout << "The packet will be forwarded with cached mac" << std::endl;

                                                                memcpy(eh.ether_shost, &name_to_mac_map[eth_iface].sll_addr[0], 6);
                                                                memcpy(eh.ether_dhost, &cached_mac_map[eth_iface].sll_addr[0], 6);

                                                                //overwrite eth header with new MAC addrs
                                                                memcpy(&buff[0], &eh, 14);

                                                                //send packet on new packet socket
                                                                send(name_to_socket_map[eth_iface], buff, rec, 0);

                                                                memset(&buff[0], 0, sizeof(buff));

                                                        } else {

                                                                // add the cache to our array, to send onward later
                                                                // when we receive the ARP Response.

                                                                std::cout << "Caching our Packet" << std::endl;
                                                                datacache_t cache;
                                                                cache.eth_iface = eth_iface;
                                                                cache.bytes = rec;
                                                                memcpy(cache.buff, &buff, sizeof(buff));

                                                                data_cache.push_back(cache);

                                                                // The MAC wasn't found, need to create an arp request
                                                                // convert our eth header broadcast to "ff:ff:ff..."
                                                                u_char bytes[6];
                                                                memset(bytes, 255, 6);

                                                                // convert our arp dst mac to "00:00:00:..."
                                                                u_char arp_bytes[6];
                                                                memset(arp_bytes, 0, 6);

                                                                // convert the uint32_t IP addrs to char array
                                                                u_char dst_bytes[4];
                                                                u_char src_bytes[4];
                                                                convert_addr_to_char_array(dst_bytes, ipheader.daddr);
                                                                convert_addr_to_char_array(src_bytes, name_to_ip_map[eth_iface]);

                                                                std::cout << "This packet will be forwarded on router IP: " << inet_ntoa(*(struct in_addr *)&name_to_ip_map[&eth_iface[0u]]) << std::endl;

                                                                struct ether_header ethdr = construct_eth_header(eh, bytes, name_to_mac_map[eth_iface].sll_addr, htons(ARP_PACK));

                                                                printf("Destination %s\n", ether_ntoa((struct ether_addr*)&ethdr.ether_dhost));
                                                                printf("Source %s\n", ether_ntoa((struct ether_addr*)&ethdr.ether_shost));

                                                                arpheader_t arphdr = construct_arp_packet(false, name_to_mac_map[eth_iface].sll_addr, arp_bytes, src_bytes, dst_bytes);


                                                                //overwrite eth header
                                                                memcpy(&buff[0], &ethdr, 14);
                                                                memcpy(&buff[14], &arphdr, sizeof(arphdr));

                                                                // size of 42 for an ARP Request (BAD WAY, DON"T HARD CODE)
                                                                send(name_to_socket_map[eth_iface], buff, 42, 0);

                                                                memset(&buff[0], 0, sizeof(buff));
                                                        }
                                                }
                                                //}

                                                // ARP Request
                                        } else if (type == ARP_PACK) {

                                                arpheader_t *arpheader = NULL;
                                                arpheader_t arpHdrResponse;
                                                std::cout << "Arp packet" << std::endl;

                                                arpheader = (struct arpheader *)(buff + 14);

                                                // if the ARP Packet was a Request
                                                if (arpheader->oper == htons(ARP_REQUEST)) {

                                                        //std::cout << "RECEIVED ON FD: " << i << std::endl;

                                                        //std::cout << "PORT MAC: " << ether_ntoa((struct ether_addr *)sockAddrMap[i].sll_addr) <<std::

                                                        // swap the Ethernet headers source and destination addr.
                                                        std::swap(eh.ether_shost, eh.ether_dhost);

                                                        memcpy(eh.ether_shost, &sockAddrMap[i].sll_addr[0], 6);

                                                        //printf("Destination %s\n", ether_ntoa((struct ether_addr*)&eh.ether_dhost));
                                                        //printf("Source %s\n", ether_ntoa((struct ether_addr*)&eh.ether_shost));

                                                        // construct our ARP Response Packet
                                                        arpHdrResponse.htype = arpheader->htype;
                                                        arpHdrResponse.ptype = arpheader->ptype;
                                                        arpHdrResponse.hlen = arpheader->hlen;
                                                        arpHdrResponse.plen = arpheader->plen;
                                                        arpHdrResponse.oper = htons(ARP_RESPONSE);

                                                        memcpy(arpHdrResponse.sha, sockAddrMap[i].sll_addr, 6);
                                                        memcpy(arpHdrResponse.spa, arpheader->tpa, 4);
                                                        memcpy(arpHdrResponse.tha, arpheader->sha, 6);
                                                        memcpy(arpHdrResponse.tpa, arpheader->spa, 4);

                                                        // create a sockaddr_ll just to hold our mac address
                                                        // easier to access in the map than a u_char[]
                                                        struct sockaddr_ll mac;
                                                        memcpy(mac.sll_addr, arpheader->sha, 6);

                                                        // Take the senders IP and sender MAC and cache it to our interface
                                                        uint32_t router_ip = convert_addr_to_uint32(arpheader->tpa);
                                                        std::cout << "Caching IP Address: " << inet_ntoa(*(struct in_addr*)arpHdrResponse.tpa) << std::endl;
                                                        std::string eth_iface = ip_to_name_map[router_ip];

                                                        cached_mac_map[eth_iface] = mac;

                                                        std::cout << "Cached MAC Addr: " << ether_ntoa((struct ether_addr*)mac.sll_addr) << " from interface: " << eth_iface << std::endl;

                                                        /*
                                                           std::cout << "Hardware type: " << ntohs(arpHdrResponse.htype) << std::endl;
                                                           std::cout << "Protocol type: " << ntohs(arpHdrResponse.ptype) << std::endl;
                                                           std::cout << "Operation type: " << ntohs(arpHdrResponse.oper)<< std::endl;

                                                           std::cout << "Source MAC " << ether_ntoa((struct ether_addr*)arpHdrResponse.sha) << std::endl;
                                                           std::cout << "Source IP Address: " << inet_ntoa(*(struct in_addr*)arpHdrResponse.spa) << std::endl;
                                                           std::cout << "Target MAC " << ether_ntoa((struct ether_addr*)arpHdrResponse.tha) << std::endl;
                                                           std::cout << "Target IP Address: " << inet_ntoa(*(struct in_addr*)arpHdrResponse.tpa) << std::endl;
                                                         */

                                                        memcpy(&buff[0], &eh, 14);
                                                        memcpy(&buff[14], &arpHdrResponse, sizeof(arpHdrResponse));

                                                        send(i, buff, rec, 0);

                                                        memset(&buff[0], 0, sizeof(buff));

                                                        // if the ARP Packet was a REPLY (Meaning, we sent out a request for the next destination)
                                                        // then we take the MAC Address from the reply, and send it with our cached data to forward
                                                } else if (arpheader->oper = htons(ARP_RESPONSE)) {

                                                        std::cout << "Arp Response from Arp request received" << std::endl;

                                                        // create a sockaddr_ll just to hold our mac address
                                                        // easier to access in the map than a u_char[]
                                                        struct sockaddr_ll mac;
                                                        memcpy(mac.sll_addr, arpheader->sha, 6);

                                                        // PARSE THE Response for the MAC Addr and add it to our cache
                                                        uint32_t router_ip = convert_addr_to_uint32(arpheader->tpa);
                                                        std::string eth_iface = ip_to_name_map[router_ip];

                                                        cached_mac_map[eth_iface] = mac;

                                                        std::cout << "Cached MAC Addr: " << ether_ntoa((struct ether_addr*)mac.sll_addr) << " from interface: " << eth_iface << std::endl;

                                                        // Now we can send our cached ICMP Packet on the interface
                                                        int z;
                                                        for(z = 0; z < data_cache.size(); z++) {

                                                                if (!data_cache[z].eth_iface.compare(eth_iface)) {

                                                                        std::cout << "Sending Cached Packet" << std::endl;

                                                                        memcpy(eh.ether_shost, &name_to_mac_map[eth_iface].sll_addr[0], 6);
                                                                        memcpy(eh.ether_dhost, &cached_mac_map[eth_iface].sll_addr[0], 6);
                                                                        eh.ether_type = htons(IP_PACK);

                                                                        //overwrite eth header with new MAC addrs
                                                                        memcpy(data_cache[z].buff, &eh, 14);

                                                                        std::cout << "SIZE OF CACHED PACKET: " << (size_t)strlen(data_cache[z].buff) * sizeof(u_int) << std::endl;

                                                                        //send packet on new packet socket
                                                                        //send cached buffer and buffer size
                                                                        send(name_to_socket_map[eth_iface], data_cache[z].buff, data_cache[z].bytes, 0);

                                                                        data_cache.erase(data_cache.begin() + z);

                                                                        memset(&buff[0], 0, sizeof(buff));
                                                                }
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }

        return 0;
}
