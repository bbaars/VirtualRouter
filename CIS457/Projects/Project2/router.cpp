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
#include <vector>
#include <netinet/ip.h>

#define ARP_PACK 2054
#define IP_PACK 2048
#define ICMP_PACK 1
#define ECHO_REQ 8

int main(int argc, char** argv)
{

        int packetSocket;

        // create a file descriptor set
        fd_set sockets;
        FD_ZERO(&sockets);

        // obtain a list of interfaces
        struct ifaddrs *ifaddr, *tmp;

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

                                // bind the socket to the address
                                if(bind(packetSocket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1) {
                                        std::cerr << "Error binding socket to interface " << tmp->ifa_name << std::endl;
                                }
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
                                        printf("Destination %s\n", ether_ntoa((struct ether_addr*)&eh.ether_dhost));
                                        printf("Source %s\n", ether_ntoa((struct ether_addr*)&eh.ether_shost));
                                        short type = ntohs(eh.ether_type);


                                        if(type == 0x800) {
                                                printf("IPV4\n");
                                                struct in_addr sendAddr;
                                                struct in_addr destAddr;
                                                memcpy(&ipheader, &buff[14], 20);

                                                if(ipheader.protocol == 1)
                                                        std::cout << "ICMP packet." << '\n';
                                        }
                                }


                        }
                }
        }

        return 0;
}
