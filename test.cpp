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
#include <sstream> // converting strings to ints (used for IP Addrs)
#include <bitset>
#include <vector>
#include <fstream>

/*
* Parses the past line for the delimeter, returns an array of the newly split line
*/ 
std::vector<std::string> line_split(const std::string &str, char delim) {
	
	std::stringstream stream(str);
	std::string word;
	std::vector<std::string> token;
	
	while(std::getline(stream, word, delim)) {
		std::cout << word << std::endl;
		token.push_back(word);
		
	}
	
	return token;
}

std::string get_eth_interface(uint32_t ipaddr) {
	
	std::ifstream file("r1-table.txt");
	std::string line;
	std::vector<std::string> interfaces;
	
	if(file.is_open()) {
	
		while(std::getline(file, line) && !file.eof()) {
			interfaces = line_split(line, ':');
			
		}
		
		file.close();
	}
	
	return "hello";
}


int main(int argc, char** argv) {

	std::string ip = "1.0.1.10";
	std::string mask = "192.168.1.0/24";
	std::stringstream s(ip);
	std::stringstream t(mask);
	
	int a,b,c,d;
	char ch; // temp char variable to store our '.' and '/'
	int e, f, g, h, i;
	
	// convert our IP Addr to individual Ints
	s >> a >> ch >> b >> ch >> c >> ch >> d;
	//std::cout << a << " " << b << " " << c << " " << d << std::endl;
	
	// convert our prefix to individual Ints
	t >> e >> ch >> f >> ch >> g >> ch >> h >> ch >> i;
	//std::cout << e << " " << f << " " << g << " " << h << " " << i << std::endl;
	
	//uint32_t ip_addr = a << 24 + b << 16 + c << 8 + d;
	uint32_t ip_addr = (a << 24) + (b << 16) + (c << 8) + d;
	uint32_t range = (e << 24) + (f << 16) + (g << 8) + h;
	uint32_t masked = (~uint32_t(0) << (32-i));
	
	std::bitset<32> x(ip_addr);
	std::bitset<32> y(range);
	std::bitset<32> z(masked);
	
	uint32_t test = ntohl(range);
	
	std::cout << x << std::endl;
	std::cout << ip_addr << std::endl;
	std::cout << y << std::endl;
	std::cout << range << std::endl;
	std::cout << z << std::endl;
	std::cout << masked << std::endl;
	
	
	if ((ip_addr & masked) == (range & masked)) {
		std::cout << "TRUE" << std::endl;
	}
	
	get_eth_interface(ip_addr);
	
	return 0;
}

