#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <vector>
#include <stdlib.h>
#include <map>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <tuple>
#include <string>
#include <iostream>
using namespace std;

// Vector of tuples. First is lookup IP, second is next IP Hop, third is interface.
vector<tuple<string, string, string>> routing_table;

// Build table will initialize the routing_table vector based on the routing-table files.
void buildTable(char * name)
{
	FILE * file;
	if(strncmp(name, "r1", 2) == 0)
		file = fopen("r1-table.txt", "r");
	else
		file = fopen("r2-table.txt", "r");
	// Reading file line by line, tokenize each line.
	char line[30];

	while(fgets(line, 30, file) != NULL){
		char *token;
		token = strtok(line, " ");
		// Not doing loop, since hould be 3 fields only.
		
		string key = token;
		token = strtok(NULL, " ");

		string nextIP = token;
		token = strtok(NULL, " ");

		string interface = token;

		routing_table.push_back(make_tuple(key, nextIP, interface));
	}

	fclose(file);
	return;
}

// Look Route looks through the routing table for the ip requested.
pair<string, string> lookRoute(struct in_addr &dest)
{
	char * tempIP = inet_ntoa(dest);
	printf("Looking for IP %s in table\n", tempIP);
	pair<string, string> result = make_pair("", "");
	// Loop through table. If prefix matches, found it. Otherwise, send pair of <"","">
	// which tells program to drop packet.
	for(auto a: routing_table)
	{
		printf("Look route compare %s and %s\n", get<0>(a).c_str(), tempIP);
		if(strncmp(get<0>(a).c_str(), tempIP, 6) == 0){
			result = make_pair(get<1>(a), get<2>(a));
		}
	}
	printf("Look route returning: %s %s\n", result.first.c_str(), result.second.c_str());
	return result;
}

// Our arphdr, pretty much like the linux ones.
typedef struct arphdr
{
    unsigned short int ar_hrd;		/* Format of hardware address.  */
    unsigned short int ar_pro;		/* Format of protocol address.  */
    unsigned char ar_hln;		/* Length of hardware address.  */
    unsigned char ar_pln;		/* Length of protocol address.  */
    unsigned short int ar_op;		/* ARP opcode (command).  */
} arphdr;


// "Simple" checksum algorithim inspired by minirighi.sourceforget.net
unsigned short generateChecksum(char *buf, int size)
{
	unsigned long sum = 0;
	uint16_t ip;
	unsigned char *place = (unsigned char *)buf;

	while(size > 1){
		ip = (short)(((short)place[1]) << 8) | place[0];
		sum += ip;
		if( sum & 0x80000000) // Carry
			sum = (sum & 0xFFFF) + (sum >> 16);
		size -= 2;
		place += 2;
	}
	// More Carries
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	// Invert sum
	return(~sum);
}

// Checks our IPs. Strict either makes it match on exact match, or by prefix.
int checkIPS(char* destIP, vector<in_addr> &ips, int strict)
{
	if(strict){
		for(int i = 0; i < ips.size(); i++){
			char *src = inet_ntoa(ips[i]);
			if(strncmp(src, destIP, strlen(src)) == 0)
				return 1;
		}
	}
	if(!strict){
		for(int i = 0; i < ips.size(); i++){
			char *src = inet_ntoa(ips[i]);
			if(strncmp(src, destIP, 6) == 0)
				return 1;
		}
		printf("Returning\n");
	}
	return 0;
}

// Return 1 if not valid, 0 if valid.
int checkChecksum(char* buf, int size)
{
	// To check checksum, go thorugh size bytes of buf, adding as words. If end up with 0
	// it is right.
	
	// Using generateChecksum function to check it. Assuming buf points to IP header, size is IP size.
	// Assuming Checksum field was not cleared to 0 before.
	unsigned short check = generateChecksum(buf, size);
	if(check == 0)
		return 0;
	return 1;
}
// Check if MAC is one of our MACS
int checkMAC(char* destMAC, vector<char *> &mac)
{
	for(auto const& value: mac){
		if(strncmp(destMAC, value, 6) == 0)
			return true;
	}
	return 0;
}

// Returns the MAC address based on the interface requested. 
void getMyMac(char* interface, map<string, unsigned char*> &macs, unsigned char *toGet){
	// Look for key that contains interface. Return that value.
	unsigned char *mac;

	string key = interface;

	mac = macs[key];
	
	memcpy(toGet, mac, 6);

	return;

}

int main(){
	int eth0_socket;
	int eth1_socket;
	int eth2_socket;
	int eth3_socket;
  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1){
    perror("getifaddrs");
    return 1;
  }
	fd_set sockets;
	FD_ZERO(&sockets); // Socket Set
	vector<struct in_addr> myIP; // List of router IPs
	map<string, unsigned char*> myMAC;  // Map of interface to MAC addresses.
	map<int, char*> myInterface; // Socket ID to interface.
	map<string, in_addr> interToIP; // Interface to IP
 //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next){
    //Check if this is a packet address, there will be one per
    //interface.  There are IPv4 and IPv6 as well, but we don't care
    //about those for the purpose of enumerating interfaces. We can
    //use the AF_INET addresses in this list for example to get a list
    //of our own IP addresses
    	// Making a list of our/this router's IPs
	if(tmp->ifa_addr->sa_family==AF_INET){		
		auto tempAddr = ((struct sockaddr_in *)tmp->ifa_addr)->sin_addr;
		myIP.push_back(tempAddr);
		char* interface = tmp->ifa_name;
		interface += 3;
		interToIP[interface] = tempAddr;
	}
    if(tmp->ifa_addr->sa_family==AF_PACKET){
	unsigned char temp[6];
	memcpy(temp, tmp->ifa_addr->sa_data, 6);

	char* tempo = tmp->ifa_name;
	tempo += 3;
	string key = tempo;
	myMAC[key] = temp;	
       printf("Interface: %s\n",tmp->ifa_name);
      //create a packet socket on interface r?-eth1
      if(!strncmp(&(tmp->ifa_name[3]),"eth1",4)){
	printf("Creating Socket on interface %s\n",tmp->ifa_name);
	//create a packet socket
	//AF_PACKET makes it a packet socket
	//SOCK_RAW makes it so we get the entire packet
	//could also use SOCK_DGRAM to cut off link layer header
	//ETH_P_ALL indicates we want all (upper layer) protocols
	//we could specify just a specific one
	eth1_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(eth1_socket<0){
	  perror("socket");
	  return 2;
	}
	//Bind the socket to the address, so we only get packets
	//recieved on this specific interface. For packet sockets, the
	//address structure is a struct sockaddr_ll (see the man page
	//for "packet"), but of course bind takes a struct sockaddr.
	//Here, we can use the sockaddr we got from getifaddrs (which
	//we could convert to sockaddr_ll if we needed to)
	if(bind(eth1_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
	  perror("bind");
	}
	// Add this socket to the list of sockets
	FD_SET(eth1_socket, &sockets);
	char * interface = tmp->ifa_name;
	interface += 3;
	myInterface[eth1_socket] = interface;
	interface -= 3;
	buildTable(interface);
      }
	// Setting up eth2
	if(!strncmp(&(tmp->ifa_name[3]),"eth2", 4)){
		printf("Creating socket on eth2\n");
		eth2_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(eth2_socket<0){
			perror("eth2_socket");
			return 2;
		}
		if(bind(eth2_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
			perror("eth2_bind");
		}
		FD_SET(eth2_socket, &sockets);
		char* interface = tmp->ifa_name;
		interface += 3;
		myInterface[eth2_socket] = interface;
	}
	// setup eth0
	if(!strncmp(&(tmp->ifa_name[3]), "eth0", 4)){
		printf("Creating socket on eth0\n");
		eth0_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(eth0_socket<0){
			perror("eth0_socket");
			return 2;
		}
		if(bind(eth0_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
			perror("eth0_bind");
		}
		FD_SET(eth0_socket, &sockets);
		char* interface = tmp->ifa_name;
		interface += 3;
		myInterface[eth0_socket] = interface;
	}
	// setup eth3
	if(!strncmp(&(tmp->ifa_name[3]), "eth3", 4)){
		printf("Creating socket on eth3\n");
		eth3_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if(eth3_socket<0){
			perror("eth3_socket");
			return 2;
		}
		if(bind(eth3_socket, tmp->ifa_addr, sizeof(struct sockaddr_ll)) == -1){
			perror("eth3_bind");
		}
		FD_SET(eth3_socket, &sockets);
		char* interface = tmp->ifa_name;
		interface += 3;
		myInterface[eth3_socket] = interface;
	}
    }
  }
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("Ready to recieve now\n");
  while(1){
    char buf[1500];
    struct sockaddr_ll recvaddr;
    socklen_t recvaddrlen=sizeof(struct sockaddr_ll);
    //we can use recv, since the addresses are in the packet, but we
    //use recvfrom because it gives us an easy way to determine if
    //this packet is incoming or outgoing (when using ETH_P_ALL, we
    //see packets in both directions. Only outgoing can be seen when
    //using a packet socket with some specific protocol)

	// Using select to choose which socket to handle
	
	fd_set tmp_set = sockets;
	select(FD_SETSIZE, &tmp_set, NULL, NULL, NULL);
	int i;
	
	for(i = 0; i < FD_SETSIZE; ++i){
		if(FD_ISSET(i, &tmp_set)){	

    int n = recvfrom(i, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);

    //ignore outgoing packets (we can't disable some from being sent
    //by the OS automatically, for example ICMP port unreachable
    //messages, so we will just ignore them here)
    if(recvaddr.sll_pkttype==PACKET_OUTGOING)
      continue;
    //start processing all others
    printf("Got a %d byte packet\n", n);
	// Processing a recieved packet
	
	// Reading ethernet / link layer of packet
	char toSend[1500];
	char* current = buf;
	ether_header packetEth;	
	memcpy(&packetEth, buf, sizeof(ether_header));
	current += sizeof(ether_header);

	// If protocol is arp, read the data as arp
	if(ntohs(packetEth.ether_type) == ETHERTYPE_ARP)
	{
		printf("Got an ARP packet!\n");
		// Current points to the start of the data, that data is ARP
		arphdr packetArp;
		memcpy(&packetArp, current, sizeof(arphdr));
		current += sizeof(arphdr);
		// Current points to Sender Hardware Address now.
	
		// Check if it is request: If so, do the request
		if(ntohs(packetArp.ar_op) == 1){
			printf("Arp request!\n");
			//Check if the dest IP is me		
			// Copying the addresses.
			char senderHardware[6]; 
			char destHardware[6];
			unsigned long senderProto;
			unsigned long destProto;
			memcpy(&senderHardware, current, 6);
			current += 6;
			memcpy(&senderProto, current, 4);
			current += 4;
			// Don't bother copying the destHardware, since that's what I'm sending back.
			current += 6; // Pointing at destProtocol
			memcpy(&destProto, current, 4);


			in_addr tempIPStuff;
			tempIPStuff.s_addr = destProto;
			char* tempIPStuffChar = inet_ntoa(tempIPStuff);
			char *realIP = (char *)malloc(strlen(tempIPStuffChar));
			memcpy(realIP, tempIPStuffChar, strlen(tempIPStuffChar));
			if(checkIPS(realIP, myIP, 0) == 1){
				printf("One of My IPs requested\n");
				// Requested one of my IP's MAC/Hardware address.
				// Change to Response OP, switch source and destination, put in my MAC.
				packetArp.ar_op = htons(2); // Set to Reply
				
				// call function to find our MAC to send.
				// function needs to know interface and will just look at map setup earlier
				unsigned char *myMac = (unsigned char*)malloc(6); 
				getMyMac(myInterface[i], myMAC, myMac);	

				// Switching addresses
				memcpy(&destHardware, &senderHardware, 6);
				
				memcpy(&senderHardware, myMac, 6);
				auto temp = senderProto;
				senderProto = destProto;
				destProto =  temp;
				

				// Creating Ethernet header to send with
				// Source should now be mac address we found.
				// Destination is old source
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, myMac, 6);

				// Send - First copy ethernet, then ARPhdr, then the addresses to toSend, then send on socket. 
				char* currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);
				memcpy(currentSend, &packetArp, sizeof(arphdr));
				currentSend += sizeof(arphdr);
				memcpy(currentSend, &senderHardware, 6);
				currentSend += 6;
				memcpy(currentSend, &senderProto, 4);
				currentSend += 4;
				memcpy(currentSend, &destHardware, 6);
				currentSend += 6;
				memcpy(currentSend, &destProto, 4);

				printf("Sending arp response\n");
				send(i, toSend, n, 0);
			}
			free(realIP);
		}	


	}
	// If type is IP, need to copy IP header to see what the protocol is.
  	else if(ntohs(packetEth.ether_type) == ETHERTYPE_IP)
	{
		// Current is pointing to start of IP frame.
		printf("IP type packet\n");
		ip packetIP;
		memcpy(&packetIP, current, sizeof(ip));
		current += sizeof(ip); // Poiting to IP data
		// Check if destination is one of my IPs, otherwise routing stuff in else.	
		char* toTest = inet_ntoa(packetIP.ip_dst);
		char *realTest = (char *)malloc(strlen(toTest));
		memcpy(realTest, toTest, strlen(toTest));

		// Checking if IP packet is for me exactly (on any interface).
		if(checkIPS(realTest, myIP, 1) == 1){
			printf("IP packet for me!\n");
			
			// Check if it is protocol ICMP
			if((packetIP.ip_p) == 1){
				printf("We got an ICMP request!\n");
				icmphdr packetICMP;
				memcpy(&packetICMP, current, sizeof(icmphdr));
				current += sizeof(icmphdr);
	
				if(packetICMP.type == ICMP_ECHO){ // echo
					printf("Echo request\n");
					// building up packet to send back. Mostly just switching things around.
					// not changing IP checksum, but am changing ICMP checksum by nature of new opcode.
					char toSend[1500];
					
					// Mac or Link Layer generation
					char tempHardware[6];
					memcpy(&tempHardware, &packetEth.ether_dhost, 6);
					memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
					memcpy(&packetEth.ether_shost, &tempHardware, 6);
									
					// IP header changing
					in_addr tempAddr;
					memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
					memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
					memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

					// ICMP changing
					packetICMP.type = ICMP_ECHOREPLY;
					
					// Changing checksum - For part1, trying to be sneaky and not calculate it fully.
					packetICMP.checksum = packetICMP.checksum + 8;

					// Start with copy of sent data.
					char *currentSend = toSend;
					memcpy(&toSend, &buf, 1500);

					// Copy over Link layer
					memcpy(currentSend, &packetEth, sizeof(ether_header));
					currentSend += sizeof(ether_header);

					// Copy over IP/Network layer
					memcpy(currentSend, &packetIP, sizeof(ip));
					currentSend += sizeof(ip);

					// Copy over ICMP
					memcpy(currentSend, &packetICMP, sizeof(icmphdr));
					
					printf("Sending echo response seqid %d\n", packetICMP.un.echo.id);
					send(i, toSend, n, 0);
					continue;
				}// Else, do everything we normally do. This is redudant, kept for 'robust' code.
			// Check TTL
			auto ttl = packetIP.ip_ttl - 1;
			if(ttl <= 0){
				ip oldIP;
				memcpy(&oldIP, &packetIP, sizeof(ip));
				printf("TTL Expire\n");
				// Drop and send ICMP error back. Size is regular packet + 8 orig data.
				int sizeHelp = sizeof(ether_header) + sizeof(ip) + sizeof(icmphdr) + 8;
				char toSend[1500];
				icmphdr packetICMP;

				// Generate/Switch Link layer
				char tempHardware[6];
				memcpy(&tempHardware, &packetEth.ether_dhost, 6);
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, &tempHardware, 6);

				// Setup IP header.
				in_addr tempAddr;
				memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
				memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
				memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

				// Generate ICMP Info
				packetICMP.type = ICMP_TIME_EXCEEDED;
				packetICMP.code = ICMP_EXC_TTL;
				packetICMP.checksum = 0;

				char justICMP[4];
				memcpy(justICMP, &packetICMP, 4);
				packetICMP.checksum = generateChecksum(justICMP, 4);

				char *currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);

				memcpy(currentSend, &packetIP, sizeof(ip));
				currentSend += sizeof(ip);

				memcpy(currentSend, &packetICMP, sizeof(icmphdr));
				currentSend += sizeof(icmphdr);
				// Copy over old IP, plus 8 bytes of data.

				memcpy(currentSend, &oldIP, sizeof(ip));
				currentSend += sizeof(ip);

				char * temp = buf + sizeHelp - 8 - sizeof(icmphdr);
				memcpy(currentSend, temp, 8);
				currentSend -= sizeof(ip);
				currentSend -= sizeof(icmphdr);
				packetICMP.checksum = generateChecksum(currentSend, sizeof(ip) + 16);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));

				printf("Sending TTL\n");
				send(i, toSend, sizeHelp + sizeof(ip), 0);
				continue;
			}
			// Everything is correct so far.
			// Since TTL is changed, change IP header checksum.
			packetIP.ip_ttl = ttl;
			packetIP.ip_sum = 0;
			char justIP[20];
			memcpy(justIP, &packetIP, 20);
			packetIP.ip_sum = generateChecksum(justIP, 20);

			// Look up destination in routing table. Returns empty pair if not found.
			auto tableResult = lookRoute(packetIP.ip_dst);
			if(tableResult.first == ""){
				// Send ICMP error back
				printf("Destination not found in table\n");
				ip oldIP;
				memcpy(&oldIP, &packetIP, sizeof(ip));
				int sizeHelp = sizeof(ether_header) + sizeof(ip) + sizeof(icmphdr) + 8;
				char toSend[1500];
				icmphdr packetICMP;

				// Link Layer
				char tempHardware[6];
				memcpy(&tempHardware, &packetEth.ether_dhost, 6);
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, &tempHardware, 6);

				// IP header
				in_addr tempAddr;
				memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
				memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
				memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

				// ICMP
				packetICMP.type = ICMP_DEST_UNREACH;
				packetICMP.code = ICMP_NET_UNREACH;
				packetICMP.checksum = 0;

				char justICMP[4];
				memcpy(justICMP, &packetICMP, 4);
				packetICMP.checksum = generateChecksum(justICMP, 4);

				char *currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);

				memcpy(currentSend, &packetIP, sizeof(ip));
				currentSend += sizeof(ip);

				memcpy(currentSend, &packetICMP, sizeof(icmphdr));
				currentSend += sizeof(icmphdr);
				// Copy over old IP, plus 8 bytes of data.

				memcpy(currentSend, &oldIP, sizeof(ip));
				currentSend += sizeof(ip);

				char * temp = buf + sizeHelp - 8 - sizeof(icmphdr);
				memcpy(currentSend, temp, 8);
				currentSend -= sizeof(ip);
				currentSend -= sizeof(icmphdr);
				packetICMP.checksum = generateChecksum(currentSend, sizeof(ip) + 16);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));

				printf("Sending TTL\n");
				send(i, toSend, sizeHelp + sizeof(ip), 0);
				continue;
			}
			// Can use info found to pass packet along.
			// Check if need to hop IP
			printf("Doing intermediate ARP\n");
			auto toARP = packetIP.ip_dst;
			if(tableResult.first.length() > 2)
				inet_aton(tableResult.first.c_str(), &toARP);
			int arpSocket;
			char *interface = (char *)tableResult.second.c_str();
			interface += 3;
			for(auto b:myInterface){
				if(strncmp(b.second, interface, 4) == 0){
					arpSocket = b.first;
					break;
				}
			}
			// Build ARP Link layer
			ether_header arpEther;
			arpEther.ether_type = htons(ETHERTYPE_ARP);
			for(int a = 0; a < 6; a++){
				arpEther.ether_dhost[a] = -1;
			}
			unsigned char *myMac = (unsigned char*)malloc(6);
			getMyMac(myInterface[arpSocket], myMAC, myMac);
			memcpy(&arpEther.ether_shost, myMac, 6);
			// Build ARP packet
			arphdr arpArp;
			arpArp.ar_hrd = htons(1);
			arpArp.ar_pro = htons(0x800);
			arpArp.ar_hln = 6;
			arpArp.ar_pln = 4;
			arpArp.ar_op = htons(1);
			char arpSend[1500];
			char *arpSendTo = arpSend;
			memcpy(arpSendTo, &arpEther, sizeof(ether_header));
			arpSendTo += sizeof(ether_header);
			memcpy(arpSendTo, &arpArp, sizeof(arphdr));
			arpSendTo += sizeof(arphdr);

			memcpy(arpSendTo, &arpEther.ether_shost, 6);
			arpSendTo += 6;
			memcpy(arpSendTo, &packetIP.ip_src, 4);
			arpSendTo += 4;
			char destHardware[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
			memcpy(arpSendTo, &destHardware, 6);
			arpSendTo += 6;
			memcpy(arpSendTo, &toARP, 4);

			struct timeval time;
			time.tv_sec = 0;
			time.tv_usec = 100000;
			if(setsockopt(arpSocket, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time)) < 0){
				printf("error setting timeout\n");
			}

			printf("Send Arp request\n");
			send(arpSocket, arpSend, sizeof(arphdr) + sizeof(ether_header) + 20, 0);
			char arpResponse[1500];
			int test = recvfrom(arpSocket, arpResponse, 1500, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
			printf("Got %d bytes\n", test);
			if(test < 0){ // no response
				// Send error back
				ip oldIP;
				memcpy(&oldIP, &packetIP, sizeof(ip));
				printf("No response on ARP\n");
				int sizeHelp = sizeof(ether_header) + sizeof(ip) + sizeof(icmphdr) + 8;
				char toSend[1500];
				icmphdr packetICMP;

				char tempHardware[6];
				memcpy(&tempHardware, &packetEth.ether_dhost, 6);
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, &tempHardware, 6);

				in_addr tempAddr;
				memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
				memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
				memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

				packetICMP.type = ICMP_DEST_UNREACH;
				packetICMP.code = ICMP_HOST_UNREACH;
				packetICMP.checksum = 0;

				char justICMP[4];
				memcpy(justICMP, &packetICMP, 4);
				packetICMP.checksum = generateChecksum(justICMP, 4);

				char *currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);

				memcpy(currentSend, &packetIP, sizeof(ip));
				currentSend += sizeof(ip);

				memcpy(currentSend, &packetICMP, sizeof(icmphdr));
				currentSend += sizeof(icmphdr);

				// Copy over old IP, plus 8 bytes of data.

				memcpy(currentSend, &oldIP, sizeof(ip));
				currentSend += sizeof(ip);

				char * temp = buf + sizeHelp - 8 - sizeof(icmphdr);
				memcpy(currentSend, temp, 8);
				currentSend -= sizeof(ip);
				currentSend -= sizeof(icmphdr);
				packetICMP.checksum = generateChecksum(currentSend, sizeof(ip) + 16);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));

				printf("Sending TTL\n");
				send(i, toSend, sizeHelp + sizeof(ip), 0);
				continue;
			}
			// Need to read the ARP response
			printf("Got ARP response\n");
			char *currentResponse = arpResponse;
			ether_header arpRepEth;
			arphdr arpRepArp;

			memcpy(&arpRepEth, currentResponse, sizeof(ether_header));
			currentResponse += sizeof(ether_header);
			memcpy(&arpRepArp, currentResponse, sizeof(arphdr));
			currentResponse += sizeof(arphdr);			
			if(arpRepArp.ar_op != ntohs(2)){
				// just drop packet
				continue;
			}
			memcpy(&packetEth.ether_shost, arpEther.ether_shost, 6);
			memcpy(&packetEth.ether_dhost, currentResponse, 6);

			if(packetEth.ether_shost == packetEth.ether_dhost){
				printf("Sending same Mac for source adn dest\n");
				return 1;
			}

			printf("Source is %d\n", packetEth.ether_shost);
			printf("Dest is %d\n", packetEth.ether_dhost);

			// Can do final send - copy orig packet, just overwrite link layer.
			printf("Forward packet\n");
			char toSend[1500];
			memcpy(toSend, buf, 1500);
			memcpy(toSend, &packetEth, sizeof(ether_header));
			send(arpSocket, toSend, n, 0);
			}
		}
		else{ // I need to look at routing table
			// Checksum and TTL first.
			char* headerIP = current - sizeof(ip);
			// Returns 1 if invalid
			if(checkChecksum(headerIP, sizeof(ip))){
				// Drop packet. Don't send error back, not needed.
				printf("Invalid checksum\n");
				continue;
			}
			// Check TTL
			auto ttl = packetIP.ip_ttl - 1;
			if(ttl <= 0){
				printf("TTL Expire\n");
				printf("Copy over old IP\n");
				ip oldIP;
				memcpy(&oldIP, &packetIP, sizeof(ip));
				// Drop and send ICMP error back. Size is regular packet + 8 orig data.
				int sizeHelp = sizeof(ether_header) + sizeof(ip) + sizeof(icmphdr) + 8;
				char toSend[1500];
				icmphdr packetICMP;

				// Generate/Switch Link layer
				char tempHardware[6];
				memcpy(&tempHardware, &packetEth.ether_dhost, 6);
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, &tempHardware, 6);

				// Setup IP header.
				in_addr tempAddr;
				memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
				memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
				memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

				// Generate ICMP Info
				packetICMP.type = ICMP_TIME_EXCEEDED;
				packetICMP.code = ICMP_EXC_TTL;
				packetICMP.checksum = 0;

				char *currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);

				memcpy(currentSend, &packetIP, sizeof(ip));
				currentSend += sizeof(ip);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));
				currentSend += sizeof(icmphdr);
				printf("Copying new stuff\n");
				// Copy over old IP, plus 8 bytes of data.

				memcpy(currentSend, &oldIP, sizeof(ip));
				currentSend += sizeof(ip);

				char * temp = buf + sizeHelp - 8 - sizeof(icmphdr);
				memcpy(currentSend, temp, 8);
				currentSend -= sizeof(ip);
				currentSend -= sizeof(icmphdr);
				packetICMP.checksum = generateChecksum(currentSend, sizeof(ip) + 16);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));

				printf("Sending TTL\n");
				send(i, toSend, sizeHelp + sizeof(ip), 0);
				continue;
			}
			// Everything is correct so far.
			// Since TTL is changed, change IP header checksum.
			packetIP.ip_ttl = ttl;
			packetIP.ip_sum = 0;
			char justIP[20];
			memcpy(justIP, &packetIP, 20);
			packetIP.ip_sum = generateChecksum(justIP, 20);

			// Look up destination in routing table. Returns empty pair if not found.
			auto tableResult = lookRoute(packetIP.ip_dst);
			if(tableResult.first == ""){
				// Send ICMP error back
				printf("Destination not found in table\n");
				ip oldIP;
				memcpy(&oldIP, &packetIP, sizeof(ip));
				int sizeHelp = sizeof(ether_header) + sizeof(ip) + sizeof(icmphdr) + 8;
				char toSend[1500];
				icmphdr packetICMP;

				// Link Layer
				char tempHardware[6];
				memcpy(&tempHardware, &packetEth.ether_dhost, 6);
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, &tempHardware, 6);

				// IP header
				in_addr tempAddr;
				memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
				memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
				memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

				// ICMP
				packetICMP.type = ICMP_DEST_UNREACH;
				packetICMP.code = ICMP_NET_UNREACH;
				packetICMP.checksum = 0;

				char justICMP[4];
				memcpy(justICMP, &packetICMP, 4);
				packetICMP.checksum = generateChecksum(justICMP, 4);

				char *currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);

				memcpy(currentSend, &packetIP, sizeof(ip));
				currentSend += sizeof(ip);

				memcpy(currentSend, &packetICMP, sizeof(icmphdr));
				currentSend += sizeof(icmphdr);

				// Copy over old IP, plus 8 bytes of data.

				memcpy(currentSend, &oldIP, sizeof(ip));
				currentSend += sizeof(ip);

				char * temp = buf + sizeHelp - 8 - sizeof(icmphdr);
				memcpy(currentSend, temp, 8);
				currentSend -= sizeof(ip);
				currentSend -= sizeof(icmphdr);
				packetICMP.checksum = generateChecksum(currentSend, sizeof(ip) + 16);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));

				printf("Sending TTL\n");
				send(i, toSend, sizeHelp + sizeof(ip), 0);
				continue;
			}
			// Can use info found to pass packet along.
			// Check if need to hop IP
			printf("Doing intermediate ARP\n");
			auto toARP = packetIP.ip_dst;
			if(tableResult.first.length() > 2)
				inet_aton(tableResult.first.c_str(), &toARP);
			int arpSocket;
			char *interface = (char *)tableResult.second.c_str();
			interface += 3;
			printf("About to check interfaces\n");
			for(auto b:myInterface){
				printf("Interface searching compare %s to %s\n", b.second, interface);
				if(strncmp(b.second, interface, 4) == 0){
					arpSocket = b.first;
					break;
				}
			}
			// Build ARP Link layer
			ether_header arpEther;
			arpEther.ether_type = htons(ETHERTYPE_ARP);
			for(int a = 0; a < 6; a++){
				arpEther.ether_dhost[a] = -1;
			}
			unsigned char *myMac = (unsigned char*)malloc(6);
			getMyMac(myInterface[arpSocket], myMAC, myMac);
			memcpy(&arpEther.ether_shost, myMac, 6);
			// Build ARP packet
			arphdr arpArp;
			arpArp.ar_hrd = htons(1);
			arpArp.ar_pro = htons(0x800);
			arpArp.ar_hln = 6;
			arpArp.ar_pln = 4;
			arpArp.ar_op = htons(1);
			char arpSend[1500];
			char *arpSendTo = arpSend;
			memcpy(arpSendTo, &arpEther, sizeof(ether_header));
			arpSendTo += sizeof(ether_header);
			memcpy(arpSendTo, &arpArp, sizeof(arphdr));
			arpSendTo += sizeof(arphdr);

			memcpy(arpSendTo, &arpEther.ether_shost, 6);
			arpSendTo += 6;
			memcpy(arpSendTo, &packetIP.ip_src, 4);
			arpSendTo += 4;
			char destHardware[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
			memcpy(arpSendTo, &destHardware, 6);
			arpSendTo += 6;
			memcpy(arpSendTo, &toARP, 4);

			printf("Send Arp request\n");
			send(arpSocket, arpSend, sizeof(arphdr) + sizeof(ether_header) + 20, 0);
			char arpResponse[1500];
			int test = recvfrom(arpSocket, arpResponse, 1500, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
			printf("Got %d bytes\n", test);
			if(test < 0){ // no response
				perror("ARP ERROR\n");
				// Send error back
				printf("No response on ARP\n");
				ip oldIP;
				memcpy(&oldIP, &packetIP, sizeof(ip));
				int sizeHelp = sizeof(ether_header) + sizeof(ip) + sizeof(icmphdr) + 8;
				char toSend[1500];
				icmphdr packetICMP;

				char tempHardware[6];
				memcpy(&tempHardware, &packetEth.ether_dhost, 6);
				memcpy(&packetEth.ether_dhost, &packetEth.ether_shost, 6);
				memcpy(&packetEth.ether_shost, &tempHardware, 6);

				in_addr tempAddr;
				memcpy(&tempAddr, &packetIP.ip_src, sizeof(in_addr));
				memcpy(&packetIP.ip_src, &packetIP.ip_dst, sizeof(in_addr));
				memcpy(&packetIP.ip_dst, &tempAddr, sizeof(in_addr));

				packetICMP.type = ICMP_DEST_UNREACH;
				packetICMP.code = ICMP_HOST_UNREACH;
				packetICMP.checksum = 0;

				char justICMP[4];
				memcpy(justICMP, &packetICMP, 4);
				packetICMP.checksum = generateChecksum(justICMP, 4);

				char *currentSend = toSend;
				memcpy(currentSend, &packetEth, sizeof(ether_header));
				currentSend += sizeof(ether_header);

				memcpy(currentSend, &packetIP, sizeof(ip));
				currentSend += sizeof(ip);

				memcpy(currentSend, &packetICMP, sizeof(icmphdr));
				currentSend += sizeof(icmphdr);

				// Copy over old IP, plus 8 bytes of data.

				memcpy(currentSend, &oldIP, sizeof(ip));
				currentSend += sizeof(ip);

				char * temp = buf + sizeHelp - 8 - sizeof(icmphdr);
				memcpy(currentSend, temp, 8);
				currentSend -= sizeof(ip);
				currentSend -= sizeof(icmphdr);
				packetICMP.checksum = generateChecksum(currentSend, sizeof(ip) + 16);
				memcpy(currentSend, &packetICMP, sizeof(icmphdr));

				printf("Sending TTL\n");
				send(i, toSend, sizeHelp + sizeof(ip), 0);
				continue;
			}
			// Need to read the ARP response
			printf("Got ARP response\n");
			char *currentResponse = arpResponse;
			ether_header arpRepEth;
			arphdr arpRepArp;

			memcpy(&arpRepEth, currentResponse, sizeof(ether_header));
			currentResponse += sizeof(ether_header);
			memcpy(&arpRepArp, currentResponse, sizeof(arphdr));
			currentResponse += sizeof(arphdr);			
			if(arpRepArp.ar_op != ntohs(2)){
				// just drop packet
				continue;
			}
			memcpy(&packetEth.ether_shost, arpEther.ether_shost, 6);
			memcpy(&packetEth.ether_dhost, currentResponse, 6);

			if(packetEth.ether_shost == packetEth.ether_dhost){
				printf("Sending same Mac for source adn dest\n");
				return 1;
			}

			printf("Source is %d\n", packetEth.ether_shost);
			printf("Dest is %d\n", packetEth.ether_dhost);

			// Can do final send - copy orig packet, just overwrite link layer.
			printf("Forward packet\n");
			char toSend[1500];
			memcpy(toSend, &packetEth, sizeof(ether_header));
			char* sending = toSend + sizeof(ether_header);
			char* currentBuf = buf + sizeof(ether_header);
			memcpy(sending, currentBuf, 1500 - sizeof(ether_header));
			int sentBytes = send(arpSocket, toSend, n, 0);
			printf("SentBytes %d\n", sentBytes);
		}
	}
  }
}}
  //exit
  return 0;
}


