#include "utils.h"

//--------------------------------------------------------------------------------------------------------------------------

#define ETH_P_STP 0x0026

//--------------------------------------------------------------------------------------------------------------------------

int create_raw_socket(const char* interface)
{
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;

	int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));

	return sockfd;
}

//--------------------------------------------------------------------------------------------------------------------------

int receive_packet(int sockfd, unsigned char* buffer)
{
	struct sockaddr saddr;
	socklen_t saddr_len = sizeof(saddr);

	int packet_size = recvfrom(sockfd, buffer, BUF_SIZE, 0, &saddr, &saddr_len);
	
	return packet_size;
}

//--------------------------------------------------------------------------------------------------------------------------

int send_packet(int sockfd, const unsigned char* buffer, int packet_size)
{
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_protocol = htons(ETH_P_ALL);

	int send_size = sendto(sockfd, buffer, packet_size, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));

	return send_size;
}

//--------------------------------------------------------------------------------------------------------------------------

void print_packet_info(const unsigned char* buffer)
{
	struct ethhdr* eth_header = (struct ethhdr*)buffer;

	if (ntohs(eth_header->h_proto) == ETH_P_ARP)
	{
		struct ether_arp* arp_header = (struct ether_arp*)(buffer + sizeof(struct ethhdr));
		printf("src_IP=%s;  ",  inet_ntoa(*(struct in_addr*)&arp_header->arp_spa));
		printf("dst_IP=%s;  ",  inet_ntoa(*(struct in_addr*)&arp_header->arp_tpa));
		printf("protocol=ARP;\n\n");
		return;
	}

	if (ntohs(eth_header->h_proto) == ETH_P_STP)
	{
		printf("protocol=STP;\n\n");
		return;
	}

	struct ip* ip_header = (struct ip*)(buffer + sizeof(struct ethhdr));
	int ip_header_len = ip_header->ip_hl * 4;

	printf("src_ip=%s;  dst_ip=%s;  ", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

	if (ip_header->ip_p == IPPROTO_TCP)
	{
		struct tcphdr* tcp_header = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_header_len);
		printf("protocol=TCP;  ");
		printf("src_port=%d;  ", ntohs(tcp_header->th_sport));
		printf("dst_port=%d  ", ntohs(tcp_header->th_dport));
	}
	else if (ip_header->ip_p == IPPROTO_UDP)
	{
		struct udphdr* udp_header = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ip_header_len);
		printf("protocol=UDP;  ");
		printf("src_port=%d;  ", ntohs(udp_header->uh_sport));
		printf("dst_port=%d;  ", ntohs(udp_header->uh_dport));
	}
	else
	{
		printf("protocol=other;  protocol_number=%d;", ip_header->ip_p);
	}

	printf("\n\n");
}


//--------------------------------------------------------------------------------------------------------------------------
