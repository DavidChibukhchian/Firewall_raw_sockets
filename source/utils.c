#include "utils.h"

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


int send_packet(int sockfd, unsigned char* buffer, int packet_size)
{
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(struct sockaddr_ll));
	sa.sll_protocol = htons(ETH_P_ALL);

	int send_size = sendto(sockfd, buffer, packet_size, 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll));

	return send_size;
}

//--------------------------------------------------------------------------------------------------------------------------

struct in_addr string_to_ip(const char* ip_string)
{
	struct in_addr ip_addr;
	inet_pton(AF_INET, ip_string, &ip_addr);

	return ip_addr;
}

//--------------------------------------------------------------------------------------------------------------------------
