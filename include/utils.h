#ifndef UTILS_H
#define UTILS_H

//--------------------------------------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <unistd.h>
#include <asm-generic/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <sys/ioctl.h>

//--------------------------------------------------------------------------------------------------------------------------

#define BUF_SIZE 65536

//--------------------------------------------------------------------------------------------------------------------------

int create_raw_socket(const char* interface, int* index);

int receive_packet(int sockfd, unsigned char* buffer);

int send_packet(int sockfd, const unsigned char* buffer, int packet_size, int index);

void print_packet_info(const unsigned char* buffer);

//--------------------------------------------------------------------------------------------------------------------------

#endif // UTILS_H
