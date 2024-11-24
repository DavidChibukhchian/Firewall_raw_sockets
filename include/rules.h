#ifndef RULES_H
#define RULES_H

//--------------------------------------------------------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

//--------------------------------------------------------------------------------------------------------------------------

#define MAX_RULES_COUNT 100
#define MAX_LINE_SIZE 512

//--------------------------------------------------------------------------------------------------------------------------

typedef struct {
	int action;
	int protocol; 
	struct in_addr src_ip;
	struct in_addr dst_ip;
	int src_port;
	int dst_port;
} FilterRule;

//--------------------------------------------------------------------------------------------------------------------------

int load_rules(const char* rules_filename, FilterRule* rules);

int apply_rules(unsigned char* buffer, FilterRule* rules, int rules_count);

//--------------------------------------------------------------------------------------------------------------------------

#endif // RULES_H
