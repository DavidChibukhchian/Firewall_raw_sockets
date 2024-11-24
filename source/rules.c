#include "rules.h"

//--------------------------------------------------------------------------------------------------------------------------

#define ETH_P_STP 0x0026

//--------------------------------------------------------------------------------------------------------------------------

int load_rules(const char* rules_filename, FilterRule* rules)
{
	FILE* rules_file = fopen(rules_filename, "r");
	if (!rules_file)
	{
		return -1;
	}

	char line[MAX_LINE_SIZE] = {'\0'};
	int rules_count = 0;

	while (fgets(line, MAX_LINE_SIZE, rules_file))
	{
		if (rules_count >= MAX_RULES_COUNT) break;

		int action = 0;
		char protocol_name[10] = {'\0'};
		char src_ip[INET_ADDRSTRLEN] = {'\0'}; 
		char dst_ip[INET_ADDRSTRLEN] = {'\0'};
		int src_port = 0;
		int dst_port = 0;
		if (sscanf(line, "%d %s %s %s %d %d", &action, protocol_name, src_ip, dst_ip, &src_port, &dst_port) != 6)
		{
			continue;
		}

		FilterRule rule;
		//----------------------parsing-a-rule----------------------//
		if (action == 0)
		{
			rule.action = 0;
		}
		else if (action == 1)
		{
			rule.action = 1;
		}
		else
		{
			continue;
		}

		if      (strcmp(protocol_name, "TCP")  == 0)
		{
			rule.protocol = IPPROTO_TCP;
		}
		else if (strcmp(protocol_name, "UDP")  == 0)
		{
			rule.protocol = IPPROTO_UDP;
		}
		else if (strcmp(protocol_name, "ICMP") == 0)
		{
			rule.protocol = IPPROTO_ICMP;
		}
		else
		{
			continue;
		}

		if (strcmp(src_ip, "0.0.0.0") == 0)
		{
			rule.src_ip.s_addr = INADDR_ANY;
		}
		else
		{
			inet_pton(AF_INET, src_ip, &rule.src_ip);
		}
		if (strcmp(dst_ip, "0.0.0.0") == 0)
		{
			rule.dst_ip.s_addr = INADDR_ANY;
		}
		else
		{
			inet_pton(AF_INET, dst_ip, &rule.dst_ip);
		}

		rule.src_port = src_port;
		rule.dst_port = dst_port;
		//----------------------parsing-a-rule----------------------//
		
		rules[rules_count] = rule;
		rules_count++;
	}

	fclose(rules_file);

	return rules_count;
}

//--------------------------------------------------------------------------------------------------------------------------

int apply_rules(unsigned char* buffer, FilterRule* rules, int rules_count)
{
	struct ethhdr* eth_header = (struct ethhdr*)buffer;
	if (ntohs(eth_header->h_proto) == ETH_P_ARP || ntohs(eth_header->h_proto) == ETH_P_STP)
	{
		return 0;
	}

	struct ip* ip_header = (struct ip*)(buffer + sizeof(struct ethhdr));
	int ip_header_len = ip_header->ip_hl * 4;

	struct tcphdr* tcp_header = NULL;
	struct udphdr* udp_header = NULL;

	if      (ip_header->ip_p == IPPROTO_TCP)
	{
		tcp_header = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_header_len);
	}
	else if (ip_header->ip_p == IPPROTO_UDP)
	{
		udp_header = (struct udphdr*)(buffer + sizeof(struct ethhdr) + ip_header_len);
	}


	const int is_blacklist = rules[rules_count - 1].action;

	for (int i = 0; i < rules_count; i++)
	{
		FilterRule* rule = &rules[i];

		if ((rule->src_ip.s_addr != INADDR_ANY && ip_header->ip_src.s_addr != rule->src_ip.s_addr) ||
		     (rule->dst_ip.s_addr != INADDR_ANY && ip_header->ip_dst.s_addr != rule->dst_ip.s_addr))
		{
			continue;
		}
		if (rule->protocol != 0 && rule->protocol != ip_header->ip_p)
			continue;

		if (ip_header->ip_p == IPPROTO_TCP)
		{
			if ((rule->src_port != 0 && ntohs(tcp_header->th_sport) != rule->src_port) ||
			    (rule->dst_port != 0 && ntohs(tcp_header->th_dport) != rule->dst_port))
			{
				continue;
			}
		}
		else if (ip_header->ip_p == IPPROTO_UDP)
		{
			if ((rule->src_port != 0 && ntohs(udp_header->uh_sport) != rule->src_port) ||
			    (rule->dst_port != 0 && ntohs(udp_header->uh_dport) != rule->dst_port))
			{
				continue;
			}
		}

		return is_blacklist;
	}

	return !is_blacklist;
}


//--------------------------------------------------------------------------------------------------------------------------
