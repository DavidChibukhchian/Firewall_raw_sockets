#include "rules.h"

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
	
}


//--------------------------------------------------------------------------------------------------------------------------
