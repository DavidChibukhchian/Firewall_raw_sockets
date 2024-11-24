#include <signal.h>
#include "utils.h"
#include "rules.h"

//--------------------------------------------------------------------------------------------------------------------------

volatile sig_atomic_t stop = 0;

void handler(int sig)
{
	stop = 1;
}

//--------------------------------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	if (argc != 4)
	{
		printf("ERROR: Wrong number of arguments.\n");
		printf("Run %s <interface1> <interface2> <rules.txt>", argv[0]);
		return -1;
	}

	const char* interface1     = argv[1];
	const char* interface2     = argv[2];
	const char* rules_filename = argv[3];

	int sockfd1 = create_raw_socket(interface1);
	int sockfd2 = create_raw_socket(interface2);

	FilterRule rules[MAX_RULES_COUNT];
	int rules_count = load_rules(rules_filename, rules);
	if (rules_count <= 0)
	{
		printf("ERROR: Unable to load rules.\n");
		return -2;
	}

	unsigned char buffer[BUF_SIZE];
	signal(SIGINT, handler);
	while (!stop)
	{
		int packet_size = receive_packet(sockfd1, buffer);
		if (packet_size == -1)
		{
			printf("ERROR: Failed to receive a packet.\n");
			printf("Firewall continues working...\n");
			continue;
		}

		if (!apply_rules(buffer, rules, rules_count))
		{
			int send_size = send_packet(sockfd2, buffer, packet_size);
			if (send_size == -1)
			{
				printf("ERROR: Failed to send a packet.\n");
				printf("Firewall continues working...\n");
				continue;
			}
			printf("A packet has not been blocked.\n");
		}
		else
		{
			printf("A packet has been blocked.\n");
		}
	}

	close(sockfd1);
	close(sockfd2);

	return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
