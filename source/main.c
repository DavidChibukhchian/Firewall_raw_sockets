#include <signal.h>
#include "utils.h"
#include "rules.h"

//--------------------------------------------------------------------------------------------------------------------------

enum info_mode
{
	DO_NOT_SHOW_PACKETS_INFO,
	SHOW_ALLOWED_PACKETS_INFO,
	SHOW_BLOCKED_PACKETS_INFO
};

//--------------------------------------------------------------------------------------------------------------------------

volatile sig_atomic_t stop = 0;

void handler(int sig)
{
	stop = 1;
}

//--------------------------------------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	if ((argc != 4) && (argc != 5))
	{
		printf("ERROR: Wrong number of arguments.\n");
		printf("Run %s <interface1> <interface2> <rules.txt> [mode]\n\n", argv[0]);
		return -1;
	}

	const char* interface1     = argv[1];
	const char* interface2     = argv[2];
	const char* rules_filename = argv[3];
	enum info_mode mode = DO_NOT_SHOW_PACKETS_INFO;
	if (argc == 5)
	{
		if      (strcmp(argv[4], "allowed") == 0)
		{
			mode = SHOW_ALLOWED_PACKETS_INFO;
		}
		else if (strcmp(argv[4], "blocked") == 0)
		{
			mode = SHOW_BLOCKED_PACKETS_INFO;
		}
	}


	int index1 = 0;
	int index2 = 0;
	int sockfd1 = create_raw_socket(interface1, &index1);
	int sockfd2 = create_raw_socket(interface2, &index2);

	FilterRule rules[MAX_RULES_COUNT];
	int rules_count = load_rules(rules_filename, rules);
	if (rules_count <= 0)
	{
		printf("ERROR: Unable to load rules.\n\n");
		return -3;
	}


	unsigned char buffer[BUF_SIZE];
	signal(SIGINT, handler);
	while (!stop)
	{
		memset(buffer, 0, BUF_SIZE);
		int packet_size = receive_packet(sockfd1, buffer);

		if (!apply_rules(buffer, rules, rules_count))
		{
			send_packet(sockfd2, buffer, packet_size, index2);

			if (mode == SHOW_ALLOWED_PACKETS_INFO)
			{
				printf("A packet has been allowed. Info: ");
				print_packet_info(buffer);
			}
		}
		else
		{
			if (mode == SHOW_BLOCKED_PACKETS_INFO)
			{
				printf("A packet has been blocked. Info: ");
				print_packet_info(buffer);
			}
		}
	}


	close(sockfd1);
	close(sockfd2);

	return 0;
}

//--------------------------------------------------------------------------------------------------------------------------
