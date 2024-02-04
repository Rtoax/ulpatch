#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>


void *pdlsym(pid_t pid, void *base, const char *symbol);

void usage(int exitcode)
{
	fprintf(stderr, "tst [options]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -p,--pid  [PID]\n");
	fprintf(stderr, "  -a,--base [ADDR]\n");
	fprintf(stderr, "\n");
	exit(exitcode);
}

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	unsigned long base_addr = 0;
	void *addr;

	struct option options[] = {
		{"pid", required_argument, 0, 'p'},
		{"base", required_argument, 0, 'a'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};
	while (1) {
		int option_index = 0;
		char c = getopt_long(argc, argv, "p:a:h", options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 'a':
			if (optarg[0] != '0' || optarg[1] != 'x') {
				fprintf(stderr, "ERROR: base addr must start with 0x.\n");
				exit(1);
			}
			base_addr = strtoul(optarg, NULL, 16);
			break;
		case 'h':
			usage(0);
			break;
		default:
			fprintf(stderr, "ERROR: unknown arg option %s.\n", optarg);
			usage(1);
		}
	}

	if (pid == 0) {
		fprintf(stderr, "ERROR: Must specify pid with -p.\n");
		exit(1);
	}
	if (base_addr == 0) {
		fprintf(stderr, "ERROR: Must specify pid with -a.\n");
		exit(1);
	}

	char *symbol = "print_hello";
	addr = pdlsym(pid, (void *)base_addr, symbol);
	fprintf(stdout, "%s : %lx\n", symbol, (unsigned long)addr);

	return 0;
}
