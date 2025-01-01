// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>


struct pelf;
struct pelf *openp(pid_t pid, off_t base);
off_t pdlsym(struct pelf *pelf, const char *symbol);

void usage(int exitcode)
{
	fprintf(stderr, "tst [options]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -p,--pid  [PID]\n");
	fprintf(stderr, "  -a,--base [ADDR]\n");
	fprintf(stderr, "  -s,--sym  [SYM]\n");
	fprintf(stderr, "\n");
	exit(exitcode);
}

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	unsigned long base_addr = 0;
	unsigned long addr;
	char *sym = NULL;

	struct option options[] = {
		{"pid", required_argument, 0, 'p'},
		{"base", required_argument, 0, 'a'},
		{"sym", required_argument, 0, 's'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};
	while (1) {
		int option_index = 0;
		char c = getopt_long(argc, argv, "p:a:s:h", options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'p':
			pid = atoi(optarg);
			break;
		case 's':
			sym = strdup(optarg);
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
			fprintf(stderr, "ERROR: unknown arg option %d %s.\n",
				c, optarg);
			/**
			 * FIXME: I don't know why c==255 on ThinkForce aarch64
			 */
			if (pid != 0 && base_addr != 0 && sym != 0)
				goto while_done;
			usage(1);
		}
	}

	if (pid == 0) {
		fprintf(stderr, "ERROR: Must specify pid with -p.\n");
		exit(1);
	}
	if (base_addr == 0) {
		fprintf(stderr, "ERROR: Must specify base address with -a.\n");
		exit(1);
	}
	if (!sym) {
		fprintf(stderr, "ERROR: Must specify sym with -s.\n");
		exit(1);
	}

while_done:
	char *symbol = sym;
	struct pelf *pelf = openp(pid, base_addr);
	if (!pelf)
		return -1;

	addr = pdlsym(pelf, symbol);
	fprintf(stderr, "%s address %lx\n", symbol, addr);

	return 0;
}
