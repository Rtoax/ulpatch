#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <ctype.h>
#include <assert.h>

#ifdef HAVE_LINENOISE
#include <linenoise.h>
#else
#include <utils/linenoise/linenoise.h>
#endif

#include <elf/elf_api.h>
#include <cli/cli_api.h>
#include <cli/cli_help.h>

#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>
#include <utils/callback.h>

struct cli_struct cli;

static LIST_HEAD(help_entries_list);
static int help_entries_len = 0;

static INIT_CB_CHAIN(pre_commands);

int cli_register_pre_command_cb(int (*cb)(void *arg), void *cb_arg)
{
	return insert_callback(&pre_commands, cb, cb_arg);
}

void cli_destroy_pre_commands()
{
	destroy_chain(&pre_commands);
}

static char **cli_split_args(const char *line, int *argc)
{
	const char *p = line;
	char **argv = NULL;

	*argc = 0;

	while (*p) {
		while (*p && isspace(*p)) p++;
		if (*p) {
			const char *tail = p;
			while (*tail && !isspace(*tail))
				tail++;

			int arglen = tail - p;
			char *arg = malloc(arglen + 1);
			strncpy(arg, p, arglen);
			arg[arglen] = '\0';
			(*argc)++;

			// +1 means end with NULL
			argv = (char**)realloc(argv, ((*argc) + 1) * sizeof(char *));
			argv[(*argc) - 1] = arg;
			argv[(*argc)] = NULL;

			p = tail;
		}
	}
	return argv;
}

static void cli_free_args(int argc, char **argv)
{
	int i;
	for (i = 0; i < argc; i++) {
		free(argv[i]);
	}
	free(argv);
}

static void completionCallback(const char *buf, linenoiseCompletions *lc)
{
	size_t startpos = 0;
	size_t matchlen;
	struct help_entry *entry;

	if (!strncasecmp(buf, "help ", 5)) {
		startpos = 5;
		while (isspace(buf[startpos])) startpos++;
	}

	list_for_each_entry(entry, &help_entries_list, node) {
		matchlen = strlen(buf + startpos);
		if (strncasecmp(buf + startpos, entry->full, matchlen) == 0) {
			char *tmp = malloc(startpos);
			memset(tmp, 0, sizeof(char) * startpos);
			strncpy(tmp, buf, startpos);
			strcat(tmp, entry->full);
			linenoiseAddCompletion(lc, tmp);
			free(tmp);
		}
	}
}

static char *hintsCallback(const char *buf, int *color, int *bold)
{
	int argc, rawargc, matchlen = 0;
	char **argv = cli_split_args(buf, &argc), **rawargv;
	//int buflen = strlen(buf);
	struct help_entry *entry = NULL;

	/* Check if the argument list is empty and return ASAP. */
	if (argc == 0) {
		cli_free_args(argc, argv);
		return NULL;
	}

	/* Search longest matching prefix command */
	struct help_entry *tmp = NULL;
	list_for_each_entry(tmp, &help_entries_list, node) {
		rawargv = cli_split_args(tmp->full, &rawargc);
		if (rawargc <= argc) {
			int j;
			for (j = 0; j < rawargc; j++) {
				if (strcasecmp(rawargv[j], argv[j])) {
					break;
				}
			}
			if (j == rawargc && rawargc > matchlen) {
				matchlen = rawargc;
				entry = tmp;
			}
		}
		cli_free_args(rawargc, rawargv);
	}
	cli_free_args(argc, argv);

	if (entry) {
		*color = 90;
		*bold = 0;

		/* Two 1, one for space, one for '\0' */
		int len = strlen(entry->help.params) + 1 + 1;
		char *hint = malloc(sizeof(char) * len);
		hint[0] = ' ';
		strcpy(hint + 1, entry->help.params);

		return hint;
	}

	return NULL;
}

static void freeHintsCallback(void *ptr)
{
	free(ptr);
}

static int
help_entry_compare(void *priv, struct list_head *a, struct list_head *b)
{
	struct help_entry *entrya = container_of(a, struct help_entry, node);
	struct help_entry *entryb = container_of(b, struct help_entry, node);
	return strcmp(entrya->full, entryb->full);
}

static void cli_init_help(void)
{
	int i, nr_cmds = sizeof(commands_help)/sizeof(commands_help[0]);

	for (i = 0; i < nr_cmds; i++) {
		struct command_help *cmdhelp = &commands_help[i];
		struct help_entry *entry = malloc(sizeof(struct help_entry));
		assert(entry && "malloc entry fatal.");

		entry->argv = cli_split_args(cmdhelp->name, &entry->argc);
		entry->full = strdup(cmdhelp->name);
		entry->help.name = cmdhelp->name;
		entry->help.params = cmdhelp->params;
		entry->help.summary = cmdhelp->summary;

		help_entries_len++;
		list_add(&entry->node, &help_entries_list);
	}

	list_sort(NULL, &help_entries_list, help_entry_compare);
}

static void output_generic_help(void)
{
	printf(
		"elftools %s\n"
		"To get help about ELFTools commands type:\n"
		"      \"help <command>\" for help on <command>\n"
		"      \"help <tab>\" to get a list of possible help topics\n"
		"      \"quit\" to exit\n"
		"\n",
		elftools_version()
	);
}

/* Output command help to stdout. */
static void output_command_help(struct help_entry *entry)
{
    printf("\r\n  \x1b[1m%s\x1b[0m \x1b[90m%s\x1b[0m\r\n",
		entry->help.name, entry->help.params);
    printf("  \x1b[33msummary:\x1b[0m %s\r\n", entry->help.summary);
}

static void output_help(int argc, char **argv)
{
	struct help_entry *entry = NULL;

	if (argc == 1) {
		output_generic_help();
		return;
	}

	list_for_each_entry(entry, &help_entries_list, node) {
		if (argc - 1 <= entry->argc) {
			int j;
			for (j = 1; j < argc; j++) {
				if (strcasecmp(argv[j], entry->argv[j - 1]) != 0) break;
			}
			if (j == argc) {
				output_command_help(entry);
			}
		}
	}
}

static void issue_command(int argc, char **argv)
{
	int ret;
	ret = cli_send_command(argc, argv);
	if (ret != 0) {
		fprintf(stderr, "ERROR command. %s\n", strerror(-ret));
	}
}

static void print_cli_logo(void)
{
#define ANSI "\033[1;32m"
#define END	"\033[m"
	printf(
	"\n"
	ANSI"    ______   __________          __    "END"      ___\n"
	ANSI"   / __/ /  / __/_  __/__  ___  / /__  "END" ____/ (_)\n"
	ANSI"  / _// /__/ _/  / / / _ \\/ _ \\/ (_-<"END"  / __/ / /\n"
	ANSI" /___/____/_/   /_/  \\___/\\___/_/___/"END"  \\__/_/_/\n"
	"\n"
	"%s\n"
	"\n"
	"Welcome to ELFTools Command Line:\n"
	"\n"
	" input 'help' command to show help info"
	"\n"
	"\n",
	elftools_version()
	);
}

void cli_main(int argc, char *argv[])
{
	int __unused history = 0;
	char *line = NULL;
	char *historyfile = NULL; //TODO

	pthread_setname_np(pthread_self(), "elftools-cli");

	linenoiseSetMultiLine(1);
	linenoiseSetCompletionCallback(completionCallback);
	linenoiseSetHintsCallback(hintsCallback);
	linenoiseSetFreeHintsCallback(freeHintsCallback);

	cli_init_help();
	cli.elf_client_fd = create_elf_client();

	int handler_ack(void) { return 0; }
	client_register(cli.elf_client_fd, CLIENT_CLI, handler_ack);

	if (isatty(fileno(stdin))) {
		history = 1;
		if (historyfile != NULL) {
			linenoiseHistoryLoad(historyfile);
		}
	}

	launch_chain(&pre_commands);
	print_cli_logo();

	/* Main loop of linenoise */
	while ((line = linenoise("elftools> ")) != NULL) {
		int cli_argc;
		char __unused **cli_argv;

		if (line[0] != '\0') {
			cli_argv = cli_split_args(line, &cli_argc);

			if (history) linenoiseHistoryAdd(line);
			if (historyfile) linenoiseHistorySave(historyfile);

			if (strcasecmp(cli_argv[0], "quit") == 0 ||
				strcasecmp(cli_argv[0], "exit") == 0) {
				exit(0);
			} else if (cli_argc == 1 && !strcasecmp(cli_argv[0], "clear")) {
				linenoiseClearScreen();
			} else if (!strcasecmp(cli_argv[0], "help") ||
						!strcasecmp(cli_argv[0], "?")) {
				output_help(cli_argc, cli_argv);
			} else {
				issue_command(cli_argc, cli_argv);
			}
			cli_free_args(cli_argc, cli_argv);
		}
		linenoiseFree(line);
	}
	return;
}
