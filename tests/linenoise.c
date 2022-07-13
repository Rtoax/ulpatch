#include <errno.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/util.h>
#include <elf/elf_api.h>

#ifdef HAVE_LINENOISE
#include <linenoise.h>
#else
#include <utils/linenoise.h>
#endif

#include "test_api.h"


static void completionCallback(const char *buf, linenoiseCompletions *lc) {}

static char *hintsCallback(const char *buf, int *color, int *bold)
{
	return NULL;
}

static void freeHintsCallback(void *ptr) {}

TEST(Linenoise,	init_1,	0)
{
	linenoiseSetMultiLine(1);
	linenoiseSetCompletionCallback(completionCallback);
	linenoiseSetHintsCallback(hintsCallback);
	linenoiseSetFreeHintsCallback(freeHintsCallback);

	return 0;
}