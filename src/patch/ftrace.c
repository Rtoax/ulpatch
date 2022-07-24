#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/log.h>
#include <utils/list.h>
#include <utils/compiler.h>

const static char __unused *___ftrace_entry_funcs[] = {
    "__cyg_profile_func_enter",
    "__fentry__",
    "mcount",
    "_mcount",
    "__gnu_mcount_nc",
};

