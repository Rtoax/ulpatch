#pragma once

#include <utils/compiler.h>


#define SECTION_FTRACE_TEXT	".patch.ftrace.text"
#define SECTION_FTRACE_DATA	".patch.ftrace.data"

#define __ftrace_text __section(SECTION_FTRACE_TEXT)
#define __ftrace_data __section(SECTION_FTRACE_DATA)

