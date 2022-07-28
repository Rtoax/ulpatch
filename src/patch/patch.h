#pragma once

#include <stdbool.h>

#include <utils/compiler.h>


#define SEC_PATCH_INFO_NAME	".patchinfo"

#define __PATCH_INFO(tag, name, info)	\
	static const char name[]	\
	__section(SEC_PATCH_INFO_NAME) __attribute__((unused, aligned(1)))	\
	= #tag "=" info

#define PATCH_INFO(tag, info)	__PATCH_INFO(tag, tag, info)


#define PATCH_AUTHOR(_author)	PATCH_INFO(author, _author)


bool is_ftrace_entry(char *func);

