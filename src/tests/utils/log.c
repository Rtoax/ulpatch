// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao <rtoax@foxmail.com> */
#include <utils/log.h>
#include <utils/list.h>
#include <elf/elf_api.h>

#include "../test_api.h"

TEST(Log,	log,	0)
{
	ldebug("DEBUG\n");
	linfo("INFO\n");
	lnotice("NOTICE\n");
	lwarning("WARN\n");
	lerror("ERROR\n");
	lcrit("CRIT\n");
	lalert("ALERT\n");
	lemerg("EMERG\n");

	return 0;
}

TEST(Log,	log_no_prefix,	0)
{
	set_log_prefix(true);

	debug("DEBUG\n");
	info("INFO\n");
	notice("NOTICE\n");
	warning("WARN\n");
	error("ERROR\n");
	crit("CRIT\n");
	alert("ALERT\n");
	emerg("EMERG\n");

	return 0;
}

TEST(Log,	set_log_level,	0)
{
	set_log_level(LOG_CRIT);

	ldebug("DEBUG\n");
	linfo("INFO\n");
	lnotice("NOTICE\n");
	lwarning("WARN\n");
	lerror("ERROR\n");
	lcrit("CRIT\n");
	lalert("ALERT\n");
	lemerg("EMERG\n");

	set_log_level(LOG_DEBUG);

	return 0;
}

TEST(Log,	set_log_prefix,	0)
{
	set_log_prefix(false);

	ldebug("DEBUG\n");
	linfo("INFO\n");
	lnotice("NOTICE\n");
	lwarning("WARN\n");
	lerror("ERROR\n");
	lcrit("CRIT\n");
	lalert("ALERT\n");
	lemerg("EMERG\n");

	set_log_prefix(true);

	ldebug("DEBUG\n");
	linfo("INFO\n");
	lnotice("NOTICE\n");
	lwarning("WARN\n");
	lerror("ERROR\n");
	lcrit("CRIT\n");
	lalert("ALERT\n");
	lemerg("EMERG\n");

	return 0;
}

