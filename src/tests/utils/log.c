// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <utils/log.h>
#include <utils/list.h>
#include <elf/elf_api.h>

#include <tests/test_api.h>


TEST(Log, log, 0)
{
	ldebug("DEBUG\n");
	linfo("INFO\n");
	lnotice("NOTICE\n");
	lwarning("WARN\n");
	lerror("ERROR\n");
	lcrit("CRIT\n");
	lalert("ALERT\n");
	lemerg("EMERG\n");

	lwarning("LIST: %s\n", log_level_list());

	return 0;
}

TEST(Log, log_no_prefix, 0)
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

TEST(Log, set_log_level, 0)
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

TEST(Log, set_log_prefix, 0)
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

TEST(Log, str2loglevel, 0)
{
	if (LOG_INFO != str2loglevel("info") || LOG_INFO != str2loglevel("INFO"))
		return -1;
	if (LOG_INFO != str2loglevel("inf"))
		return -1;
	if (LOG_DEBUG != str2loglevel("debug"))
		return -1;
	if (LOG_DEBUG != str2loglevel("dbg"))
		return -1;
	return 0;
}

