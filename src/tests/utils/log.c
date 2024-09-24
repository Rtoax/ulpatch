// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2024 Rong Tao */
#include <utils/log.h>
#include <utils/list.h>
#include <elf/elf-api.h>

#include <tests/test-api.h>

TEST_STUB(utils_log);

TEST(Log, log, 0)
{
	ulp_debug("DEBUG\n");
	ulp_info("INFO\n");
	ulp_notice("NOTICE\n");
	ulp_warning("WARN\n");
	ulp_error("ERROR\n");
	ulp_crit("CRIT\n");
	ulp_alert("ALERT\n");
	ulp_emerg("EMERG\n");

	ulp_warning("LIST: %s\n", log_level_list());

	return 0;
}

TEST(Log, set_log_level, 0)
{
	set_log_level(LOG_CRIT);

	ulp_debug("DEBUG\n");
	ulp_info("INFO\n");
	ulp_notice("NOTICE\n");
	ulp_warning("WARN\n");
	ulp_error("ERROR\n");
	ulp_crit("CRIT\n");
	ulp_alert("ALERT\n");
	ulp_emerg("EMERG\n");

	set_log_level(LOG_DEBUG);

	return 0;
}

TEST(Log, set_log_prefix, 0)
{
	set_log_prefix(false);

	ulp_debug("DEBUG\n");
	ulp_info("INFO\n");
	ulp_notice("NOTICE\n");
	ulp_warning("WARN\n");
	ulp_error("ERROR\n");
	ulp_crit("CRIT\n");
	ulp_alert("ALERT\n");
	ulp_emerg("EMERG\n");

	set_log_prefix(true);

	ulp_debug("DEBUG\n");
	ulp_info("INFO\n");
	ulp_notice("NOTICE\n");
	ulp_warning("WARN\n");
	ulp_error("ERROR\n");
	ulp_crit("CRIT\n");
	ulp_alert("ALERT\n");
	ulp_emerg("EMERG\n");

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

