// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include "utils/log.h"
#include "utils/list.h"
#include "elf/elf-api.h"

#include "tests/test-api.h"


TEST(Utils_log, log, 0)
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

TEST(Utils_log, set_log_level, 0)
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

TEST(Utils_log, set_log_prefix, 0)
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

TEST(Utils_log, str2loglevel, 0)
{
	if (LOG_DEBUG != str2loglevel("debug") ||
            LOG_DEBUG != str2loglevel("DEBUG") ||
            LOG_DEBUG != str2loglevel("DBG") ||
            LOG_DEBUG != str2loglevel("dbg"))
		return -1;

	if (LOG_INFO != str2loglevel("info") ||
            LOG_INFO != str2loglevel("INFO") ||
            LOG_INFO != str2loglevel("INF") ||
	    LOG_INFO != str2loglevel("inf"))
		return -1;

	if (LOG_NOTICE != str2loglevel("notice") ||
            LOG_NOTICE != str2loglevel("NOTICE") ||
            LOG_NOTICE != str2loglevel("NOTE") ||
            LOG_NOTICE != str2loglevel("note"))
		return -1;

	if (LOG_WARNING != str2loglevel("warning") ||
            LOG_WARNING != str2loglevel("WARNING") ||
            LOG_WARNING != str2loglevel("WARN") ||
            LOG_WARNING != str2loglevel("warn"))
		return -1;

	if (LOG_ERR != str2loglevel("error") ||
            LOG_ERR != str2loglevel("ERROR") ||
            LOG_ERR != str2loglevel("ERR") ||
            LOG_ERR != str2loglevel("err"))
		return -1;

	if (LOG_CRIT != str2loglevel("crit") ||
            LOG_CRIT != str2loglevel("CRIT"))
		return -1;

	if (LOG_ALERT != str2loglevel("alert") ||
            LOG_ALERT != str2loglevel("ALERT"))
		return -1;

	if (LOG_EMERG != str2loglevel("emerg") ||
            LOG_EMERG != str2loglevel("EMERG"))
		return -1;

        if (str2loglevel("Unknown-value") != -EINVAL ||
            str2loglevel(NULL) != -EINVAL)
		return -1;

	return 0;
}
