// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2024-2026 Rong Tao */
#pragma once

#define CMD_RETURN_SUCCESS_VALUE 0x123

/**
 * We need to replace the return or exit action of ulpatch(argc, argv). When
 * ulpatch() is called by the ulpatch command, it should exit() normally. If
 * it is called in tests, the original exit() should be replaced with return.
 *
 * At the same time, the return value CMD_RETURN_SUCCESS_VALUE is used to
 * indicate that ulpatch() returns successfully in the unit test.
 */
#if defined(ULP_CMD_MAIN)
# define cmd_exit(v) exit(v)
# define cmd_exit_success() exit(0)
#else
# define cmd_exit(v) do { return v; } while (0)
# define cmd_exit_success() do { return CMD_RETURN_SUCCESS_VALUE; } while (0)
#endif

/**
 * When we want to test in code, the following interfaces are very useful.
 *
 * The ulpatch command is implemented using ulpatch(argc, argv) which allows
 * easy testing of the ulpatch command line without the need for execv(2).
 */
int ulftrace(int argc, char *argv[]);
int ulpatch(int argc, char *argv[]);
int ulpinfo(int argc, char *argv[]);
int ultask(int argc, char *argv[]);
