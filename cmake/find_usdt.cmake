# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
# - Try to find systemtap-sdt-devel
# Once done this will define
#

INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
// provide by systemtap-sdt-devel
#include <sys/sdt.h>
int main() {
	return 0;
}" HAVE_SDT_H)

CHECK_C_SOURCE_COMPILES("
// provide by systemtap-sdt-devel
#include <sys/sdt.h>
int main() {
	DTRACE_PROBE(hello-usdt, probe-main);
	return 0;
}" HAVE_SDT_DTRACE_PROBE)

mark_as_advanced(HAVE_SDT_H HAVE_SDT_DTRACE_PROBE)
