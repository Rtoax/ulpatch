# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn>
#
if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64")
add_subdirectory(x86_64/)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64")
add_subdirectory(aarch64/)
endif()

