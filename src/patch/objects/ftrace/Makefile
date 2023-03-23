# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2023 CESTC, Co. Rong Tao <rongtao@cestc.cn>
#
ifdef FTRACE_OBJ
TARGETS = $(FTRACE_OBJ)
else
TARGETS = ftrace-mcount.obj
endif

DEBUG = yes
SRC_PATH := $(shell pwd)
CC = gcc

CFLAGS := -Werror -Wall

ifdef DEBUG
CFLAGS += -DDEBUG -O0
endif

ifdef INCS1
CFLAGS += $(INCS1)
else
CFLAGS += -I ../../../
endif

ALL: $(TARGETS)

%.d: %.c
	@echo -e "Generate \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) -MM -MF "$@" -MG -MP -MT"$@" -MT"$(<:.c=.oc)" $(<)

%.oS: %.S
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

%.oc: %.c %.d
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

$(TARGETS): mcount.oc mcount.oS
	@echo -e "Target   \033[1;32m$(@)\033[m"
	@$(LD) -relocatable -o $(@) $(^) $(STATIC_OPTS) $(LDLIBS)

clean:
	@echo -e "Clean   \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.oc *.oS *.d
