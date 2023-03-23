# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 CESTC, Co. Rong Tao <rongtao@cestc.cn>
#
ifdef UPATCH_HELLO_OBJ
TARGETS = $(UPATCH_HELLO_OBJ)
else
TARGETS = upatch-hello.obj
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

%.o: %.c %.d
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

$(TARGETS): hello.o
	@echo -e "Target   \033[1;32m$(@)\033[m"
	@mv $(<) $(@)

clean:
	@echo -e "Clean   \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.oc *.oS *.d
