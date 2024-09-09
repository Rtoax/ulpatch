# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2024 Rong Tao
#
SHELL = bash

ULP_CONFIG :=

ifndef ULP_CONFIG
  ULP_CONFIG=$(shell which ulp-config 2>/dev/null)
  ifeq ($(wildcard ${ULP_CONFIG}),)
    $(error Not found ulp-config, Please install ulpatch first)
  endif
endif


ifdef FTRACE_OBJ
TARGETS = $(FTRACE_OBJ)
else
TARGETS = ftrace-mcount.obj
endif

CC = gcc

CFLAGS := -Werror -Wall
CFLAGS += -O0

ifdef INCS1
CFLAGS += $(INCS1)
else
CFLAGS += -I ../../../
endif

CFLAGS += $(shell ${ULP_CONFIG} --cflags)

LDFLAGS := $(shell ${ULP_CONFIG} --ldflags)

ALL: $(TARGETS)

%.oS: %.S
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

%.oc: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

$(TARGETS): mcount.oc mcount.oS
	@echo -e "Target   \033[1;32m$(@)\033[m"
	@$(LD) -o $(@) $(^) $(LDFLAGS)

clean:
	@echo -e "Clean   \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.oc *.oS
