# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
SHELL = bash

ULP_CONFIG :=

ifndef ULP_CONFIG
  ULP_CONFIG=$(shell which ulp-config 2>/dev/null)
  ifeq ($(wildcard ${ULP_CONFIG}),)
    $(error Not found ulp-config, Please install ulpatch first)
  endif
endif

TARGETS = hello.ulp

CC = gcc

LDFLAGS :=

CFLAGS := -Werror -Wall
CFLAGS += -O0
CFLAGS += $(shell ${ULP_CONFIG} --cflags)

LDFLAGS := $(shell ${ULP_CONFIG} --ldflags)

ifdef INCS1
  CFLAGS += $(INCS1)
else
  CFLAGS += -I../../../
endif

$(info ulp-config: ${ULP_CONFIG})

ALL: $(TARGETS)

hello.ulp: hello.o

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) -o $(@) -c $(<)

$(TARGETS): %:
	@echo -e "Target   \033[1;32m$(@)\033[m"
	@ld ${LDFLAGS} -o $(@) $(<)

clean:
	@echo -e "Clean   \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.oc *.oS *.o
