# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao
#
SHELL = bash

DESTDIR := /usr/share/ulpatch/ftrace/

ULP_CONFIG :=

ifndef ULP_CONFIG
  ULP_CONFIG=$(shell which ulpconfig 2>/dev/null)
  ifeq ($(wildcard ${ULP_CONFIG}),)
    $(error Not found ulpconfig, Please install ulpatch first)
  endif
endif

TARGETS :=
TARGETS += empty.ulp
TARGETS += printf.ulp

CC = gcc

LDFLAGS :=

CFLAGS := -Werror -Wall
CFLAGS += -O0
CFLAGS += $(shell ${ULP_CONFIG} --cflags)

LDFLAGS := $(shell ${ULP_CONFIG} --ldflags)

ifdef INCS1
  CFLAGS += $(INCS1)
else
  CFLAGS += -I../../
endif

$(info ulpconfig: ${ULP_CONFIG})

ALL: $(TARGETS)

empty.ulp: empty.o
printf.ulp: printf.o

%.o: %.c
	@echo -e "       CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) -o $(@) -c $(<)

$(TARGETS): %:
	@echo -e "       LD  \033[1;32m$(@)\033[m"
	@ld ${LDFLAGS} -o $(@) $(<)

install:
	@echo -e "       INSTALL  \033[1;32m$(TARGETS)\033[m"
	@install -m 644 -vp ${TARGETS} ${DESTDIR}

clean:
	@echo -e "       RM  \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.o
