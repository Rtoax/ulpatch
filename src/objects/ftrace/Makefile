# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
SHELL := bash
DESTDIR := /usr/share/ulpatch/ftrace/
ULP_CONFIG :=

ifndef ULP_CONFIG
  ULP_CONFIG := $(shell which ulpconfig 2>/dev/null)
  ifeq ($(wildcard ${ULP_CONFIG}),)
    $(error Not found ulpconfig, Please install ulpatch first)
  endif
endif

TARGETS := ftrace-mcount.obj

CC := gcc

CFLAGS := -Werror -Wall
CFLAGS += -O0

ifdef INCLUDES
  CFLAGS += $(INCLUDES)
else
  CFLAGS += -I../../
endif

CFLAGS += $(shell ${ULP_CONFIG} --cflags)

LDFLAGS := $(shell ${ULP_CONFIG} --ldflags)

.PHONY: ALL
ALL: $(TARGETS)

ftrace-mcount.obj: mcount.oc mcount.oS

%.oS: %.S
	@echo -e "       CC(ASM)  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

%.oc: %.c
	@echo -e "       CC(C)  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

$(TARGETS): %:
	@echo -e "       LD  \033[1;32m$(@)\033[m"
	@$(LD) -o $(@) $(^) $(LDFLAGS)

.PHONY: install
install:
	@echo -e "       INSTALL  \033[1;32m$(TARGETS)\033[m"
	@install -m 644 -vp ${TARGETS} ${DESTDIR}

.PHONY: clean
clean:
	@echo -e "       RM  \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.oc *.oS
