# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024-2025 Rong Tao
SHELL := bash
DESTDIR := /usr/share/ulpatch/ftrace/
ULP_CONFIG :=

ifndef ULP_CONFIG
  ULP_CONFIG := $(shell which ulpconfig 2>/dev/null)
  ifeq ($(wildcard ${ULP_CONFIG}),)
    $(error Not found ulpconfig, Please install ulpatch first)
  endif
endif

TARGETS :=
TARGETS += empty.ulp
TARGETS += printf.ulp

CC := gcc

LDFLAGS :=

CFLAGS := -Werror -Wall
CFLAGS += -O0
CFLAGS += $(shell ${ULP_CONFIG} --cflags)

LDFLAGS := $(shell ${ULP_CONFIG} --ldflags)

ifdef INCLUDES
  CFLAGS += $(INCLUDES)
else
  CFLAGS += -I../../
endif

ifdef DEBUG
  $(info ulpconfig: ${ULP_CONFIG})
endif

.PHONY: ALL
ALL: $(TARGETS)

empty.ulp: empty.o
printf.ulp: printf.o

%.o: %.c
	@echo -e "       CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) -o $(@) -c $(<)

$(TARGETS): %:
	@echo -e "       LD  \033[1;32m$(@)\033[m"
	@ld ${LDFLAGS} -o $(@) $(<)

.PHONY: install
install:
	@echo -e "       INSTALL  \033[1;32m$(TARGETS)\033[m"
	@install -m 644 -vp ${TARGETS} ${DESTDIR}

.PHONY: clean
clean:
	@echo -e "       RM  \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.o
