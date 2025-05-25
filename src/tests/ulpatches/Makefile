# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024-2025 Rong Tao
include ../../../scripts/verbose.mk
SHELL := bash
DESTDIR := /usr/share/ulpatch/ftrace/
include ../../ulpconfig.mk

TARGETS :=
TARGETS += empty.ulp
TARGETS += printf.ulp

CC := gcc

LDFLAGS :=

CFLAGS := -Werror -Wall
CFLAGS += -O0
CFLAGS += $(shell ${ULPCONFIG} --cflags)

LDFLAGS := $(shell ${ULPCONFIG} --ldflags)

ifdef INCLUDES
  CFLAGS += $(INCLUDES)
else
  CFLAGS += -I../../
endif

.PHONY: ALL
ALL: $(TARGETS)

empty.ulp: empty.o
printf.ulp: printf.o

%.o: %.c
	@echo -e "       CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	${Q}$(CC) $(CFLAGS) -o $(@) -c $(<)

$(TARGETS): %:
	@echo -e "       LD  \033[1;32m$(@)\033[m"
	${Q}ld ${LDFLAGS} -o $(@) $(<)

.PHONY: install
install:
	@echo -e "       INSTALL  \033[1;32m$(TARGETS)\033[m"
	${Q}install -m 644 -vp ${TARGETS} ${DESTDIR}

.PHONY: clean
clean:
	@echo -e "       RM  \033[1;32m$(@)\033[m"
	${Q}rm -f ${TARGETS} *.o
