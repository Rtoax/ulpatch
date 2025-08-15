# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022-2025 Rong Tao
include ../../scripts/verbose.mk

TARGETS += symbol

CC = gcc

CFLAGS :=
LDFLAGS :=

CFLAGS += -Wall
CFLAGS += -O0 -g -ggdb

LDFLAGS += -lbfd -lopcodes

BINUTILS_VERSION = $(shell ld.bfd --version | grep -o [0-9].[0-9]\. | sed -n '1p')
BINUTILS_VERSION_MAJOR = $(shell echo ${BINUTILS_VERSION} | awk -F '.' '{print $$1}')
BINUTILS_VERSION_MINOR = $(shell echo ${BINUTILS_VERSION} | awk -F '.' '{print $$2}')

ifdef V
  $(info Binutils version ${BINUTILS_VERSION_MAJOR}.${BINUTILS_VERSION_MINOR})
endif
ifneq (${BINUTILS_VERSION_MAJOR},2)
  $(error Not support binutils ${BINUTILS_VERSION})
endif

CFLAGS += -DBINUTILS_VERSION_MAJOR=${BINUTILS_VERSION_MAJOR}
CFLAGS += -DBINUTILS_VERSION_MINOR=${BINUTILS_VERSION_MINOR}

.PHONY: build
build: ${TARGETS}
	@echo -e " \033[1;33m Done \033[m"

symbol: symbol.o

%.o: %.c
	@echo -e "  CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	${Q}$(CC) -o $(@) -c $(<) $(CFLAGS) $(CFLAGS_$(*))

$(TARGETS): %:
	@echo -e "  LD  \033[1;32m$(@)\033[m"
	${Q}$(CC) -o $(@) $(^) $(LDFLAGS) $(LDFLAGS_$(*)) $(CFLAGS) $(CFLAGS_$(*))

.PHONY: test
test: ${TARGETS}
	@echo -e "  TEST  \033[1;32m$(TARGETS)\033[m"

.PHONY: clean
clean:
	@echo -e "  CLEAN  \033[1;32m$(TARGETS)\033[m"
	${Q}rm -f ${TARGETS} *.o *.out
