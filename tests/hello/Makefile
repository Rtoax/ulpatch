# SPDX-License-Identifier: GPL-2.0-or-later
# Wrote by Rong Tao.
include ../../scripts/verbose.mk
include ../../src/ulpconfig.mk
SHELL := bash

CC := gcc
LD := ld

CFLAGS :=
CFLAGS_NOLIBC :=
LDFLAGS :=
CFLAGS_ULP :=

ULP_META_H := /usr/include/ulpatch/meta.h
ifeq ($(wildcard ${ULP_META_H}),)
  $(warning Not found ${ULP_META_H}, use source code)
  ifeq ($(wildcard ulpatch),)
    $(shell ln -s ../../src/patch/ ulpatch)
  endif
  ULP_META_H := ./ulpatch/meta.h
  CFLAGS += -I.
  CFLAGS_ULP += -I.
endif

CFLAGS += -O0 -ggdb -g
CFLAGS += -pthread
ifdef MCOUNT
  CFLAGS += -pg
endif

TARGETS := hello
TARGETS += hello-pie
TARGETS += test

TARGETS_ULP += patch-empty.ulp
TARGETS_ULP += patch-asm-exit.ulp
TARGETS_ULP += patch-asm-sleep.ulp
TARGETS_ULP += patch-asm-write.ulp
TARGETS_ULP += patch-add-vars.ulp
TARGETS_ULP += patch-failed-bss.ulp
ifndef NOLIBC
  TARGETS_ULP += patch-asm-puts.ulp
  TARGETS_ULP += patch-print.ulp
  TARGETS_ULP += patch-pthread.ulp
endif

CFLAGS_ULP += $(shell ${ULPCONFIG} --cc=${CC} --cflags)
CFLAGS_ULP += -O0
# FIXME: This PIC option should move to ulpconfig, just for test here.
ifdef ULP_PIC
  CFLAGS_ULP += -fpic
  CFLAGS_ULP += -fno-common
endif
ifdef NOLIBC
  CFLAGS += -DNOLIBC=1
  CFLAGS_ULP += -DNOLIBC=1
  CFLAGS_NOLIBC += -nolibc
endif
ifdef NO_STATIC_VAR
  CFLAGS += -DNO_STATIC_VAR=1
  CFLAGS_ULP += -DNO_STATIC_VAR=1
endif

ifdef STATIC
  CFLAGS += -static
endif

ifdef STACK
  CFLAGS += -DSTACK=1
endif

LDFLAGS_ULP := $(shell ${ULPCONFIG} --ld=${LD} --ldflags)

ifdef DEBUG
  $(info CFLAGS = ${CFLAGS})
  $(info CFLAGS_ULP = ${CFLAGS_ULP})
  $(info LDFLAGS_ULP = ${LDFLAGS_ULP})
endif

.PHONY: build
build: ${TARGETS_ULP} ${TARGETS}

hello: hello.o
hello-pie: hello-pie.o
test: test.o $(addsuffix .o, $(basename $(TARGETS_ULP)))

CFLAGS_hello_common := -g -ggdb -flto -pthread
CFLAGS_hello := ${CFLAGS_hello_common} -no-pie
CFLAGS_hello-pie := ${CFLAGS_hello_common} -fpie
LDFLAGS_hello-pie := -pie
CFLAGS_test := $(CFLAGS_ULP)


%.o: %.c
	@echo -e " CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(Q)$(CC) -o $(@) -c $(<) $(CFLAGS) $(CFLAGS_$(*)) ${CFLAGS_ULP}

%.ulpo: %.c
	@echo -e " CC ULP  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(Q)$(CC) -o $(@) -c $(<) $(CFLAGS_ULP) ${CFLAGS_NOLIBC}

%.ulp: %.ulpo
	@echo -e " LD ULP  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(Q)$(LD) ${LDFLAGS_ULP} -o $(@) $(<)
	$(Q)rm -f $(<)

$(TARGETS): %:
	@echo -e " LD  \033[1;32m$(@)\033[m"
	$(Q)$(CC) -o $(@) $(^) $(LDFLAGS) $(LDFLAGS_$(*)) $(CFLAGS) $(CFLAGS_$(*))
	$(Q)strip $(@) -o $(@).stripped

.PHONY: clean
clean:
	@echo -e " CLEAN   \033[1;32m$(TARGETS) $(TARGETS_ULP)\033[m"
	$(Q)rm -f $(TARGETS) $(TARGETS_ULP) *.o *.ulpo core.* *.stripped *.ulp
	${Q}rm -f ulpatch
