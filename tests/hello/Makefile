# This is ULPatch test Makefile wrote by Rong Tao.
SHELL := bash
ifeq ($(V),1)
  Q =
else
  Q = @
  MAKEFLAGS += --silent
  MAKEFLAGS += --no-print-directory
endif
export Q

CC := gcc
LD := ld

CFLAGS :=
LDFLAGS :=

HDR_META := /usr/include/ulpatch/meta.h
ULP_CONFIG := $(shell which ulpconfig 2>/dev/null)

ifeq ($(wildcard ${HDR_META}),)
  $(error Not found ${HDR_META}, Please install ulpatch first)
endif

# Since ULPatch support ulpconfig command, we should use it first.
ifeq ($(wildcard ${ULP_CONFIG}),)
  $(error Not found ulpconfig, Please install ulpatch first)
endif

CFLAGS += -O0 -ggdb -g
CFLAGS += -pthread
ifdef MCOUNT
  CFLAGS += -pg
endif

TARGETS := hello
TARGETS += hello-pie
TARGETS += test

TARGETS_ULP := patch-print.ulp
TARGETS_ULP += patch-empty.ulp
TARGETS_ULP += patch-asm-exit.ulp
TARGETS_ULP += patch-asm-sleep.ulp
TARGETS_ULP += patch-asm-puts.ulp
TARGETS_ULP += patch-asm-write.ulp
TARGETS_ULP += patch-add-vars.ulp
TARGETS_ULP += patch-failed-bss.ulp
TARGETS_ULP += patch-pthread.ulp

CFLAGS_ULP := $(shell ${ULP_CONFIG} --cc=${CC} --cflags)
CFLAGS_ULP += -O0
# FIXME: This PIC option should move to ulpconfig, just for test here.
ifdef ULP_PIC
  CFLAGS_ULP += -fpic
  CFLAGS_ULP += -fno-common
endif
ifdef NO_LIBC
  CFLAGS += -DNO_LIBC=1
  CFLAGS_ULP += -DNO_LIBC=1
endif
ifdef NO_STATIC_VAR
  CFLAGS += -DNO_STATIC_VAR=1
  CFLAGS_ULP += -DNO_STATIC_VAR=1
endif
ifeq ($(shell uname -m),aarch64)
  # TODO
endif

ifdef STATIC
  CFLAGS += -static
endif

ifdef STACK
  CFLAGS += -DSTACK=1
endif

LDFLAGS_ULP := $(shell ${ULP_CONFIG} --ld=${LD} --ldflags)

$(info CFLAGS = ${CFLAGS})
$(info CFLAGS_ULP = ${CFLAGS_ULP})
$(info LDFLAGS_ULP = ${LDFLAGS_ULP})

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
	$(Q)$(CC) -o $(@) -c $(<) $(CFLAGS_ULP)

%.ulp: %.ulpo
	@echo -e " LD ULP  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(Q)cp $(<) $(@).no-build-id
	$(Q)$(LD) ${LDFLAGS_ULP} -o $(@) $(<)

$(TARGETS): %:
	@echo -e " LD  \033[1;32m$(@)\033[m"
	$(Q)$(CC) -o $(@) $(^) $(LDFLAGS) $(LDFLAGS_$(*)) $(CFLAGS) $(CFLAGS_$(*))
	$(Q)strip $(@) -o $(@).stripped

.PHONY: clean
clean:
	@echo -e " CLEAN   \033[1;32m$(TARGETS) $(TARGETS_ULP)\033[m"
	$(Q)rm -f $(TARGETS) $(TARGETS_ULP) *.o *.ulpo core.* *.ulp.no-build-id *.stripped
