# This is ULPatch test Makefile wrote by Rong Tao.
CC = gcc
LD = ld

HDR_META=/usr/include/ulpatch/meta.h
ULP_CONFIG=$(shell which ulp-config 2>/dev/null)

ifeq ($(wildcard ${HDR_META}),)
  $(error Not found ${HDR_META}, Please install ulpatch first)
endif

# Since ULPatch support ulp-config command, we should use it first.
ifeq ($(wildcard ${ULP_CONFIG}),)
  $(error Not found ulp-config, Please install ulpatch first)
endif

CFLAGS :=
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
TARGETS_ULP += patch-asm-puts.ulp
TARGETS_ULP += patch-asm-write.ulp
TARGETS_ULP += patch-add-vars.ulp
TARGETS_ULP += patch-failed-bss.ulp
TARGETS_ULP += patch-pthread.ulp

CFLAGS_ULP := $(shell ${ULP_CONFIG} --cflags)
CFLAGS_ULP += -O0
# FIXME: This PIC option should move to ulp-config, just for test here.
ifdef ULP_PIC
  CFLAGS_ULP += -fpic
  CFLAGS_ULP += -fno-PIE
  CFLAGS_ULP += -fno-common
endif
ifdef NOLIBC
  CFLAGS += -DNOLIBC=1
  CFLAGS_ULP += -DNOLIBC=1
endif
ifdef NOSTATIC
  CFLAGS += -DNOSTATIC=1
  CFLAGS_ULP += -DNOSTATIC=1
endif
ifeq ($(shell uname -m),aarch64)
  # TODO
endif

LDFLAGS_ULP := $(shell ${ULP_CONFIG} --ldflags)

$(info CFLAGS_ULP = ${CFLAGS_ULP})
$(info LDFLAGS_ULP = ${LDFLAGS_ULP})

build: ${TARGETS_ULP} ${TARGETS}

hello: hello.o
hello-pie: hello-pie.o
test: test.o $(addsuffix .o, $(basename $(TARGETS_ULP)))

CFLAGS_hello := -g -ggdb -flto -pthread -no-pie
CFLAGS_hello-pie := ${CFLAGS_hello} -fpie
LDFLAGS_hello-pie := -pie
CFLAGS_test := $(CFLAGS_ULP)

%.o: %.c
	@echo -e " CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) -o $(@) -c $(<) $(CFLAGS) $(CFLAGS_$(*)) ${CFLAGS_ULP}

%.ulpo: %.c
	@echo -e " CC ULP  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) -o $(@) -c $(<) $(CFLAGS_ULP)

%.ulp: %.ulpo
	@echo -e " LD ULP  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@cp $(<) $(@).no-build-id
	@$(LD) ${LDFLAGS_ULP} -o $(@) $(<)

$(TARGETS): %:
	@echo -e " LD  \033[1;32m$(@)\033[m"
	@$(CC) -o $(@) $(^) $(LDLIBS) $(LDFLAGS) $(LDFLAGS_$(*)) $(CFLAGS) $(CFLAGS_$(*))
	@strip $(@) -o $(@).stripped

clean:
	@echo -e "Target   \033[1;32m$(TARGETS) $(TARGETS_ULP)\033[m"
	@rm -f $(TARGETS) $(TARGETS_ULP) *.o *.ulpo core.* *.ulp.no-build-id *.stripped
