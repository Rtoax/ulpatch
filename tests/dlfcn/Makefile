include ../../scripts/verbose.mk
SHELL = bash

CC = gcc
LD = ld

CFLAGS :=
CFLAGS += -O0 -ggdb -g
CFLAGS += -pthread

TARGETS := hello
TARGETS += hello-pie
TARGETS += pdlsym_tst

TARGETS_PATCH_SO := patch.so

build: ${TARGETS} ${TARGETS_PATCH_SO}

hello: hello.o
hello-pie: hello-pie.o
pdlsym_tst: pdlsym_tst.o pdlsym_mine.o

CFLAGS_hello := -g -ggdb -flto -pthread -DWITH_DLOPEN_TEST=1
CFLAGS_hello-pie := ${CFLAGS_hello} -fpie
LDFLAGS_hello-pie := -pie

%.o: %.c
	@echo -e "CC  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(Q)$(CC) -o $(@) -c $(<) $(CFLAGS) $(CFLAGS_$(*))

%.so: %.c
	@echo -e "CC SO  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(Q)$(CC) -o $(@) $(<) -shared -fpic $(CFLAGS) $(CFLAGS_$(*))

$(TARGETS): %:
	@echo -e "LD   \033[1;32m$(@)\033[m"
	$(Q)$(CC) -o $(@) $(^) $(LDLIBS) $(LDFLAGS) $(LDFLAGS_$(*)) $(CFLAGS) $(CFLAGS_$(*))
	$(Q)strip $(@) -o $(@).stripped

clean:
	@echo -e "CLEAN   \033[1;32m$(TARGETS) ${TARGETS_PATCH_SO}\033[m"
	$(Q)rm -f $(TARGETS) $(TARGETS_PATCH_SO) *.o *.stripped
