# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 Rong Tao <rtoax@foxmail.com>
#
ifdef ULPATCH_HELLO_OBJ
TARGETS = $(ULPATCH_HELLO_OBJ)
else
TARGETS = hello.obj
endif

CC = gcc

CFLAGS := -Werror -Wall
CFLAGS += -O0

ifdef INCS1
CFLAGS += $(INCS1)
else
CFLAGS += -I../../../
endif

ALL: $(TARGETS)

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	@$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

$(TARGETS): hello.o
	@echo -e "Target   \033[1;32m$(@)\033[m"
	@ld -relocatable -o $(@) --build-id=sha1 $(<)

clean:
	@echo -e "Clean   \033[1;32m$(@)\033[m"
	@rm -f ${TARGETS} *.oc *.oS *.o
