CC = gcc
LD = ld

HDR_META=/usr/include/ulpatch/meta.h
ifneq ($(wildcard ${HDR_META}),)
$(info Already install ulpatch)
else
$(error Please install ulpatch first)
endif

CFLAGS :=
CFLAGS += -O0 -ggdb -g
CFLAGS += -pthread
CFLAGS += -D__ULP_DEV
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

CFLAGS_ULP :=
CFLAGS_ULP += -O0
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
ifeq ($(shell uname -m),x86_64)
	CFLAGS_ULP += -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx
	CFLAGS_ULP += -fcf-protection=branch -fno-jump-tables
	CFLAGS_ULP += -m64 -falign-jumps=1
endif
ifeq ($(shell uname -m),aarch64)
	# TODO
endif

LDFLAGS_ULP :=
LDFLAGS_ULP += -relocatable --build-id=sha1
LDFLAGS_ULP += -z noexecstack
ifneq ($(shell ld --help | grep no-warn-rwx-segments || true),)
LDFLAGS_ULP += --no-warn-rwx-segments
endif

build: ${TARGETS_ULP} ${TARGETS}

hello: hello.o
hello-pie: hello-pie.o
test: test.o $(addsuffix .o, $(basename $(TARGETS_ULP)))

CFLAGS_hello := -g -ggdb -flto -pthread
CFLAGS_hello-pie := ${CFLAGS_hello} -fpie
LDFLAGS_hello-pie := -pie

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) -o $(@) -c $(<) $(CFLAGS) $(CFLAGS_$(*))

%.ulpo: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) -o $(@) -c $(<) $(CFLAGS_ULP)

%.ulp: %.ulpo
	@echo -e "Gen ulpatch  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	cp $(<) $(@).no-build-id
	$(LD) ${LDFLAGS_ULP} -o $(@) $(<)

$(TARGETS): %:
	@echo -e "Target   \033[1;32m$(@)\033[m"
	$(CC) -o $(@) $(^) $(LDLIBS) $(LDFLAGS) $(LDFLAGS_$(*)) $(CFLAGS) $(CFLAGS_$(*))
	strip $(@) -o $(@).stripped

clean:
	rm -f $(TARGETS) *.o *.ulp *.ulpo core.* *.ulp.no-build-id *.stripped
