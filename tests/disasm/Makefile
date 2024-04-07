TARGETS := disasm-tst0
TARGETS += disasm-tst1

CC = gcc

CFLAGS :=
LDFLAGS :=

CFLAGS += -lbfd -lopcodes
CFLAGS += -Wall
CFLAGS += -O0 -g -ggdb

LDFLAGS += -lbfd -lopcodes

BINUTILS_VERSION = $(shell ld -v | grep -o [0-9].[0-9]\.)
BINUTILS_VERSION_MAJOR = $(shell echo ${BINUTILS_VERSION} | awk -F '.' '{print $$1}')
BINUTILS_VERSION_MINOR = $(shell echo ${BINUTILS_VERSION} | awk -F '.' '{print $$2}')

$(info Binutils version ${BINUTILS_VERSION_MAJOR}.${BINUTILS_VERSION_MINOR})
ifneq (${BINUTILS_VERSION_MAJOR},2)
$(error Not support binutils ${BINUTILS_VERSION})
endif

CFLAGS += -DBINUTILS_VERSION_MAJOR=${BINUTILS_VERSION_MAJOR}
CFLAGS += -DBINUTILS_VERSION_MINOR=${BINUTILS_VERSION_MINOR}

build: ${TARGETS}

disasm-tst0: disasm-tst0.o
disasm-tst1: disasm-tst1.o

clean:
	rm -f ${TARGETS} *.o *.d
