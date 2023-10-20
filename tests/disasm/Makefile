TARGETS := disasm-tst0
TARGETS += disasm-tst1

CFLAGS = -lopcodes -Wall -O0 -g -ggdb

build: ${TARGETS}

disasm-tst0: disasm-tst0.o
disasm-tst1: disasm-tst1.o

clean:
	rm -f ${TARGETS} *.o *.d
