CC = gcc
LD = ld

CFLAGS :=
CFLAGS += -O0 -ggdb -g
CFLAGS += -pthread

TARGETS := hello
TARGETS += pdlsym_tst

TARGETS_PATCH_SO := patch.so

build: ${TARGETS} ${TARGETS_PATCH_SO}

hello: hello.o
pdlsym_tst: pdlsym_tst.o pdlsym_mine.o

CFLAGS_hello := -g -ggdb -flto -pthread -DWITH_DLOPEN_TEST=1

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

%.so: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) $(<) -shared -fpic

$(TARGETS): %:
	@echo -e "Target   \033[1;32m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) $(^) $(LDLIBS) $(LDFLAGS) $(LDFLAGS_$(*))
	strip $(@) -o $(@).stripped

clean:
	rm -f $(TARGETS) $(TARGETS_PATCH_SO) *.o *.stripped
