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
