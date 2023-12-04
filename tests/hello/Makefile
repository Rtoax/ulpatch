
DHR_META=/usr/include/upatch/meta.h
HAVE_INSTALLED=$(shell if [[ -e ${DHR_META} ]]; then echo YES; fi)
ifeq (${HAVE_INSTALLED},YES)
$(info Already install upatch)
else
$(error Please install upatch first)
endif

TARGETS := hello

TARGETS_UP := patch-print.up
TARGETS_UP += patch-empty.up
TARGETS_UP += patch-asm-exit.up
TARGETS_UP += patch-in-patch.up
TARGETS_UP += patch-asm-print.up

build: ${TARGETS_UP} ${TARGETS}

hello: hello.o

CFLAGS_hello := -g -ggdb

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

%.up: %.o
	@echo -e "Gen upatch  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	mv $(<) $(@)
	@echo -e "\033[1;33m-----------$(@)-----------\033[m"
	readelf --relocs $(@)
	readelf --syms $(@)

$(TARGETS): %:
	@echo -e "Target   \033[1;32m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) $(^) $(LDLIBS) $(LDFLAGS) $(LDFLAGS_$(*))

clean:
	rm -f $(TARGETS) *.o *.up core.*
