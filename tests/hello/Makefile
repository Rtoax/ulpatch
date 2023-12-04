
DHR_META=/usr/include/upatch/meta.h
HAVE_INSTALLED=$(shell if [[ -e ${DHR_META} ]]; then echo YES; fi)
ifeq (${HAVE_INSTALLED},YES)
$(info Already install upatch)
else
$(error Please install upatch first)
endif

TARGETS := hello

TARGETS_UP := patch-print.up
TARGETS_UP += patch-asm-exit.up

build: ${TARGETS_UP} ${TARGETS}

hello: hello.o

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) $(CFLAGS) -o $(@) -c $(<)

%.up: %.o
	@echo -e "Gen upatch  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	mv $(<) $(@)
	readelf --relocs $(@)

clean:
	rm -f $(TARGETS) *.o *.up
