
DHR_META=/usr/include/ulpatch/meta.h
HAVE_INSTALLED=$(shell if [[ -e ${DHR_META} ]]; then echo YES; fi)
ifeq (${HAVE_INSTALLED},YES)
$(info Already install ulpatch)
else
$(error Please install ulpatch first)
endif

TARGETS := hello

TARGETS_ULP := patch-print.ulp
TARGETS_ULP += patch-empty.ulp
TARGETS_ULP += patch-asm-exit.ulp
TARGETS_ULP += patch-asm-puts.ulp
TARGETS_ULP += patch-asm-print.ulp
TARGETS_ULP += patch-add-vars.ulp
TARGETS_ULP += patch-failed-bss.ulp

build: ${TARGETS_ULP} ${TARGETS}

hello: hello.o

CFLAGS_hello := -g -ggdb -flto

%.o: %.c
	@echo -e "Compile  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) -c $(<)

%.ulp: %.o
	@echo -e "Gen ulpatch  \033[1m$(<)\033[m to \033[1m$(@)\033[m"
	cp $(<) $(@).no-build-id
	ld -r -o $(@) --build-id=sha1 $(<)
	@echo -e "\033[1;33m-----------$(@)-----------\033[m"
	readelf --relocs $(@)
	readelf --syms $(@)

$(TARGETS): %:
	@echo -e "Target   \033[1;32m$(@)\033[m"
	$(CC) $(CFLAGS) $(CFLAGS_$(*)) -o $(@) $(^) $(LDLIBS) $(LDFLAGS) $(LDFLAGS_$(*))

clean:
	rm -f $(TARGETS) *.o *.ulp core.* *.ulp.no-build-id
