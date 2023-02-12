#include <stdio.h>
#include <bfd.h>
#include <dis-asm.h>

#include "elfcomm.h"

#define xvec_get_elf_backend_data(xvec) \
  ((const struct elf_backend_data *) (xvec)->backend_data)

#define get_elf_backend_data(abfd) \
   xvec_get_elf_backend_data ((abfd)->xvec)

#if 0
static bfd_vma start_address = (bfd_vma)-1;
static bfd_vma stop_address = (bfd_vma)-1;
#endif

/* The number of zeroes we want to see before we start skipping them.
   The number is arbitrarily chosen.  */

#define DEFAULT_SKIP_ZEROES 8

/* The number of zeroes to skip at the end of a section.  If the
   number of zeroes at the end is between SKIP_ZEROES_AT_END and
   SKIP_ZEROES, they will be disassembled.  If there are fewer than
   SKIP_ZEROES_AT_END, they will be skipped.  This is a heuristic
   attempt to avoid disassembling zeroes inserted by section
   alignment.  */

#define DEFAULT_SKIP_ZEROES_AT_END 3

#define __unused __attribute__((unused))


struct objdump_disasm_info {
	bfd *abfd;
	bool require_sec;
	disassembler_ftype disassemble_fn;
	arelent *reloc;
	const char *symbol;
};

static enum bfd_endian endian = BFD_ENDIAN_UNKNOWN;

static char *disassembler_options = NULL;

static asymbol **syms;
static long symcount = 0;

static asymbol **dynsyms;
static long dynsymcount = 0;

static asymbol *synthsyms;
static long synthcount = 0;

static long sorted_symcount = 0;
static asymbol **sorted_syms;

static const char * disasm_sym;     /* Disassembly start symbol.  */

static int prefix_addresses;
static int exit_status = 0;

static asymbol **slurp_symtab(bfd *abfd)
{
	symcount = 0;
	if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
		return NULL;

	long storage = bfd_get_symtab_upper_bound(abfd);
	if (storage < 0) {
		fprintf(stderr, "failed to read symbol table from: %s",
			bfd_get_filename (abfd));
		fprintf(stderr, "error message was");
		abort();
	}

	if (storage == 0)
		return NULL;

	asymbol **sy = (asymbol **) malloc(storage);
	symcount = bfd_canonicalize_symtab(abfd, sy);
	if (symcount < 0)
		fprintf(stderr, bfd_get_filename(abfd));

	return sy;
}

static asymbol **slurp_dynamic_symtab(bfd *abfd)
{
	dynsymcount = 0;
	long storage = bfd_get_dynamic_symtab_upper_bound(abfd);
	if (storage < 0) {
		if (!(bfd_get_file_flags (abfd) & DYNAMIC)) {
			fprintf(stderr, "%s: not a dynamic object", bfd_get_filename(abfd));
			exit_status = 1;
			return NULL;
		}

		fprintf(stderr, bfd_get_filename(abfd));
		abort();
	}

	if (storage == 0)
		return NULL;

	asymbol **sy = (asymbol **) malloc(storage);
	dynsymcount = bfd_canonicalize_dynamic_symtab(abfd, sy);
	if (dynsymcount < 0) {
		fprintf(stderr, bfd_get_filename(abfd));
		abort();
	}

	return sy;
}

static bool is_significant_symbol_name(const char * name)
{
	return startswith(name, ".plt") || startswith(name, ".got");
}

static long remove_useless_symbols(asymbol **symbols, long count)
{
	asymbol **in_ptr = symbols, **out_ptr = symbols;

	while (--count >= 0) {
		asymbol *sym = *in_ptr++;

		if (sym->name == NULL || sym->name[0] == '\0')
			continue;
		if ((sym->flags & (BSF_DEBUGGING | BSF_SECTION_SYM))
			&& ! is_significant_symbol_name(sym->name))
			continue;
		if (bfd_is_und_section(sym->section)
			|| bfd_is_com_section(sym->section))
			continue;

		*out_ptr++ = sym;
	}
	return out_ptr - symbols;
}

static void
objdump_print_addr(bfd_vma vma, struct disassemble_info *inf, bool skip_zeroes)
{
	fprintf(stderr, "objdump_print_address TODO\n");
	abort();
}

static void
objdump_print_address(bfd_vma vma, struct disassemble_info *inf)
{
	objdump_print_addr(vma, inf, !prefix_addresses);
}

static asymbol *
objdump_symbol_at_address(bfd_vma vma, struct disassemble_info *inf)
{
	asymbol *sym = NULL;

	//sym = find_symbol_for_address(vma, inf, NULL);
	fprintf(stderr, "objdump_symbol_at_address TODO\n");
	abort();
	if (sym != NULL && bfd_asymbol_value(sym) == vma)
		return sym;

	return NULL;
}

static int
compare_relocs(const void *ap, const void *bp)
{
	const arelent *a = * (const arelent **) ap;
	const arelent *b = * (const arelent **) bp;

	if (a->address > b->address)
		return 1;
	else if (a->address < b->address)
		return -1;

	/* So that associated relocations tied to the same address show up
	   in the correct order, we don't do any further sorting.  */
	if (a > b)
		return 1;
	else if (a < b)
		return -1;
	else
		return 0;
}

static void
disassemble_section(bfd *abfd, asection *section, void *inf)
{
	fprintf(stderr, "disassemble_section TODO\n");
}

static void disassemble_data(bfd *abfd)
{
	int i;
	struct disassemble_info __unused disasm_info;
	struct objdump_disasm_info __unused aux;

	sorted_symcount = symcount ? symcount : dynsymcount;
	sorted_syms = (asymbol **) malloc ((sorted_symcount + synthcount)
		* sizeof (asymbol *));

	if (sorted_symcount != 0) {
		memcpy(sorted_syms, symcount ? syms : dynsyms,
			sorted_symcount * sizeof (asymbol *));

		sorted_symcount = remove_useless_symbols(sorted_syms, sorted_symcount);
	}

	for (i = 0; i < synthcount; ++i) {
		sorted_syms[sorted_symcount] = synthsyms + i;
		++sorted_symcount;
	}

	init_disassemble_info(&disasm_info, stdout, (fprintf_ftype)fprintf);

	disasm_info.application_data = (void *) &aux;
	aux.abfd = abfd;
	aux.require_sec = false;
	disasm_info.dynrelbuf = NULL;
	disasm_info.dynrelcount = 0;
	aux.reloc = NULL;
	aux.symbol = disasm_sym;

	disasm_info.print_address_func = objdump_print_address;
	disasm_info.symbol_at_address_func = objdump_symbol_at_address;

	if (endian != BFD_ENDIAN_UNKNOWN) {
		struct bfd_target *xvec;
		xvec = (struct bfd_target *) malloc(sizeof (struct bfd_target));
		memcpy(xvec, abfd->xvec, sizeof(struct bfd_target));
		xvec->byteorder = endian;
		abfd->xvec = xvec;
	}
	/* Use libopcodes to locate a suitable disassembler.  */
	aux.disassemble_fn = disassembler (bfd_get_arch (abfd),
	bfd_big_endian (abfd),
	bfd_get_mach (abfd), abfd);

	if (!aux.disassemble_fn) {
		fprintf(stderr, "can't disassemble for architecture %s\n",
			bfd_printable_arch_mach(bfd_get_arch(abfd), 0));
		exit_status = 1;
		return;
	}

	disasm_info.flavour = bfd_get_flavour (abfd);
	disasm_info.arch = bfd_get_arch (abfd);
	disasm_info.mach = bfd_get_mach (abfd);
	disasm_info.disassembler_options = disassembler_options;
	disasm_info.octets_per_byte = bfd_octets_per_byte (abfd, NULL);
	disasm_info.skip_zeroes = DEFAULT_SKIP_ZEROES;
	disasm_info.skip_zeroes_at_end = DEFAULT_SKIP_ZEROES_AT_END;
	disasm_info.disassembler_needs_relocs = false;

	if (bfd_big_endian(abfd))
		disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_BIG;
	else if (bfd_little_endian(abfd))
		disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_LITTLE;
	else
		/* ??? Aborting here seems too drastic.  We could default to big or little
		 instead.  */
		disasm_info.endian = BFD_ENDIAN_UNKNOWN;

	disasm_info.endian_code = disasm_info.endian;

	/* Allow the target to customize the info structure.  */
	disassemble_init_for_target (& disasm_info);

	/* Pre-load the dynamic relocs as we may need them during the disassembly.  */
	long relsize = bfd_get_dynamic_reloc_upper_bound (abfd);

	if (relsize > 0) {
		disasm_info.dynrelbuf = (arelent **) malloc(relsize);
		disasm_info.dynrelcount
			= bfd_canonicalize_dynamic_reloc(abfd, disasm_info.dynrelbuf, dynsyms);
		if (disasm_info.dynrelcount < 0)
			fprintf(stderr, bfd_get_filename(abfd));

		/* Sort the relocs by address.  */
		qsort(disasm_info.dynrelbuf, disasm_info.dynrelcount, sizeof(arelent *),
			compare_relocs);
	}

	disasm_info.symtab = sorted_syms;
	disasm_info.symtab_size = sorted_symcount;

	bfd_map_over_sections(abfd, disassemble_section, &disasm_info);

	free(disasm_info.dynrelbuf);
	disasm_info.dynrelbuf = NULL;
	free(sorted_syms);
	disassemble_free_target(&disasm_info);
}

static void dump_bfd(bfd *abfd, bool is_mainfile)
{
	if (bfd_big_endian(abfd)) {
		byte_get = byte_get_big_endian;
		endian = BFD_ENDIAN_BIG;
	} else if (bfd_little_endian(abfd)) {
		byte_get = byte_get_little_endian;
		endian = BFD_ENDIAN_LITTLE;
	} else
		byte_get = NULL;

	syms = slurp_symtab(abfd);

	if (is_mainfile) {
		dynsyms = slurp_dynamic_symtab(abfd);
	}

	synthcount = bfd_get_synthetic_symtab(abfd, symcount, syms,
					dynsymcount, dynsyms,
					&synthsyms);
	if (synthcount < 0)
		synthcount = 0;

	disassemble_data(abfd);

	if (syms) {
		free(syms);
		syms = NULL;
	}
	if (dynsyms) {
		free(dynsyms);
		dynsyms = NULL;
	}

	if (synthsyms) {
		free(synthsyms);
		synthsyms = NULL;
	}
	symcount = 0;
	dynsymcount = 0;
	synthcount = 0;
}

int main(int argc, char *argv[])
{
	bfd *file;
	char **matching;

	char *filename = argv[0];
	char *target = NULL;

	file = bfd_openr(filename, target);

	if (bfd_check_format(file, bfd_archive)) {
		printf("%s is bfd archive, do nothing, close\n", filename);
		goto close;
	}

	if (bfd_check_format_matches(file, bfd_object, &matching)) {
		printf("%s is bfd_object\n", filename);
		dump_bfd(file, true);
	}

close:
	bfd_close(file);

	return 0;
}

