#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <bfd.h>
#include <dis-asm.h>


#define __unused __attribute__((unused))


static asymbol **syms;
static long symcount = 0;

static asymbol **dynsyms;
static long dynsymcount = 0;

static asymbol *synthsyms;
static long synthcount = 0;

static long sorted_symcount = 0;
static asymbol **sorted_syms;



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
		if (!(bfd_get_file_flags(abfd) & DYNAMIC)) {
			fprintf(stderr, "%s: not a dynamic object", bfd_get_filename(abfd));
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

static inline bool
_startswith(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

static bool is_significant_symbol_name(const char * name)
{
	return _startswith(name, ".plt") || _startswith(name, ".got");
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

static bool asymbol_is_plt(asymbol *sym)
{
	return strstr(sym->name, "@plt") ? true : false;
}

static const char* asymbol_pure_name(asymbol *sym, char *buf, int blen)
{
	char *name = strstr(sym->name, "@");
	if (!name)
		return sym->name;

	unsigned int len = name - sym->name;
	if (len > blen) {
		fprintf(stderr, "Too short buffer length.\n");
		return NULL;
	}

	strncpy(buf, sym->name, len);
	buf[len] = '\0';

	return buf;
}

static void disassemble_data(bfd *abfd)
{
	int i;

	sorted_symcount = symcount ? symcount : dynsymcount;
	sorted_syms = (asymbol **) malloc((sorted_symcount + synthcount)
		* sizeof(asymbol *));

	if (sorted_symcount != 0) {
		memcpy(sorted_syms, symcount ? syms : dynsyms,
			sorted_symcount * sizeof(asymbol *));

		sorted_symcount = remove_useless_symbols(sorted_syms, sorted_symcount);
	}

	for (i = 0; i < synthcount; ++i) {
		sorted_syms[sorted_symcount] = synthsyms + i;
		++sorted_symcount;
	}

	for (i = 0; i < sorted_symcount; i++) {
		asymbol *s = sorted_syms[i];
		char buf[256];

		printf("SYM: %#016lx  %s %s\n", bfd_asymbol_value(s),
			asymbol_pure_name(s, buf, sizeof(buf)),
			asymbol_is_plt(s) ? "PLT" : "");
	}

	free(sorted_syms);
}

static void dump_bfd(bfd *abfd, bool is_mainfile)
{
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

static char *elf_filename = NULL;

static void usage(int eval)
{
	printf("\n");
	printf(" -h, --help   show help info\n");
	printf(" -f, --file   specify elf file\n");
	printf("\n");

	exit(eval);
}

static void parse_config(int argc, char *argv[])
{
	struct option options[] = {
	{ "help",       no_argument,       0, 'h' },
	{ "file",       required_argument, 0, 'f' },
	{ NULL }
	};

	while (1) {
		int c;
		int option_index = 0;
		c = getopt_long(argc, argv, "hf:", options, &option_index);
		if (c < 0) {
			break;
		}
		switch (c) {
		case 'h':
			usage(0);
			break;
		case 'f':
			elf_filename = optarg;
			break;
		default:
			break;
		}
	}

	if (!elf_filename) {
		fprintf(stderr, "Must specify -f, --file argument.\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	bfd *file;
	char **matching;

	parse_config(argc, argv);

	char *filename = elf_filename;
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

