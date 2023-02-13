#include <stdio.h>
#include <bfd.h>
#include <dis-asm.h>
#include <demangle.h>

#include "elfcomm.h"

#define xvec_get_elf_backend_data(xvec) \
  ((const struct elf_backend_data *) (xvec)->backend_data)

#define get_elf_backend_data(abfd) \
   xvec_get_elf_backend_data ((abfd)->xvec)

static bfd_vma start_address = (bfd_vma)-1;
static bfd_vma stop_address = (bfd_vma)-1;

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

static int demangle_flags = DMGL_ANSI | DMGL_PARAMS;

static int do_demangle;
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

static inline bool
sym_ok (bool want_section,
	bfd *abfd ATTRIBUTE_UNUSED,
	long place,
	asection *sec,
	struct disassemble_info *inf)
{
  if (want_section)
    {
      /* NB: An object file can have different sections with the same
	 section name.  Compare compare section pointers if they have
	 the same owner.  */
      if (sorted_syms[place]->section->owner == sec->owner
	  && sorted_syms[place]->section != sec)
	return false;

      /* Note - we cannot just compare section pointers because they could
	 be different, but the same...  Ie the symbol that we are trying to
	 find could have come from a separate debug info file.  Under such
	 circumstances the symbol will be associated with a section in the
	 debug info file, whilst the section we want is in a normal file.
	 So the section pointers will be different, but the section names
	 will be the same.  */
      if (strcmp (bfd_section_name (sorted_syms[place]->section),
		  bfd_section_name (sec)) != 0)
	return false;
    }

  return inf->symbol_is_valid (sorted_syms[place], inf);
}

/* Locate a symbol given a bfd and a section (from INFO->application_data),
   and a VMA.  If INFO->application_data->require_sec is TRUE, then always
   require the symbol to be in the section.  Returns NULL if there is no
   suitable symbol.  If PLACE is not NULL, then *PLACE is set to the index
   of the symbol in sorted_syms.  */

static asymbol *
find_symbol_for_address (bfd_vma vma,
			 struct disassemble_info *inf,
			 long *place)
{
  /* @@ Would it speed things up to cache the last two symbols returned,
     and maybe their address ranges?  For many processors, only one memory
     operand can be present at a time, so the 2-entry cache wouldn't be
     constantly churned by code doing heavy memory accesses.  */

  /* Indices in `sorted_syms'.  */
  long min = 0;
  long max_count = sorted_symcount;
  long thisplace;
  struct objdump_disasm_info *aux;
  bfd *abfd;
  asection *sec;
  unsigned int opb;
  bool want_section;
  long rel_count;

  if (sorted_symcount < 1)
    return NULL;

  aux = (struct objdump_disasm_info *) inf->application_data;
  abfd = aux->abfd;
  sec = inf->section;
  opb = inf->octets_per_byte;

  /* Perform a binary search looking for the closest symbol to the
     required value.  We are searching the range (min, max_count].  */
  while (min + 1 < max_count)
    {
      asymbol *sym;

      thisplace = (max_count + min) / 2;
      sym = sorted_syms[thisplace];

      if (bfd_asymbol_value (sym) > vma)
	max_count = thisplace;
      else if (bfd_asymbol_value (sym) < vma)
	min = thisplace;
      else
	{
	  min = thisplace;
	  break;
	}
    }

  /* The symbol we want is now in min, the low end of the range we
     were searching.  If there are several symbols with the same
     value, we want the first one.  */
  thisplace = min;
  while (thisplace > 0
	 && (bfd_asymbol_value (sorted_syms[thisplace])
	     == bfd_asymbol_value (sorted_syms[thisplace - 1])))
    --thisplace;

  /* Prefer a symbol in the current section if we have multple symbols
     with the same value, as can occur with overlays or zero size
     sections.  */
  min = thisplace;
  while (min < max_count
	 && (bfd_asymbol_value (sorted_syms[min])
	     == bfd_asymbol_value (sorted_syms[thisplace])))
    {
      if (sym_ok (true, abfd, min, sec, inf))
	{
	  thisplace = min;

	  if (place != NULL)
	    *place = thisplace;

	  return sorted_syms[thisplace];
	}
      ++min;
    }

  /* If the file is relocatable, and the symbol could be from this
     section, prefer a symbol from this section over symbols from
     others, even if the other symbol's value might be closer.

     Note that this may be wrong for some symbol references if the
     sections have overlapping memory ranges, but in that case there's
     no way to tell what's desired without looking at the relocation
     table.

     Also give the target a chance to reject symbols.  */
  want_section = (aux->require_sec
		  || ((abfd->flags & HAS_RELOC) != 0
		      && vma >= bfd_section_vma (sec)
		      && vma < (bfd_section_vma (sec)
				+ bfd_section_size (sec) / opb)));

  if (! sym_ok (want_section, abfd, thisplace, sec, inf))
    {
      long i;
      long newplace = sorted_symcount;

      for (i = min - 1; i >= 0; i--)
	{
	  if (sym_ok (want_section, abfd, i, sec, inf))
	    {
	      if (newplace == sorted_symcount)
		newplace = i;

	      if (bfd_asymbol_value (sorted_syms[i])
		  != bfd_asymbol_value (sorted_syms[newplace]))
		break;

	      /* Remember this symbol and keep searching until we reach
		 an earlier address.  */
	      newplace = i;
	    }
	}

      if (newplace != sorted_symcount)
	thisplace = newplace;
      else
	{
	  /* We didn't find a good symbol with a smaller value.
	     Look for one with a larger value.  */
	  for (i = thisplace + 1; i < sorted_symcount; i++)
	    {
	      if (sym_ok (want_section, abfd, i, sec, inf))
		{
		  thisplace = i;
		  break;
		}
	    }
	}

      if (! sym_ok (want_section, abfd, thisplace, sec, inf))
	/* There is no suitable symbol.  */
	return NULL;
    }

  /* If we have not found an exact match for the specified address
     and we have dynamic relocations available, then we can produce
     a better result by matching a relocation to the address and
     using the symbol associated with that relocation.  */
  rel_count = inf->dynrelcount;
  if (!want_section
      && sorted_syms[thisplace]->value != vma
      && rel_count > 0
      && inf->dynrelbuf != NULL
      && inf->dynrelbuf[0]->address <= vma
      && inf->dynrelbuf[rel_count - 1]->address >= vma
      /* If we have matched a synthetic symbol, then stick with that.  */
      && (sorted_syms[thisplace]->flags & BSF_SYNTHETIC) == 0)
    {
      arelent **  rel_low;
      arelent **  rel_high;

      rel_low = inf->dynrelbuf;
      rel_high = rel_low + rel_count - 1;
      while (rel_low <= rel_high)
	{
	  arelent **rel_mid = &rel_low[(rel_high - rel_low) / 2];
	  arelent * rel = *rel_mid;

	  if (rel->address == vma)
	    {
	      /* Absolute relocations do not provide a more helpful
		 symbolic address.  Find a non-absolute relocation
		 with the same address.  */
	      arelent **rel_vma = rel_mid;
	      for (rel_mid--;
		   rel_mid >= rel_low && rel_mid[0]->address == vma;
		   rel_mid--)
		rel_vma = rel_mid;

	      for (; rel_vma <= rel_high && rel_vma[0]->address == vma;
		   rel_vma++)
		{
		  rel = *rel_vma;
		  if (rel->sym_ptr_ptr != NULL
		      && ! bfd_is_abs_section ((* rel->sym_ptr_ptr)->section))
		    {
		      if (place != NULL)
			* place = thisplace;
		      return * rel->sym_ptr_ptr;
		    }
		}
	      break;
	    }

	  if (vma < rel->address)
	    rel_high = rel_mid;
	  else if (vma >= rel_mid[1]->address)
	    rel_low = rel_mid + 1;
	  else
	    break;
	}
    }

  if (place != NULL)
    *place = thisplace;

  return sorted_syms[thisplace];
}

/* Print an address (VMA) to the output stream in INFO.
   If SKIP_ZEROES is TRUE, omit leading zeroes.  */

static void
objdump_print_value (bfd *abfd, bfd_vma vma, struct disassemble_info *inf,
		     bool skip_zeroes)
{
  char buf[30];
  char *p;

  bfd_sprintf_vma (abfd, buf, vma);
  if (! skip_zeroes)
    p = buf;
  else
    {
      for (p = buf; *p == '0'; ++p)
	;
      if (*p == '\0')
	--p;
    }
  printf("%s", p);
}

/* Print the name of a symbol.  */

static void
objdump_print_symname (bfd *abfd, struct disassemble_info *inf,
		       asymbol *sym)
{
  char *alloc;
  const char *name, *version_string = NULL;
  bool hidden = false;

  alloc = NULL;
  name = bfd_asymbol_name (sym);
  if (do_demangle && name[0] != '\0')
    {
      /* Demangle the name.  */
      alloc = bfd_demangle (abfd, name, demangle_flags);
      if (alloc != NULL)
	name = alloc;
    }

  if ((sym->flags & (BSF_SECTION_SYM | BSF_SYNTHETIC)) == 0)
    version_string = bfd_get_symbol_version_string (abfd, sym, true,
						    &hidden);

  if (bfd_is_und_section (bfd_asymbol_section (sym)))
    hidden = true;

//  name = sanitize_string (name);

  if (inf != NULL)
    {
		printf("%s", name);
      if (version_string && *version_string != '\0')
		printf(hidden ? "@%s" : "@@%s", version_string);
    }
  else
    {
      printf ("%s", name);
      if (version_string && *version_string != '\0')
	printf (hidden ? "@%s" : "@@%s", version_string);
    }

  if (alloc != NULL)
    free (alloc);
}

static void
objdump_print_addr_with_sym(bfd *abfd, asection *sec, asymbol *sym,
	bfd_vma vma, struct disassemble_info *inf, bool skip_zeroes)
{
	objdump_print_value(abfd, vma, inf, skip_zeroes);

	if (sym == NULL) {
		bfd_vma secaddr;

		printf("<%s", bfd_section_name(sec));

		secaddr = bfd_section_vma(sec);

		if (vma < secaddr) {
			objdump_print_value(abfd, secaddr - vma, inf, true);
		} else if (vma > secaddr) {
			objdump_print_value(abfd, vma - secaddr, inf, true);
		} else
			printf(">");
	} else {
		printf("<");

		objdump_print_symname(abfd, inf, sym);

		if (bfd_asymbol_value(sym) == vma)
			;
		else if ((bfd_get_file_flags(abfd) & (EXEC_P | DYNAMIC))
			&& bfd_is_und_section(sym->section))
			;
		else if (bfd_asymbol_value(sym) > vma) {
			objdump_print_value(abfd, bfd_asymbol_value(sym) - vma, inf, true);
		} else if (vma > bfd_asymbol_value(sym)) {
			objdump_print_value(abfd, vma - bfd_asymbol_value(sym), inf, true);
		}

		printf(">\n");
	}
}

static int
compare_symbols(const void *ap, const void *bp)
{
	const asymbol *a = (const asymbol *)ap;
	const asymbol *b = (const asymbol *)bp;

	if (bfd_asymbol_value(a) > bfd_asymbol_value(b))
		return 1;
	else if (bfd_asymbol_value(a) < bfd_asymbol_value(b))
		return -1;
	else
		return 0;

	// TODO
}

static void
disassemble_section(bfd *abfd, asection *section, void *inf)
{
	bfd_vma sign_adjust = 0;
	struct disassemble_info *pinfo = (struct disassemble_info *) inf;
	unsigned long addr_offset;
	bfd_size_type datasize = 0;
	unsigned int opb = pinfo->octets_per_byte;
	bfd_byte *data = NULL;
	bfd_vma stop_offset;
	asymbol *sym = NULL;
	long place = 0;

	datasize = bfd_section_size(section);
	if (datasize == 0)
		return;

	if (start_address == (bfd_vma)-1
		|| start_address < section->vma)
		addr_offset = 0;
	else
		addr_offset = start_address - section->vma;

	if (stop_address == (bfd_vma)-1)
		stop_offset = datasize / opb;

	if (addr_offset >= stop_offset)
		return;

	if (!bfd_malloc_and_get_section(abfd, section, &data)) {
		fprintf(stderr, "Reading seciton %s failed because: %s\n",
			section->name, bfd_errmsg(bfd_get_error()));
	}

	pinfo->buffer = data;
	pinfo->buffer_vma = section->vma;
	pinfo->buffer_length = datasize;
	pinfo->section = section;

	if (sorted_symcount > 1)
		qsort(sorted_syms, sorted_symcount, sizeof(asymbol *),
			compare_symbols);

	sym = (asymbol *) find_symbol_for_address(section->vma + addr_offset,
							(struct disassemble_info *)inf, &place);

	while (addr_offset < stop_offset) {
		bfd_vma addr;
		asymbol *nextsym;
		bfd_vma nextstop_offset;

		addr = section->vma + addr_offset;
		addr = ((addr & ((sign_adjust << 1) - 1)) ^ sign_adjust) - sign_adjust;

		if (sym != NULL && bfd_asymbol_value(sym) < addr) {
			int x;
			for (x = place;
				(x < sorted_symcount &&
					(bfd_asymbol_value(sorted_syms[x]) <= addr));
				++x)
				continue;

			pinfo->symbols = sorted_syms + place;
			pinfo->num_symbols = x - place;
			pinfo->symtab_pos = place;

		} else {
			pinfo->symbols = NULL;
			pinfo->num_symbols = 0;
			pinfo->symtab_pos = -1;
		}

		objdump_print_addr_with_sym(abfd, section, sym, addr, pinfo, false);

		if (sym != NULL) {
			for (++place; place < sorted_symcount; place++) {
				sym = sorted_syms[place];
				if (bfd_asymbol_value(sym) != addr)
					break;
				if (pinfo->symbol_is_valid(sym, pinfo))
					continue;
				if (strcmp(bfd_section_name(sym->section),
						bfd_section_name(section)) != 0)
					break;

				objdump_print_addr_with_sym(abfd, section, sym, addr, pinfo,
					false);
			}
		}

		if (sym != NULL && bfd_asymbol_value(sym) > addr)
			nextsym = sym;
		else if (sym == NULL)
			nextsym = NULL;
		else {
#define is_valid_next_sym(SYM) \
  (strcmp (bfd_section_name ((SYM)->section), bfd_section_name (section)) == 0 \
   && (bfd_asymbol_value (SYM) > bfd_asymbol_value (sym)) \
   && pinfo->symbol_is_valid (SYM, pinfo))

			while (place < sorted_symcount
				&& !is_valid_next_sym(sorted_syms[place]))
				++place;

			if (place >= sorted_symcount)
				nextsym = NULL;
			else
				nextsym = sorted_syms[place];
		}

		if (sym != NULL && bfd_asymbol_value(sym) > addr)
			nextstop_offset = bfd_asymbol_value(sym) - section->vma;
		else if (nextsym == NULL)
			nextstop_offset = stop_offset;
		else
			nextstop_offset = bfd_asymbol_value(nextsym) - section->vma;

		if (nextstop_offset > stop_offset
			|| nextstop_offset <= addr_offset)
			nextstop_offset = stop_offset;

		if (abfd && sym && sym->name) {
			/* TODO: Do Print */
		}
		
		addr_offset = nextstop_offset;
		sym = nextsym;
	}

	free(data);
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

