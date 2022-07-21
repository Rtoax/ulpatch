#include <stdint.h>
#include <stdio.h>
#include <libelf.h>
#include <stdbool.h>
#include <errno.h>

#include <elf/elf_api.h>
#include <utils/util.h>
#include <utils/log.h>


int handle_notes(struct elf_file *elf, GElf_Shdr *shdr, Elf_Scn *scn)
{
	Elf_Data *data = elf_getdata(scn, NULL);

	if (!data)
		goto bad_note;

#if 0

	size_t offset  = 0;
	GElf_Nhdr nhdr;
	size_t name_offset;
	size_t desc_offset;

	while (offset < data->d_size
		&& (offset = gelf_getnote))
	// TODO
#endif

	return 0;

bad_note:
	return -ENODATA;
}
