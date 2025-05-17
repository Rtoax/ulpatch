// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2022-2025 Rong Tao */
#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <elf.h>
#include <dirent.h>

#include <utils/log.h>
#include <task/task.h>


int load_task_auxv(pid_t pid, struct task_struct_auxv *pauxv)
{
	int fd, n, ret = 0;
	char buf[PATH_MAX];
	GElf_auxv_t auxv;

	memset(pauxv, 0x00, sizeof(struct task_struct_auxv));

	snprintf(buf, PATH_MAX - 1, "/proc/%d/auxv", pid);
	fd = open(buf, O_RDONLY);
	if (fd == -1) {
		ret = -errno;
		ulp_error("Open %s failed, %m\n", buf);
		goto exit;
	}

	while (true) {
		n = read(fd, &auxv, sizeof(auxv));
		if (n < sizeof(auxv))
			break;
		switch (auxv.a_type) {
		case AT_PHDR:
			pauxv->auxv_phdr = auxv.a_un.a_val;
			break;
		case AT_PHENT:
			pauxv->auxv_phent = auxv.a_un.a_val;
			break;
		case AT_PHNUM:
			pauxv->auxv_phnum = auxv.a_un.a_val;
			break;
		case AT_BASE:
			pauxv->auxv_interp = auxv.a_un.a_val;
			break;
		case AT_ENTRY:
			pauxv->auxv_entry = auxv.a_un.a_val;
			break;
		}
	}

	if (pauxv->auxv_phdr == 0) {
		ulp_error("Not found AT_PHDR in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_phent == 0) {
		ulp_error("Not found AT_PHENT in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_phnum == 0) {
		ulp_error("Not found AT_PHNUM in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_interp == 0) {
		ulp_error("Not found AT_BASE in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}
	if (pauxv->auxv_entry == 0) {
		ulp_error("Not found AT_ENTRY in %s\n", buf);
		errno = ENOENT;
		ret = -errno;
		goto close_exit;
	}

close_exit:
	close(fd);
exit:
	return ret;
}

int print_task_auxv(FILE *fp, const struct task_struct *task)
{
	const struct task_struct_auxv *pauxv;

	if (!task || !(task->fto_flag & FTO_AUXV)) {
		ulp_error("Not set FTO_AUXV.\n");
		errno = EINVAL;
		return -EINVAL;
	}

	pauxv = &task->auxv;

	if (!fp)
		fp = stdout;

	fprintf(fp, "%-8s %-16s\n", "TYPE", "VALUE");
	fprintf(fp, "%-8s %-#16lx\n", "AT_PHDR", pauxv->auxv_phdr);
	fprintf(fp, "%-8s %ld (%-#lx)\n", "AT_PHENT", pauxv->auxv_phent,
							pauxv->auxv_phent);
	fprintf(fp, "%-8s %ld (%-#lx)\n", "AT_PHNUM", pauxv->auxv_phnum,
							pauxv->auxv_phnum);
	fprintf(fp, "%-8s %-#16lx\n", "AT_BASE", pauxv->auxv_interp);
	fprintf(fp, "%-8s %-#16lx\n", "AT_ENTRY", pauxv->auxv_entry);

	return 0;
}
