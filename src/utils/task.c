#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "log.h"
#include "task.h"

LIST_HEAD(tasks_list);

int open_pid_maps(pid_t pid)
{
	int ret;
	char maps[] = "/proc/1234567890/maps";

	snprintf(maps, sizeof(maps), "/proc/%d/maps", pid);
	ret = open(maps, O_RDONLY);
	if (ret <= 0) {
		lerror("open %s failed. %s\n", maps, strerror(errno));
		ret = -errno;
	}
	return ret;
}

int open_pid_mem(pid_t pid)
{
	char mem[] = "/proc/1234567890/mem";
	snprintf(mem, sizeof(mem), "/proc/%d/mem", pid);
	int memfd = open(mem, O_RDWR);
	if (memfd <= 0) {
		lerror("open %s failed. %s\n", mem, strerror(errno));
	}
	return memfd;
}

struct vma_struct *alloc_vma()
{
	struct vma_struct *vma = malloc(sizeof(struct vma_struct));
	assert(vma && "alloc vma failed.");
	memset(vma, 0x00, sizeof(struct vma_struct));

	vma->type = VMA_NONE;

	list_init(&vma->node);

	return vma;
}

int insert_vma(struct task *task, struct vma_struct *vma)
{
	list_add(&vma->node, &task->vmas);
	return 0;
}

int free_vma(struct vma_struct *vma)
{
	if (!vma)
		return -1;

	free(vma);
	return 0;
}

static unsigned int __perms2prot(char *perms)
{
	unsigned int prot = 0;

	if (perms[0] == 'r')
		prot |= PROT_READ;
	if (perms[1] == 'w')
		prot |= PROT_WRITE;
	if (perms[2] == 'x')
		prot |= PROT_EXEC;
	/* Ignore 'p'/'s' flag, we don't need it */
	return prot;
}

static int read_task_vmas(struct task *task)
{
	FILE *mapsfp;
	struct vma_struct *vma;

	lseek(task->proc_maps_fd, 0, SEEK_SET);
	mapsfp = fdopen(task->proc_maps_fd, "r");
	fseek(mapsfp, 0, SEEK_SET);
	do {
		unsigned long start, end, offset;
		unsigned int maj, min, inode;
		char perms[5], name_[256];
		int r;
		char line[1024];

		if (!fgets(line, sizeof(line), mapsfp))
			break;

		r = sscanf(line, "%lx-%lx %s %lx %x:%x %d %255s",
				&start, &end, perms, &offset,
				&maj, &min, &inode, name_);
		if (r <= 0) {
			lerror("sscanf failed.\n");
			return -1;
		}

		vma = alloc_vma();

		vma->start = start;
		vma->end = end;
		memcpy(vma->perms, perms, sizeof(vma->perms));
		vma->prot = __perms2prot(perms);
		vma->offset = offset;
		vma->maj = maj;
		vma->min = min;
		vma->inode = inode;
		strncpy(vma->name_, name_, sizeof(vma->name_));
		vma->type = get_vma_type(task->comm, name_);

		insert_vma(task, vma);
	} while (1);

	fclose(mapsfp);

	return 0;
}

void print_vma(struct vma_struct *vma)
{
	if (!vma) {
		lerror("Invalide pointer.\n");
		return;
	}
	printf("%10s: %016lx-%016lx %6s %8lx %4x:%4x %8d %s\n",
			VMA_TYPE_NAME(vma->type),
			vma->start, vma->end, vma->perms, vma->offset,
			vma->maj, vma->min, vma->inode, vma->name_);
}

void dump_task_vmas(struct task *task)
{
	struct vma_struct *vma;

	list_for_each_entry(vma, &task->vmas, node) {
		print_vma(vma);
	}
}

static int free_task_vmas(struct task *task)
{
	struct vma_struct *vma, *tmpvma;

	list_for_each_entry_safe(vma, tmpvma, &task->vmas, node) {
		list_del(&vma->node);
		free_vma(vma);
	}

	return 0;
}

static int __get_comm(struct task *task)
{
	char path[128], realpath[128];
	ssize_t ret;

	snprintf(path, sizeof(path), "/proc/%d/exe", task->pid);
	ret = readlink(path, realpath, sizeof(realpath));
	if (ret < 0) {
		lerror("readlink %s failed, %s\n", path, strerror(errno));
		return -errno;
	}
	realpath[ret] = '\0';
	task->comm = strdup(realpath);

	return 0;
}

struct task *open_task(pid_t pid)
{
	struct task *task = NULL;
	int memfd, mapsfd;

	memfd = open_pid_mem(pid);
	if (memfd <= 0) {
		return NULL;
	}

	mapsfd = open_pid_maps(pid);
	if (mapsfd <= 0) {
		return NULL;
	}

	task = malloc(sizeof(struct task));
	assert(task && "malloc failed");

	list_init(&task->vmas);

	task->pid = pid;
	__get_comm(task);
	task->proc_mem_fd = memfd;
	task->proc_maps_fd = mapsfd;
	lseek(mapsfd, 0, SEEK_SET);

	read_task_vmas(task);

	list_add(&task->node, &tasks_list);

	return task;
}

int free_task(struct task *task)
{
	list_del(&task->node);
	close(task->proc_mem_fd);
	close(task->proc_maps_fd);

	free_task_vmas(task);
	free(task->comm);

	free(task);

	return 0;
}

