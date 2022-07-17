#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/wait.h>

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

static inline int __vma_rb_cmp(struct rb_node *node, unsigned long key)
{
	struct vma_struct *vma = rb_entry(node, struct vma_struct, node_rb);
	struct vma_struct *new = (struct vma_struct *)key;

	if (new->end <= vma->start)
		return -1;
	else if (vma->start < new->end && vma->end > new->start)
		return 0;
	else if (vma->end <= new->start)
		return 1;

	assert(0 && "Try insert illegal vma.");
	return 0;
}

int insert_vma(struct task *task, struct vma_struct *vma)
{
	list_add(&vma->node, &task->vmas);
	rb_insert_node(&task->vmas_rb, &vma->node_rb,
		__vma_rb_cmp, (unsigned long)vma);
	return 0;
}

int unlink_vma(struct task *task, struct vma_struct *vma)
{
	list_del(&vma->node);
	rb_erase(&vma->node_rb, &task->vmas_rb);
	return 0;
}

int free_vma(struct vma_struct *vma)
{
	if (!vma)
		return -1;

	free(vma);
	return 0;
}

static inline int __find_vma_cmp(struct rb_node *node, unsigned long vaddr)
{
	struct vma_struct *vma = rb_entry(node, struct vma_struct, node_rb);

	if (vma->start > vaddr)
		return -1;
	else if (vma->start <= vaddr && vma->end > vaddr)
		return 0;
	else
		return 1;
}

struct vma_struct *find_vma(struct task *task, unsigned long vaddr)
{
	struct rb_node * rnode =
		rb_search_node(&task->vmas_rb, __find_vma_cmp, vaddr);
	if (rnode) {
		return rb_entry(rnode, struct vma_struct, node_rb);
	}
	return NULL;
}

struct vma_struct *next_vma(struct task *task, struct vma_struct *prev)
{
	struct rb_node *next;

	next = prev?rb_next(&prev->node_rb):rb_first(&task->vmas_rb);

	return  next?rb_entry(next, struct vma_struct, node_rb):NULL;
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
		unlink_vma(task, vma);
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
	rb_init(&task->vmas_rb);

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

int task_attach(pid_t pid)
{
	int ret;
	int status;

	ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (ret != 0) {
		lerror("Attach %d failed. %s\n", pid, strerror(errno));
		return -errno;
	}
	do {
		ret = waitpid(pid, &status, __WALL);
		if (ret < 0) {
			lerror("can't wait for pid %d\n", pid);
			return -errno;
		}
		ret = 0;

		/* We are expecting SIGSTOP */
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)
			break;

		/* If we got SIGTRAP because we just got out of execve, wait
		 * for the SIGSTOP
		 */
		if (WIFSTOPPED(status))
			status = (WSTOPSIG(status) == SIGTRAP) ? 0 : WSTOPSIG(status);
		else if (WIFSIGNALED(status))
			/* Resend signal */
			status = WTERMSIG(status);

		ret = ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)status);
		if (ret < 0) {
			lerror("can't cont tracee\n");
			return -errno;
		}
	} while (1);

	return ret;
}

int task_detach(pid_t pid)
{
	long rv;
	rv = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (rv != 0) {
		lerror("Detach %d failed. %s\n", pid, strerror(errno));
		return -errno;
	}

	return rv;
}

