#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "proc.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

uint64 sys_gettimeofday(TimeVal *val, int _tz)
{
	TimeVal time;
	struct proc *p = curr_proc();

	uint64 cycle = get_cycle();
	time.sec = cycle / CPU_FREQ;
	time.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;

	int ret = copyout(p->pagetable, (uint64)val, (char *)&time,
			  sizeof(TimeVal));
	if (ret < 0)
		return -1;

	return 0;
}

uint64 sys_sbrk(int n)
{
	uint64 addr;
	struct proc *p = curr_proc();
	addr = p->program_brk;
	if (growproc(n) < 0)
		return -1;
	return addr;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/

uint64 sys_task_info(struct TaskInfo *ti)
{
	struct TaskInfo info;
	struct proc *proc_r = curr_proc();
	info.status = Running;

	uint64 now = get_cycle() * 1000 / CPU_FREQ;
	uint64 before = proc_r->start_time * 1000 / CPU_FREQ;

	info.time = now - before;

	for (uint64 i = 0; i < MAX_SYSCALL_NUM; ++i) {
		info.syscall_times[i] = proc_r->syscall_times[i];
	}

	int ret = copyout(proc_r->pagetable, (uint64)ti, (char *)&info,
			  sizeof(struct TaskInfo));
	if (ret < 0)
		return -1;

	return 0;
}

int sys_mmap(void *start, unsigned long long len, int port, int flag, int fd)
{
	if (len == 0)
		return 0;
	if ((port & ~0x7) != 0)
		return -1;
	if ((port & 0x7) == 0)
		return -1;
	if ((uint64)start != PGROUNDDOWN((uint64)start))
		return -1;
	int pte_flag = 0;
	if ((port & 0x1) != 0)
		pte_flag |= PTE_R;
	if ((port & 0x2) != 0)
		pte_flag |= PTE_W;
	if ((port & 0x4) != 0)
		pte_flag |= PTE_X;
	pte_flag |= (PTE_U | PTE_V);
	len = PGROUNDUP(len);
	struct proc *p = curr_proc();
	for (int i = 0; i < len / PGSIZE; i++) {
		uint64 va = (uint64)start + i * PGSIZE;
		void *pa = kalloc();
		if (pa == 0)
			return -1;
		uint64 vpa = walkaddr(p->pagetable, va);
		if (vpa != 0)
			return -1;
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, pte_flag) <
		    0) {
			panic("mappages fail");
		}
	}

	return 0;
}

int sys_munmap(void *start, unsigned long long len)
{
	if ((uint64)start != PGROUNDDOWN((uint64)start))
		return -1;
	if (len == 0)
		return 0;
	struct proc *p = curr_proc();
	len = PGROUNDUP(len);
	for (int i = 0; i < len / PGSIZE; i++) {
		uint64 va = (uint64)start + i * PGSIZE;
		uint64 vpa = useraddr(p->pagetable, va);
		if (vpa == 0)
			return -1;
		uvmunmap(p->pagetable, va, 1, 1);
	}
	return 0;
}

extern char trap_page[];

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);

	++curr_proc()->syscall_times[id];

	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday((TimeVal *)args[0], args[1]);
		break;
	case SYS_sbrk:
		ret = sys_sbrk(args[0]);
		break;

	case SYS_task_info:
		ret = sys_task_info((struct TaskInfo *)args[0]);
		break;

	case SYS_mmap:
		ret = sys_mmap((void *)args[0], (unsigned long long)args[1],
			       (int)args[2], (int)args[3], (int)args[4]);
		break;

	case SYS_munmap:
		ret = sys_munmap((void *)args[0], (unsigned long long)args[1]);
		break;

	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
