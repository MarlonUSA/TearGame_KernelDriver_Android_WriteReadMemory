/*
 * memory.c — access_process_vm 版 (SKJH 路线)
 *
 * GKI 不 export access_process_vm / find_task_by_vpid, 通过 entry.c 的 kallsyms 解析后
 * 用全局指针调用.
 *
 * 必须在 process context 调用 (ioctl 路径 OK, hardirq/perf BP handler 不可调).
 */

#include "memory.h"
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>

/* 由 entry.c resolve 后填入 */
extern int (*kfn_access_process_vm)(struct task_struct *, unsigned long,
                                    void *, int, unsigned int);
extern struct task_struct *(*kfn_find_task_by_vpid)(pid_t);

static struct task_struct *find_task(pid_t pid)
{
    struct task_struct *task = NULL;
    if (!kfn_find_task_by_vpid) return NULL;
    rcu_read_lock();
    task = kfn_find_task_by_vpid(pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    return task;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    int n;

    if (size == 0 || size > (1024 * 1024)) return false;
    if (!kfn_access_process_vm) return false;

    task = find_task(pid);
    if (!task) return false;

    n = kfn_access_process_vm(task, addr, buffer, (int)size, FOLL_FORCE);

    put_task_struct(task);
    return n == (int)size;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    int n;

    if (size == 0 || size > (1024 * 1024)) return false;
    if (!kfn_access_process_vm) return false;

    task = find_task(pid);
    if (!task) return false;

    n = kfn_access_process_vm(task, addr, buffer, (int)size, FOLL_FORCE | FOLL_WRITE);

    put_task_struct(task);
    return n == (int)size;
}
