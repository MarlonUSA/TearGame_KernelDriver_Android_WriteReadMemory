/*
 * process.c — 无锁 get_module_base (kprobe 原子上下文安全)
 *
 * 不加 mmap_read_lock, 用 RCU 保护遍历 VMA
 */

#include "process.h"
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/dcache.h>

uintptr_t get_module_base(pid_t pid, char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    unsigned long addr;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return 0;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return 0; }

    /* 无锁遍历: 用 find_vma 逐段查找 */
    addr = 0;
    while ((vma = find_vma(mm, addr)) != NULL) {
        addr = vma->vm_end;
        if (vma->vm_file) {
            char buf[256];
            char *path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf) - 1);
            if (!IS_ERR(path_nm)) {
                const char *basename = kbasename(path_nm);
                if (strcmp(basename, name) == 0) {
                    base_addr = vma->vm_start;
                    break;
                }
            }
        }
    }

    put_task_struct(task);
    return base_addr;
}

/* Shoot 必须 trap 真代码段, 不是 r--p data 段 (base+0x1000 经常落在 readonly data).
 * 遍历找该 lib 的第一个 r-xp 段. */
uintptr_t get_module_code_seg(pid_t pid, char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t code_seg = 0;
    unsigned long addr;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return 0;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return 0;
    mm = task->mm;
    if (!mm) { put_task_struct(task); return 0; }

    addr = 0;
    while ((vma = find_vma(mm, addr)) != NULL) {
        addr = vma->vm_end;
        if (vma->vm_file && (vma->vm_flags & VM_EXEC) && (vma->vm_flags & VM_READ)) {
            char buf[256];
            char *path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf) - 1);
            if (!IS_ERR(path_nm)) {
                const char *basename = kbasename(path_nm);
                if (strcmp(basename, name) == 0) {
                    code_seg = vma->vm_start;
                    break;
                }
            }
        }
    }

    put_task_struct(task);
    return code_seg;
}
