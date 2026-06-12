/*
 * memory.c — 无锁页表遍历读写 (kprobe 原子上下文安全)
 *
 * 不用 access_process_vm (需要 mmap_lock 睡眠锁)
 * 直接遍历页表 + kmap_atomic 访问物理页
 */

#include "memory.h"
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/pgtable.h>

static struct task_struct *find_task(pid_t pid)
{
    struct pid *pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) return NULL;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    return task;
}

static struct page *vaddr_to_page(struct mm_struct *mm, uintptr_t vaddr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep, pte;

    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) return NULL;

    if (pmd_trans_huge(*pmd))
        return pmd_page(*pmd) + ((vaddr & ~PMD_MASK) >> PAGE_SHIFT);

    if (pmd_bad(*pmd)) return NULL;

    ptep = pte_offset_kernel(pmd, vaddr);
    if (!ptep) return NULL;

    pte = *ptep;
    if (!pte_present(pte)) return NULL;

    return pte_page(pte);
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    size_t done = 0;

    if (size == 0 || size > (1024 * 1024)) return false;

    task = find_task(pid);
    if (!task) return false;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return false; }

    while (done < size) {
        struct page *page;
        void *kaddr;
        size_t offset = (addr + done) & ~PAGE_MASK;
        size_t chunk = min(size - done, (size_t)(PAGE_SIZE - offset));

        page = vaddr_to_page(mm, addr + done);
        if (!page) break;

        kaddr = kmap_atomic(page);
        memcpy((char *)buffer + done, kaddr + offset, chunk);
        kunmap_atomic(kaddr);
        done += chunk;
    }

    put_task_struct(task);
    return done == size;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    size_t done = 0;

    if (size == 0 || size > (1024 * 1024)) return false;

    task = find_task(pid);
    if (!task) return false;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return false; }

    while (done < size) {
        struct page *page;
        void *kaddr;
        size_t offset = (addr + done) & ~PAGE_MASK;
        size_t chunk = min(size - done, (size_t)(PAGE_SIZE - offset));

        page = vaddr_to_page(mm, addr + done);
        if (!page) break;

        kaddr = kmap_atomic(page);
        memcpy(kaddr + offset, (char *)buffer + done, chunk);
        kunmap_atomic(kaddr);
        flush_dcache_page(page);
        done += chunk;
    }

    put_task_struct(task);
    return done == size;
}
