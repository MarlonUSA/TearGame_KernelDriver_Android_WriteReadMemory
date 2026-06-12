/**
 * USA Kernel Driver — Hook Edition
 * 通过自定义 syscall 号通信, 无设备文件/proc/任何文件痕迹
 *
 * 原理:
 *   1. 用 kprobe 找到 kallsyms_lookup_name
 *   2. 用 kallsyms 找到 sys_call_table
 *   3. 在未使用的 syscall 号 (600) 注册我们的处理函数
 *   4. 用户态直接 syscall(600, cmd, arg) 通信
 *   5. 反作弊完全看不到——没有 /dev, /proc, /sys 任何痕迹
 *
 * 用户态调用方式:
 *   syscall(600, OP_READ_MEM, &cm);
 *   syscall(600, OP_WRITE_MEM, &cm);
 *   syscall(600, OP_MODULE_BASE, &mb);
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <asm/unistd.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

/* 自定义 syscall 号 (选一个不会被用到的大号) */
#define USA_SYSCALL_NR 600

/* 魔数验证 (防止误触发) */
#define USA_MAGIC 0x55534100  /* "USA\0" */

MODULE_LICENSE("GPL");

/* =====================================================================
 * kallsyms_lookup_name 获取 (kprobe 方式)
 * ===================================================================== */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln_func = NULL;

static int resolve_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    kln_func = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return kln_func ? 0 : -EFAULT;
}

/* =====================================================================
 * sys_call_table 操作
 * ===================================================================== */

static void **sys_call_table = NULL;
static void *original_syscall = NULL;

/*
 * ARM64 上修改 sys_call_table 的正确方式:
 * 直接遍历页表找到 PTE，翻转写保护位
 * 参考: github.com/memory1337/syscall_hook_forlinux
 */

static pte_t *pte_from_addr(unsigned long addr)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;
    struct mm_struct *mm;

    mm = (struct mm_struct *)kln_func("init_mm");
    if (!mm) return NULL;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    {
        p4d_t *p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
        pud = pud_offset(p4d, addr);
    }
#else
    pud = pud_offset(pgd, addr);
#endif
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep || pte_none(*ptep)) return NULL;

    return ptep;
}

static void make_addr_rw(unsigned long addr)
{
    pte_t *ptep = pte_from_addr(addr);
    if (ptep) {
        *ptep = pte_mkwrite(pte_mkdirty(*ptep));
        /* 清除 PTE_RDONLY bit (bit 7 on ARM64) */
        *ptep = clear_pte_bit(*ptep, __pgprot(PTE_RDONLY));
        flush_tlb_all();
    }
}

static void make_addr_ro(unsigned long addr)
{
    pte_t *ptep = pte_from_addr(addr);
    if (ptep) {
        *ptep = pte_wrprotect(*ptep);
        flush_tlb_all();
    }
}

/* =====================================================================
 * 自定义 syscall 处理函数
 *
 * 用户态调用: syscall(600, magic, cmd, arg)
 *   magic = 0x55534100 (验证是我们的请求)
 *   cmd   = OP_READ_MEM / OP_WRITE_MEM / OP_MODULE_BASE
 *   arg   = 指向参数结构体的指针
 * ===================================================================== */

static long usa_syscall_handler(unsigned long magic, unsigned long cmd,
                                unsigned long arg, unsigned long unused1,
                                unsigned long unused2, unsigned long unused3)
{
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100] = {0};

    /* 魔数验证 */
    if (magic != USA_MAGIC) {
        /* 不是我们的请求, 调用原始 syscall (如果有的话) */
        if (original_syscall) {
            typedef long (*syscall_fn_t)(unsigned long, unsigned long,
                                        unsigned long, unsigned long,
                                        unsigned long, unsigned long);
            return ((syscall_fn_t)original_syscall)(magic, cmd, arg,
                                                   unused1, unused2, unused3);
        }
        return -ENOSYS;
    }

    switch (cmd) {
    case OP_READ_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        return 0;

    case OP_WRITE_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        return 0;

    case OP_MODULE_BASE:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        if (copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1))
            return -EFAULT;
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        return 0;

    default:
        return -EINVAL;
    }
}

/* =====================================================================
 * 隐藏功能 (与 dev 版相同)
 * ===================================================================== */

static struct list_head *saved_prev = NULL;
static int hidden = 0;

static void hide_module(void)
{
    if (hidden) return;
    saved_prev = THIS_MODULE->list.prev;
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    hidden = 1;
}

static void unhide_module(void)
{
    if (!hidden || !saved_prev) return;
    list_add(&THIS_MODULE->list, saved_prev);
    hidden = 0;
}

/* =====================================================================
 * 模块初始化 / 卸载
 * ===================================================================== */

static int __init driver_entry(void)
{
    int ret;

    /* 1. 获取 kallsyms_lookup_name */
    ret = resolve_kallsyms();
    if (ret) return ret;

    /* 2. 找到 sys_call_table */
    sys_call_table = (void **)kln_func("sys_call_table");
    if (!sys_call_table) return -ENOENT;

    /* 3. 保存原始 syscall 600，翻转 PTE 写保护，替换 */
    original_syscall = sys_call_table[USA_SYSCALL_NR];
    make_addr_rw((unsigned long)&sys_call_table[USA_SYSCALL_NR]);
    sys_call_table[USA_SYSCALL_NR] = (void *)usa_syscall_handler;
    make_addr_ro((unsigned long)&sys_call_table[USA_SYSCALL_NR]);

    /* 4. 隐藏模块 */
    hide_module();

    /* 零日志 */
    return 0;
}

static void __exit driver_unload(void)
{
    /* 恢复原始 syscall */
    if (sys_call_table && original_syscall) {
        make_addr_rw((unsigned long)&sys_call_table[USA_SYSCALL_NR]);
        sys_call_table[USA_SYSCALL_NR] = original_syscall;
        make_addr_ro((unsigned long)&sys_call_table[USA_SYSCALL_NR]);
    }

    /* 恢复模块链表 */
    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
