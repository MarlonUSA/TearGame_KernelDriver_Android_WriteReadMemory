/**
 * USA Kernel Driver — Hook Edition v6
 *
 * 通信方式: hook sys_getpid (syscall 172)
 *   - 正常调用 getpid → 返回 PID (原始行为)
 *   - 调用 getpid 且 x1=魔数 → 执行内存读写命令
 *   - sys_call_table 被修改但用的是常见 syscall, 不起疑
 *   - 参考: Skjh 驱动的通信方式
 *
 * 页表修改: 直接翻转 PTE 写保护位 (ARM64)
 *   - 参考: github.com/memory1337/syscall_hook_forlinux
 *
 * 用户态调用:
 *   syscall(__NR_getpid, USA_MAGIC, OP_READ_MEM, &cm);
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <asm/unistd.h>
#include <linux/uaccess.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

/* hook getpid (ARM64 syscall 172) — 和 Skjh 一样 */
#define USA_HOOK_NR __NR_getpid

#define USA_MAGIC 0x55534100

MODULE_LICENSE("GPL");

/* =====================================================================
 * kallsyms (kprobe 方式)
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
 * PTE 页表操作 (ARM64)
 * 参考: github.com/memory1337/syscall_hook_forlinux/set_page_flags.h
 * ===================================================================== */

static void **sys_call_table = NULL;
static void *orig_getpid = NULL;

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

static void make_rw(unsigned long addr)
{
    pte_t *ptep = pte_from_addr(addr);
    if (ptep) {
        *ptep = pte_mkwrite(pte_mkdirty(*ptep));
        *ptep = clear_pte_bit(*ptep, __pgprot(PTE_RDONLY));
        flush_tlb_all();
    }
}

static void make_ro(unsigned long addr)
{
    pte_t *ptep = pte_from_addr(addr);
    if (ptep) {
        *ptep = pte_wrprotect(*ptep);
        flush_tlb_all();
    }
}

/* =====================================================================
 * Hook getpid 处理函数
 *
 * ARM64 syscall 签名: long sys_xxx(struct pt_regs *regs)
 * regs->regs[0] = arg0 (x0), regs->regs[1] = arg1 (x1), ...
 *
 * 正常 getpid: 无参数, 返回 PID
 * 我们的协议: 如果 x0 == USA_MAGIC, 则 x1=cmd, x2=arg
 * ===================================================================== */

typedef long (*syscall_fn_t)(const struct pt_regs *);

static long usa_hooked_getpid(const struct pt_regs *regs)
{
    unsigned long magic = regs->regs[0];
    unsigned long cmd   = regs->regs[1];
    unsigned long arg   = regs->regs[2];

    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100] = {0};

    /* 不是我们的请求 → 调原始 getpid */
    if (magic != USA_MAGIC)
        return ((syscall_fn_t)orig_getpid)(regs);

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
        return ((syscall_fn_t)orig_getpid)(regs);
    }
}

/* =====================================================================
 * 隐藏
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
 * 初始化 / 卸载
 * ===================================================================== */

static int __init driver_entry(void)
{
    int ret;

    ret = resolve_kallsyms();
    if (ret) return ret;

    sys_call_table = (void **)kln_func("sys_call_table");
    if (!sys_call_table) return -ENOENT;

    /* 保存原始 getpid, PTE 翻转, 替换 */
    orig_getpid = sys_call_table[USA_HOOK_NR];
    make_rw((unsigned long)&sys_call_table[USA_HOOK_NR]);
    sys_call_table[USA_HOOK_NR] = (void *)usa_hooked_getpid;
    make_ro((unsigned long)&sys_call_table[USA_HOOK_NR]);

    hide_module();
    return 0;
}

static void __exit driver_unload(void)
{
    if (sys_call_table && orig_getpid) {
        make_rw((unsigned long)&sys_call_table[USA_HOOK_NR]);
        sys_call_table[USA_HOOK_NR] = orig_getpid;
        make_ro((unsigned long)&sys_call_table[USA_HOOK_NR]);
    }
    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
