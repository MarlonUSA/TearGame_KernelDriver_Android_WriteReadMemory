/**
 * USA Kernel Driver — Hook Edition v7
 *
 * hook getpid + aarch64_insn_patch_text_nosync 写 sys_call_table
 * 参考: SKJH Feng驱动 (set_page_exec_nolock + my_aarch64_insn_patch_text)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

#define USA_HOOK_NR __NR_getpid
#define USA_MAGIC   0x55534100

MODULE_LICENSE("GPL");

/* =====================================================================
 * kallsyms (kprobe)
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
 * 安全写 sys_call_table (ARM64)
 *
 * 用 aarch64_insn_patch_text_nosync:
 *   - 内核自己 patch 代码/数据用的函数
 *   - 使用 fixmap 映射物理页，完全绕过页表权限
 *   - 正确处理 cache coherency
 *   - 参考: SKJH Feng驱动
 * ===================================================================== */

static void **sys_call_table = NULL;
static void *orig_getpid = NULL;

typedef int (*insn_patch_fn_t)(void *addr, u32 insn);
static insn_patch_fn_t my_patch_text = NULL;

static void write_syscall_entry(int nr, void *handler)
{
    unsigned long val = (unsigned long)handler;
    u32 lo = (u32)(val & 0xFFFFFFFF);
    u32 hi = (u32)(val >> 32);

    if (my_patch_text) {
        my_patch_text(&sys_call_table[nr], lo);
        my_patch_text((void *)((unsigned long)&sys_call_table[nr] + 4), hi);
    }
}

/* =====================================================================
 * Hook getpid 处理
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

    /* aarch64_insn_patch_text_nosync: 内核用 fixmap 安全写只读内存 */
    my_patch_text = (insn_patch_fn_t)kln_func("aarch64_insn_patch_text_nosync");
    if (!my_patch_text) return -ENOENT;

    sys_call_table = (void **)kln_func("sys_call_table");
    if (!sys_call_table) return -ENOENT;

    orig_getpid = sys_call_table[USA_HOOK_NR];
    write_syscall_entry(USA_HOOK_NR, (void *)usa_hooked_getpid);

    hide_module();
    return 0;
}

static void __exit driver_unload(void)
{
    if (sys_call_table && orig_getpid)
        write_syscall_entry(USA_HOOK_NR, orig_getpid);
    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
