/**
 * USA Kernel Driver — Hook Edition v8
 *
 * hook getpid + aarch64_insn_patch_text_nosync 写 sys_call_table
 * v8: 加入硬件断点/看门狗 (hardware watchpoint) 支持
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#ifdef CONFIG_HAVE_HW_BREAKPOINT
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#define USA_HAS_HW_BP 1
#else
#define USA_HAS_HW_BP 0
#endif

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
 * 硬件断点 (Hardware Watchpoint) — 条件编译
 * ===================================================================== */

#if USA_HAS_HW_BP

typedef struct perf_event *(*register_user_hw_breakpoint_t)(
    struct perf_event_attr *attr,
    perf_overflow_handler_t triggered,
    void *context,
    struct task_struct *tsk);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef struct task_struct *(*find_task_by_vpid_t)(pid_t pid);

static register_user_hw_breakpoint_t  fn_register_user_hw_bp  = NULL;
static unregister_hw_breakpoint_t     fn_unregister_hw_bp     = NULL;
static find_task_by_vpid_t            fn_find_task_by_vpid    = NULL;

static struct perf_event *usa_bp_event[USA_MAX_HW_BP] = {NULL};

static struct {
    int hit;
    uintptr_t hit_addr;
    uintptr_t hit_pc;
    unsigned long regs[31];
    int hit_count;
} usa_bp_state[USA_MAX_HW_BP];

static DEFINE_SPINLOCK(bp_lock);

static void usa_bp_handler(struct perf_event *bp,
                           struct perf_sample_data *data,
                           struct pt_regs *regs)
{
    int i;
    unsigned long flags;
    spin_lock_irqsave(&bp_lock, flags);
    for (i = 0; i < USA_MAX_HW_BP; i++) {
        if (usa_bp_event[i] == bp) {
            usa_bp_state[i].hit = 1;
            usa_bp_state[i].hit_pc = regs->pc;
            usa_bp_state[i].hit_addr = bp->attr.bp_addr;
            usa_bp_state[i].hit_count++;
            if (regs->regs)
                memcpy(usa_bp_state[i].regs, regs->regs, sizeof(unsigned long) * 31);
            break;
        }
    }
    spin_unlock_irqrestore(&bp_lock, flags);
}

static int resolve_hw_bp_symbols(void)
{
    if (!kln_func) return -EFAULT;
    fn_register_user_hw_bp = (register_user_hw_breakpoint_t)kln_func("register_user_hw_breakpoint");
    fn_unregister_hw_bp = (unregister_hw_breakpoint_t)kln_func("unregister_hw_breakpoint");
    fn_find_task_by_vpid = (find_task_by_vpid_t)kln_func("find_task_by_vpid");
    return (fn_register_user_hw_bp && fn_unregister_hw_bp && fn_find_task_by_vpid) ? 0 : -ENOENT;
}

static int usa_set_hw_bp(HW_BP_REQUEST *req)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    struct perf_event *bp;
    int idx = req->index;
    if (idx < 0 || idx >= USA_MAX_HW_BP) return -EINVAL;
    if (!fn_register_user_hw_bp || !fn_find_task_by_vpid) return -ENOENT;
    if (usa_bp_event[idx]) { fn_unregister_hw_bp(usa_bp_event[idx]); usa_bp_event[idx] = NULL; }
    rcu_read_lock();
    task = fn_find_task_by_vpid(req->pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;
    hw_breakpoint_init(&attr);
    attr.bp_addr = req->addr;
    switch (req->len) {
    case 1: attr.bp_len = HW_BREAKPOINT_LEN_1; break;
    case 2: attr.bp_len = HW_BREAKPOINT_LEN_2; break;
    case 4: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
    case 8: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
    default: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
    }
    switch (req->type) {
    case USA_HW_BP_READ:  attr.bp_type = HW_BREAKPOINT_R; break;
    case USA_HW_BP_WRITE: attr.bp_type = HW_BREAKPOINT_W; break;
    case USA_HW_BP_RW:    attr.bp_type = HW_BREAKPOINT_RW; break;
    default: attr.bp_type = HW_BREAKPOINT_W; break;
    }
    bp = fn_register_user_hw_bp(&attr, usa_bp_handler, NULL, task);
    put_task_struct(task);
    if (IS_ERR(bp)) return PTR_ERR(bp);
    usa_bp_event[idx] = bp;
    memset(&usa_bp_state[idx], 0, sizeof(usa_bp_state[idx]));
    return 0;
}

static void usa_clear_hw_bp(int idx)
{
    if (idx < 0 || idx >= USA_MAX_HW_BP) return;
    if (usa_bp_event[idx]) { fn_unregister_hw_bp(usa_bp_event[idx]); usa_bp_event[idx] = NULL; memset(&usa_bp_state[idx], 0, sizeof(usa_bp_state[idx])); }
}

static void usa_clear_all_bp(void) { int i; for (i = 0; i < USA_MAX_HW_BP; i++) usa_clear_hw_bp(i); }

#else /* !USA_HAS_HW_BP */

static int resolve_hw_bp_symbols(void) { return -ENOENT; }
static int usa_set_hw_bp(HW_BP_REQUEST *req) { return -ENOSYS; }
static void usa_clear_hw_bp(int idx) { }
static void usa_clear_all_bp(void) { }

/* 空的 bp_state 用于 GET_BP_INFO */
static struct { int hit; uintptr_t hit_addr; uintptr_t hit_pc; unsigned long regs[31]; int hit_count; } usa_bp_state[USA_MAX_HW_BP];
static DEFINE_SPINLOCK(bp_lock);

#endif /* USA_HAS_HW_BP */

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
    HW_BP_REQUEST bp_req;
    HW_BP_HIT bp_hit;
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

    /* ===== 硬件断点 ===== */

    case OP_SET_HW_BP:
        if (copy_from_user(&bp_req, (void __user *)arg, sizeof(bp_req)))
            return -EFAULT;
        return usa_set_hw_bp(&bp_req);

    case OP_CLEAR_HW_BP:
        if (copy_from_user(&bp_req, (void __user *)arg, sizeof(bp_req)))
            return -EFAULT;
        usa_clear_hw_bp(bp_req.index);
        return 0;

    case OP_GET_BP_INFO: {
        int idx;
        unsigned long flags;
        if (copy_from_user(&bp_hit, (void __user *)arg, sizeof(bp_hit)))
            return -EFAULT;
        idx = bp_hit.index;
        if (idx < 0 || idx >= USA_MAX_HW_BP)
            return -EINVAL;
        spin_lock_irqsave(&bp_lock, flags);
        bp_hit.hit       = usa_bp_state[idx].hit;
        bp_hit.hit_addr  = usa_bp_state[idx].hit_addr;
        bp_hit.hit_pc    = usa_bp_state[idx].hit_pc;
        bp_hit.hit_count = usa_bp_state[idx].hit_count;
        memcpy(bp_hit.regs, usa_bp_state[idx].regs, sizeof(bp_hit.regs));
        usa_bp_state[idx].hit = 0; /* 读后清除 hit 标志 */
        spin_unlock_irqrestore(&bp_lock, flags);
        if (copy_to_user((void __user *)arg, &bp_hit, sizeof(bp_hit)))
            return -EFAULT;
        return 0;
    }

    case OP_CLEAR_ALL_BP:
        usa_clear_all_bp();
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

    my_patch_text = (insn_patch_fn_t)kln_func("aarch64_insn_patch_text_nosync");
    if (!my_patch_text) return -ENOENT;

    sys_call_table = (void **)kln_func("sys_call_table");
    if (!sys_call_table) return -ENOENT;

    /* 解析硬件断点 API (可选, 失败不阻止加载) */
    resolve_hw_bp_symbols();

    orig_getpid = sys_call_table[USA_HOOK_NR];
    write_syscall_entry(USA_HOOK_NR, (void *)usa_hooked_getpid);

    hide_module();
    return 0;
}

static void __exit driver_unload(void)
{
    usa_clear_all_bp();

    if (sys_call_table && orig_getpid)
        write_syscall_entry(USA_HOOK_NR, orig_getpid);
    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
