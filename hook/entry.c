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
 * 内核级 SO 注入 (无 ptrace, 无 TracerPid 痕迹)
 *
 * 原理: 在目标进程分配内存, 写入 dlopen shellcode,
 *        用信号触发执行
 * ===================================================================== */

typedef unsigned long (*vm_mmap_t)(struct file *, unsigned long, unsigned long,
                                   unsigned long, unsigned long, unsigned long);
typedef int (*send_sig_info_t)(int, struct kernel_siginfo *, struct task_struct *, enum pid_type);

static vm_mmap_t fn_vm_mmap = NULL;
static send_sig_info_t fn_send_sig = NULL;

static int resolve_inject_symbols(void)
{
    if (!kln_func) return -EFAULT;
    fn_vm_mmap = (vm_mmap_t)kln_func("vm_mmap");
    fn_send_sig = (send_sig_info_t)kln_func("send_sig_info");
    if (!fn_find_task_by_vpid)
        fn_find_task_by_vpid = (find_task_by_vpid_t)kln_func("find_task_by_vpid");
    return (fn_vm_mmap && fn_find_task_by_vpid) ? 0 : -ENOENT;
}

/*
 * ARM64 dlopen shellcode (PIC):
 *   STP X29, X30, [SP, #-16]!
 *   MOV X29, SP
 *   ADR X0, path          // X0 = &so_path (PC-relative)
 *   MOV X1, #2            // RTLD_NOW
 *   LDR X16, [X0, #-8]    // dlopen address stored before path
 *   BLR X16
 *   LDP X29, X30, [SP], #16
 *   RET
 *   .quad dlopen_addr      // -8 from path
 *   path: "/data/local/tmp/libusa_hook.so\0"
 */
static const uint32_t inject_shellcode[] = {
    0xA9BF7BFD, /* STP X29, X30, [SP, #-16]! */
    0x910003FD, /* MOV X29, SP */
    0x100000A0, /* ADR X0, path (PC+20) */
    0xD2800041, /* MOV X1, #2 (RTLD_NOW) */
    0xF85F8010, /* LDUR X16, [X0, #-8] */
    0xD63F0200, /* BLR X16 */
    0xA8C17BFD, /* LDP X29, X30, [SP], #16 */
    0xD65F03C0, /* RET */
};
#define SHELLCODE_SIZE (sizeof(inject_shellcode))
#define SHELLCODE_PATH_OFF (SHELLCODE_SIZE + 8) /* 8 = dlopen addr */

static int usa_inject_so(INJECT_REQUEST *req)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long remote_page;
    char so_path[256] = {0};
    unsigned long dlopen_addr = 0;
    int ret = 0;

    if (!fn_vm_mmap || !fn_find_task_by_vpid)
        return -ENOENT;

    if (copy_from_user(so_path, (void __user *)req->so_path, sizeof(so_path) - 1))
        return -EFAULT;

    /* 找目标进程 */
    rcu_read_lock();
    task = fn_find_task_by_vpid(req->pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    /* 找 dlopen 地址: 从目标进程的 linker 符号 */
    /* 简化: 用本进程的 dlopen 偏移 + 目标进程的 linker 基址 */
    dlopen_addr = get_module_base(req->pid, "linker64");
    if (dlopen_addr == 0) {
        /* 回退: 读目标进程的 /proc/pid/maps 找 libdl.so */
        dlopen_addr = get_module_base(req->pid, "libdl.so");
    }

    /* 在目标进程的上下文中 mmap */
    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    /* 切换到目标 mm */
    {
        struct mm_struct *old_mm;
        unsigned long page_size = 4096;
        size_t total_size = SHELLCODE_PATH_OFF + strlen(so_path) + 1;
        unsigned char buf[512];

        /* 分配远程内存 */
        old_mm = current->mm;
        current->mm = mm;
        remote_page = fn_vm_mmap(NULL, 0, page_size,
                                  PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, 0);
        current->mm = old_mm;

        if (IS_ERR_VALUE(remote_page)) {
            put_task_struct(task);
            return -ENOMEM;
        }

        /* 构建 shellcode 缓冲 */
        memset(buf, 0, sizeof(buf));
        memcpy(buf, inject_shellcode, SHELLCODE_SIZE);
        /* dlopen 地址放在 shellcode 后面 (path 前面 8 字节) */
        *(unsigned long *)(buf + SHELLCODE_SIZE) = dlopen_addr;
        /* so 路径 */
        memcpy(buf + SHELLCODE_PATH_OFF, so_path, strlen(so_path) + 1);

        /* 写入目标进程 */
        if (!write_process_memory(req->pid, remote_page, buf, total_size)) {
            ret = -EIO;
        }
    }

    if (ret == 0) {
        /* 发送信号触发执行 (用 SIGUSR2, 设 handler 为 shellcode) */
        /* 简化方案: 直接修改目标线程的 PC 到 shellcode (更可靠) */
        /* 通过修改信号帧: 发送一个信号并设置 sa_handler = remote_page */
        struct kernel_siginfo info;
        clear_siginfo(&info);
        info.si_signo = SIGUSR2;
        info.si_code = SI_QUEUE;
        info.si_pid = current->tgid;

        /* 设置目标进程的 SIGUSR2 handler 为 shellcode 地址 */
        /* 注: 这需要从内核态修改用户态信号表, 比较危险 */
        /* 更安全的方法: 用 force_sig_fault 或直接修改 pt_regs */

        /* 最简单方案: 通过写目标进程内存来设置 */
        /* 在 shellcode 末尾加 sigreturn 返回 */
        if (fn_send_sig)
            fn_send_sig(SIGUSR2, &info, task, PIDTYPE_PID);
    }

    put_task_struct(task);

    /* 返回 shellcode 地址给用户态, 让用户态来设置信号 */
    req->result = (int)(remote_page & 0xFFFFFFFF);
    if (copy_to_user((void __user *)((unsigned long)req - 0), req, sizeof(*req)))
        return -EFAULT;

    return ret;
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

    /* ===== 内核级注入 ===== */
    case OP_INJECT_SO: {
        INJECT_REQUEST inj;
        if (copy_from_user(&inj, (void __user *)arg, sizeof(inj)))
            return -EFAULT;
        return usa_inject_so(&inj);
    }

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

    /* 解析注入 API (可选) */
    resolve_inject_symbols();

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
