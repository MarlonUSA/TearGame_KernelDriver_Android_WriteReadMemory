/**
 * USA Kernel Driver v14 — SKJH 架构复刻
 *
 * 通信: kprobe pre_handler on __arm64_sys_getpid + PID 过滤
 * 读写: 页表遍历 (无锁, 原子上下文安全)
 * 注入: UXN Shoot (页表陷阱 + HW 执行断点 + 栈改写)
 * 隐藏: 模块摘除 + kprobe 摘除
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pid.h>
#include <linux/proc_fs.h>
#include <linux/pgtable.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/signal.h>
#include <asm/unistd.h>
#include <asm/tlbflush.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

MODULE_LICENSE("GPL");

/* =====================================================================
 * 模块参数
 * ===================================================================== */

static int comm_pid = -1;
module_param(comm_pid, int, 0);

static unsigned long usa_magic = 0x55534100;
module_param(usa_magic, ulong, 0);

/* =====================================================================
 * kallsyms 解析
 * ===================================================================== */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln_func;

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
 * 共享页 — kprobe handler 通过 kernel VA 直接访问
 *
 * 布局 (4096 bytes):
 *   [0]   u32 state    0=idle 1=pending 2=done
 *   [4]   u32 magic
 *   [8]   u32 cmd
 *   [12]  i32 pid
 *   [16]  u64 addr
 *   [24]  u64 size
 *   [32]  i64 result
 *   [40]  u8  name[256]
 *   [296] u8  data[3800]
 * ===================================================================== */

#define SHM_STATE_IDLE    0
#define SHM_STATE_PENDING 1
#define SHM_STATE_DONE    2

struct usa_shm {
    volatile uint32_t state;
    uint32_t magic;
    uint32_t cmd;
    int32_t  pid;
    uint64_t addr;
    uint64_t size;
    int64_t  result;
    char     name[256];
    uint8_t  data[3800];
};

static struct page *shm_page;
static struct usa_shm *shm;

/* /proc mmap */
static vm_fault_t usa_vm_fault(struct vm_fault *vmf)
{
    get_page(shm_page);
    vmf->page = shm_page;
    return 0;
}

static const struct vm_operations_struct usa_vm_ops = {
    .fault = usa_vm_fault,
};

static int usa_proc_mmap(struct file *file, struct vm_area_struct *vma)
{
    if (vma->vm_end - vma->vm_start != PAGE_SIZE)
        return -EINVAL;
    vma->vm_ops = &usa_vm_ops;
    return 0;
}

static const struct proc_ops usa_proc_ops = {
    .proc_mmap = usa_proc_mmap,
};

static struct proc_dir_entry *usa_proc_entry;

/* =====================================================================
 * Shoot 注入系统 — UXN 页表陷阱 + HW 执行断点
 * ===================================================================== */

typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
static find_task_by_vpid_t fn_find_task_by_vpid;

typedef unsigned long (*vm_mmap_t)(struct file *, unsigned long, unsigned long,
                                   unsigned long, unsigned long, unsigned long);
static vm_mmap_t fn_vm_mmap;

typedef void (*use_mm_fn_t)(struct mm_struct *);
static use_mm_fn_t fn_use_mm;
static use_mm_fn_t fn_unuse_mm;

typedef void (*flush_tlb_page_fn_t)(struct vm_area_struct *, unsigned long);
static flush_tlb_page_fn_t fn_flush_tlb_page;

static int resolve_symbols(void)
{
    if (!kln_func) return -EFAULT;
    fn_find_task_by_vpid = (find_task_by_vpid_t)kln_func("find_task_by_vpid");
    fn_vm_mmap = (vm_mmap_t)kln_func("vm_mmap");
    fn_use_mm = (use_mm_fn_t)kln_func("kthread_use_mm");
    fn_unuse_mm = (use_mm_fn_t)kln_func("kthread_unuse_mm");
    if (!fn_use_mm) fn_use_mm = (use_mm_fn_t)kln_func("use_mm");
    if (!fn_unuse_mm) fn_unuse_mm = (use_mm_fn_t)kln_func("unuse_mm");
    fn_flush_tlb_page = (flush_tlb_page_fn_t)kln_func("flush_tlb_page");
    return fn_find_task_by_vpid ? 0 : -ENOENT;
}

/* 获取用户页 PTE 指针 */
static pte_t *get_user_ptep(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;

    return pte_offset_kernel(pmd, addr);
}

/* ARM64 PTE UXN (User eXecute Never) 位操作 */
#define PTE_UXN_BIT  (1ULL << 54)

static void set_pte_uxn(pte_t *ptep, unsigned long addr, struct mm_struct *mm)
{
    pte_t pte = READ_ONCE(*ptep);
    pte_t new_pte = __pte(pte_val(pte) | PTE_UXN_BIT);
    set_pte(ptep, new_pte);
    /* flush TLB for this page */
    __flush_tlb_kernel_pgtable(addr);
}

static void clear_pte_uxn(pte_t *ptep, unsigned long addr, struct mm_struct *mm)
{
    pte_t pte = READ_ONCE(*ptep);
    pte_t new_pte = __pte(pte_val(pte) & ~PTE_UXN_BIT);
    set_pte(ptep, new_pte);
    __flush_tlb_kernel_pgtable(addr);
}

/*
 * dlopen shellcode (ARM64, PIC)
 * Layout: [code 32B] [orig_pc 8B] [dlopen_addr 8B] [path NUL-term]
 *
 * STP X29, X30, [SP, #-16]!
 * MOV X29, SP
 * ADR X0, path            ; X0 = &path (PC-relative, offset +40 from here)
 * MOV X1, #2              ; RTLD_NOW
 * LDR X16, [X0, #-8]      ; dlopen_addr (at path-8)
 * BLR X16                 ; dlopen(path, 2)
 * LDP X29, X30, [SP], #16
 * LDR X16, [X0, #-16]     ; orig_pc (at path-16)
 * BR  X16                 ; jump back to original PC
 */
static const uint32_t shoot_shellcode[] = {
    0xA9BF7BFD, /* STP X29, X30, [SP, #-16]! */
    0x910003FD, /* MOV X29, SP */
    0x10000140, /* ADR X0, #40  (→ path at code+48) */
    0xD2800041, /* MOV X1, #2   (RTLD_NOW) */
    0xF85F8010, /* LDUR X16, [X0, #-8]  → dlopen_addr */
    0xD63F0200, /* BLR X16 */
    0xA8C17BFD, /* LDP X29, X30, [SP], #16 */
    0xF8500010, /* LDUR X16, [X0, #-16] → orig_pc */
    0xD61F0200, /* BR X16 */
};
/* code: 36 bytes (9 insns), pad to 32 aligned: use 36 */
#define SHOOT_CODE_SIZE  36
/* [36] orig_pc 8B, [44] dlopen_addr 8B, [52] path string */
#define SHOOT_ORIGPC_OFF 36
#define SHOOT_DLOPEN_OFF 44
#define SHOOT_PATH_OFF   52

/* Shoot 状态 */
static struct {
    int active;
    pid_t target_pid;
    unsigned long trap_addr;
    pte_t *trap_ptep;
    struct mm_struct *trap_mm;
    unsigned long remote_page;
    struct perf_event *bp_event;
} shoot_state;

static DEFINE_SPINLOCK(shoot_lock);

/* HW 执行断点 handler — 游戏线程命中 UXN 陷阱后触发 */
static void shoot_bp_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    unsigned long flags;

    spin_lock_irqsave(&shoot_lock, flags);
    if (!shoot_state.active) {
        spin_unlock_irqrestore(&shoot_lock, flags);
        return;
    }

    /* 改线程 PC 到 shellcode */
    regs->pc = shoot_state.remote_page;

    /* 恢复页面可执行 */
    if (shoot_state.trap_ptep)
        clear_pte_uxn(shoot_state.trap_ptep, shoot_state.trap_addr, shoot_state.trap_mm);

    shoot_state.active = 0;
    spin_unlock_irqrestore(&shoot_lock, flags);
}

/* 执行 Shoot 注入 */
static int usa_shoot_inject(int target_pid, const char *so_path, unsigned long dlopen_addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long remote_page;
    unsigned long code_addr;
    unsigned char buf[512];
    size_t total_size;
    pte_t *ptep;
    struct perf_event_attr attr;
    struct perf_event *bp;

    if (!fn_find_task_by_vpid || !fn_vm_mmap) return -ENOENT;
    if (!dlopen_addr) return -EINVAL;

    rcu_read_lock();
    task = fn_find_task_by_vpid(target_pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    /* 在目标进程分配 RWX 内存 */
    if (fn_use_mm && fn_unuse_mm) {
        mmget(mm);
        fn_use_mm(mm);
        remote_page = fn_vm_mmap(NULL, 0, 4096,
                                  PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, 0);
        fn_unuse_mm(mm);
        mmput(mm);
    } else {
        put_task_struct(task);
        return -ENOSYS;
    }

    if (IS_ERR_VALUE(remote_page)) {
        put_task_struct(task);
        return -ENOMEM;
    }

    /* 找游戏代码页 (linker64 的 r-xp 页) 用于设置 UXN 陷阱 */
    code_addr = get_module_base(target_pid, "libUE4.so");
    if (!code_addr) code_addr = get_module_base(target_pid, "linker64");
    if (!code_addr) {
        put_task_struct(task);
        return -ENODATA;
    }
    /* 用代码段的第一页 + 一些偏移确保是热路径 */
    code_addr += 0x1000;

    /* 构建 shellcode */
    total_size = SHOOT_PATH_OFF + strlen(so_path) + 1;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, shoot_shellcode, SHOOT_CODE_SIZE);
    /* orig_pc: shellcode 执行完跳回的地址 = code_addr (被陷阱的地址) */
    *(unsigned long *)(buf + SHOOT_ORIGPC_OFF) = code_addr;
    *(unsigned long *)(buf + SHOOT_DLOPEN_OFF) = dlopen_addr;
    memcpy(buf + SHOOT_PATH_OFF, so_path, strlen(so_path) + 1);

    /* 写入目标进程 */
    if (!write_process_memory(target_pid, remote_page, buf, total_size)) {
        put_task_struct(task);
        return -EIO;
    }

    /* 获取目标代码页 PTE */
    ptep = get_user_ptep(mm, code_addr);
    if (!ptep) {
        put_task_struct(task);
        return -EFAULT;
    }

    /* 设置 HW 执行断点 */
    hw_breakpoint_init(&attr);
    attr.bp_addr = code_addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;

    bp = register_user_hw_breakpoint(&attr, shoot_bp_handler, NULL, task);
    if (IS_ERR(bp)) {
        /* 回退: 不用 HW BP, 直接用 UXN + 修改 thread PC */
        /* 简化方案: 直接找一个睡眠线程改它的 PC */
        put_task_struct(task);
        return PTR_ERR(bp);
    }

    /* 记录 Shoot 状态 */
    spin_lock_irq(&shoot_lock);
    shoot_state.active = 1;
    shoot_state.target_pid = target_pid;
    shoot_state.trap_addr = code_addr;
    shoot_state.trap_ptep = ptep;
    shoot_state.trap_mm = mm;
    shoot_state.remote_page = remote_page;
    shoot_state.bp_event = bp;
    spin_unlock_irq(&shoot_lock);

    /* 设置 UXN 陷阱 — 游戏线程执行到这页就会触发 */
    set_pte_uxn(ptep, code_addr, mm);

    put_task_struct(task);
    return 0;
}

/* =====================================================================
 * Maps 隐藏
 * ===================================================================== */

static int usa_hide_maps(pid_t target_pid, const char *lib_name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    unsigned long addr;

    if (!fn_find_task_by_vpid) return -ENOENT;
    rcu_read_lock();
    task = fn_find_task_by_vpid(target_pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    addr = 0;
    while ((vma = find_vma(mm, addr)) != NULL) {
        addr = vma->vm_end;
        if (vma->vm_file) {
            char pathbuf[256];
            char *path = d_path(&vma->vm_file->f_path, pathbuf, sizeof(pathbuf));
            if (!IS_ERR(path) && strstr(path, lib_name)) {
                fput(vma->vm_file);
                vma->vm_file = NULL;
            }
        }
    }

    put_task_struct(task);
    return 0;
}

/* =====================================================================
 * kprobe 命令处理 — 在 pre_handler 原子上下文执行
 * 所有操作必须无锁 (页表遍历, RCU, kmap_atomic)
 * ===================================================================== */

static void process_command(void)
{
    uint32_t cmd = shm->cmd;
    int32_t pid  = shm->pid;
    uint64_t addr = shm->addr;
    uint64_t size = shm->size;

    switch (cmd) {
    case OP_READ_MEM:
        if (size > sizeof(shm->data)) size = sizeof(shm->data);
        shm->result = read_process_memory(pid, addr, shm->data, size) ? 0 : -EIO;
        break;

    case OP_WRITE_MEM:
        if (size > sizeof(shm->data)) size = sizeof(shm->data);
        shm->result = write_process_memory(pid, addr, shm->data, size) ? 0 : -EIO;
        break;

    case OP_MODULE_BASE:
        shm->result = (int64_t)get_module_base(pid, shm->name);
        break;

    case OP_INJECT_SO:
        shm->result = usa_shoot_inject(pid, shm->name, (unsigned long)addr);
        break;

    case OP_HIDE_MAPS:
        shm->result = usa_hide_maps(pid, shm->name);
        break;

    default:
        shm->result = -EINVAL;
        break;
    }
}

/* =====================================================================
 * kprobe on __arm64_sys_getpid — 通信触发器
 *
 * 99.99% 的 getpid 调用: PID 不匹配 → 立刻 return 0
 * 只有 overlay 进程的 getpid 会触发命令处理
 * ===================================================================== */

static int kp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    if (current->tgid != comm_pid)
        return 0;

    /* PID 匹配, 检查共享页是否有待处理命令 */
    if (READ_ONCE(shm->state) != SHM_STATE_PENDING)
        return 0;

    /* MAGIC 验证 */
    if (shm->magic != (uint32_t)(usa_magic & 0xFFFFFFFF))
        return 0;

    smp_rmb();
    process_command();
    smp_wmb();

    WRITE_ONCE(shm->state, SHM_STATE_DONE);
    return 0;
}

static struct kprobe kp_getpid = {
    .symbol_name = "__arm64_sys_getpid",
    .pre_handler = kp_pre_handler,
};

/* =====================================================================
 * 隐藏
 * ===================================================================== */

static struct list_head *saved_prev;
static int hidden;

static void hide_kprobe_from_list(struct kprobe *kp)
{
    if (kp->hlist.pprev) {
        hlist_del_rcu(&kp->hlist);
        kp->hlist.pprev = NULL;
    }
}

static void __maybe_unused hide_module(void)
{
    if (hidden) return;
    saved_prev = THIS_MODULE->list.prev;
    list_del_init(&THIS_MODULE->list);
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

    resolve_symbols();

    /* 共享页 */
    shm_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!shm_page) return -ENOMEM;
    shm = (struct usa_shm *)page_address(shm_page);

    /* /proc 入口 */
    usa_proc_entry = proc_create("gki_tracing", 0666, NULL, &usa_proc_ops);
    if (!usa_proc_entry) {
        __free_page(shm_page);
        return -ENOMEM;
    }

    /* kprobe on getpid */
    ret = register_kprobe(&kp_getpid);
    if (ret < 0) {
        proc_remove(usa_proc_entry);
        __free_page(shm_page);
        return ret;
    }

    /* 隐藏 kprobe */
    hide_kprobe_from_list(&kp_getpid);

    memset(&shoot_state, 0, sizeof(shoot_state));
    return 0;
}

static void __exit driver_unload(void)
{
    /* 清理 Shoot */
    if (shoot_state.bp_event) {
        unregister_hw_breakpoint(shoot_state.bp_event);
        shoot_state.bp_event = NULL;
    }

    unregister_kprobe(&kp_getpid);
    if (usa_proc_entry) proc_remove(usa_proc_entry);
    unhide_module();
    if (shm_page) __free_page(shm_page);
}

module_init(driver_entry);
module_exit(driver_unload);
