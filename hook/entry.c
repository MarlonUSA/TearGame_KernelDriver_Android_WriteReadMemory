/**
 * USA Kernel Driver v16 — 真正的 SKJH 架构
 *
 * 通信: HW Write Watchpoint on overlay 的 comm_addr (per-task, 不动 syscall)
 * 注入: HW Execution Breakpoint + UXN (Shoot)
 * 读写: 页表遍历 (atomic context 安全)
 * 隐藏: 模块摘链表
 *
 * 核心: 模块加载后没有任何 kprobe 残留
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
#include <linux/mman.h>
#include <uapi/asm-generic/mman-common.h>
#include <linux/highmem.h>
#include <linux/pid.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/workqueue.h>
#include <linux/task_work.h>
#include <linux/kernfs.h>
#include <linux/pgtable.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
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
MODULE_PARM_DESC(comm_pid, "Overlay process PID");

static unsigned long comm_addr = 0;
module_param(comm_addr, ulong, 0);
MODULE_PARM_DESC(comm_addr, "Overlay user-space comm buffer address");

static unsigned long usa_magic = 0x55534100;
module_param(usa_magic, ulong, 0);
MODULE_PARM_DESC(usa_magic, "Communication MAGIC");

/* =====================================================================
 * 共享内存结构 (overlay 用户态分配, 内核通过 HW watchpoint 监视触发)
 *
 * overlay 写 state 字段 → 触发 HW write watchpoint → 内核处理
 * ===================================================================== */

#define SHM_STATE_IDLE    0
#define SHM_STATE_PENDING 1
#define SHM_STATE_DONE    2

struct usa_shm {
    volatile uint32_t state;    /* 4 字节, HW watchpoint 监视此字段 */
    uint32_t magic;
    uint32_t cmd;
    int32_t  pid;
    uint64_t addr;
    uint64_t size;
    int64_t  result;
    char     name[256];
    uint8_t  data[3800];
};

/* =====================================================================
 * kallsyms 解析 (init 时一次, 用完 unregister)
 * ===================================================================== */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln_func;

static int resolve_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    kln_func = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);  /* 立即注销, 之后系统里无 kprobe 残留 */
    return kln_func ? 0 : -EFAULT;
}

/* =====================================================================
 * 内核符号解析
 * ===================================================================== */

typedef struct task_struct *(*find_task_by_vpid_t)(pid_t);
static find_task_by_vpid_t fn_find_task_by_vpid;

typedef unsigned long (*vm_mmap_t)(struct file *, unsigned long, unsigned long,
                                   unsigned long, unsigned long, unsigned long);
static vm_mmap_t fn_vm_mmap;

typedef int (*vm_mprotect_t)(unsigned long, size_t, unsigned long);
static vm_mprotect_t fn_vm_mprotect;
/* Android GKI 把 vm_mprotect/do_mprotect_pkey 都 static, kallsyms 拿不到.
 * 退路: __arm64_sys_mprotect(struct pt_regs *) — syscall 入口, 内部 dispatch 到 do_mprotect_pkey.
 * 用 fake pt_regs 把 x0/x1/x2 灌成 (addr, len, prot) 即可. */
typedef long (*arm64_sys_mprotect_t)(const struct pt_regs *);
static arm64_sys_mprotect_t fn_arm64_sys_mprotect;

typedef void (*use_mm_fn_t)(struct mm_struct *);
static use_mm_fn_t fn_use_mm;
static use_mm_fn_t fn_unuse_mm;

typedef struct perf_event *(*register_user_hw_breakpoint_t)(
    struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *);
typedef void (*perf_event_enable_t)(struct perf_event *);
/* rwProcMem33 next-instruction BP 方案需要 modify_user_hw_breakpoint 动态改 attr */
typedef int (*modify_user_hw_breakpoint_t)(struct perf_event *bp, struct perf_event_attr *attr);
static modify_user_hw_breakpoint_t fn_modify_user_hw_breakpoint;
/* SKJH 实际用的 API */
typedef struct perf_event *(*perf_event_create_kernel_counter_t)(
    struct perf_event_attr *, int cpu, struct task_struct *,
    perf_overflow_handler_t, void *);
typedef int (*perf_event_release_kernel_t)(struct perf_event *);
/* IRQ-safe disable, 在 NMI/IRQ context 用 IPI 同步 disable */
typedef void (*perf_event_disable_inatomic_t)(struct perf_event *);
static register_user_hw_breakpoint_t fn_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t fn_unregister_hw_breakpoint;
static perf_event_enable_t fn_perf_event_enable;
static perf_event_create_kernel_counter_t fn_perf_event_create_kernel_counter;
static perf_event_release_kernel_t fn_perf_event_release_kernel;
static perf_event_disable_inatomic_t fn_perf_event_disable_inatomic;

typedef void (*kernfs_remove_t)(struct kernfs_node *);
static kernfs_remove_t fn_kernfs_remove;

/* SKJH 用 access_process_vm 做跨进程内存读写 (GKI 不导出, kallsyms 解析) */
typedef int (*access_process_vm_t)(struct task_struct *, unsigned long,
                                   void *, int, unsigned int);
static access_process_vm_t fn_access_process_vm;

/* uprobe API (kallsyms 解析, GKI 可能不导出) */
#include <linux/uprobes.h>
typedef int (*uprobe_register_t)(struct inode *, loff_t, struct uprobe_consumer *);
typedef int (*uprobe_unregister_t)(struct inode *, loff_t, struct uprobe_consumer *);
static uprobe_register_t   fn_uprobe_register;
static uprobe_unregister_t fn_uprobe_unregister;

/* task_work_add GKI 不导出, 用 kallsyms 解析 */
typedef int (*task_work_add_t)(struct task_struct *, struct callback_head *, enum task_work_notify_mode);
static task_work_add_t fn_task_work_add;

/* ARM64 custom overflow_handler 不 single-step bug 的修复:
 * 在 handler 里手动调 user_enable_single_step(current) 模拟 default_overflow_compatible
 * mainline 6.13+ 才彻底修, 我们 6.12 必须 wallplate 这个 */
typedef void (*user_enable_single_step_t)(struct task_struct *);
user_enable_single_step_t fn_user_enable_single_step_p;

/* 暴露给 memory.c 用 */
int (*kfn_access_process_vm)(struct task_struct *, unsigned long, void *, int, unsigned int) = NULL;
struct task_struct *(*kfn_find_task_by_vpid)(pid_t) = NULL;

static int resolve_symbols(void)
{
    if (!kln_func) return -EFAULT;
    fn_find_task_by_vpid = (find_task_by_vpid_t)kln_func("find_task_by_vpid");
    fn_vm_mmap = (vm_mmap_t)kln_func("vm_mmap");
    fn_vm_mprotect = (vm_mprotect_t)kln_func("vm_mprotect");
    if (!fn_vm_mprotect)
        fn_vm_mprotect = (vm_mprotect_t)kln_func("do_mprotect_pkey");
    fn_arm64_sys_mprotect = (arm64_sys_mprotect_t)kln_func("__arm64_sys_mprotect");
    pr_info("usa_hook: vm_mprotect=%px arm64_sys_mprotect=%px\n",
            fn_vm_mprotect, fn_arm64_sys_mprotect);
    fn_use_mm = (use_mm_fn_t)kln_func("kthread_use_mm");
    fn_unuse_mm = (use_mm_fn_t)kln_func("kthread_unuse_mm");
    if (!fn_use_mm) fn_use_mm = (use_mm_fn_t)kln_func("use_mm");
    if (!fn_unuse_mm) fn_unuse_mm = (use_mm_fn_t)kln_func("unuse_mm");
    fn_register_user_hw_breakpoint = (register_user_hw_breakpoint_t)kln_func("register_user_hw_breakpoint");
    fn_unregister_hw_breakpoint = (unregister_hw_breakpoint_t)kln_func("unregister_hw_breakpoint");
    fn_perf_event_enable = (perf_event_enable_t)kln_func("perf_event_enable");
    fn_perf_event_create_kernel_counter = (perf_event_create_kernel_counter_t)kln_func("perf_event_create_kernel_counter");
    fn_perf_event_release_kernel = (perf_event_release_kernel_t)kln_func("perf_event_release_kernel");
    fn_perf_event_disable_inatomic = (perf_event_disable_inatomic_t)kln_func("perf_event_disable_inatomic");
    /* 备用名 (旧 kernel) */
    if (!fn_perf_event_disable_inatomic)
        fn_perf_event_disable_inatomic = (perf_event_disable_inatomic_t)kln_func("_perf_event_disable");
    fn_access_process_vm = (access_process_vm_t)kln_func("access_process_vm");
    /* 用 %px 看真实地址 (绕过 printk hash). 如果是 NULL/0 → kallsyms 没拿到符号 */
    pr_info("usa_hook: REAL access_pvm=%px (NULL? %d)\n",
            fn_access_process_vm, fn_access_process_vm == NULL);
    pr_info("usa_hook: kern_counter=%p release=%p enable=%p\n",
            fn_perf_event_create_kernel_counter,
            fn_perf_event_release_kernel,
            fn_perf_event_enable);

    fn_user_enable_single_step_p =
        (user_enable_single_step_t)kln_func("user_enable_single_step");
    pr_info("usa_hook: user_enable_single_step=%px\n", fn_user_enable_single_step_p);
    fn_modify_user_hw_breakpoint =
        (modify_user_hw_breakpoint_t)kln_func("modify_user_hw_breakpoint");
    pr_info("usa_hook: modify_user_hw_breakpoint=%px\n", fn_modify_user_hw_breakpoint);

    fn_uprobe_register   = (uprobe_register_t)kln_func("uprobe_register");
    fn_uprobe_unregister = (uprobe_unregister_t)kln_func("uprobe_unregister");
    pr_info("usa_hook: uprobe_register=%px unregister=%px\n",
            fn_uprobe_register, fn_uprobe_unregister);
    fn_task_work_add = (task_work_add_t)kln_func("task_work_add");
    pr_info("usa_hook: task_work_add=%px\n", fn_task_work_add);
    fn_kernfs_remove = (kernfs_remove_t)kln_func("kernfs_remove");
    /* 把指针 export 给 memory.c */
    kfn_access_process_vm = fn_access_process_vm;
    kfn_find_task_by_vpid = fn_find_task_by_vpid;
    return fn_find_task_by_vpid && fn_register_user_hw_breakpoint && fn_access_process_vm ? 0 : -ENOENT;
}

/* =====================================================================
 * 页表 PTE 操作 (Shoot 注入用 UXN)
 * ===================================================================== */

/* UXN trap 路径 (apex 库不 enforce 已知 issue) — 已废弃, Shoot 改用 uprobe */

/* =====================================================================
 * Shoot 注入系统 (HW exec BP, 一次性)
 * ===================================================================== */

/* ARM64 shellcode v2 — calls __loader_dlopen(path, RTLD_NOW, caller_addr).
 * Android 7+ libdl 的 dlopen 受 caller namespace 限制 (查 caller_addr 找 lib namespace);
 * shellcode 跑在 anon RWX 页, caller_addr 是 anon → find_containing_library 返 NULL → fail.
 * 用 linker64 的 __loader_dlopen 显式传 caller_addr=linker64_base+0x1000 (linker namespace)
 * 绕过 namespace 检查. 这是 AndKittyInjector 等成熟项目的标准做法.
 *
 *   stp x29, x30, [sp, #-32]!     ; save frame
 *   mov x29, sp
 *   adr x19, data                  ; x19 = data base (orig_pc)
 *   ldr x16, [x19, #8]             ; x16 = __loader_dlopen
 *   add x0, x19, #24               ; x0 = path (data+24)
 *   movz x1, #2                    ; x1 = RTLD_NOW
 *   ldr x2, [x19, #16]             ; x2 = caller_addr (data+16)
 *   blr x16                        ; __loader_dlopen(path, RTLD_NOW, caller)
 *   ldp x29, x30, [sp], #32
 *   ldr x16, [x19]                 ; x16 = orig_pc
 *   br x16                         ; jump back to game
 * data: { orig_pc, __loader_dlopen_addr, caller_addr, path[] }
 */
/* shellcode v3 — HW-BP save-all/call-dlopen/restore-all/b trap_uva.
 * 44 insns + 4 个 8B literal (dlopen / caller / trap_uva / path). 详见 b-route 设计文档. */
static const uint32_t shoot_shellcode[] = {
    0xD10443FF, /* 0x00 sub  sp, sp, #0x110           */
    0xA90007E0, /* 0x04 stp  x0,  x1,  [sp, #0x00]    */
    0xA9010FE2, /* 0x08 stp  x2,  x3,  [sp, #0x10]    */
    0xA90217E4, /* 0x0C stp  x4,  x5,  [sp, #0x20]    */
    0xA9031FE6, /* 0x10 stp  x6,  x7,  [sp, #0x30]    */
    0xA90427E8, /* 0x14 stp  x8,  x9,  [sp, #0x40]    */
    0xA9052FEA, /* 0x18 stp  x10, x11, [sp, #0x50]    */
    0xA90637EC, /* 0x1C stp  x12, x13, [sp, #0x60]    */
    0xA9073FEE, /* 0x20 stp  x14, x15, [sp, #0x70]    */
    0xA90847F0, /* 0x24 stp  x16, x17, [sp, #0x80]    */
    0xA9094FF2, /* 0x28 stp  x18, x19, [sp, #0x90]    */
    0xA90A57F4, /* 0x2C stp  x20, x21, [sp, #0xA0]    */
    0xA90B5FF6, /* 0x30 stp  x22, x23, [sp, #0xB0]    */
    0xA90C67F8, /* 0x34 stp  x24, x25, [sp, #0xC0]    */
    0xA90D6FFA, /* 0x38 stp  x26, x27, [sp, #0xD0]    */
    0xA90E77FC, /* 0x3C stp  x28, x29, [sp, #0xE0]    */
    0xF9007BFE, /* 0x40 str  x30,      [sp, #0xF0]    */
    0xD53B4209, /* 0x44 mrs  x9, nzcv                 */
    0xF9007FE9, /* 0x48 str  x9,       [sp, #0xF8]    */
    0x58000330, /* 0x4C ldr  x16, dlopen_lit (PC+0x64)*/
    0x100003C0, /* 0x50 adr  x0,  path_str  (PC+0x78) */
    0xD2800041, /* 0x54 mov  x1,  #2                  */
    0x58000302, /* 0x58 ldr  x2,  caller_lit(PC+0x60) */
    0xD63F0200, /* 0x5C blr  x16  __loader_dlopen     */
    0xF9407FE9, /* 0x60 ldr  x9,       [sp, #0xF8]    */
    0xD51B4209, /* 0x64 msr  nzcv, x9                 */
    0xF9407BFE, /* 0x68 ldr  x30,      [sp, #0xF0]    */
    0xA94007E0, /* 0x6C ldp  x0,  x1,  [sp, #0x00]    */
    0xA9410FE2, /* 0x70 ldp  x2,  x3,  [sp, #0x10]    */
    0xA94217E4, /* 0x74 ldp  x4,  x5,  [sp, #0x20]    */
    0xA9431FE6, /* 0x78 ldp  x6,  x7,  [sp, #0x30]    */
    0xA94427E8, /* 0x7C ldp  x8,  x9,  [sp, #0x40]    */
    0xA9452FEA, /* 0x80 ldp  x10, x11, [sp, #0x50]    */
    0xA94637EC, /* 0x84 ldp  x12, x13, [sp, #0x60]    */
    0xA9473FEE, /* 0x88 ldp  x14, x15, [sp, #0x70]    */
    0xA9494FF2, /* 0x8C ldp  x18, x19, [sp, #0x90] (x16/x17 ABI 临时寄存器不恢复) */
    0xA94A57F4, /* 0x90 ldp  x20, x21, [sp, #0xA0]    */
    0xA94B5FF6, /* 0x94 ldp  x22, x23, [sp, #0xB0]    */
    0xA94C67F8, /* 0x98 ldp  x24, x25, [sp, #0xC0]    */
    0xA94D6FFA, /* 0x9C ldp  x26, x27, [sp, #0xD0]    */
    0xA94E77FC, /* 0xA0 ldp  x28, x29, [sp, #0xE0]    */
    0x910443FF, /* 0xA4 add  sp, sp, #0x110           */
    0x580000D0, /* 0xA8 ldr  x16, trap_lit  (PC+0x18) */
    0xD61F0200, /* 0xAC br   x16  跳回 trap_uva 重执行原指令 */
};
#define SHOOT_CODE_SIZE   176  /* 44 insns * 4 = 0xB0 */
#define SHOOT_DLOPEN_OFF  176  /* 0xB0 — __loader_dlopen literal     */
#define SHOOT_CALLER_OFF  184  /* 0xB8 — caller_addr literal         */
#define SHOOT_TRAP_OFF    192  /* 0xC0 — trap_uva literal (回跳目标) */
#define SHOOT_PATH_OFF    200  /* 0xC8 — path string                 */

#define MAX_SHOOT_SLOTS    8
/* HW-BP based Shoot (B route, 替代 uprobe — 详见 SKJH 真实方案):
 * 1. perf_event_create_kernel_counter(HW_BREAKPOINT_X, bp_addr=trap_uva, task=game) — 零代码修改
 * 2. game 任一线程执行到 trap_uva → HW exec BP fire → shoot_hwbp_handler (IRQ ctx)
 * 3. handler 用 cmpxchg 抢占 fired 标志 (CPU 间去重) → 改 regs->pc = shellcode_uva
 * 4. handler 同步 disable_inatomic (本 CPU IPI) + schedule task_work
 * 5. task_work 跑在目标线程 ret-to-user 前, perf_event_release_kernel 摘 BP, 释放 slot
 * 6. ret-to-user → 跳到 shellcode → save-all/dlopen/restore-all/b trap_uva → 此时 BP 已摘, 正常执行
 */
struct shoot_slot {
    int active;
    pid_t target_pid;
    unsigned long trap_addr;            /* user VA — HW BP 监视地址 */
    unsigned long shellcode_addr;       /* user VA (vm_mmap RWX 页) */
    struct task_struct      *task;      /* 目标 task, 持 get_task_struct */
    struct perf_event       *bp;        /* HW exec BP */
    struct callback_head     twork;     /* task_work_add 拆 BP 用 */
    struct work_struct       teardown;  /* fallback: 拆 BP 走 system_wq */
    atomic_t                 fired;     /* 0=armed 1=已 fire (cmpxchg 去重) */
};
static struct shoot_slot shoot_slots[MAX_SHOOT_SLOTS];

static DEFINE_SPINLOCK(shoot_lock);

/* 拆 BP 的延迟工作 — 在 task_work / system_wq 跑, 持锁安全 */
static void shoot_teardown_wq(struct work_struct *w)
{
    struct shoot_slot *s = container_of(w, struct shoot_slot, teardown);
    if (s->bp && fn_perf_event_release_kernel) {
        fn_perf_event_release_kernel(s->bp);
        s->bp = NULL;
    }
    if (s->task) { put_task_struct(s->task); s->task = NULL; }
    s->active = 0;
    pr_info("usa_hook: shoot: slot teardown done\n");
}

/* task_work activator — 由 hwbp handler schedule, 跑在目标线程 ret-to-user 前.
 * 此时不在 IRQ ctx, perf_event_release_kernel 可安全调 (会拿 ctx->mutex). */
static void shoot_hwbp_activate_tw(struct callback_head *head)
{
    struct shoot_slot *s = container_of(head, struct shoot_slot, twork);
    shoot_teardown_wq(&s->teardown);
}

/* HW exec BP handler — IRQ-disabled context, 不能 sleep/拿 mutex */
static void shoot_hwbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs)
{
    struct shoot_slot *s = bp->overflow_handler_context;
    /* 1. cmpxchg 抢 fired — 防多核重入 / 同条指令两次 fire */
    if (atomic_cmpxchg(&s->fired, 0, 1) != 0) return;
    pr_info("usa_hook: ★★★ SHOOT HWBP FIRE! pc=0x%lx tgid=%d → shellcode=0x%lx\n",
            (unsigned long)regs->pc, current->tgid, s->shellcode_addr);
    /* 2. 把目标线程的 ret-to-user PC 改到 shellcode (shellcode 末尾 b trap_uva 回原指令) */
    regs->pc = s->shellcode_addr;
    /* 3. 本 CPU 立即 disable BP (IPI 同步), 避免 single-step 走老路径触发死循环 */
    if (fn_perf_event_disable_inatomic)
        fn_perf_event_disable_inatomic(bp);
    /* 4. 调度 task_work 在 ret-to-user 前 release_kernel BP.
     *    若 task_work_add 失败/未解析 (task exiting) 退到 system_wq. */
    if (fn_task_work_add && current == s->task &&
        !fn_task_work_add(current, &s->twork, TWA_RESUME))
        return;
    schedule_work(&s->teardown);
}

/* 候选注入目标库 — 按优先级尝试. 找到第一个存在的就用它作为 trap page. */
static const char *shoot_target_libs[] = {
    "libUE4.so",        /* UE4 游戏 */
    "libil2cpp.so",     /* Unity 游戏 */
    "libc.so",          /* 任何进程都频繁调 syscall wrapper, BP 一定 fire */
    "libsystemui.so",
    "linker64",
    NULL,
};

/* uprobe-based Shoot SO 注入 (v2 with __loader_dlopen + caller_addr).
 * trap_addr=0 → 自动取 libUE4 code_seg 中间页 (HOT 函数概率)
 * caller_addr → 传给 shellcode 给 __loader_dlopen 第 3 参数 (linker64_base+0x1000) */
static int do_shoot_inject(pid_t target_pid, const char *so_path,
                           unsigned long dlopen_addr, unsigned long trap_addr,
                           unsigned long caller_addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *trap_vma;
    struct perf_event_attr attr;
    struct perf_event *bp;
    unsigned long remote_page;
    unsigned char buf[512];
    size_t total_size;
    int slot, i, ret;
    unsigned long flags;

    pr_info("usa_hook: shoot_inject pid=%d so=%s dlopen=0x%lx trap=0x%lx\n",
            target_pid, so_path, dlopen_addr, trap_addr);

    if (!fn_perf_event_create_kernel_counter || !fn_perf_event_release_kernel) {
        pr_warn("usa_hook: shoot: perf_event_create/release not resolved\n");
        return -ENOSYS;
    }
    if (!fn_perf_event_disable_inatomic) {
        pr_warn("usa_hook: shoot: perf_event_disable_inatomic not resolved\n");
        return -ENOSYS;
    }
    if (!fn_vm_mmap || !fn_use_mm || !fn_unuse_mm) return -ENOSYS;
    if (!dlopen_addr) return -EINVAL;

    rcu_read_lock();
    task = fn_find_task_by_vpid(target_pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) { pr_warn("usa_hook: shoot: task not found pid=%d\n", target_pid); return -ESRCH; }

    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    /* 1. 在 target mm 内 vm_mmap 一块 RWX 页给 shellcode */
    mmget(mm);
    fn_use_mm(mm);
    remote_page = fn_vm_mmap(NULL, 0, 4096,
                              PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, 0);
    fn_unuse_mm(mm);
    mmput(mm);
    if (IS_ERR_VALUE(remote_page)) {
        pr_warn("usa_hook: shoot: vm_mmap failed: %ld\n", (long)remote_page);
        put_task_struct(task);
        return (int)(long)remote_page;
    }
    pr_info("usa_hook: shoot: shellcode page = 0x%lx\n", remote_page);

    /* 2. 找 trap_addr — explicit 或自动取 lib code_seg 中间 */
    if (!trap_addr) {
        /* PRIMARY: libc clock_gettime — high-freq (Android logging + render timing).
         * NOT in dlopen's lock chain (avoids the pthread_mutex_lock recursive deadlock crash).
         * Offset verified for Android 14 apex bionic libc.so on 6.1-GKI. */
        {
            unsigned long libc_base = get_module_base(target_pid, "libc.so");
            if (libc_base) {
                trap_addr = libc_base + 0x56df8;  /* clock_gettime — Android 14 apex bionic libc */
                pr_info("usa_hook: shoot: AUTO trap = libc clock_gettime @ 0x%lx (libc base 0x%lx)\n",
                        trap_addr, libc_base);
            }
        }
    }
    if (!trap_addr) {
        unsigned long code_addr = 0;
        for (i = 0; shoot_target_libs[i]; i++) {
            code_addr = get_module_code_seg(target_pid, (char *)shoot_target_libs[i]);
            if (code_addr) {
                pr_info("usa_hook: shoot: AUTO found %s code_seg @ 0x%lx\n",
                        shoot_target_libs[i], code_addr);
                /* 找最大可执行段, 取中间页 */
                {
                    struct vm_area_struct *vma;
                    unsigned long ad = code_addr, end = code_addr;
                    while ((vma = find_vma(mm, ad)) != NULL) {
                        if (!(vma->vm_flags & VM_EXEC)) break;
                        if (vma->vm_start > end + 0x10000) break; /* 不连续 */
                        end = vma->vm_end;
                        ad = vma->vm_end;
                        if (end - code_addr > (256UL << 20)) break;
                    }
                    if (end - code_addr > 0x2000)
                        trap_addr = ((code_addr + (end - code_addr) / 2) & ~0xFFFUL) + 0x10;
                    else
                        trap_addr = code_addr + 0x10;
                }
                pr_info("usa_hook: shoot: AUTO trap_addr = 0x%lx\n", trap_addr);
                break;
            }
        }
    }
    if (!trap_addr) {
        pr_warn("usa_hook: shoot: no trap_addr (pid=%d)\n", target_pid);
        put_task_struct(task);
        return -ENODATA;
    }

    /* 3. 校验 trap_addr 落在可执行 VMA (HWBP-X 不需要 file-backed, anon RWX 也行) */
    mmap_read_lock(mm);
    trap_vma = find_vma(mm, trap_addr);
    if (!trap_vma || trap_addr < trap_vma->vm_start) {
        mmap_read_unlock(mm);
        pr_warn("usa_hook: shoot: trap_addr 0x%lx no VMA\n", trap_addr);
        put_task_struct(task);
        return -EINVAL;
    }
    if (!(trap_vma->vm_flags & VM_EXEC)) {
        mmap_read_unlock(mm);
        pr_warn("usa_hook: shoot: trap_addr 0x%lx not executable\n", trap_addr);
        put_task_struct(task);
        return -EINVAL;
    }
    mmap_read_unlock(mm);

    /* 4. 写 shellcode 到 remote RWX 页 */
    total_size = SHOOT_PATH_OFF + strlen(so_path) + 1;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, shoot_shellcode, SHOOT_CODE_SIZE);
    *(unsigned long *)(buf + SHOOT_TRAP_OFF)   = trap_addr;
    *(unsigned long *)(buf + SHOOT_DLOPEN_OFF) = dlopen_addr;
    *(unsigned long *)(buf + SHOOT_CALLER_OFF) = caller_addr;
    memcpy(buf + SHOOT_PATH_OFF, so_path, strlen(so_path) + 1);
    pr_info("usa_hook: shoot: shellcode data: trap=0x%lx __loader_dlopen=0x%lx caller=0x%lx path=%s\n",
            trap_addr, dlopen_addr, caller_addr, so_path);
    if (!write_process_memory(target_pid, remote_page, buf, total_size)) {
        pr_warn("usa_hook: shoot: write shellcode failed\n");
        put_task_struct(task);
        return -EIO;
    }
    pr_info("usa_hook: shoot: shellcode written (size=%zu)\n", total_size);

    /* Android 14 W^X: 翻转 RW → RX (mmap 时禁止 PROT_EXEC+PROT_WRITE 同时).
     * 用 __arm64_sys_mprotect 走 syscall 入口 — fake pt_regs (x0=addr/x1=len/x2=prot).
     *
     * SELinux 关卡: kworker 的 scontext=u:r:kernel:s0 没 execmem 权限 (avc denied).
     * 解法: override_creds(game_task->cred) 让 selinux_file_mprotect 用 untrusted_app_30
     *      的 SID 校验 (Android app 有 execmem 给 ART JIT/dex2oat), 校验过. */
    {
        int mp_ret = -ENOSYS;
        const struct cred *old_cred = NULL, *task_cred = NULL;

        task_cred = get_task_cred(task);
        if (task_cred)
            old_cred = override_creds(task_cred);

        mmget(mm);
        fn_use_mm(mm);
        if (fn_vm_mprotect) {
            mp_ret = fn_vm_mprotect(remote_page, 4096, PROT_READ | PROT_EXEC);
        } else if (fn_arm64_sys_mprotect) {
            struct pt_regs fake_regs;
            memset(&fake_regs, 0, sizeof(fake_regs));
            fake_regs.regs[0] = remote_page;
            fake_regs.regs[1] = 4096;
            fake_regs.regs[2] = PROT_READ | PROT_EXEC;
            mp_ret = (int)fn_arm64_sys_mprotect(&fake_regs);
        }
        fn_unuse_mm(mm);
        mmput(mm);

        if (old_cred) revert_creds(old_cred);
        if (task_cred) put_cred(task_cred);

        if (mp_ret < 0) {
            pr_warn("usa_hook: shoot: mprotect RX failed: %d (vm_mprotect=%px arm64_sys=%px) — try `setenforce 0` 临时排查\n",
                    mp_ret, fn_vm_mprotect, fn_arm64_sys_mprotect);
            put_task_struct(task);
            return mp_ret;
        }
        pr_info("usa_hook: shoot: page flipped RW->RX OK (via %s, override_creds=%s)\n",
                fn_vm_mprotect ? "vm_mprotect" : "__arm64_sys_mprotect",
                old_cred ? "yes" : "no");
    }

    /* 5. 占 slot */
    spin_lock_irqsave(&shoot_lock, flags);
    for (slot = 0; slot < MAX_SHOOT_SLOTS; slot++)
        if (!shoot_slots[slot].active) break;
    if (slot >= MAX_SHOOT_SLOTS) {
        spin_unlock_irqrestore(&shoot_lock, flags);
        put_task_struct(task);
        return -ENOMEM;
    }
    shoot_slots[slot].active         = 1;
    shoot_slots[slot].target_pid     = target_pid;
    shoot_slots[slot].trap_addr      = trap_addr;
    shoot_slots[slot].shellcode_addr = remote_page;
    shoot_slots[slot].task           = task;   /* 持 ref, 在 teardown 里 put */
    shoot_slots[slot].bp             = NULL;
    atomic_set(&shoot_slots[slot].fired, 0);
    INIT_WORK(&shoot_slots[slot].teardown, shoot_teardown_wq);
    init_task_work(&shoot_slots[slot].twork, shoot_hwbp_activate_tw);
    spin_unlock_irqrestore(&shoot_lock, flags);

    /* 5.5 C阶段诊断: 读 dlopen_addr 处 4 字节, 验是否为 AArch64 BTI prologue.
     *      __loader_dlopen 在 Android 14 bionic linker64 编译为 BTI-marked,
     *      入口指令必须是 BTI c/j/jc (0xD503245F / 0xD503241F / 0xD503243F).
     *      如果不是, 说明 inject7 用户态算的 dlopen_addr 错了 (例如 base 偏移错
     *      或者拿到的是非 BTI 的旧 linker), HWBP 触发后 blr 过去必 SIGILL.
     *      用 fn_access_process_vm 跨进程读 — gup_flags=0 表示只读. */
    if (fn_access_process_vm) {
        u32 bti_insn = 0;
        int rd = fn_access_process_vm(task, dlopen_addr, &bti_insn,
                                       sizeof(bti_insn), 0 /* read */);
        if (rd != sizeof(bti_insn)) {
            pr_warn("usa_hook: shoot: DLOPEN_ADDR_INVALID read failed at 0x%lx (rd=%d) — refuse HWBP arm\n",
                    dlopen_addr, rd);
            spin_lock_irqsave(&shoot_lock, flags);
            shoot_slots[slot].active = 0;
            shoot_slots[slot].task   = NULL;
            spin_unlock_irqrestore(&shoot_lock, flags);
            put_task_struct(task);
            return -EFAULT;
        }
        {
            bool valid_prologue = false;
            /* HINT #N family: opcode bits 31-12 == 0xD5032, bits 4-0 == 0x1F.
             * Covers nop, yield, wfe, wfi, sev, sevl, esb, csdb,
             *        paciasp/paci1sp/pacibsp, autiasp/autibsp, autiaz/autibz,
             *        bti c/j/jc — all valid AArch64 function-entry hints. */
            if ((bti_insn & 0xFFFFF01F) == 0xD503201F) {
                valid_prologue = true;
            }
            /* stp x29, x30, [sp, #-N]!  (0xA9B?7BFD — frame-setup) */
            if ((bti_insn & 0xFFC07FFF) == 0xA9807BFD) {
                valid_prologue = true;
            }
            /* sub sp, sp, #imm */
            if ((bti_insn & 0xFF8003FF) == 0xD10003FF) {
                valid_prologue = true;
            }
            /* Only refuse if bytes look obviously unmapped (all-zero).
             * Otherwise log + proceed even if prologue is unknown — HWBP arm
             * itself doesn't care about target instruction, only execution
             * trap. inject7 may legitimately land on PAC/STP/SUB prologues. */
            if (bti_insn == 0x00000000) {
                pr_warn("usa_hook: shoot: DLOPEN_ADDR_INVALID bytes=0 (unmapped?) @ dlopen=0x%lx — refuse HWBP arm\n",
                        dlopen_addr);
                spin_lock_irqsave(&shoot_lock, flags);
                shoot_slots[slot].active = 0;
                shoot_slots[slot].task   = NULL;
                spin_unlock_irqrestore(&shoot_lock, flags);
                put_task_struct(task);
                return -EINVAL;
            }
            pr_info("usa_hook: shoot: prologue check dlopen=0x%lx insn=0x%x %s\n",
                    dlopen_addr, bti_insn,
                    valid_prologue ? "PROLOGUE_OK" : "PROLOGUE_UNKNOWN_proceed");
        }
    } else {
        pr_warn("usa_hook: shoot: fn_access_process_vm 未解析, 跳过 BTI 验证\n");
    }

    /* 6. 注册 HW 执行断点 (HW_BREAKPOINT_X) — kernel 自动给 target_task 装 dbg regs.
     *    game 任一线程执行到 trap_addr → 硬件 Watchpoint trap → shoot_hwbp_handler
     *    → 改 regs->pc → shellcode → __loader_dlopen → br trap_addr 回到游戏
     *    优势 vs uprobe:
     *      - 不动 inode/页, 不污染其他进程 (perf_event 限定 task)
     *      - 不在共享 .text 写 BRK, 反作弊看不到指令改动
     *      - 卸载安全 (perf_event_release_kernel 即可) */
    /* C阶段诊断: 验 dlopen_addr 是否合法 (期望 AArch64 BTI 头 0xD5032[145]F) */
    {
        u32 dlopen_bytes = 0;
        int rd = fn_access_process_vm ? fn_access_process_vm(task, dlopen_addr,
                                                              &dlopen_bytes, 4, 0) : -1;
        bool valid_prologue = false;
        /* HINT #N family (bti / paciasp / pacibsp / nop / yield / ...) */
        if ((dlopen_bytes & 0xFFFFF01F) == 0xD503201F) {
            valid_prologue = true;
        }
        /* stp x29, x30, [sp, #-N]! frame setup */
        if ((dlopen_bytes & 0xFFC07FFF) == 0xA9807BFD) {
            valid_prologue = true;
        }
        /* sub sp, sp, #imm */
        if ((dlopen_bytes & 0xFF8003FF) == 0xD10003FF) {
            valid_prologue = true;
        }
        pr_info("usa_hook: DLOPEN_VALIDATE addr=0x%lx read=%d bytes=0x%08x %s\n",
                dlopen_addr, rd, dlopen_bytes,
                (rd <= 0)                    ? "READ_FAIL" :
                (dlopen_bytes == 0x00000000) ? "BAD_NOT_VALID_PROLOGUE_unmapped" :
                valid_prologue               ? "PROLOGUE_OK" :
                                               "PROLOGUE_UNKNOWN_proceed");
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr     = trap_addr;
    attr.bp_len      = HW_BREAKPOINT_LEN_4;
    attr.bp_type     = HW_BREAKPOINT_X;
    attr.disabled    = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv  = 1;
    bp = fn_perf_event_create_kernel_counter(&attr, -1, task,
                                              shoot_hwbp_handler,
                                              &shoot_slots[slot]);
    if (IS_ERR(bp)) {
        ret = PTR_ERR(bp);
        pr_warn("usa_hook: shoot: perf_event_create_kernel_counter failed: %d\n", ret);
        spin_lock_irqsave(&shoot_lock, flags);
        shoot_slots[slot].active = 0;
        shoot_slots[slot].task   = NULL;
        spin_unlock_irqrestore(&shoot_lock, flags);
        put_task_struct(task);
        return ret;
    }
    shoot_slots[slot].bp = bp;
    pr_info("usa_hook: shoot: ★ HWBP-X ARMED @0x%lx pid=%d slot=%d bp=%px\n",
            trap_addr, target_pid, slot, bp);
    /* 注意: task ref 仍然持有, 由 shoot_teardown_wq 在 fire 后 put.
     *       如果 game 永远不触发, 模块卸载会在 shoot_cleanup_all 里 put. */
    return 0;
}

/* Shoot 工作队列 */
struct shoot_work {
    struct work_struct work;
    pid_t target_pid;
    char so_path[256];
    unsigned long dlopen_addr;
    unsigned long trap_addr;
    unsigned long caller_addr;
};

static void shoot_work_fn(struct work_struct *w)
{
    struct shoot_work *sw = container_of(w, struct shoot_work, work);
    do_shoot_inject(sw->target_pid, sw->so_path, sw->dlopen_addr, sw->trap_addr, sw->caller_addr);
    kfree(sw);
}

static int queue_shoot_inject(pid_t pid, const char *so_path,
                              unsigned long dlopen_addr, unsigned long trap_addr,
                              unsigned long caller_addr)
{
    struct shoot_work *sw = kmalloc(sizeof(*sw), GFP_ATOMIC);
    if (!sw) return -ENOMEM;
    INIT_WORK(&sw->work, shoot_work_fn);
    sw->target_pid = pid;
    strncpy(sw->so_path, so_path, sizeof(sw->so_path) - 1);
    sw->so_path[sizeof(sw->so_path) - 1] = 0;
    sw->dlopen_addr = dlopen_addr;
    sw->trap_addr = trap_addr;
    sw->caller_addr = caller_addr;
    schedule_work(&sw->work);
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
 * 通信命令处理 (在 HW watchpoint handler 中调用)
 * ===================================================================== */

/* PAN-safe 版本: 用 copy_from_user/copy_to_user 而不是直接 deref user pointer.
 * ARM64 6.x 默认开 PAN (Privileged Access Never), 内核直接 deref user pointer 会 panic. */
/* header part of usa_shm: 不含 data[] 大数组 (3800 bytes) */
struct usa_shm_hdr {
    volatile uint32_t state;
    uint32_t magic;
    uint32_t cmd;
    int32_t  pid;
    uint64_t addr;
    uint64_t size;
    int64_t  result;
    char     name[256];
};

static void process_command(struct usa_shm __user *ushm)
{
    struct usa_shm_hdr *khdr;
    uint32_t cmd;
    int32_t pid;
    uint64_t addr;
    uint64_t size;
    void *kbuf = NULL;
    int64_t result = -EINVAL;

    /* heap 分配避免大栈帧 (struct usa_shm 4KB > 2KB stack limit) */
    khdr = kmalloc(sizeof(*khdr), GFP_KERNEL);
    if (!khdr) return;
    if (copy_from_user(khdr, ushm, sizeof(*khdr))) {
        pr_warn("usa_hook: copy_from_user shm header failed\n");
        kfree(khdr);
        return;
    }
    cmd = khdr->cmd;
    pid = khdr->pid;
    addr = khdr->addr;
    size = khdr->size;

    pr_info("usa_hook: process_command cmd=0x%x pid=%d addr=0x%llx size=%llu\n",
            cmd, pid, addr, size);

    switch (cmd) {
    case OP_READ_MEM:
        if (size > 3800) size = 3800;
        kbuf = kmalloc(size, GFP_KERNEL);
        if (!kbuf) { result = -ENOMEM; break; }
        result = read_process_memory(pid, addr, kbuf, size) ? 0 : -EIO;
        if (result == 0)
            if (copy_to_user(ushm->data, kbuf, size)) result = -EFAULT;
        kfree(kbuf);
        break;

    case OP_WRITE_MEM:
        if (size > 3800) size = 3800;
        kbuf = kmalloc(size, GFP_KERNEL);
        if (!kbuf) { result = -ENOMEM; break; }
        if (copy_from_user(kbuf, ushm->data, size)) { kfree(kbuf); result = -EFAULT; break; }
        result = write_process_memory(pid, addr, kbuf, size) ? 0 : -EIO;
        kfree(kbuf);
        break;

    case OP_MODULE_BASE:
        khdr->name[sizeof(khdr->name) - 1] = 0;
        result = (int64_t)get_module_base(pid, khdr->name);
        break;

    case OP_INJECT_SO: {
        /* INJECT_SO 参数传递:
         *   addr  = __loader_dlopen_addr (linker64 内函数地址)
         *   size  = trap_addr (game user VA, 0=自动)
         *   data[0..7] = caller_addr (linker64_base+0x1000, 给 __loader_dlopen 第 3 参数)
         *   name  = so path
         */
        unsigned long caller_arg = 0;
        khdr->name[sizeof(khdr->name) - 1] = 0;
        /* 从 user shm->data 头 8 字节读 caller_addr (PAN-safe) */
        if (copy_from_user(&caller_arg, ushm->data, sizeof(caller_arg)))
            caller_arg = 0;
        result = queue_shoot_inject(pid, khdr->name, (unsigned long)addr,
                                    (unsigned long)size, caller_arg);
        break;
    }

    case OP_HIDE_MAPS:
        khdr->name[sizeof(khdr->name) - 1] = 0;
        result = usa_hide_maps(pid, khdr->name);
        break;

    default:
        result = -EINVAL;
        break;
    }

    /* 把 result 写回用户态 (PAN-safe) — 用 copy_to_user 绕过 volatile qualifier 问题 */
    if (copy_to_user((void __user *)&ushm->result, &result, sizeof(result)))
        pr_warn("usa_hook: copy_to_user result failed\n");
    kfree(khdr);
}

/* =====================================================================
 * 通信 HW Watchpoint Handler
 *
 * overlay 写 shm->state = PENDING 时触发
 * current == overlay 的线程 (HW BP scoped to comm_pid task)
 * ===================================================================== */

/* 给 overlay 所有线程都注册 BP (SKJH add_comm_thread_breakpoint)
 * register_user_hw_breakpoint 是 per-thread, 必须遍历 thread_group
 * 用 delayed_work 定期扫描新线程 */
#define MAX_COMM_BPS 64
static struct perf_event *comm_bps[MAX_COMM_BPS];
static pid_t comm_bp_tids[MAX_COMM_BPS]; /* 已注册的 tid */
static int comm_bp_count;
static DEFINE_MUTEX(comm_bp_mutex);
static struct delayed_work comm_bp_scan_work;

static atomic_t comm_bp_hits = ATOMIC_INIT(0);

/* ARM64 software step: 需要同时设 SPSR.SS=1 + MDSCR_EL1.SS=1 */
#ifndef DBG_SPSR_SS
#define DBG_SPSR_SS    (1UL << 21)
#endif
#ifndef DBG_MDSCR_SS
#define DBG_MDSCR_SS   (1UL << 0)
#endif

static inline void enable_mdscr_ss(void)
{
    u64 mdscr;
    asm volatile("mrs %0, mdscr_el1" : "=r" (mdscr));
    mdscr |= DBG_MDSCR_SS;
    asm volatile("msr mdscr_el1, %0" :: "r" (mdscr));
}

/* ========================================================================
 * HW Watchpoint single-step 修复 — 复刻 abcz316/rwProcMem33 的 next-instruction
 *
 * 原理: ARM64 kernel 6.12 看到 custom overflow handler 就跳过 single-step 路径,
 *       导致 STR 死循环. mainline 6.13+ 才修.
 *
 * 解决: handler 第 1 次 fire 时, 把 BP 临时改成监视 PC+4 (执行型 BP).
 *       ARM kernel 重新 install 后 ERET → STR 完成 → 跑下一条指令 →
 *       下一条指令的执行 BP fire (第 2 次). 第 2 次 fire 时把 BP 恢复成原 watchpoint.
 *
 * 每个 BP 都需要一对 attr: original (watchpoint) + next_instruction (X type)
 * ======================================================================== */

#include "arm64_register_helper.h"

/* 每个监视的 (tid,addr) 都有一对 attr 状态 */
struct comm_bp_state {
    struct perf_event       *bp;
    struct perf_event_attr   original_attr;
    struct perf_event_attr   next_instruction_attr;  /* bp_addr=0 表示当前是 original */
    pid_t                    tid;
    bool                     is_32bit;
};
static struct comm_bp_state g_comm_bp_states[MAX_COMM_BPS];
static int g_comm_bp_state_count = 0;

static bool arm64_move_bp_to_next_instruction(struct perf_event *bp,
                                              uint64_t next_pc,
                                              struct perf_event_attr *original_attr,
                                              struct perf_event_attr *next_attr)
{
    int result;
    if (!bp || !original_attr || !next_attr || !next_pc || !fn_modify_user_hw_breakpoint)
        return false;
    memcpy(next_attr, original_attr, sizeof(*next_attr));
    next_attr->bp_addr = next_pc;
    next_attr->bp_len  = HW_BREAKPOINT_LEN_4;
    next_attr->bp_type = HW_BREAKPOINT_X;
    next_attr->disabled = 0;
    result = fn_modify_user_hw_breakpoint(bp, next_attr);
    if (result) {
        next_attr->bp_addr = 0;
        return false;
    }
    return true;
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp,
                                          struct perf_event_attr *original_attr,
                                          struct perf_event_attr *next_attr)
{
    int result;
    if (!bp || !original_attr || !next_attr || !fn_modify_user_hw_breakpoint)
        return false;
    result = fn_modify_user_hw_breakpoint(bp, original_attr);
    if (result) return false;
    next_attr->bp_addr = 0;  /* 标记已恢复 */
    return true;
}

static struct comm_bp_state *find_bp_state(struct perf_event *bp)
{
    int i;
    for (i = 0; i < g_comm_bp_state_count; i++)
        if (g_comm_bp_states[i].bp == bp)
            return &g_comm_bp_states[i];
    return NULL;
}

static void comm_bp_handler(struct perf_event *bp,
                            struct perf_sample_data *data,
                            struct pt_regs *regs)
{
    struct comm_bp_state *st;
    int hits = atomic_inc_return(&comm_bp_hits);

    if (hits <= 5)
        pr_info("usa_hook: BP HIT #%d pc=0x%lx\n", hits, (unsigned long)regs->pc);

    st = find_bp_state(bp);
    if (!st) {
        /* 退化路径: 找不到状态 → 直接 disable 防死循环 */
        if (user_mode(regs))
            toggle_bp_registers_directly(&bp->attr, false, 0);
        return;
    }

    if (st->next_instruction_attr.bp_addr != regs->pc) {
        /* 第 1 次 fire (watchpoint on STR) — 处理命令 */
        if (user_mode(regs)) {
            bool moved = false;
            if (!st->is_32bit)
                moved = arm64_move_bp_to_next_instruction(bp, regs->pc + 4,
                                                          &st->original_attr,
                                                          &st->next_instruction_attr);
            if (!moved) {
                /* fallback — 直接关掉 BP 让 STR 完成 (这次通信丢失但设备不死锁) */
                toggle_bp_registers_directly(&st->original_attr, st->is_32bit, 0);
            }
        }
    } else {
        /* 第 2 次 fire (X 在 PC+4) — STR 已完成, 恢复 BP 监视原 watchpoint */
        if (!arm64_recovery_bp_to_original(bp, &st->original_attr, &st->next_instruction_attr)) {
            toggle_bp_registers_directly(&st->next_instruction_attr, st->is_32bit, 0);
        }
    }
}

static bool tid_already_registered(pid_t tid)
{
    int i;
    for (i = 0; i < comm_bp_count; i++)
        if (comm_bp_tids[i] == tid) return true;
    return false;
}

static int scan_and_register_threads(void)
{
    struct task_struct *leader, *t;
    struct task_struct *new_threads[MAX_COMM_BPS];
    pid_t new_tids[MAX_COMM_BPS];
    struct perf_event_attr attr;
    struct perf_event *bp;
    int n_new = 0, new_registered = 0, i;

    if (comm_pid < 0 || !comm_addr) return -EINVAL;

    /* 第一阶段: RCU 下找新线程 */
    mutex_lock(&comm_bp_mutex);
    rcu_read_lock();
    leader = fn_find_task_by_vpid(comm_pid);
    if (!leader) {
        rcu_read_unlock();
        mutex_unlock(&comm_bp_mutex);
        return -ESRCH;
    }
    get_task_struct(leader);

    /* 只给 leader 注册 BP (ARM64 只有 4 个 watchpoint slot)
     * 多个线程同时活跃会 ENOSPC. SKJH 用 slot 池管理多 task.
     * 我们简化: 只用 leader, overlay 必须把所有 comm 串行到 leader 线程 */
    if (!tid_already_registered(leader->pid)) {
        get_task_struct(leader);
        new_threads[n_new] = leader;
        new_tids[n_new] = leader->pid;
        n_new++;
    }
    /* 注释掉 for_each_thread 全量注册:
    for_each_thread(leader, t) {
        if (comm_bp_count + n_new >= MAX_COMM_BPS) break;
        if (tid_already_registered(t->pid)) continue;
        get_task_struct(t);
        new_threads[n_new] = t;
        new_tids[n_new] = t->pid;
        n_new++;
    } */
    (void)t;
    rcu_read_unlock();
    put_task_struct(leader);

    if (n_new == 0) {
        mutex_unlock(&comm_bp_mutex);
        return 0;
    }

    /* 第二阶段: 给新线程注册 BP */
    hw_breakpoint_init(&attr);
    attr.bp_addr = comm_addr;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_W;

    for (i = 0; i < n_new; i++) {
        /* register_user_hw_breakpoint 内部做了 install + enable
         * perf_event_create_kernel_counter 创建后 state=INACTIVE 需要手动 install */
        bp = fn_register_user_hw_breakpoint(&attr, comm_bp_handler, NULL, new_threads[i]);

        if (!IS_ERR(bp)) {
            comm_bps[comm_bp_count] = bp;
            comm_bp_tids[comm_bp_count] = new_tids[i];
            comm_bp_count++;
            new_registered++;
            pr_info("usa_hook: BP registered tid=%d state_before_enable=%d attr.bp_addr=0x%llx\n",
                    new_tids[i], bp->state, bp->attr.bp_addr);
            if (fn_perf_event_enable) {
                fn_perf_event_enable(bp);
                pr_info("usa_hook: BP enabled tid=%d state_after=%d\n",
                        new_tids[i], bp->state);
            }
        } else {
            pr_info("usa_hook: BP fail tid=%d err=%ld state_after=%d\n",
                    new_tids[i], PTR_ERR(bp), bp ? bp->state : -999);
        }
        put_task_struct(new_threads[i]);
    }
    mutex_unlock(&comm_bp_mutex);

    if (new_registered > 0)
        pr_info("usa_hook: +%d new BPs (total %d) for pid=%d\n",
                new_registered, comm_bp_count, comm_pid);
    return new_registered;
}

/* 定期扫描新线程 (现已废弃, 改用 ioctl 注册) */
static void __maybe_unused comm_bp_scan_fn(struct work_struct *work)
{
    scan_and_register_threads();
    /* 每 500ms 重新扫描 */
    schedule_delayed_work(&comm_bp_scan_work, msecs_to_jiffies(500));
}

/* =====================================================================
 * ioctl 接口: overlay 自己 ioctl 注册 BP (current = overlay, BP 立即激活)
 * 这是关键! 从 insmod 上下文注册 BP 不激活, 必须 overlay 主动 ioctl
 * ===================================================================== */

#define USA_IOC_MAGIC 'U'
#define USA_IOC_REGISTER_COMM _IOW(USA_IOC_MAGIC, 1, unsigned long)
#define USA_IOC_SEND_CMD      _IOWR(USA_IOC_MAGIC, 2, unsigned long)

/* 给 current task 注册 BP. 必须由 overlay 自己 ioctl 触发! */
static int register_bp_for_current(unsigned long addr)
{
    struct perf_event_attr attr;
    struct perf_event *bp;
    struct comm_bp_state *st;
    pid_t my_tid = current->pid;

    mutex_lock(&comm_bp_mutex);

    if (tid_already_registered(my_tid)) {
        mutex_unlock(&comm_bp_mutex);
        pr_info("usa_hook: ioctl: tid=%d already registered\n", my_tid);
        return 0;
    }
    if (comm_bp_count >= MAX_COMM_BPS || g_comm_bp_state_count >= MAX_COMM_BPS) {
        mutex_unlock(&comm_bp_mutex);
        return -ENOSPC;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = addr;
    attr.bp_len  = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_W;
    attr.disabled = 0;

    bp = fn_register_user_hw_breakpoint(&attr, comm_bp_handler, NULL, current);
    if (IS_ERR(bp)) {
        mutex_unlock(&comm_bp_mutex);
        pr_info("usa_hook: ioctl BP fail tid=%d err=%ld\n", my_tid, PTR_ERR(bp));
        return (int)PTR_ERR(bp);
    }

    /* 保存到 next-instruction state 数组 (handler 用) */
    st = &g_comm_bp_states[g_comm_bp_state_count];
    st->bp = bp;
    memcpy(&st->original_attr, &attr, sizeof(attr));
    memset(&st->next_instruction_attr, 0, sizeof(st->next_instruction_attr));
    st->tid = my_tid;
    st->is_32bit = is_compat_thread(task_thread_info(current));
    g_comm_bp_state_count++;

    comm_bps[comm_bp_count] = bp;
    comm_bp_tids[comm_bp_count] = my_tid;
    comm_bp_count++;
    mutex_unlock(&comm_bp_mutex);

    pr_info("usa_hook: ioctl: tid=%d BP registered (state=%d) for addr=0x%lx [next-inst mode]\n",
            my_tid, bp->state, addr);
    return 0;
}

/* ========================================================================
 * Anti-ptrace detection — 复刻 rwProcMem33 anti_ptrace_detection.h
 *
 * 外部进程 (反作弊) 用 PTRACE_GETREGSET + NT_ARM_HW_BREAK/NT_ARM_HW_WATCH
 * 查询某 task 的 HW BP 寄存器, 能直接看到我们注册的地址.
 * 我们 kretprobe on arch_ptrace, 在 return 时清掉结果里地址匹配的项.
 * ======================================================================== */

#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET   0x4204
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK    0x402
#endif
#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH    0x403
#endif

struct hook_ptrace_data {
    struct iovec iov;
    bool         interested;
};

static bool is_our_bp_addr(uint64_t addr)
{
    int i;
    bool found = false;
    if (!addr) return false;
    mutex_lock(&comm_bp_mutex);
    for (i = 0; i < g_comm_bp_state_count; i++) {
        if (g_comm_bp_states[i].original_attr.bp_addr == addr) {
            found = true;
            break;
        }
    }
    mutex_unlock(&comm_bp_mutex);
    return found;
}

static int entry_ptrace_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long request = regs->regs[1];
    unsigned long addr = (unsigned long)regs->regs[2];
    struct hook_ptrace_data *d = (struct hook_ptrace_data *)ri->data;
    d->iov.iov_base = NULL;
    d->iov.iov_len  = 0;
    d->interested = false;
    if (request == PTRACE_GETREGSET &&
        (addr == NT_ARM_HW_BREAK || addr == NT_ARM_HW_WATCH)) {
        unsigned long iov_user_ptr = regs->regs[3];
        if (!iov_user_ptr) return 0;
        if (copy_from_user(&d->iov, (struct iovec __user *)iov_user_ptr,
                           sizeof(struct iovec)) != 0)
            return 0;
        d->interested = true;
    }
    return 0;
}

static int ret_ptrace_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct hook_ptrace_data *d = (struct hook_ptrace_data *)ri->data;
    struct user_hwdebug_state *old_st = NULL, *new_st = NULL;
    size_t copy_size;
    int i, y = 0;

    if (!d->interested || !d->iov.iov_base || !d->iov.iov_len) return 0;
    if (!access_ok((void __user *)d->iov.iov_base, d->iov.iov_len)) return 0;

    old_st = kmalloc(sizeof(*old_st), GFP_KERNEL);
    new_st = kmalloc(sizeof(*new_st), GFP_KERNEL);
    if (!old_st || !new_st) goto out;

    copy_size = min(d->iov.iov_len, sizeof(*old_st));
    if (copy_from_user(old_st, (void __user *)d->iov.iov_base, copy_size) != 0)
        goto out;

    memcpy(new_st, old_st, sizeof(*new_st));
    memset(new_st->dbg_regs, 0, sizeof(new_st->dbg_regs));
    for (i = 0; i < ARRAY_SIZE(old_st->dbg_regs); i++) {
        if (!is_our_bp_addr(old_st->dbg_regs[i].addr)) {
            memcpy(&new_st->dbg_regs[y++], &old_st->dbg_regs[i],
                   sizeof(old_st->dbg_regs[i]));
        }
    }
    if (copy_to_user((void __user *)d->iov.iov_base, new_st, copy_size) == 0)
        pr_info_ratelimited("usa_hook: hid HW BP from ptrace GETREGSET\n");

out:
    kfree(old_st);
    kfree(new_st);
    return 0;
}

static struct kretprobe kretp_ptrace = {
    .kp.symbol_name = "arch_ptrace",
    .data_size      = sizeof(struct hook_ptrace_data),
    .entry_handler  = entry_ptrace_handler,
    .handler        = ret_ptrace_handler,
    .maxactive      = 20,
};

static long usa_proc_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    unsigned long addr;

    switch (cmd) {
    case USA_IOC_REGISTER_COMM:
        /* 注册 HW BP 给 caller, 用 rwProcMem33 next-instruction 方案防死循环 */
        if (copy_from_user(&addr, (void __user *)arg, sizeof(addr)))
            return -EFAULT;
        if (!comm_addr) comm_addr = addr;
        if (!comm_pid) comm_pid = current->tgid;
        return register_bp_for_current(addr);

    case USA_IOC_SEND_CMD: {
        /* PAN-safe: 不直接 deref user pointer, 用 copy_from/to_user */
        struct usa_shm __user *ushm;
        uint32_t done_state = SHM_STATE_DONE;
        if (copy_from_user(&addr, (void __user *)arg, sizeof(addr)))
            return -EFAULT;
        if (!addr) return -EINVAL;
        ushm = (struct usa_shm __user *)addr;
        process_command(ushm);
        /* state 是 volatile uint32_t, put_user 不接受 volatile qualifier
         * 用 copy_to_user 走 raw bytes 绕过 */
        if (copy_to_user((void __user *)&ushm->state, &done_state, sizeof(done_state)))
            return -EFAULT;
        return 0;
    }

    default:
        return -ENOTTY;
    }
}

static const struct proc_ops usa_proc_ops = {
    .proc_ioctl = usa_proc_ioctl,
    .proc_compat_ioctl = usa_proc_ioctl,
};

static struct proc_dir_entry *usa_proc_entry;

static int register_comm_watchpoint(void)
{
    /* 创建 /proc/usa_hook 给 overlay ioctl */
    usa_proc_entry = proc_create("usa_hook", 0666, NULL, &usa_proc_ops);
    if (!usa_proc_entry) {
        pr_info("usa_hook: proc_create failed\n");
        return -ENOMEM;
    }
    pr_info("usa_hook: /proc/usa_hook created, waiting for overlay ioctl\n");
    return 0;
}

/* =====================================================================
 * 隐藏
 * ===================================================================== */

static struct list_head *saved_prev;
static int module_hidden;

static void __maybe_unused hide_module(void)
{
    struct kernfs_node *kn;
    if (module_hidden) return;

    saved_prev = THIS_MODULE->list.prev;
    list_del_init(&THIS_MODULE->list);

    if (fn_kernfs_remove) {
        kn = THIS_MODULE->mkobj.kobj.sd;
        if (kn) {
            fn_kernfs_remove(kn);
            THIS_MODULE->mkobj.kobj.sd = NULL;
        }
    }

    module_hidden = 1;
}

static void unhide_module(void)
{
    if (!module_hidden || !saved_prev) return;
    list_add(&THIS_MODULE->list, saved_prev);
    module_hidden = 0;
}

/* =====================================================================
 * 初始化 / 卸载
 * ===================================================================== */

static int __init driver_entry(void)
{
    int ret;

    ret = resolve_kallsyms();
    if (ret) return ret;

    ret = resolve_symbols();
    if (ret) {
        pr_info("usa_hook: resolve_symbols failed %d\n", ret);
        return ret;
    }

    /* 注册通信 HW watchpoint */
    ret = register_comm_watchpoint();
    if (ret) {
        pr_info("usa_hook: register_comm_watchpoint failed %d\n", ret);
        return ret;
    }

    /* 注册反 ptrace 检测 — 让外部 PTRACE_GETREGSET 看不到我们的 HW BP */
    ret = register_kretprobe(&kretp_ptrace);
    if (ret < 0) {
        pr_info("usa_hook: register_kretprobe(arch_ptrace) failed %d (continuing)\n", ret);
        /* 非致命, 继续 */
    } else {
        pr_info("usa_hook: anti-ptrace kretprobe registered\n");
    }

    /* 隐藏模块 (调试期关闭, 方便 rmmod) */
    /* hide_module(); */

    memset(shoot_slots, 0, sizeof(shoot_slots));
    pr_info("usa_hook: loaded, comm_pid=%d comm_addr=0x%lx\n",
            comm_pid, comm_addr);
    return 0;
}

static void __exit driver_unload(void)
{
    int i;

    /* 注销反 ptrace kretprobe */
    if (kretp_ptrace.kp.addr)
        unregister_kretprobe(&kretp_ptrace);

    /* 删除 /proc 入口 */
    if (usa_proc_entry) {
        proc_remove(usa_proc_entry);
        usa_proc_entry = NULL;
    }

    /* 拆所有 Shoot HWBP slot (B route): perf_event_release_kernel 安全 (无 inode/mmap_lock 依赖).
     * 注意必须在 process 上下文调; driver_unload 就是 process ctx 所以 OK. */
    if (fn_perf_event_release_kernel) {
        int si;
        for (si = 0; si < MAX_SHOOT_SLOTS; si++) {
            unsigned long fl;
            struct perf_event *bp = NULL;
            struct task_struct *tk = NULL;
            spin_lock_irqsave(&shoot_lock, fl);
            if (shoot_slots[si].active) {
                bp = shoot_slots[si].bp;
                tk = shoot_slots[si].task;
                shoot_slots[si].bp     = NULL;
                shoot_slots[si].task   = NULL;
                shoot_slots[si].active = 0;
            }
            spin_unlock_irqrestore(&shoot_lock, fl);
            if (bp) fn_perf_event_release_kernel(bp);
            if (tk) put_task_struct(tk);
        }
    }

    /* 注销所有线程的通信 HW BP */
    if (fn_unregister_hw_breakpoint) {
        for (i = 0; i < comm_bp_count; i++) {
            if (comm_bps[i]) {
                fn_unregister_hw_breakpoint(comm_bps[i]);
                comm_bps[i] = NULL;
            }
        }
        comm_bp_count = 0;
    }

    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
