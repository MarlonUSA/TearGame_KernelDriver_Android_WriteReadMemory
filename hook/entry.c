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
#include <linux/kernfs.h>
#include <linux/pgtable.h>
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

typedef void (*use_mm_fn_t)(struct mm_struct *);
static use_mm_fn_t fn_use_mm;
static use_mm_fn_t fn_unuse_mm;

typedef struct perf_event *(*register_user_hw_breakpoint_t)(
    struct perf_event_attr *, perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *);
static register_user_hw_breakpoint_t fn_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t fn_unregister_hw_breakpoint;

typedef void (*kernfs_remove_t)(struct kernfs_node *);
static kernfs_remove_t fn_kernfs_remove;

static int resolve_symbols(void)
{
    if (!kln_func) return -EFAULT;
    fn_find_task_by_vpid = (find_task_by_vpid_t)kln_func("find_task_by_vpid");
    fn_vm_mmap = (vm_mmap_t)kln_func("vm_mmap");
    fn_use_mm = (use_mm_fn_t)kln_func("kthread_use_mm");
    fn_unuse_mm = (use_mm_fn_t)kln_func("kthread_unuse_mm");
    if (!fn_use_mm) fn_use_mm = (use_mm_fn_t)kln_func("use_mm");
    if (!fn_unuse_mm) fn_unuse_mm = (use_mm_fn_t)kln_func("unuse_mm");
    fn_register_user_hw_breakpoint = (register_user_hw_breakpoint_t)kln_func("register_user_hw_breakpoint");
    fn_unregister_hw_breakpoint = (unregister_hw_breakpoint_t)kln_func("unregister_hw_breakpoint");
    fn_kernfs_remove = (kernfs_remove_t)kln_func("kernfs_remove");
    return fn_find_task_by_vpid && fn_register_user_hw_breakpoint ? 0 : -ENOENT;
}

/* =====================================================================
 * 页表 PTE 操作 (Shoot 注入用 UXN)
 * ===================================================================== */

static pte_t *get_user_ptep(struct mm_struct *mm, unsigned long addr)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd;
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

#define PTE_UXN_BIT (1ULL << 54)

static void set_pte_uxn(pte_t *ptep, unsigned long addr)
{
    pte_t pte = READ_ONCE(*ptep);
    set_pte(ptep, __pte(pte_val(pte) | PTE_UXN_BIT));
    __flush_tlb_kernel_pgtable(addr);
}

static void clear_pte_uxn(pte_t *ptep, unsigned long addr)
{
    pte_t pte = READ_ONCE(*ptep);
    set_pte(ptep, __pte(pte_val(pte) & ~PTE_UXN_BIT));
    __flush_tlb_kernel_pgtable(addr);
}

/* =====================================================================
 * Shoot 注入系统 (HW exec BP, 一次性)
 * ===================================================================== */

static const uint32_t shoot_shellcode[] = {
    0xA9BF7BFD, 0x910003FD, 0x10000140, 0xD2800041,
    0xF85F8010, 0xD63F0200, 0xA8C17BFD, 0xF8500010,
    0xD61F0200,
};
#define SHOOT_CODE_SIZE  36
#define SHOOT_ORIGPC_OFF 36
#define SHOOT_DLOPEN_OFF 44
#define SHOOT_PATH_OFF   52

#define MAX_SHOOT_SLOTS 4
static struct {
    int active;
    pid_t target_pid;
    unsigned long trap_addr;
    pte_t *trap_ptep;
    unsigned long shellcode_addr;
    struct perf_event *bp_event;
} shoot_slots[MAX_SHOOT_SLOTS];

static DEFINE_SPINLOCK(shoot_lock);

static void shoot_bp_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&shoot_lock, flags);
    for (i = 0; i < MAX_SHOOT_SLOTS; i++) {
        if (shoot_slots[i].active && shoot_slots[i].bp_event == bp) {
            regs->pc = shoot_slots[i].shellcode_addr;
            if (shoot_slots[i].trap_ptep)
                clear_pte_uxn(shoot_slots[i].trap_ptep, shoot_slots[i].trap_addr);
            shoot_slots[i].active = 0;
            break;
        }
    }
    spin_unlock_irqrestore(&shoot_lock, flags);
}

/* 在 workqueue 中执行 (vm_mmap 需要 sleep) */
static int do_shoot_inject(pid_t target_pid, const char *so_path,
                           unsigned long dlopen_addr)
{
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long remote_page, code_addr;
    unsigned char buf[512];
    size_t total_size;
    pte_t *ptep;
    struct perf_event_attr attr;
    struct perf_event *bp;
    int slot;
    unsigned long flags;

    if (!fn_vm_mmap || !fn_use_mm || !fn_unuse_mm) return -ENOSYS;
    if (!dlopen_addr) return -EINVAL;

    rcu_read_lock();
    task = fn_find_task_by_vpid(target_pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) return -ESRCH;

    mm = task->mm;
    if (!mm) { put_task_struct(task); return -EINVAL; }

    mmget(mm);
    fn_use_mm(mm);
    remote_page = fn_vm_mmap(NULL, 0, 4096,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, 0);
    fn_unuse_mm(mm);
    mmput(mm);

    if (IS_ERR_VALUE(remote_page)) {
        put_task_struct(task);
        return (int)(long)remote_page;
    }

    code_addr = get_module_base(target_pid, "libUE4.so");
    if (!code_addr) code_addr = get_module_base(target_pid, "linker64");
    if (!code_addr) { put_task_struct(task); return -ENODATA; }
    code_addr += 0x1000;

    total_size = SHOOT_PATH_OFF + strlen(so_path) + 1;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, shoot_shellcode, SHOOT_CODE_SIZE);
    *(unsigned long *)(buf + SHOOT_ORIGPC_OFF) = code_addr;
    *(unsigned long *)(buf + SHOOT_DLOPEN_OFF) = dlopen_addr;
    memcpy(buf + SHOOT_PATH_OFF, so_path, strlen(so_path) + 1);

    if (!write_process_memory(target_pid, remote_page, buf, total_size)) {
        put_task_struct(task);
        return -EIO;
    }

    ptep = get_user_ptep(mm, code_addr);
    if (!ptep) { put_task_struct(task); return -EFAULT; }

    hw_breakpoint_init(&attr);
    attr.bp_addr = code_addr;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.bp_type = HW_BREAKPOINT_X;

    bp = fn_register_user_hw_breakpoint(&attr, shoot_bp_handler, NULL, task);
    if (IS_ERR(bp)) { put_task_struct(task); return (int)PTR_ERR(bp); }

    spin_lock_irqsave(&shoot_lock, flags);
    for (slot = 0; slot < MAX_SHOOT_SLOTS; slot++)
        if (!shoot_slots[slot].active) break;
    if (slot >= MAX_SHOOT_SLOTS) {
        spin_unlock_irqrestore(&shoot_lock, flags);
        fn_unregister_hw_breakpoint(bp);
        put_task_struct(task);
        return -ENOMEM;
    }
    shoot_slots[slot].active = 1;
    shoot_slots[slot].target_pid = target_pid;
    shoot_slots[slot].trap_addr = code_addr;
    shoot_slots[slot].trap_ptep = ptep;
    shoot_slots[slot].shellcode_addr = remote_page;
    shoot_slots[slot].bp_event = bp;
    spin_unlock_irqrestore(&shoot_lock, flags);

    set_pte_uxn(ptep, code_addr);
    put_task_struct(task);
    return 0;
}

/* Shoot 工作队列 */
struct shoot_work {
    struct work_struct work;
    pid_t target_pid;
    char so_path[256];
    unsigned long dlopen_addr;
};

static void shoot_work_fn(struct work_struct *w)
{
    struct shoot_work *sw = container_of(w, struct shoot_work, work);
    do_shoot_inject(sw->target_pid, sw->so_path, sw->dlopen_addr);
    kfree(sw);
}

static int queue_shoot_inject(pid_t pid, const char *so_path, unsigned long dlopen_addr)
{
    struct shoot_work *sw = kmalloc(sizeof(*sw), GFP_ATOMIC);
    if (!sw) return -ENOMEM;
    INIT_WORK(&sw->work, shoot_work_fn);
    sw->target_pid = pid;
    strncpy(sw->so_path, so_path, sizeof(sw->so_path) - 1);
    sw->so_path[sizeof(sw->so_path) - 1] = 0;
    sw->dlopen_addr = dlopen_addr;
    schedule_work(&sw->work);
    return 0;  /* 异步派发, 立即返回 */
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

static void process_command(struct usa_shm *shm)
{
    uint32_t cmd = shm->cmd;
    int32_t pid = shm->pid;
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
        shm->result = queue_shoot_inject(pid, shm->name, (unsigned long)addr);
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
 * 通信 HW Watchpoint Handler
 *
 * overlay 写 shm->state = PENDING 时触发
 * current == overlay 的线程 (HW BP scoped to comm_pid task)
 * ===================================================================== */

static struct perf_event *comm_bp;

static void comm_bp_handler(struct perf_event *bp,
                            struct perf_sample_data *data,
                            struct pt_regs *regs)
{
    struct usa_shm *shm = (struct usa_shm *)comm_addr;
    uint32_t state;

    if (!comm_addr) return;

    /* current 是 overlay (HW BP scoped). 直接读 user 内存
     * 此时 overlay 刚写完 state, 页一定在 TLB 里 */
    state = READ_ONCE(shm->state);
    if (state != SHM_STATE_PENDING) return;

    if (shm->magic != (uint32_t)(usa_magic & 0xFFFFFFFF)) return;

    smp_rmb();
    process_command(shm);
    smp_wmb();

    WRITE_ONCE(shm->state, SHM_STATE_DONE);
}

static int register_comm_watchpoint(void)
{
    struct task_struct *task;
    struct perf_event_attr attr;
    struct perf_event *bp;

    if (comm_pid < 0 || !comm_addr) {
        pr_info("usa_hook: invalid comm_pid=%d or comm_addr=0x%lx\n",
                comm_pid, comm_addr);
        return -EINVAL;
    }

    rcu_read_lock();
    task = fn_find_task_by_vpid(comm_pid);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    if (!task) {
        pr_info("usa_hook: overlay task pid=%d not found\n", comm_pid);
        return -ESRCH;
    }

    hw_breakpoint_init(&attr);
    attr.bp_addr = comm_addr;            /* overlay 用户内存地址 */
    attr.bp_len  = HW_BREAKPOINT_LEN_4;  /* 监视 4 字节 (state 字段) */
    attr.bp_type = HW_BREAKPOINT_W;      /* 写触发 */

    bp = fn_register_user_hw_breakpoint(&attr, comm_bp_handler, NULL, task);
    put_task_struct(task);

    if (IS_ERR(bp)) {
        pr_info("usa_hook: register HW watchpoint failed %ld\n", PTR_ERR(bp));
        return (int)PTR_ERR(bp);
    }

    comm_bp = bp;
    return 0;
}

/* =====================================================================
 * 隐藏
 * ===================================================================== */

static struct list_head *saved_prev;
static int module_hidden;

static void hide_module(void)
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

    /* 隐藏模块 */
    hide_module();

    memset(shoot_slots, 0, sizeof(shoot_slots));
    pr_info("usa_hook: loaded, comm_pid=%d comm_addr=0x%lx\n",
            comm_pid, comm_addr);
    return 0;
}

static void __exit driver_unload(void)
{
    int i;

    /* 注销 Shoot HW BPs */
    for (i = 0; i < MAX_SHOOT_SLOTS; i++) {
        if (shoot_slots[i].bp_event && fn_unregister_hw_breakpoint) {
            fn_unregister_hw_breakpoint(shoot_slots[i].bp_event);
            shoot_slots[i].bp_event = NULL;
        }
    }

    /* 注销通信 HW BP */
    if (comm_bp && fn_unregister_hw_breakpoint) {
        fn_unregister_hw_breakpoint(comm_bp);
        comm_bp = NULL;
    }

    unhide_module();
}

module_init(driver_entry);
module_exit(driver_unload);
