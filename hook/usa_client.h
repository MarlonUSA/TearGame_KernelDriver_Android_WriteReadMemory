/**
 * usa_client.h v15 — SKJH 通信协议
 *
 * 流程:
 *   1. overlay 启动, malloc 4KB 对齐缓冲, mlock 锁定
 *   2. overlay exec loader.sh, 传 comm_pid + comm_addr 给 insmod
 *   3. overlay 写命令到缓冲, 调 getpid() 触发 kprobe
 *   4. 内核 kprobe handler 直接读 overlay 用户内存, 处理, 写回
 *   5. overlay 读结果
 */

#ifndef USA_CLIENT_H
#define USA_CLIENT_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#define USA_IOC_MAGIC 'U'
#define USA_IOC_REGISTER_COMM _IOW(USA_IOC_MAGIC, 1, unsigned long)
#define USA_IOC_SEND_CMD      _IOWR(USA_IOC_MAGIC, 2, unsigned long)

/* 操作码 */
#define OP_READ_MEM     0x801
#define OP_WRITE_MEM    0x802
#define OP_MODULE_BASE  0x803
#define OP_INJECT_SO    0x820
#define OP_HIDE_MAPS    0x830

/* 共享缓冲状态 */
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

/* 跨翻译单元共享: 必须只在一个 .o (定义 USA_CLIENT_DEFINE 的 TU, 如 main.cpp) 实例化
 * 其他 TU 仅 extern 引用同一份, 否则 main.cpp 设置的 _usa_shm 在别处仍是 NULL */
#ifdef USA_CLIENT_DEFINE
struct usa_shm *_usa_shm = NULL;
uint32_t _usa_magic = 0x55aabbcc;
pthread_mutex_t _usa_mtx = PTHREAD_MUTEX_INITIALIZER;
pid_t _usa_comm_tid = 0;
#else
extern struct usa_shm *_usa_shm;
extern uint32_t _usa_magic;
extern pthread_mutex_t _usa_mtx;
extern pid_t _usa_comm_tid;
#endif
/* TLS: 每线程一份, 各 TU 引用同一 TLS slot (链接器去重) */
static __thread int _usa_fd = -1;

/* ====== 初始化: 分配 + mlock + 加载驱动 ====== */

/*
 * 调用方式 (overlay 主进程内):
 *   usa_shm_setup() 分配 4KB 对齐缓冲, 返回地址
 *   然后 overlay 用 system() 执行 loader.sh, 传 comm_pid + comm_addr
 *   loader.sh 做 insmod 加载驱动
 */
static inline unsigned long usa_shm_setup(void)
{
    void *buf;
    struct rlimit rl;

    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_MEMLOCK, &rl);

    /* 用 mmap 而不是 posix_memalign:
     * scudo allocator 返回的内存 VMA flags 可能让 kernel HW BP 拒绝
     * mmap MAP_PRIVATE|MAP_ANONYMOUS 是干净独立的 VMA */
    buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        fprintf(stderr, "usa_shm_setup: mmap failed: %s\n", strerror(errno));
        return 0;
    }

    if (mlock(buf, 4096) != 0) {
        fprintf(stderr, "usa_shm_setup: mlock failed: %s (errno=%d) — 继续但 handler 可能 page fault\n",
                strerror(errno), errno);
    }

    /* fault-in: 触摸所有字节 */
    memset(buf, 0, 4096);
    *(volatile uint32_t *)buf = 0;  /* 确保第一个 word 已分配 */

    _usa_shm = (struct usa_shm *)buf;
    _usa_shm->state = SHM_STATE_IDLE;
    return (unsigned long)buf;
}

static inline int usa_load_driver(const char *ko_path)
{
    char cmd[512];
    if (!_usa_shm) return -1;
    snprintf(cmd, sizeof(cmd),
             "su -c 'insmod %s usa_magic=0x%x'",
             ko_path, _usa_magic);
    return system(cmd);
}

/* 注册 BP 给当前线程 (rwProcMem33 next-instruction 方案已修死循环 bug).
 * 仍保留 ioctl SEND_CMD 作 fallback / explicit 同步路径. */
static inline int usa_register_thread(void)
{
    int fd, ret;
    unsigned long addr;
    if (!_usa_shm) return -1;
    addr = (unsigned long)_usa_shm;
    fd = open("/proc/usa_hook", O_RDWR);
    if (fd < 0) return -1;
    ret = ioctl(fd, USA_IOC_REGISTER_COMM, &addr);
    close(fd);
    return ret;
}

static inline void usa_shm_cleanup(void)
{
    if (_usa_shm) {
        munlock(_usa_shm, 4096);
        free(_usa_shm);
        _usa_shm = NULL;
    }
}

/* ====== 发送命令: 写共享页 → getpid() 触发 kprobe → 读结果 ====== */

static inline int64_t usa_send_cmd(uint32_t cmd, int32_t pid,
                                    uint64_t addr, uint64_t size)
{
    int64_t result;
    unsigned long shm_addr;

    if (!_usa_shm) return -ENODEV;

    /* 每线程打开自己的 fd (TLS) */
    if (_usa_fd < 0) {
        _usa_fd = open("/proc/usa_hook", O_RDWR);
        if (_usa_fd < 0) return -ENODEV;
    }

    pthread_mutex_lock(&_usa_mtx);

    _usa_shm->magic  = _usa_magic;
    _usa_shm->cmd    = cmd;
    _usa_shm->pid    = pid;
    _usa_shm->addr   = addr;
    _usa_shm->size   = size;
    _usa_shm->result = 0;
    /* 注意: 故意不写 state = SHM_STATE_PENDING.
     * 那条 STR 会触发 HW Watchpoint, 而 ARM64 kernel 6.12 对 custom overflow handler
     * 不做 single-step (mainline 6.13+ 才修), 导致 STR 死循环.
     * 通信走纯 ioctl 同步处理, 不依赖 BP fire. */

    shm_addr = (unsigned long)_usa_shm;
    if (ioctl(_usa_fd, USA_IOC_SEND_CMD, &shm_addr) < 0) {
        pthread_mutex_unlock(&_usa_mtx);
        return -errno;
    }

    result = _usa_shm->result;
    _usa_shm->state = SHM_STATE_IDLE;
    pthread_mutex_unlock(&_usa_mtx);
    return result;
}

/* ====== 内存读写 ====== */

static inline int usa_read(int pid, unsigned long addr, void *buf, unsigned long size)
{
    int64_t ret;
    if (!_usa_shm || size > sizeof(_usa_shm->data)) return -1;
    ret = usa_send_cmd(OP_READ_MEM, pid, addr, size);
    if (ret == 0)
        memcpy(buf, _usa_shm->data, size);
    return (int)ret;
}

static inline int usa_write(int pid, unsigned long addr, void *buf, unsigned long size)
{
    if (!_usa_shm || size > sizeof(_usa_shm->data)) return -1;
    memcpy(_usa_shm->data, buf, size);
    return (int)usa_send_cmd(OP_WRITE_MEM, pid, addr, size);
}

static inline unsigned long usa_get_module_base(int pid, const char *name)
{
    if (!_usa_shm) return 0;
    memset(_usa_shm->name, 0, sizeof(_usa_shm->name));
    strncpy(_usa_shm->name, name, sizeof(_usa_shm->name) - 1);
    int64_t ret = usa_send_cmd(OP_MODULE_BASE, pid, 0, 0);
    return (ret > 0) ? (unsigned long)ret : 0;
}

static inline int usa_driver_loaded(void)
{
    /* 驱动加载会创建 /proc/usa_hook 节点, 直接 access 检查
     * 不调 usa_send_cmd 避免依赖 BP / ioctl 副作用 */
    if (!_usa_shm) return 0;
    if (access("/proc/usa_hook", F_OK) != 0) return 0;
    return 1;
}

/* ====== SO 注入 (异步, Shoot 系统) ====== */

static inline int usa_inject_so(int pid, const char *path, unsigned long dlopen_addr)
{
    if (!_usa_shm) return -ENODEV;
    pthread_mutex_lock(&_usa_mtx);
    memset(_usa_shm->name, 0, sizeof(_usa_shm->name));
    strncpy(_usa_shm->name, path, sizeof(_usa_shm->name) - 1);
    pthread_mutex_unlock(&_usa_mtx);
    /* 返回 -EAGAIN 表示已派发到 workqueue, 用户态需轮询完成状态 */
    return (int)usa_send_cmd(OP_INJECT_SO, pid, dlopen_addr, 0);
}

/* ====== Maps 隐藏 ====== */

static inline int usa_hide_maps(int pid, const char *lib_name)
{
    if (!_usa_shm) return -1;
    memset(_usa_shm->name, 0, sizeof(_usa_shm->name));
    strncpy(_usa_shm->name, lib_name, sizeof(_usa_shm->name) - 1);
    return (int)usa_send_cmd(OP_HIDE_MAPS, pid, 0, 0);
}

/* ====== C++ 模板 ====== */

#ifdef __cplusplus
template <typename T>
static inline T usa_read_val(int pid, unsigned long addr) {
    T val{};
    usa_read(pid, addr, &val, sizeof(T));
    return val;
}

template <typename T>
static inline void usa_write_val(int pid, unsigned long addr, T val) {
    usa_write(pid, addr, &val, sizeof(T));
}
#endif

#endif /* USA_CLIENT_H */
