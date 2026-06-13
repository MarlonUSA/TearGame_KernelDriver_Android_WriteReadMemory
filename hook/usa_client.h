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
#include <sys/mman.h>
#include <sys/syscall.h>

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

static struct usa_shm *_usa_shm = NULL;
static uint32_t _usa_magic = 0x55aabbcc;
static pthread_mutex_t _usa_mtx = PTHREAD_MUTEX_INITIALIZER;

/* ====== 初始化: 分配 + mlock + 加载驱动 ====== */

/*
 * 调用方式 (overlay 主进程内):
 *   usa_shm_setup() 分配 4KB 对齐缓冲, 返回地址
 *   然后 overlay 用 system() 执行 loader.sh, 传 comm_pid + comm_addr
 *   loader.sh 做 insmod 加载驱动
 */
static inline unsigned long usa_shm_setup(void)
{
    void *buf = NULL;
    /* 4KB 对齐分配 */
    if (posix_memalign(&buf, 4096, 4096) != 0) return 0;
    memset(buf, 0, 4096);
    /* mlock 防止换出 (内核访问时不 page fault) */
    if (mlock(buf, 4096) != 0) {
        /* 不 fatal, 继续 */
    }
    _usa_shm = (struct usa_shm *)buf;
    _usa_shm->state = SHM_STATE_IDLE;
    return (unsigned long)buf;
}

static inline int usa_load_driver(const char *ko_path)
{
    char cmd[512];
    if (!_usa_shm) return -1;
    snprintf(cmd, sizeof(cmd),
             "su -c 'insmod %s comm_pid=%d comm_addr=0x%lx usa_magic=0x%x'",
             ko_path, getpid(), (unsigned long)_usa_shm, _usa_magic);
    return system(cmd);
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
    int retries;
    int64_t result;

    if (!_usa_shm) return -ENODEV;
    pthread_mutex_lock(&_usa_mtx);

    /* 先写所有字段 (这些写入不在 watchpoint 监视范围内) */
    _usa_shm->magic  = _usa_magic;
    _usa_shm->cmd    = cmd;
    _usa_shm->pid    = pid;
    _usa_shm->addr   = addr;
    _usa_shm->size   = size;
    _usa_shm->result = 0;

    /* 最后写 state = PENDING
     * 这一行写入触发 HW Write Watchpoint
     * → 内核 comm_bp_handler 立刻执行 (在 overlay 线程上下文)
     * → 处理完毕, 写 state = DONE
     * → 这次写返回时, state 已经是 DONE */
    __atomic_store_n(&_usa_shm->state, SHM_STATE_PENDING, __ATOMIC_RELEASE);

    /* HW watchpoint handler 同步执行完了, 检查结果 */
    if (__atomic_load_n(&_usa_shm->state, __ATOMIC_ACQUIRE) == SHM_STATE_DONE) {
        result = _usa_shm->result;
        __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&_usa_mtx);
        return result;
    }

    /* 备用轮询 (handler 应该是同步的, 这里几乎用不到) */
    for (retries = 0; retries < 1000; retries++) {
        if (__atomic_load_n(&_usa_shm->state, __ATOMIC_ACQUIRE) == SHM_STATE_DONE) {
            result = _usa_shm->result;
            __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&_usa_mtx);
            return result;
        }
        usleep(10);
    }

    __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&_usa_mtx);
    return -ETIMEDOUT;
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
    /* 简单方式: 试调用一个无害命令, 看 result 是否变化 */
    if (!_usa_shm) return 0;
    int64_t ret = usa_send_cmd(OP_MODULE_BASE, getpid(), 0, 0);
    return (ret != -ENODEV && ret != -ETIMEDOUT);
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
