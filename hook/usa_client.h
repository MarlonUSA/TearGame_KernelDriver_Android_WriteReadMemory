/**
 * usa_client.h — kprobe getpid 触发 + 共享页通信
 *
 * 流程:
 *   usa_shm_init()      → mmap /proc/gki_tracing 获取共享页
 *   写命令到共享页
 *   getpid()            → 触发 kprobe → 内核处理命令
 *   读结果从共享页
 */

#ifndef USA_CLIENT_H
#define USA_CLIENT_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* 操作码 */
#define OP_READ_MEM     0x801
#define OP_WRITE_MEM    0x802
#define OP_MODULE_BASE  0x803
#define OP_INJECT_SO    0x820
#define OP_HIDE_MAPS    0x830

/* 共享页状态 */
#define SHM_STATE_IDLE    0
#define SHM_STATE_PENDING 1
#define SHM_STATE_DONE    2

/* 共享页布局 (和 entry.c 一致) */
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
static uint32_t _usa_magic = 0;
static pthread_mutex_t _usa_mtx = PTHREAD_MUTEX_INITIALIZER;

#define USA_MAGIC_PATH "/data/local/tmp/.gs_m"
#define USA_PROC_PATH  "/proc/gki_tracing"

/* ====== 初始化 ====== */

static inline int usa_shm_init(void)
{
    int fd;
    FILE *f;
    char buf[32] = {0};

    f = fopen(USA_MAGIC_PATH, "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f))
            _usa_magic = (uint32_t)strtoul(buf, NULL, 16);
        fclose(f);
    }

    fd = open(USA_PROC_PATH, O_RDWR);
    if (fd < 0) return -1;

    _usa_shm = (struct usa_shm *)mmap(NULL, 4096,
                                       PROT_READ | PROT_WRITE,
                                       MAP_SHARED, fd, 0);
    close(fd);

    if (_usa_shm == MAP_FAILED) {
        _usa_shm = NULL;
        return -1;
    }
    return 0;
}

static inline void usa_shm_cleanup(void)
{
    if (_usa_shm) { munmap(_usa_shm, 4096); _usa_shm = NULL; }
}

/* ====== 发送命令: 写共享页 → getpid() 触发 kprobe → 读结果 ====== */

static inline int64_t usa_send_cmd(uint32_t cmd, int32_t pid,
                                    uint64_t addr, uint64_t size)
{
    int retries;
    int64_t result;

    if (!_usa_shm) return -1;
    pthread_mutex_lock(&_usa_mtx);

    _usa_shm->magic  = _usa_magic;
    _usa_shm->cmd    = cmd;
    _usa_shm->pid    = pid;
    _usa_shm->addr   = addr;
    _usa_shm->size   = size;
    _usa_shm->result = 0;
    __atomic_store_n(&_usa_shm->state, SHM_STATE_PENDING, __ATOMIC_RELEASE);

    /* getpid() 触发 kprobe → 内核在 pre_handler 里处理命令 */
    syscall(__NR_ioprio_get, 0, 0);

    /* kprobe pre_handler 同步执行完毕, 检查结果 */
    if (__atomic_load_n(&_usa_shm->state, __ATOMIC_ACQUIRE) == SHM_STATE_DONE) {
        result = _usa_shm->result;
        __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&_usa_mtx);
        return result;
    }

    /* 备用: 等几次 (不应该到这里, pre_handler 是同步的) */
    for (retries = 0; retries < 100; retries++) {
        syscall(__NR_ioprio_get, 0, 0);
        if (__atomic_load_n(&_usa_shm->state, __ATOMIC_ACQUIRE) == SHM_STATE_DONE) {
            result = _usa_shm->result;
            __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&_usa_mtx);
            return result;
        }
        usleep(100);
    }

    __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&_usa_mtx);
    return -1;
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

/* ====== 检测驱动 ====== */

static inline int usa_driver_loaded(void)
{
    return (_usa_shm != NULL) || (access(USA_PROC_PATH, F_OK) == 0);
}

/* ====== SO 注入 (传入 dlopen 地址, 由 overlay 计算) ====== */

static inline int usa_inject_so(int pid, const char *path, unsigned long dlopen_addr)
{
    if (!_usa_shm) return -999;
    pthread_mutex_lock(&_usa_mtx);

    __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
    memset(_usa_shm->name, 0, sizeof(_usa_shm->name));
    strncpy(_usa_shm->name, path, sizeof(_usa_shm->name) - 1);
    _usa_shm->magic  = _usa_magic;
    _usa_shm->cmd    = OP_INJECT_SO;
    _usa_shm->pid    = pid;
    _usa_shm->addr   = dlopen_addr;
    _usa_shm->size   = 0;
    _usa_shm->result = 0;
    __atomic_store_n(&_usa_shm->state, SHM_STATE_PENDING, __ATOMIC_RELEASE);

    /* 触发 kprobe */
    syscall(__NR_ioprio_get, 0, 0);

    /* Shoot 注入是异步的 (等游戏线程触发 UXN 陷阱)
     * 但 vm_mmap + shellcode 写入是同步的 */
    int retries;
    for (retries = 0; retries < 1000; retries++) {
        if (__atomic_load_n(&_usa_shm->state, __ATOMIC_ACQUIRE) == SHM_STATE_DONE)
            break;
        syscall(__NR_ioprio_get, 0, 0);
        usleep(100);
    }

    int64_t result = _usa_shm->result;
    __atomic_store_n(&_usa_shm->state, SHM_STATE_IDLE, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&_usa_mtx);
    return (int)result;
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
