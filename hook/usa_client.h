/**
 * usa_client.h — Hook 版用户态通信接口 v2
 *
 * 不需要 open 任何设备文件, 直接用 syscall 通信
 *
 * v2: 修复 opcode 和驱动一致 + 硬件断点/看门狗支持
 *
 * 用法:
 *   #include "usa_client.h"
 *
 *   // 内存读写
 *   usa_read(pid, addr, buf, size);
 *   usa_write(pid, addr, buf, size);
 *   unsigned long base = usa_get_module_base(pid, "libUE4.so");
 *
 *   // 硬件断点 (找"谁在访问这个地址")
 *   usa_set_watchpoint(0, pid, addr, USA_HW_BP_WRITE, 4);
 *   ... 等待游戏访问 ...
 *   usa_hw_bp_hit info;
 *   usa_get_bp_info(0, &info);
 *   if (info.hit) printf("指令 0x%lx 写了这个地址!", info.hit_pc);
 */

#ifndef USA_CLIENT_H
#define USA_CLIENT_H

#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* hook getpid — 和正常 getpid 调用混在一起不起疑 */
#define USA_SYSCALL_NR __NR_getpid  /* 172 on arm64 */
#define USA_MAGIC      0x55534100

/* ====== 操作码 (必须和 comm.h 一致!) ====== */
#define OP_READ_MEM     0x801
#define OP_WRITE_MEM    0x802
#define OP_MODULE_BASE  0x803
#define OP_SET_HW_BP    0x810
#define OP_CLEAR_HW_BP  0x811
#define OP_GET_BP_INFO  0x812
#define OP_CLEAR_ALL_BP 0x813
#define OP_INJECT_SO    0x820

/* ====== 硬件断点类型 ====== */
#define USA_HW_BP_READ   1
#define USA_HW_BP_WRITE  2
#define USA_HW_BP_RW     3
#define USA_MAX_HW_BP    4

/* ====== 结构体 ====== */

typedef struct {
    int pid;
    unsigned long addr;
    void *buffer;
    unsigned long size;
} usa_copy_memory;

typedef struct {
    int pid;
    char *name;
    unsigned long base;
} usa_module_base;

typedef struct {
    int pid;
    int index;           /* 0~3 */
    unsigned long addr;
    int type;            /* USA_HW_BP_READ/WRITE/RW */
    int len;             /* 1, 2, 4, 8 */
} usa_hw_bp_request;

typedef struct {
    int index;
    int hit;
    unsigned long hit_addr;
    unsigned long hit_pc;
    unsigned long regs[31];  /* x0~x30 */
    int hit_count;
} usa_hw_bp_hit;

/* ====== 内存读写 ====== */

static inline int usa_read(int pid, unsigned long addr, void *buf, unsigned long size)
{
    usa_copy_memory cm = { .pid = pid, .addr = addr, .buffer = buf, .size = size };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_READ_MEM, &cm);
}

static inline int usa_write(int pid, unsigned long addr, void *buf, unsigned long size)
{
    usa_copy_memory cm = { .pid = pid, .addr = addr, .buffer = buf, .size = size };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_WRITE_MEM, &cm);
}

static inline unsigned long usa_get_module_base(int pid, const char *name)
{
    usa_module_base mb = { .pid = pid, .name = (char *)name, .base = 0 };
    syscall(USA_SYSCALL_NR, USA_MAGIC, OP_MODULE_BASE, &mb);
    return mb.base;
}

/* ====== 检测驱动是否加载 ====== */

static inline int usa_driver_loaded(void)
{
    usa_copy_memory cm = { .pid = 0, .addr = 0, .buffer = NULL, .size = 0 };
    int ret = syscall(USA_SYSCALL_NR, USA_MAGIC, OP_READ_MEM, &cm);
    /* 如果驱动在, 返回 -EIO (因为参数无效)
     * 如果驱动不在, 返回正常的 getpid 结果 (>0) */
    return (ret < 0) ? 1 : 0;
}

/* ====== 硬件断点 ====== */

/**
 * 设置硬件看门狗
 *
 * @param index  0~3, ARM64 最多 4 个
 * @param pid    目标进程 PID
 * @param addr   要监视的地址
 * @param type   USA_HW_BP_READ / USA_HW_BP_WRITE / USA_HW_BP_RW
 * @param len    监视长度: 1, 2, 4, 8 字节
 * @return       0=成功, <0=失败
 */
static inline int usa_set_watchpoint(int index, int pid,
                                     unsigned long addr, int type, int len)
{
    usa_hw_bp_request req = {
        .pid = pid, .index = index,
        .addr = addr, .type = type, .len = len
    };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_SET_HW_BP, &req);
}

/**
 * 清除硬件断点
 */
static inline int usa_clear_watchpoint(int index)
{
    usa_hw_bp_request req = { .index = index };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_CLEAR_HW_BP, &req);
}

/**
 * 清除所有断点
 */
static inline int usa_clear_all_watchpoints(void)
{
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_CLEAR_ALL_BP, 0);
}

/**
 * 查询断点命中信息
 *
 * @param index  断点序号 0~3
 * @param info   输出, 填充命中信息
 * @return       0=成功
 *
 * 读后自动清除 hit 标志, 可循环轮询
 */
static inline int usa_get_bp_info(int index, usa_hw_bp_hit *info)
{
    info->index = index;
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_GET_BP_INFO, info);
}

/* ====== 内核级 SO 注入 (无 ptrace) ====== */

typedef struct {
    int pid;
    char *so_path;
    int result;
} usa_inject_request;

/**
 * 通过内核驱动注入 .so 到目标进程
 * 无 ptrace, 无 TracerPid 痕迹
 *
 * @param pid  目标进程 PID
 * @param path .so 文件路径
 * @return     0=成功, <0=失败
 */
static inline int usa_inject_so(int pid, const char *path)
{
    usa_inject_request req = { .pid = pid, .so_path = (char *)path, .result = 0 };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_INJECT_SO, &req);
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
