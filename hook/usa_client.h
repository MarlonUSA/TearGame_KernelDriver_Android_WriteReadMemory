/**
 * usa_client.h — Hook 版用户态通信接口
 *
 * 不需要 open 任何设备文件, 直接用 syscall 通信
 *
 * 用法:
 *   #include "usa_client.h"
 *   usa_read(pid, addr, buf, size);
 *   usa_write(pid, addr, buf, size);
 *   unsigned long base = usa_get_module_base(pid, "libUE4.so");
 */

#ifndef USA_CLIENT_H
#define USA_CLIENT_H

#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdint.h>

/* hook getpid — 用已有的 syscall, 和正常 getpid 调用混在一起不起疑 */
#define USA_SYSCALL_NR __NR_getpid  /* 172 on arm64 */
#define USA_MAGIC      0x55534100

/* 命令号 (与 comm.h 一致) */
#define OP_READ_MEM    0x100
#define OP_WRITE_MEM   0x200
#define OP_MODULE_BASE 0x300

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

/* 读取进程内存 */
static inline int usa_read(int pid, unsigned long addr, void *buf, unsigned long size)
{
    usa_copy_memory cm = { .pid = pid, .addr = addr, .buffer = buf, .size = size };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_READ_MEM, &cm);
}

/* 写入进程内存 */
static inline int usa_write(int pid, unsigned long addr, void *buf, unsigned long size)
{
    usa_copy_memory cm = { .pid = pid, .addr = addr, .buffer = buf, .size = size };
    return syscall(USA_SYSCALL_NR, USA_MAGIC, OP_WRITE_MEM, &cm);
}

/* 获取模块基址 */
static inline unsigned long usa_get_module_base(int pid, const char *name)
{
    usa_module_base mb = { .pid = pid, .name = (char *)name, .base = 0 };
    syscall(USA_SYSCALL_NR, USA_MAGIC, OP_MODULE_BASE, &mb);
    return mb.base;
}

/* 模板读取 */
#ifdef __cplusplus
template <typename T>
static inline T usa_read_val(int pid, unsigned long addr) {
    T val{};
    usa_read(pid, addr, &val, sizeof(T));
    return val;
}
#endif

#endif /* USA_CLIENT_H */
