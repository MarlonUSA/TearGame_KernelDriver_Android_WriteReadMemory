/**
 * USA Kernel Driver (Stealth Edition)
 * Based on TearGame by 泪心, stealth modifications by USA
 */

#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/version.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

/* 设备名用随机字符串, 不用明文 "TearGame" */
#define DEVICE_NAME "hwservicemanager"

/* =====================================================================
 * 隐藏功能
 * ===================================================================== */

static struct list_head *saved_prev = NULL;
static struct list_head *saved_next = NULL;
static int hidden = 0;

/* 从 /proc/modules 和 lsmod 中隐藏 */
static void hide_from_procmodules(void)
{
    if (hidden) return;

    /* 保存链表前后指针 (卸载时需要恢复) */
    saved_prev = THIS_MODULE->list.prev;
    saved_next = THIS_MODULE->list.next;

    /* 从模块链表中摘除自己 */
    list_del_init(&THIS_MODULE->list);

    hidden = 1;
}

/* 从 /sys/module/ 中隐藏 */
static void hide_from_sysmodule(void)
{
    /* 删除 kobject 使 /sys/module/<name> 消失 */
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

/* 恢复模块链表 (卸载前必须恢复，否则 rmmod 找不到) */
static void unhide_module(void)
{
    if (!hidden || !saved_prev || !saved_next) return;

    /* 重新插入链表 */
    list_add(&THIS_MODULE->list, saved_prev);
    hidden = 0;
}

/* =====================================================================
 * 驱动核心 (ioctl 通信)
 * ===================================================================== */

int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char key[0x100] = {0};
    static char name[0x100] = {0};
    static bool is_verified = false;

    if (cmd == OP_INIT_KEY && !is_verified)
    {
        if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) != 0)
        {
            return -1;
        }
    }
    switch (cmd)
    {
    case OP_READ_MEM:
    {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
        {
            return -1;
        }
        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
        {
            return -1;
        }
        break;
    }
    case OP_WRITE_MEM:
    {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
        {
            return -1;
        }
        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
        {
            return -1;
        }
        break;
    }
    case OP_MODULE_BASE:
    {
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
        {
            return -1;
        }
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
        {
            return -1;
        }
        break;
    }
    default:
        break;
    }
    return 0;
}

struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

/* =====================================================================
 * 模块初始化 — 静默加载, 零日志
 * ===================================================================== */

int __init driver_entry(void)
{
    int ret;

    /* 注册设备 (用伪装名) */
    ret = misc_register(&misc);
    if (ret != 0)
        return ret;

    /* 隐藏: 从 lsmod / /proc/modules 消失 */
    hide_from_procmodules();

    /* 隐藏: 从 /sys/module/ 消失 */
    hide_from_sysmodule();

    /* 不打印任何日志 */
    return 0;
}

void __exit driver_unload(void)
{
    /* 恢复模块链表 (否则 rmmod 会失败) */
    unhide_module();

    misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
