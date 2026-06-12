/**
 * ============================================================================
 * 泪心开源驱动 - TearGame Open Source Driver
 * ============================================================================
 * 作者 (Author): 泪心 (Tear)
 * QQ: 2254013571
 * 邮箱 (Email): tearhacker@outlook.com
 * 电报 (Telegram): t.me/TearGame
 * GitHub: github.com/tearhacker
 * ============================================================================
 * 本项目完全免费开源，代码明文公开
 * This project is completely free and open source with clear code
 * 
 * 禁止用于引流盈利，保留开源版权所有
 * Commercial use for profit is prohibited, all open source rights reserved
 * 
 * 凡是恶意盈利者需承担法律责任
 * Those who maliciously profit will bear legal responsibility
 * ============================================================================
 */

//原作者JiangNight  源码存在严重问题 加载格机 重启  黑砖    加载失败  kernel pacni 各种问题
//泪心已经彻底修复优化
	//printk(KERN_INFO "[TearGame] QQ: 2254013571\n");
	//printk(KERN_INFO "[TearGame] Email: tearhacker@outlook.com\n");
//printk(KERN_INFO "[TearGame] Telegram: t.me/TearGame\n");
	//(KERN_INFO "[TearGame] GitHub: github.com/tearhacker\n");

	//原项目链接 https://github.com/Jiang-Night/Kernel_driver_hack
	//泪心驱动完整开源读写内核源码新项目链接 https://github.com/tearhacker/TearGame_KernelDriver_Android_WriteReadMemory

	#include "process.h"
	#include <linux/sched.h>
	#include <linux/sched/mm.h>
	#include <linux/sched/task.h>
	#include <linux/module.h>
	#include <linux/mm.h>
	#include <linux/version.h>
	#include <linux/pid.h>
	#include <linux/fs.h>
	#include <linux/dcache.h>
	#include <linux/rwsem.h>
	
	/* 兼容旧内核版本的mmap锁API */
	#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
	#define mmap_read_lock(mm)    down_read(&(mm)->mmap_sem)
	#define mmap_read_unlock(mm)  up_read(&(mm)->mmap_sem)
	#endif
	//原作者JiangNight  源码存在严重问题 加载格机 重启  黑砖    加载失败  kernel pacni 各种问题
	//泪心已经彻底修复优化
		//printk(KERN_INFO "[TearGame] QQ: 2254013571\n");
		//printk(KERN_INFO "[TearGame] Email: tearhacker@outlook.com\n");
	//printk(KERN_INFO "[TearGame] Telegram: t.me/TearGame\n");
		//(KERN_INFO "[TearGame] GitHub: github.com/tearhacker\n");
	
		//原项目链接 https://github.com/Jiang-Night/Kernel_driver_hack
		//泪心驱动完整开源读写内核源码新项目链接 https://github.com/tearhacker/TearGame_KernelDriver_Android_WriteReadMemory
	
	#define ARC_PATH_MAX 256
	
	uintptr_t get_module_base(pid_t pid, char *name)
	{
		struct pid *pid_struct;
		struct task_struct *task;
		struct mm_struct *mm;
		struct vm_area_struct *vma;
		uintptr_t base_addr = 0;
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
		struct vma_iterator vmi;
	#endif
	
		pid_struct = find_get_pid(pid);
		if (!pid_struct)
			return 0;
	
		task = get_pid_task(pid_struct, PIDTYPE_PID);
		put_pid(pid_struct);
		if (!task)
			return 0;
	
		mm = get_task_mm(task);
		put_task_struct(task);
		if (!mm)
			return 0;
	
		mmap_read_lock(mm);
	
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
		vma_iter_init(&vmi, mm, 0);
		for_each_vma(vmi, vma)
	#else
		for (vma = mm->mmap; vma; vma = vma->vm_next)
	#endif
		{
			if (vma->vm_file) {
				char buf[ARC_PATH_MAX];
				char *path_nm;
	
				path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX - 1);
				if (!IS_ERR(path_nm)) {
					const char *basename = kbasename(path_nm);
					if (strcmp(basename, name) == 0) {
						base_addr = vma->vm_start;
						break;
					}
				}
			}
		}
	
		mmap_read_unlock(mm);
		mmput(mm);
		return base_addr;
	}
	