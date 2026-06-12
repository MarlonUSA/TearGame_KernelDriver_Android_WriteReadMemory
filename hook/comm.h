#ifndef _USA_COMM_H_
#define _USA_COMM_H_

/* ====== 内存读写 ====== */

typedef struct _COPY_MEMORY
{
	pid_t pid;
	uintptr_t addr;
	void *buffer;
	size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE
{
	pid_t pid;
	char *name;
	uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

/* ====== 硬件断点 ====== */

/* 断点类型 */
#define USA_HW_BP_READ   1
#define USA_HW_BP_WRITE  2
#define USA_HW_BP_RW     3

/* 最多 4 个硬件 watchpoint (ARM64 限制) */
#define USA_MAX_HW_BP    4

typedef struct _HW_BP_REQUEST
{
	pid_t pid;
	int index;           /* 0~3 */
	uintptr_t addr;
	int type;            /* USA_HW_BP_READ/WRITE/RW */
	int len;             /* 1, 2, 4, 8 */
} HW_BP_REQUEST;

typedef struct _HW_BP_HIT
{
	int index;           /* 哪个断点触发了 */
	int hit;             /* 是否命中 */
	uintptr_t hit_addr;  /* 触发地址 */
	uintptr_t hit_pc;    /* 触发时的 PC (哪条指令访问了这个地址) */
	unsigned long regs[31]; /* x0~x30 寄存器快照 */
	int hit_count;       /* 累计命中次数 */
} HW_BP_HIT;

/* ====== 操作码 ====== */

enum OPERATIONS
{
	OP_INIT_KEY    = 0x800,
	OP_READ_MEM    = 0x801,
	OP_WRITE_MEM   = 0x802,
	OP_MODULE_BASE = 0x803,

	/* 硬件断点 */
	OP_SET_HW_BP   = 0x810,
	OP_CLEAR_HW_BP = 0x811,
	OP_GET_BP_INFO = 0x812,
	OP_CLEAR_ALL_BP= 0x813,

	/* 内核级 SO 注入 */
	OP_INJECT_SO   = 0x820,
};

typedef struct _INJECT_REQUEST
{
	pid_t pid;
	char *so_path;
	int result;
} INJECT_REQUEST;

#endif /* _USA_COMM_H_ */
