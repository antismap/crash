#ifndef CRASH_ELFCORE_H
#define CRASH_ELFCORE_H

#include <linux/types.h>

/*
 *  Host-platform independent data
 */
#define ELF_PRARGSZ	(80)	/* Number of chars for args */
struct elf_prpsinfo_64
{
        char    pr_state;       /* numeric process state */
        char    pr_sname;       /* char for pr_state */
        char    pr_zomb;        /* zombie */
        char    pr_nice;        /* nice val */
        __u64   pr_flag;        /* flags */
        __u32   pr_uid;
        __u32   pr_gid;
        __u32   pr_pid, pr_ppid, pr_pgrp, pr_sid;
        /* Lots missing */
        char    pr_fname[16];   /* filename of executable */
        char    pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

struct elf_prpsinfo_32
{
        char    pr_state;       /* numeric process state */
        char    pr_sname;       /* char for pr_state */
        char    pr_zomb;        /* zombie */
        char    pr_nice;        /* nice val */
        __u32   pr_flag;        /* flags */
        __u32   pr_uid;
        __u32   pr_gid;
        __u32   pr_pid, pr_ppid, pr_pgrp, pr_sid;
        /* Lots missing */
        char    pr_fname[16];   /* filename of executable */
        char    pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

struct elf_siginfo_32
{
	__s32	si_signo;
	__s32	si_code;
	__s32	si_errno;
};

struct timeval_32
{
	__s32	tv_sec;
	__s32   tv_usec;
};



/*
 * ppc specific
 */
struct user_regs_struct_ppc {
        __u32 gpr[32];
        __u32 nip;
        __u32 msr;
        __u32 orig_gpr3;      /* Used for restarting system calls */
        __u32 ctr;
        __u32 link;
        __u32 xer;
        __u32 ccr;
        __u32 mq;             /* 601 only (not used at present) */
                                /* Used on APUS to hold IPL value. */
        __u32 trap;           /* Reason for being here */
        __u32 dar;            /* Fault registers */
        __u32 dsisr;
        __u32 result;         /* Result of a system call */
};

#define ELF_NGREG_PPC 48
typedef __u32 elf_gregset_ppc_t[ELF_NGREG_PPC];

struct elf_prstatus_ppc {
	struct elf_siginfo_32 pr_info;	/* Info associated with signal */
	__s16   pr_cursig;		/* Current signal */
	__u32   pr_sigpend;	/* Set of pending signals */
	__u32   pr_sighold;	/* Set of held signals */
	__u32   pr_pid, pr_ppid, pr_pgrp, pr_sid;
	struct timeval_32  pr_utime;
	struct timeval_32  pr_stime;
	struct timeval_32  pr_cutime;
	struct timeval_32  pr_cstime;
        elf_gregset_ppc_t  pr_reg;       /* GP registers */
        __u32 pr_fpvalid;		  /* True if math co-processor being used.  */
};



union elf_prpsinfo {
	struct elf_prpsinfo_32 i32;
	struct elf_prpsinfo_64 i64;
};

/* ARM specific - copied in part from linux tree include/uapi/linux/elfcore.h */
struct elf_siginfo
{
	int	si_signo;			/* signal number */
	int	si_code;			/* extra code */
	int	si_errno;			/* errno */
};

struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};


typedef unsigned long elf_greg_t;
#define ELF_NGREG (sizeof (struct pt_regs) / sizeof(elf_greg_t))
typedef elf_greg_t elf_gregset_t[ELF_NGREG];

struct elf_prstatus_arm
{
	struct elf_siginfo pr_info;	/* Info associated with signal */
	short	pr_cursig;		/* Current signal */
	unsigned long pr_sigpend;	/* Set of pending signals */
	unsigned long pr_sighold;	/* Set of held signals */
	pid_t	pr_pid;
	pid_t	pr_ppid;
	pid_t	pr_pgrp;
	pid_t	pr_sid;
	struct timeval pr_utime;	/* User time */
	struct timeval pr_stime;	/* System time */
	struct timeval pr_cutime;	/* Cumulative user time */
	struct timeval pr_cstime;	/* Cumulative system time */
	elf_gregset_t pr_reg;	/* GP registers */
	int pr_fpvalid;		/* True if math co-processor being used.  */
};

/* end ARM specific */

union elf_prstatus {
	struct elf_prstatus_ppc ppc;
        struct elf_prstatus_arm arm;
};


#endif /* CRASH_ELFCORE_H */
