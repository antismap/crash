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


union elf_prstatus {
	struct elf_prstatus_ppc ppc;
};

union elf_prpsinfo {
	struct elf_prpsinfo_32 i32;
	struct elf_prpsinfo_64 i64;
};


#endif /* CRASH_ELFCORE_H */
