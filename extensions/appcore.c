#include "defs.h"
#include <elf.h>
#include <string.h>
#include "crash_elfcore.h"

int _init(void);
int _fini(void);

void cmd_appcore(void);
char *help_appcore[];

static struct command_table_entry command_table[] = {
	{ "appcore", cmd_appcore, help_appcore, REFRESH_TASK_TABLE },
	{ NULL }
};

#if defined(PPC)
int supported = TRUE;
#else
int supported = FALSE;
#endif

#define trace(...) printf(__VA_ARGS__);
#define trace(...) ;

extern void hexdump(void const * data, unsigned int len)
{
	unsigned int i;
	unsigned int r,c;

	if (!data)
		return;

	if (len > 312) {
		trace("len to big %d\n",len);
		len = 312;
	}

	for (r=0,i=0; r<(len/16+(len%16!=0)); r++,i+=16)
	{
		trace("%04X:   ",i); /* location of first byte in line */

		for (c=i; c<i+8; c++) /* left half of hex dump */
			if (c<len) {
				trace("%02X ",((unsigned char const *)data)[c]);
			} else {
				trace("   "); /* pad if short line */
			}
		trace("  ");

		for (c=i+8; c<i+16; c++) /* right half of hex dump */
			if (c<len) {
				trace("%02X ",((unsigned char const *)data)[c]);
			} else {
				trace("   "); /* pad if short line */
			}
		trace("   ");

		for (c=i; c<i+16; c++) /* ASCII dump */
		{
			if (c<len) {
				if (((unsigned char const *)data)[c]>=32 &&
					((unsigned char const *)data)[c]<127) {
					trace("%c",((char const *)data)[c]);
				} else {
					trace("."); /* put this for non-printables */
				}
			} else {
				trace(" "); /* pad if short line */
			}
		}
		trace("\n");
	}
}


int
_init(void) /* Register the command set. */
{
	register_extension(command_table);
	return 1;
}

int
_fini(void)
{
	return 1;
}


/* An ELF note in memory */
struct memelfnote {
	const char *name;
	int type;
	unsigned long datasz;
	void *data;
};

/* Architecture specific data and methods. */
struct appcore_context {
	int	e_machine;
	int	ei_class;
	int	ei_data;
	int	thread_notes;
	ssize_t	(*fill_prstatus)(union elf_prstatus *,
				 struct task_context*);
	ssize_t	(*fill_prpsinfo)(union elf_prpsinfo *,
				 struct task_context*);
};

/* ELF notes for a particular thread. */
struct elf_thread_core_info {
	struct elf_thread_core_info *next;
	union elf_prstatus prstatus;
	struct memelfnote notes[0];
};

/* Information about the ELF notes. */
struct elf_note_info {
	struct elf_thread_core_info *thread;
	union elf_prpsinfo prpsinfo;
	struct memelfnote psinfo_note;
	struct memelfnote auxv_note;
	size_t size;
};

static void do_appcore(struct task_context *tc, int file, int verbose,
		       int dumpall);
static ssize_t write_elf_header(struct appcore_context*, int file, int phnum);
static ssize_t elf_phdr_size(struct appcore_context*);
static void init_note_info(struct elf_note_info *info);
static void fill_note(struct memelfnote *note, const char *name, int type,
		      unsigned int sz, void *data);
static int fill_note_info(struct appcore_context* ctx,
			  struct task_context *leader,
			  struct elf_note_info *info);
static int fill_thread_core_info(struct appcore_context* ctx,
				 struct elf_thread_core_info* t,
				 struct task_context *tc,
				 size_t *size);
static void free_note_info(struct appcore_context* ctx,
			   struct elf_note_info *info);
static int write_note_info(struct appcore_context* ctx,
			   struct elf_note_info *info,
			   int file);
static ssize_t fill_prstatus(struct appcore_context*,
			    union elf_prstatus *prstatus,
			    struct task_context *tc);
static ssize_t fill_auxv(struct appcore_context* ctx,
			 struct memelfnote * note);
static ssize_t fill_prpsinfo(struct appcore_context*,
			    union elf_prpsinfo *psinfo,
			    struct task_context *tc);
static ssize_t write_note_phdr(struct appcore_context*,
			       struct elf_note_info*,
			       int file, off_t offset);
static unsigned long vma_dump_size(char*, unsigned long);
static ssize_t write_vma_phdr(struct appcore_context*,
			      int file, int dumpall, off_t offset);
static int notesize(struct memelfnote *en);
static int writenote(struct appcore_context*, struct memelfnote *men,
		      int file);
static void printmissingpages(long missingstart, long missingend);
static void init_arch_context( struct appcore_context* );


#define WRITE(rc, fd, buf, count, caller) \
	do { \
		if ((rc = write(fd, (buf), (count))) < 0) { \
			error(INFO, caller ":write error: %s\n", \
			      strerror(errno)); \
			return rc; \
		} \
	} while(0)

/**
 * Implementation of the appcore command in crash. This function is called by
 * crash, when the user invokes the appcore command.
 */
void cmd_appcore(void)
{
	ulong pid, tgid;
	char *filename;
	int c;
	struct task_context *tc;
	int file, force, verbose, dumpall;

	trace("-> cmd_appcore\n");

	if (!supported)
		error(FATAL, "command not supported on the %s architecture\n",
		      pc->machine_type);

	trace("1\n");
	dumpall = FALSE;
	force = FALSE;
	verbose = FALSE;
	/* parse command options */
	while ((c = getopt(argcnt, args, "afv")) != EOF) {
		switch (c) {
		case 'a':
			dumpall = TRUE;
			break;
		case 'f':
			force = TRUE;
			break;
		case 'v':
			verbose = TRUE;
			break;
		default:
			argerrs++;
			break;
		}
	}

	trace("parsing done\n");

	if (argerrs || (optind != argcnt - 2))
		cmd_usage(pc->curcmd, SYNOPSIS);

	/* get pid */
	if (args[optind]) {
		/* entry number has been supplied */
		char *endptr;

		pid = strtoul(args[optind], &endptr, 0);
		if (*endptr == '\0') {
			/* parsing of pid successful */
		} else {
			error(INFO, "Invalid PID: '%s'\n\n", args[optind]);
		}
		optind++;
	} else {
		error(INFO, "No PID supplied");
	}

	trace("pid done\n");

	/* get filename */
	if (args[optind]) {
		filename = args[optind];
	} else {
		error(INFO, "No filename supplied");
	}

	trace("filename done\n");

	/* find the task_context of the supplied pid */
	if(!(tc = pid_to_context(pid)))
		error(FATAL, "Invalid PID supplied\n");

	trace("tc context %p pid %lu - ",tc,tc->pid);

	/* find the pid's thread group leader.*/
	tgid = task_tgid(tc->task);
	if(pid != tgid) {
		if (!(tc = tgid_to_context(tgid)))
			error(INFO, "Thread group leader not found\n");
	}

	trace("find task done tgpid %lu\n",tgid);

	/* open the dump file */
	file = open(filename, O_WRONLY | O_CREAT |
		    (force ? O_TRUNC : O_EXCL) | O_NOCTTY, S_IRUSR | S_IWUSR);
	if (file == -1) {
		fprintf(fp, "Opening of '%s' for writing failed. Reason: %s\n",
			filename, strerror(errno));
	} else {
		do_appcore(tc, file, verbose, dumpall);
	}

	trace("appcore write done\n");

	close(file);

	trace("<- cmd_appcore\n");
}


char *help_appcore[] = {
	"appcore",					/* command name */
	"write an application core dump to a file",	/* short description */
	"pid dumpfile [-f] [-v]",
	"  Generates an application core dump of the specified process and writes it",
	"  to the given file. The mcore dump must contain user pages to use this",
	"  command.  Version 0.5",
	"",
	"       pid  The pid of the process to dump.",
	"  filename  The file, to store the dump in. If the file already exists and",
	"            the -f switch is not set, the comand will abort.",
	"        -f  Force the appcore command to overwrite an existing file.",
	"        -v  Verbose output. If this switch is set, information on the VMAs",
	"            (Virtual Memory Areas) that are dumped and missing user pages is",
	"            printed.",
	NULL
};


/**
 * This function creates an ELF coredump file for task @tc.
 *
 * @note This is a modified version from the elf_core_dump function in the
 *	 kernel ($kernel/fs/binfmt_elf.c).
 *
 * @param tc	  Crash's task_context structure for the target process.
 * @param file	  The file descriptor to write the dump into.
 * @param verbose If true, additional information about missing pages and the
 *		  VMAs (Virtual Memory Areas) is printed on the screen.
 * @param dumpall If true, dump all the VMAs of the process.  Normally only
 *                VMAs with particular properties are dumped.
 */

static void do_appcore(struct task_context *tc, int file, int verbose,
		       int dumpall)
{
	struct appcore_context ctx;
	struct elf_note_info info;
	off_t offset, dataoff;
	ssize_t rc;
	int segs;

	/* used for dumping user pages */
	ulong vma, vm_start, vm_end, vm_flags, mm_flags;
	void *vm_next;
	char *pagebuffer = NULL;
	long pagemissingcounter, pagedumpedcounter, vmacounter;

	/* Initialize the architecture specific stuff. */
	init_arch_context(&ctx);
	init_note_info(&info);

	/* Make sure, that the filepointer points to the beginning of the
	   file. */
	if(lseek(file, 0, SEEK_SET) < 0) {
		error(INFO, "do_appcore: core seek error: %s\n",
		      strerror(errno));
		goto cleanup;
	}

	/* load process information into buffers */
	tt->current = tc;
	fill_mm_struct(tc->mm_struct);
	fill_task_struct(tc->task);

	trace("pid: tt->current->pid %lu\n",tt->current->pid);

	/* get number of segments (VMAs) */
	segs = ULONG(tt->mm_struct + OFFSET(mm_struct_map_count));
	segs = ULONG(&segs);

	trace ("segs %d\n",segs);

	/* one more for the notes section. */
	segs++;

	if(!fill_note_info(&ctx, tc, &info))
		goto cleanup;

	/* write elf header */
	if((rc = write_elf_header(&ctx, file, segs)) < 0 )
		goto cleanup;

	trace("write_elf_header %d\n",rc);

	offset = rc;				/* Elf header */

	trace("rc 0x%08lx sizeof rc %x\n",rc,sizeof(rc));
	trace("offset 0x%016llx sizeof offset %d\n",offset, sizeof(offset) );
	trace("segs 0x%08x\n",segs);
	trace("elf_phdr_size(&ctx) 0x%08lx\n",elf_phdr_size(&ctx));
	trace("mul 0x%08lx\n",segs * elf_phdr_size(&ctx));
	trace("mul plus 0x%016llx\n",offset + segs * elf_phdr_size(&ctx));

	offset += segs * elf_phdr_size(&ctx);	/* Program headers */

	trace("offset before 0x%016llx\n",offset);

	/* write the note phdr. */
	if(write_note_phdr(&ctx, &info, file, offset) < 0 )
		goto cleanup;

	trace("offset 0x%016llx\n",offset);
	trace("info.size 0x%08x\n",info.size);
	trace("PAGESIZE 0x%08x\n",PAGESIZE());
	trace("sizeof offset %x\n",sizeof(offset));
	trace("plus 0x%016llx\n",offset + info.size);

	/* VMAs are written on a page boundary. */
	dataoff = offset = roundup(offset + info.size, PAGESIZE());
	trace("dataoff 0x%016lx\n",dataoff);
	trace("offset 0x%016lx\n",offset);

	/* Write phdr of VMAs */
	if(write_vma_phdr(&ctx, file, dumpall, offset) < 0 )
		goto cleanup;

	/* Write the Elf notes. */
	if(!write_note_info(&ctx, &info, file))
		goto cleanup;

	lseek(file, dataoff, SEEK_SET);

	/* write all user pages */
	pagemissingcounter = 0;
	pagedumpedcounter = 0;
	vmacounter = 0; pagebuffer = GETBUF(PAGESIZE());
	for (vma = ULONG(&(ULONG(tt->mm_struct + OFFSET(mm_struct_mmap))));
	     vma; vma = (ulong) vm_next) {
		char *vma_buf;
		unsigned long addr, missingstart;
		int previouspagesmissing = FALSE;

		trace("vma for do_appcore 0x%08lx\n",vma);

		/* write user pages of one VMA */
		vma_buf = fill_vma_cache(vma);
		vm_start = ULONG(&(ULONG(vma_buf + OFFSET(vm_area_struct_vm_start))));
		vm_end = ULONG(&(ULONG(vma_buf + OFFSET(vm_area_struct_vm_end))));
		vm_next = VOID_PTR(vma_buf + OFFSET(vm_area_struct_vm_next));
		vm_next = ULONG(&vm_next);
		vm_flags = ULONG(&(ULONG(vma_buf + OFFSET(vm_area_struct_vm_flags))));
		mm_flags = ULONG(&(ULONG(tt->mm_struct + OFFSET(mm_struct_flags))));

		trace("vm_start 0x%08lx end 0x%08lx next %p vm_flags 0x%08lx mm_flags 0x%08lx\n",vm_start,vm_end,vm_next, vm_flags,mm_flags);

		/* skip VMAs, that do not have appropriate permissions */
		if (!dumpall && !vma_dump_size(vma_buf, mm_flags))
			continue;

		vmacounter++;

		if (verbose) {
			fprintf(fp, "Dumping VMA (%08lx - %08lx) "
				    "flags=%08lx.\n",
			       vm_start, vm_end, vm_flags);
		}

		for (addr = vm_start; addr < vm_end; addr += PAGESIZE()) {
			int res;

			// trace("readmem app pages 0x%08lx\n",addr);
			res = readmem(addr, UVADDR, pagebuffer, PAGESIZE(),
				"reading user page for application core dump",
				QUIET);

			if (!res) {
				/* user page could not be read */
				lseek(file, PAGESIZE(), SEEK_CUR);
				pagemissingcounter++;
				if (verbose && !previouspagesmissing) {
					missingstart = addr;
					previouspagesmissing = TRUE;
				}
			} else {
				write(file, pagebuffer, PAGESIZE());
				pagedumpedcounter++;
				if (verbose && previouspagesmissing) {
					printmissingpages(missingstart,
							  addr - PAGESIZE());
					previouspagesmissing = FALSE;
				}
			}

		}
		if (verbose && previouspagesmissing) {
			printmissingpages(missingstart, vm_end);
		}
	}

	/* print summary about dumping process */
	if (verbose)
		fprintf(fp, "\n");
	fprintf(fp, "VMAs processed: %ld (0x%lx)\n", vmacounter, vmacounter);
	fprintf(fp, "Pages dumped:   %ld (0x%lx)\n", pagedumpedcounter,
		pagedumpedcounter);
	fprintf(fp, "Pages missing:  %ld (0x%lx)\n", pagemissingcounter,
		pagemissingcounter);
	fprintf(fp, "Pages total:    %ld (0x%lx)\n",
		pagemissingcounter + pagedumpedcounter,
		pagemissingcounter + pagedumpedcounter);


cleanup:
	if(pagebuffer)
		FREEBUF(pagebuffer);
	free_note_info(&ctx, &info);
}

/**
 * Writes an Elf32_Ehdr structure to the dump file.
 *
 * @param ctx     Pointer to the appcore context.
 * @param file	  Dump file descriptor.
 * @param phnum	  The number of program header sections to be written.
 *
 * @return The file offset spanning the ELF header and the program header table.
 */
static ssize_t write_Elf32_header(struct appcore_context* ctx, int file,
				int phnum)
{
	Elf32_Ehdr* elf = (Elf32_Ehdr*)GETBUF(sizeof(Elf32_Ehdr));
	ssize_t rc;

	memset(elf, 0, sizeof(Elf32_Ehdr));

	memcpy(elf->e_ident, ELFMAG, SELFMAG);
	elf->e_ident[EI_CLASS] = ELFCLASS32;
	elf->e_ident[EI_DATA] = ctx->ei_data;
	elf->e_ident[EI_VERSION] = EV_CURRENT;
	elf->e_ident[EI_OSABI] = ELFOSABI_SYSV;
	elf->e_ident[EI_ABIVERSION] = 0;

	elf->e_type = ET_CORE;
	elf->e_machine = ctx->e_machine;
	elf->e_version = EV_CURRENT;
	elf->e_entry = 0;
	elf->e_phoff = sizeof(Elf32_Ehdr);
	elf->e_shoff = 0;
	elf->e_flags = 0;
	elf->e_ehsize = sizeof(Elf32_Ehdr);
	elf->e_phentsize = sizeof(Elf32_Phdr);
	elf->e_phnum = phnum;
	elf->e_shentsize = 0;
	elf->e_shnum = 0;
	elf->e_shstrndx = 0;

	trace("elf e_type %lx\n",elf->e_type);
	trace("elf e_machine %lx\n",elf->e_machine);
	trace("elf e_version %lx\n",elf->e_version);
	trace("elf e_entry %lx\n",elf->e_entry);
	trace("elf e_phoff %lx\n",elf->e_phoff);
	trace("elf e_flags %lx\n",elf->e_flags);
	trace("elf e_ehsize %lx\n",elf->e_ehsize);
	trace("elf e_phentsize %lx\n",elf->e_phentsize);
	trace("elf e_shentsize %lx\n",elf->e_shentsize);
	trace("elf e_shnum %lx\n",elf->e_shnum);
	trace("elf e_shstrndx %lx\n",elf->e_shstrndx);

	trace("elf \n");
	hexdump(elf, sizeof(Elf32_Ehdr));
	rc = write(file, elf, sizeof(Elf32_Ehdr));
	if(rc < 0)
		error(INFO, "write_Elf32_header: output error: %s\n",
		      strerror(errno));
	return rc;
}


/**
 * The architecture independent entry point for writing an ELF header to a dump
 * file.
 *
 * @param ctx     Pointer to the appcore context.
 * @param file	  Dump file descriptor.
 * @param phnum	  The number of program header sections.
 *
 * @return The size of the ELF header.
 */
static ssize_t write_elf_header(struct appcore_context* ctx, int file,
				int phnum)
{
	if(ctx->ei_class == ELFCLASS32)
		return write_Elf32_header(ctx, file, phnum);
	else
		error(FATAL, "Elf 64 not supported.");
	return -1;
}

/**
 * Returns the size of the Elf program header.
 *
 * @return The size of the Elf program header.
 */
static ssize_t elf_phdr_size(struct appcore_context* ctx)
{
	if(ctx->ei_class == ELFCLASS32)
		return sizeof(Elf32_Phdr);
	else
		return sizeof(Elf64_Phdr);
}

/******************************************************************************
 *                         Elf Notes                                          *
 *****************************************************************************/

/**
 * Initializes the elf_note_info structure.
 *
 * @param info	The 'elf_note_info' structure to be initialized.
 */
static void init_note_info(struct elf_note_info *info)
{
	memset(info, 0, sizeof(*info));
}

/**
 * Fills out the supplied memelfnote structure.
 *
 * @param note	Pointer to the memelfnote structure.
 * @param name  The note name.
 * @param type  The note type.
 * @param sz	The note size.
 * @param data	the note data.
 */
static void fill_note(struct memelfnote *note, const char *name, int type,
		unsigned int sz, void *data)
{
	note->name = name;
	note->type = type;
	note->datasz = sz;
	note->data = data;
	return;
}

/**
 * Collects all the ELF notes for the task being dumped.
 *
 * The collected notes are stored into INFO.
 *
 * @param ctx		The architecture context.
 * @param dump_task	The process being dumped.
 * @param info		The structure holding the constructed ELF notes.
 *
 * @retval	0	Error
 * @retval	1	Success
 */
static int fill_note_info(struct appcore_context *ctx,
			  struct task_context *dump_task,
			  struct elf_note_info *info)
{
	int i, cnt;
	ulong tgid = dump_task->pid;
	struct task_context *tc;
	struct elf_thread_core_info* t;
	ssize_t sz;

	/*
	 * Allocate a structure for each thread.
	 */
	tc = FIRST_CONTEXT();
	for(i = cnt = 0; i < RUNNING_TASKS(); i++, tc++) {
		if(task_tgid(tc->task) != tgid)
			continue;

		t = (struct elf_thread_core_info*)GETBUF(
				     offsetof(struct elf_thread_core_info,
				     notes[ctx->thread_notes]));
		if(tc->pid == tgid || !info->thread) {
			t->next = info->thread;
			info->thread = t;
		} else {
			/*
			 * Make sure to keep the original task at
			 * the head of the list.
			 */
			t->next = info->thread->next;
			info->thread->next = t;
		}

		/* Fill in the thread's information. */
		if(!fill_thread_core_info(ctx, t, tc, &info->size))
			return 0;
	}

	/*
	 * Fill in the process-wide notes.
	 */

	if((sz = fill_prpsinfo(ctx, &info->prpsinfo, dump_task)) < 0)
		return 0;
	fill_note(&info->psinfo_note, "CORE", NT_PRPSINFO, sz,
		  &info->prpsinfo);
	info->size += notesize(&info->psinfo_note);

	if(!fill_auxv(ctx, &info->auxv_note))
		return 0;
	info->size += notesize(&info->auxv_note);
	return 1;
}

/**
 * Collects the ELF prstatus note for a particular thread.
 *
 * @param ctx	Pointer to the architecture context.
 * @param t	Where the ELF note is to be stored.
 * @param tc    The thread under consideration.
 * @param size  (output) The size of the created ELF note.
 *
 * @retval 0	Failure.
 * @retval 1    Success.
 */
static int fill_thread_core_info(struct appcore_context* ctx,
				 struct elf_thread_core_info* t,
				 struct task_context *tc,
				 size_t * size)
{
	ssize_t sz;

	sz = fill_prstatus(ctx, &t->prstatus, tc);
	if(sz) {
		fill_note(&t->notes[0], "CORE", NT_PRSTATUS,
			  sz, &t->prstatus);
		*size += notesize(&t->notes[0]);
	}
	return 1;
}

/**
 * Releases the dynamic storage consumed by an elf_note_info structure.
 *
 * @param ctx	Pointer to the architecture context.
 * @param info  The elf_note_info structure to be released.
 */
static void free_note_info(struct appcore_context* ctx,
			   struct elf_note_info *info)
{
	struct elf_thread_core_info *threads = info->thread;
	while(threads) {
		unsigned int i;
		struct elf_thread_core_info *t = threads;
		threads = t->next;
		/* Note: We start at 1 because the storage for note 0 is
		   the 'prstatus' entry that is part of the
		   elf_thread_core_info structure. */
		for(i = 1; i < ctx->thread_notes; ++i)
			FREEBUF(t->notes[i].data);
		FREEBUF(t);
	}
	FREEBUF(info->auxv_note.data);
}

/**
 * Write all the notes for each thread.  When writing the first thread, the
 * process-wide notes are interleaved after the first thread-specific note.
 *
 * @note This is a modified version from the write_note_info function in the
 *       kernel ($kernel/fs/binfmt_elf.c).
 *
 * @param info	 Notes info data structure.
 * @param file   The destination file descriptor.
 * @param offset The destination file offset.
 */
static int write_note_info(struct appcore_context* ctx,
			   struct elf_note_info *info,
			   int file)
{
	int first = 1;
	struct elf_thread_core_info *t = info->thread;

	do {
		int i;

		trace("write note 0\n");
		if (!writenote(ctx, &t->notes[0], file))
			return 0;

		if (first) trace("write psinfo note\n");
		if (first && !writenote(ctx, &info->psinfo_note, file))
			return 0;

		if (first)  trace("write auxv_note\n");
		if (first && !writenote(ctx, &info->auxv_note, file))
			return 0;

		for (i = 1; i < ctx->thread_notes; ++i) {
			if (t->notes[i].data) trace("write note no %d\n",i);
			if (t->notes[i].data &&
			    !writenote(ctx, &t->notes[i], file))
				return 0;
		}
		first = 0;
		t = t->next;
	} while (t);

	return 1;
}

/******************************************************************************
 *                         Elf prstatus Note                                  *
 *****************************************************************************/

/**
 * Extracts the PID number of type @type from the pids array of the
 * supplied task.
 *
 * @param task  Virtual kernel address of a task_struct structure.
 * @param type  The type of process ID to get (TID, PPID, GID).
 * @param level The namespace level.  Recall that all IDs are relavant to a
 *              particular namespace, and a single process may have different
 *              IDs in different namespaces.  Namespaces are identified by an
 *              integer 'level', starting at level 0 (the default level).
 *
 * @return The PID number or 0 if an error occurred.
 */
static int task_nr_ns( ulong task, int type, int level)
{
	int nr = 0;
	ulong addr, pid_ptr;
	uint pid_level;

	addr = task + OFFSET(task_struct_pids) + (type * SIZE(pid_link)) +
		OFFSET(pid_link_pid);
	trace("task task_nr_ns %lu\n",task);
	trace("readmem addr task_nr_ns 0x%08lx\n",addr);

	if (!readmem(addr, KVADDR, &pid_ptr, sizeof(void*),
		     "task pid_link pid", RETURN_ON_ERROR|QUIET ))
	{
		error(INFO, "\ncannot read task pid_link pid of type %d\n",
		      type);
		return nr;
	}

	trace("offset pid level %lu \n",OFFSET(pid_level));
	trace("level %d\n",level);
	if( level > 0 ) {
		trace("readmem pid_ptr + offset 0x%08lx \n",pid_ptr + OFFSET(pid_level));
		if (!readmem(pid_ptr + OFFSET(pid_level), KVADDR, &pid_level,
			     sizeof(uint), "pid structure",
			     RETURN_ON_ERROR|QUIET))
		{
			error(INFO, "\ncannot read pid level\n");
			return nr;
		}
		trace("pid_level %x\n",pid_level);
		if( level > pid_level )
		{
			error(INFO, "\ninvalid namespace level: %i\n", level);
			return nr;
		}
	}
	addr = pid_ptr + OFFSET(pid_numbers) + (level * SIZE(upid)) +
		OFFSET(upid_nr);
	trace("readmem addr nr_ns upid_nr 0x%08lx\n",addr);
	if( !readmem(addr, KVADDR, &nr, sizeof(int), "upid nr",
		    RETURN_ON_ERROR|QUIET))
	{
		error(INFO, "\ncannot read nr field of upid structure\n");
		return 0;
	}
	trace("upid_nr %x\n",nr);
	return nr;
}

/**
 * Extracts the process ID number (PID) of type @type from the pids array of the
 * supplied task from the default namespace (i.e. level 0 namespace).
 *
 * @param task  Virtual kernel address of a task_struct structure.
 * @param type  The type of process ID to get (PID, SID, PGID).
 *
 * @return The PID number or 0 if an error occurred.
 */
static int task_nr( ulong task, int type )
{
	return task_nr_ns(task, type, 0);
}

/**
 * Entry point for initializing an ELF prstatus note.
 *
 * @param ctx      Pointer to the appcore context.
 * @param prstatus Pointer to a reserved prstatus structure (output).
 * @param tc       Crash's task_context for the target process.
 *
 * @return Size of the prstatus note.
 */
static ssize_t fill_prstatus(struct appcore_context* ctx,
			    union elf_prstatus* prstatus,
			    struct task_context* tc)
{
	if( ctx->fill_prstatus )
		return ctx->fill_prstatus(prstatus, tc);
	return 0;
}

static void save_timeval_32( struct timeval_32 *d, struct timeval *s )
{
	d->tv_sec = s->tv_sec;
	d->tv_usec = s->tv_usec;
	trace("time %d %d\n",d->tv_sec,d->tv_usec);
}

/**
 * Initialize the ELF prstatus note for PPC.
 *
 * @param prstatus Pointer to a reserved prstatus structure (output).
 * @param tc       Crash's task_context for the target process.
 *
 * @return Size of the prstatus note.
 */
static ssize_t fill_prstatus_ppc(union elf_prstatus *in_prstatus,
				 struct task_context *tc)
{
	int pidtype_PGID = 1, pidtype_SID = 2;
	struct timeval timeval;

	struct elf_prstatus_ppc* prstatus = &in_prstatus->ppc;
	memset(prstatus, 0, sizeof(struct elf_prstatus_ppc));

	/* copy the registers from kernel stack to pt_regs structure */
	trace("readmem fill_prstatus 0x%08lx\n",GET_STACKTOP(tc->task) - SIZE(pt_regs));
	readmem(GET_STACKTOP(tc->task) - SIZE(pt_regs), KVADDR,
		&prstatus->pr_reg, SIZE(pt_regs),
		"reading pt_regs from kernel stack", RETURN_ON_ERROR);

	/* prstatus->pr_sigpend = [task_struct]->pending.signal.sig[0] */
	prstatus->pr_sigpend =
		ULONG(tt->task_struct + OFFSET(task_struct_pending) +
		OFFSET(sigpending_signal) + OFFSET(sigset_t_sig));

	/* prstatus->pr_sighold = [task_struct]->blocked.sig[0] */
	prstatus->pr_sighold = ULONG(tt->task_struct + \
								 OFFSET(task_struct_blocked));

	/* various process IDs */
	prstatus->pr_pid = tc->pid;
	prstatus->pr_ppid = task_to_context(tc->ptask)->pid;
	prstatus->pr_pgrp = task_nr(tc->task, pidtype_PGID);
	prstatus->pr_sid = task_nr(tc->task, pidtype_SID);

	prstatus->pr_pid = ULONG(&(prstatus->pr_pid));
	prstatus->pr_ppid = ULONG(&(prstatus->pr_ppid));
	prstatus->pr_pgrp = ULONG(&(prstatus->pr_pgrp));
	prstatus->pr_sid = ULONG(&(prstatus->pr_sid));

	trace("prstatus->pr_pid %d\n",prstatus->pr_pid);
	trace("prstatus->pr_ppid %d\n",prstatus->pr_ppid);
	trace("prstatus->pr_pgrp %d\n",prstatus->pr_pgrp);
	trace("prstatus->pr_sid %d\n",prstatus->pr_sid);

	/* User Time */
	machdep->cputime_to_timeval( ULONGLONG(tt->task_struct +
				     MEMBER_OFFSET("task_struct", "utime")),
				     &timeval);
	save_timeval_32(&prstatus->pr_utime, &timeval);

	/* System Time */
	machdep->cputime_to_timeval( ULONGLONG(tt->task_struct +
				     MEMBER_OFFSET("task_struct", "stime")),
				     &timeval);
	save_timeval_32(&prstatus->pr_stime, &timeval);

	/* Children User Time */
	machdep->cputime_to_timeval( ULONGLONG(tt->task_struct +
				     MEMBER_OFFSET("task_struct", "cutime")),
				     &timeval);
	save_timeval_32(&prstatus->pr_cutime, &timeval);

	/* Children System Time */
	machdep->cputime_to_timeval( ULONGLONG(tt->task_struct +
				     MEMBER_OFFSET("task_struct", "cstime")),
				     &timeval);
	save_timeval_32(&prstatus->pr_cstime, &timeval);

	return sizeof(struct elf_prstatus_ppc);
}

/******************************************************************************
 *                         Elf OS Aux Info Note                               *
 *****************************************************************************/

/**
 * Fills out the Auxilary Vector Note section.
 *
 * The 'auxv' section provides OS information to GDB.
 *
 * @param ctx	A pointer to the architecture context.
 * @param note  Where the note is to be stored.
 *
 * @retval 1	Success.
 * @retval 0	Failure.
 */
static ssize_t fill_auxv(struct appcore_context* ctx,
			 struct memelfnote * note)
{
	ulong auxv = (ulong)(tt->mm_struct + OFFSET(mm_struct_saved_auxv));
	int i, count = 10;
	ulong * vec = (ulong*)GETBUF(count * SIZEOF_LONG);

	for( i = 0; 1; i++) {

		vec[i] = ULONG(auxv + (i * SIZEOF_LONG));

		if(!(i % 2) && (vec[i] == AT_NULL))
			break;
		/* Accomodate two NULL entries (hence count-3). */
		else if( i == count-3 ) {
			RESIZEBUF(vec, count * SIZEOF_LONG,
				  count * SIZEOF_LONG * 2);
			count *= 2;
		}
	}

	/* Add two NULL entries at the end of the vector. */
	fill_note(note, "CORE", NT_AUXV, (i+2) * SIZEOF_LONG, vec);
	return 1;
}


/******************************************************************************
 *                         Elf prpsinfo Note                                  *
 *****************************************************************************/

/**
 * Get a process's user id (uid) and group id (gid).
 *
 * @param task   Virtual address of the process's task_struct.
 * @param uid    User Id (output).
 * @param gid    Group Id (output).
 */
static void task_uid_gid( ulong task, uint* uid, uint* gid )
{
	ulong cred_ptr;
	uint val;

	*uid = *gid = 0;

	trace("readmem uid_gid 0x%08lx\n", task + OFFSET(task_struct_real_cred));
	if( !readmem(task + OFFSET(task_struct_real_cred), KVADDR, &cred_ptr,
		     sizeof(void*), "reading real_cred from task_struct",
		     RETURN_ON_ERROR))
		return;

		trace("readmem cred_ptr uid 0x%08lx\n",cred_ptr +  + OFFSET(cred_uid));
		if( !readmem(cred_ptr + OFFSET(cred_uid), KVADDR, &val,
		     sizeof(uint), "reading uid from cred",
		     RETURN_ON_ERROR))
		return;

	trace("cred uid %lx\n",val);
	*uid = val;

	trace("readmem cred_ptr gid 0x%08lx\n",cred_ptr + OFFSET(cred_gid));
	if( !readmem(cred_ptr + OFFSET(cred_gid), KVADDR, &val,
		     sizeof(uint), "reading gid from cred",
		     RETURN_ON_ERROR))
		return;

	trace("cred pid %lx\n",val);

	*gid = val;
}

/**
 * Fills the psinfo structure with information about a process.
 *
 * @param ctx    Pointer to the appcore context.
 * @param psinfo A pointer to the psinfo structure to be setup (output).
 * @param tc	 A pointer to the crash task context of the target process.
 */
static ssize_t fill_prpsinfo(struct appcore_context* ctx,
			     union  elf_prpsinfo *prpsinfo,
			     struct task_context *tc)
{
	if( ctx->fill_prpsinfo )
		return ctx->fill_prpsinfo(prpsinfo, tc);
	return 0;
}


/**
 * Fills the psinfo structure for PPC architectures.
 *
 * @param in_prpsinfo A pointer to the psinfo structure to be setup (output).
 * @param tc	      A pointer to the crash task context of the target process.
 *
 * @return Size of the prpsinfo structure.
 */
static ssize_t fill_prpsinfo_ppc(union elf_prpsinfo *in_prpsinfo,
				 struct task_context *tc)
{
	int	i, len;
	ulong	arg_start, arg_end;
	int	process_state;
	uint	uid, gid;
	struct  elf_prpsinfo_32* psinfo = &in_prpsinfo->i32;
	int	pidtype_PGID = 1, pidtype_SID = 2;


	memset(psinfo, 0, sizeof(struct elf_prpsinfo_32));

	/* get command line string of process */
	arg_start = ULONG(tt->mm_struct + OFFSET(mm_struct_arg_start));
	arg_end = ULONG(tt->mm_struct + OFFSET(mm_struct_arg_end));

	arg_start=ULONG(&arg_start);
	arg_end=ULONG(&arg_end);

	len = arg_end - arg_start;
	if (len >= ELF_PRARGSZ)
		len = ELF_PRARGSZ - 1;


	trace("readmem process args 0x%08lx len %d\n",arg_start,len);
	readmem(arg_start, UVADDR, &psinfo->pr_psargs, len,
		"reading process args", RETURN_ON_ERROR);

	for (i = 0; i < len; i++)
		if (psinfo->pr_psargs[i] == 0)
			psinfo->pr_psargs[i] = ' ';
	psinfo->pr_psargs[len] = 0;

	/* various process IDs */
	psinfo->pr_pid, tc->pid;
	psinfo->pr_ppid, task_to_context(tc->ptask)->pid;
	psinfo->pr_pgrp, task_nr(tc->task, pidtype_PGID);
	psinfo->pr_sid, task_nr(tc->task, pidtype_SID);

	psinfo->pr_pid=ULONG(&(psinfo->pr_pid));
	psinfo->pr_ppid=ULONG(&(psinfo->pr_ppid));
	psinfo->pr_pgrp=ULONG(&(psinfo->pr_pgrp));
	psinfo->pr_sid=ULONG(&(psinfo->pr_sid));

	trace("psinfo->pr_pid %d\n",psinfo->pr_pid);
	trace("psinfo->pr_ppid %d\n",psinfo->pr_ppid);
	trace("psinfo->pr_pgrp %d\n",psinfo->pr_pgrp);
	trace("psinfo->pr_sid %d\n",psinfo->pr_sid);

	process_state = ULONG(tt->task_struct + OFFSET(task_struct_state));
	process_state = process_state ? ffs(process_state) : 0;
	psinfo->pr_state = process_state;
	psinfo->pr_sname = (process_state < 0 || process_state > 5) ?
		'.' : "RSDZTD"[process_state];
	psinfo->pr_zomb = (psinfo->pr_sname == 'Z');
	psinfo->pr_flag = ULONG(tt->task_struct +
					    OFFSET(task_struct_flags));
	psinfo->pr_nice = (char)task_nice(tc);
	task_uid_gid(tc->task, &uid, &gid);
	psinfo->pr_uid = uid;
	psinfo->pr_gid = gid;
	strncpy(psinfo->pr_fname, tt->task_struct +
		OFFSET(task_struct_comm), sizeof(psinfo->pr_fname));
	return sizeof(struct elf_prpsinfo_32);
}

/*****************************************************************************/

/**
 * Writes the phdr of the note section to the dump file
 *
 * @param ctx     Pointer to the appcore context.
 * @param info    Information about the notes.
 * @param file	  The file descriptor of the dump file.
 * @param offset  The offset of the note section.
 */
static ssize_t write_note_phdr(struct appcore_context* ctx,
			       struct elf_note_info* info,
			       int file, off_t offset)
{
	Elf32_Phdr phdr32;
	ssize_t rc;

	if( ctx->ei_class == ELFCLASS32 ) {
		phdr32.p_type = PT_NOTE;
		phdr32.p_offset = offset;
		phdr32.p_vaddr = 0;
		phdr32.p_paddr = 0;
		phdr32.p_filesz = info->size;
		phdr32.p_memsz = 0;
		phdr32.p_flags = 0;
		phdr32.p_align = 0;

		/*
		trace("note phdr type %lx\n",phdr32.p_type);
		trace("note phdr offset %lx\n",phdr32.p_offset);
		trace("note phdr vaddr %lx\n",phdr32.p_vaddr);
		trace("note phdr oaddr %lx\n",phdr32.p_paddr);
		trace("note phdr filesize %lx\n",phdr32.p_filesz);
		trace("note phdr memsize %lx\n",phdr32.p_memsz);
		trace("note phdr flags %lx\n",phdr32.p_flags);
		trace("note phdr align %lx\n",phdr32.p_align);
		*/

		trace("note phdr\n");
		hexdump(&phdr32, sizeof(phdr32));

		rc = write(file, &phdr32, sizeof(phdr32));
	}

	if(rc < 0)
		error(INFO, "write_note_phdr: write error: %s",
		      strerror(errno));
	return rc;
}

/* COPIED FROM KERNEL: $kernel/include/linux/mm.h */
/*
 * vm_flags in vm_area_struct, see mm_types.h.
 */
#define VM_READ		0x00000001	/* currently active flags */
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008
#define VM_IO           0x00004000	/* Memory mapped I/O or similar */
#define VM_RESERVED	0x00080000	/* Count as reserved_vm like IO */
#define VM_HUGETLB	0x00400000	/* Huge TLB Page VM */
#define VM_ALWAYSDUMP	0x04000000	/* Always include in core dumps */
/* END COPY */

/* COPIED FROM KERNEL: $kernel/include/linux/sched.h */
/* coredump filter bits */
#define MMF_DUMP_ANON_PRIVATE	2
#define MMF_DUMP_ANON_SHARED	3
#define MMF_DUMP_MAPPED_PRIVATE	4
#define MMF_DUMP_MAPPED_SHARED	5
#define MMF_DUMP_ELF_HEADERS	6
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
/* END COPY */


/* COPIED FROM KERNEL: $kernel/fs/binfmt_elf.c */
/*
 * Decide what to dump of a segment, part, all or none.
 */
static unsigned long vma_dump_size(char* vma_buf,
                                   unsigned long mm_flags)
{
	trace("-> vma_dump_size\n");
#define FILTER(type)	(mm_flags & (1UL << MMF_DUMP_##type))

        ulong vm_flags = ULONG(vma_buf + OFFSET(vm_area_struct_vm_flags));
	void *anon_vma = VOID_PTR(vma_buf + OFFSET(vm_area_struct_anon_vma));
        void *vm_file = VOID_PTR(vma_buf + OFFSET(vm_area_struct_vm_file));
        ulong vm_pgoff = ULONG(vma_buf + OFFSET(vm_area_struct_vm_pgoff));
	ulong vm_start = ULONG(vma_buf + OFFSET(vm_area_struct_vm_start));
	ulong vm_end = ULONG(vma_buf + OFFSET(vm_area_struct_vm_end));

	vm_flags=ULONG(&vm_flags);
	anon_vma=ULONG(&(anon_vma));
	vm_file=ULONG(&(vm_file));
	vm_pgoff=ULONG(&(vm_pgoff));
	vm_start=ULONG(&(vm_start));
	vm_end=ULONG(&(vm_end));

	trace("mm_flags 0x%08lx\n",mm_flags);
	trace("vm_flags 0x%08lx\n",vm_flags);
	trace("anon_vma %p\n",anon_vma);
	trace("vm_file %p\n",vm_file);
	trace("vm_pgoff 0x%08lx\n",vm_pgoff);
	trace("vm_start 0x%08lx\n",vm_start);
	trace("vm_end 0x%08lx\n",vm_end);

	/* The vma can be set up to tell us the answer directly.  */
	if (vm_flags & VM_ALWAYSDUMP)
		goto whole;

	/* Hugetlb memory check */
	if (vm_flags & VM_HUGETLB) {
		if ((vm_flags & VM_SHARED) && FILTER(HUGETLB_SHARED))
			goto whole;
		if (!(vm_flags & VM_SHARED) && FILTER(HUGETLB_PRIVATE))
			goto whole;
	}

	/* Do not dump I/O mapped devices or special mappings */
	if (vm_flags & (VM_IO | VM_RESERVED))
		return 0;

	/* By default, dump shared memory if mapped from an anonymous file. */
#if 0
	if (vma->vm_flags & VM_SHARED) {
		if (vma->vm_file->f_path.dentry->d_inode->i_nlink == 0 ?
		    FILTER(ANON_SHARED) : FILTER(MAPPED_SHARED))
			goto whole;
		return 0;
	}
#endif
	if (vm_flags & VM_SHARED) {
            if FILTER(MAPPED_SHARED)
                goto whole;
            return 0;
        }


	/* Dump segments that have been written to.  */
	if (anon_vma && FILTER(ANON_PRIVATE))
		goto whole;
	if (vm_file == NULL)
		return 0;

	if (FILTER(MAPPED_PRIVATE))
		goto whole;

	/*
	 * If this looks like the beginning of a DSO or executable mapping,
	 * check for an ELF header.  If we find one, dump the first page to
	 * aid in determining what was mapped here.
	 */
	if (FILTER(ELF_HEADERS) &&
	    vm_pgoff == 0 && (vm_flags & VM_READ)) {
		__u32 word;
		/*
		 * Doing it this way gets the constant folded by GCC.
		 */
		union {
			__u32 cmp;
			char elfmag[SELFMAG];
		} magic;
		magic.elfmag[EI_MAG0] = ELFMAG0;
		magic.elfmag[EI_MAG1] = ELFMAG1;
		magic.elfmag[EI_MAG2] = ELFMAG2;
		magic.elfmag[EI_MAG3] = ELFMAG3;

		trace("readmem vm_start 0x%08lx\n",vm_start);
		if(!readmem(vm_start, UVADDR, &word, sizeof(__u32),
			"reading user page for ELF binary", QUIET)) {
			word = 0;
		}

		trace("vmstart word %ux magic %x\n",word, magic.cmp);

		if (word == magic.cmp) {
				trace("<- vma_dump_size PAGESIZE");
				return PAGESIZE();
		}
	}

#undef	FILTER
	trace("<- vma_dump_size 0\n");
	return 0;

whole:
	trace("<- vma_dump_size vm_end - vm_start %d\n",vm_end - vm_start);
	return vm_end - vm_start;
}
/* END COPY */

/**
 * Writes all phdrs of the vma sections to the dump file
 *
 * @param ctx     Pointer to the appcore_context.
 * @param file	  File descriptor of the dump file.
 * @param dumpall Dump all VMA sections, regardless of their properties.
 */
static ssize_t write_vma_phdr(struct appcore_context* ctx,
			      int file, int dumpall, off_t offset)
{
	ulong vma, vm_start, vm_end, vm_flags, p_flags, mm_flags;
	void *vm_next;
	Elf32_Phdr phdr32;
	char *vma_buf;
	size_t memsz, filesz;
	ssize_t rc, total = 0;

	trace("write_vma_phdr\n");

	for (vma = ULONG(&(ULONG(tt->mm_struct + OFFSET(mm_struct_mmap))));
	     vma; vma = (ulong) vm_next)
	{
		vma_buf = fill_vma_cache(vma);

		trace("vma in write_vma_phdr 0x%08lx\n",vma);

		vm_start = ULONG(&(ULONG(vma_buf + OFFSET(vm_area_struct_vm_start))));
		vm_end = ULONG(&(ULONG(vma_buf + OFFSET(vm_area_struct_vm_end))));
		vm_next = ULONG(&(VOID_PTR(vma_buf + OFFSET(vm_area_struct_vm_next))));
		vm_flags = ULONG(&(ULONG(vma_buf + OFFSET(vm_area_struct_vm_flags))));
		mm_flags = ULONG(&(ULONG(tt->mm_struct + OFFSET(mm_struct_flags))));
		memsz = vm_end - vm_start;
		filesz = (dumpall || vma_dump_size(vma_buf, mm_flags)) ? memsz : 0;

		p_flags = vm_flags & VM_READ ? PF_R : 0;
		if (vm_flags & VM_WRITE)
			p_flags |= PF_W;
		if (vm_flags & VM_EXEC)
			p_flags |= PF_X;

		if( ctx->ei_class == ELFCLASS32 ) {
			phdr32.p_type = PT_LOAD;
			phdr32.p_offset = offset;
			phdr32.p_vaddr = vm_start;
			phdr32.p_paddr = 0;
			phdr32.p_filesz = filesz;
			phdr32.p_memsz = memsz;
			phdr32.p_flags = p_flags;
			phdr32.p_align = PAGESIZE();

			trace("vma phdr type %lx\n",phdr32.p_type);
			trace("vma phdr offset %lx\n",phdr32.p_offset);
			trace("vma phdr vaddr %lx\n",phdr32.p_vaddr);
			trace("vma phdr oaddr %lx\n",phdr32.p_paddr);
			trace("vma phdr filesize %lx\n",phdr32.p_filesz);
			trace("vma phdr memsize %lx\n",phdr32.p_memsz);
			trace("vma phdr flags %lx\n",phdr32.p_flags);
			trace("vma phdr align %lx\n",phdr32.p_align);

			trace("vma_phdr\n");
			hexdump(&phdr32, sizeof(phdr32));
			rc = write(file, &phdr32, sizeof(phdr32));
			if(rc < 0) {
				error(INFO,
				      "write_vma_phdr: write error: %s",
				      strerror(errno));
				return rc;
			}
			total += rc;
		}
		offset += filesz;
	}
	return total;
}


/**
 * Calculates the size of the memelfnote. This includes the size of the
 * referenced data.
 *
 * @param en The reference to the note.
 *
 * @return   The size in bytes.
 */
static int notesize(struct memelfnote *en)
{
	int sz;

	sz = sizeof(Elf32_Nhdr);
	sz += roundup(strlen(en->name) + 1, 4);
	sz += roundup(en->datasz, 4);

	return sz;
}

void swap_prsstatus(struct elf_prstatus_ppc * prsstatus)
{
	trace("swapping prsstatus\n");
	prsstatus->pr_info.si_signo=SHORT(&(prsstatus->pr_info.si_signo));
	prsstatus->pr_info.si_errno=SHORT(&(prsstatus->pr_info.si_errno));
	prsstatus->pr_info.si_code=SHORT(&(prsstatus->pr_info.si_code));
	prsstatus->pr_cursig=SHORT(&(prsstatus->pr_cursig));
	prsstatus->pr_sigpend=ULONG(&(prsstatus->pr_sigpend));
	prsstatus->pr_sighold=ULONG(&(prsstatus->pr_sighold));

	prsstatus->pr_pid=ULONG(&(prsstatus->pr_pid));
	prsstatus->pr_ppid=ULONG(&(prsstatus->pr_ppid));
	prsstatus->pr_pgrp=ULONG(&(prsstatus->pr_pgrp));
	prsstatus->pr_sid=ULONG(&(prsstatus->pr_sid));
}


/**
 * Writes the note given by @men to the file specified by @file.
 * The information of @men is copied to a Elf32_Nhdr struct, which is then
 * written to the file.
 *
 * @note modified version from kernel: $kernel/fs/binfmt_elf.c
 *
 * @param ctx  The appcore context pointer.
 * @param men  A pointer to the note
 * @param file The file descriptor of the the opened dump file.
 */
static int writenote(struct appcore_context* ctx, struct memelfnote *men,
		      int file)
{
	Elf32_Nhdr en32;
	off_t curpos;
	unsigned long n_namesz;
	ssize_t rc;

	n_namesz = strlen(men->name) + 1;

	if( ctx->ei_class == ELFCLASS32 )
	{
		en32.n_namesz = n_namesz;
		en32.n_descsz = men->datasz;
		en32.n_type = men->type;

		trace("write note namesz %lx \n",en32.n_namesz);
		trace("write note desc %lx \n",en32.n_descsz);
		trace("write note type %lx \n",en32.n_type);

		trace("writenote\n");
		hexdump(&en32, sizeof(en32));

		WRITE(rc, file, &en32, sizeof(en32), "writenote");
	}

	trace("sizeof prpsinfo  %d \n",sizeof(union elf_prpsinfo));
	trace("sizeof prstatus  %d \n",sizeof(union elf_prstatus));

	trace("write note namesz  %s \n",men->name);
	hexdump(men->name, n_namesz);
	WRITE(rc, file, men->name, n_namesz, "writenote");

	curpos = lseek(file, 0, SEEK_CUR);
	lseek(file, roundup(curpos, 4), SEEK_SET);

	if (men->datasz == sizeof(union elf_prstatus) && men->type == NT_PRSTATUS) {
		swap_prsstatus( (struct elf_prstatus_ppc *)men->data);
	}

	hexdump(men->data, men->datasz);
	WRITE(rc, file, men->data, men->datasz, "writenote");

	curpos = lseek(file, 0, SEEK_CUR);
	lseek(file, roundup(curpos, 4), SEEK_SET);

	return 1;
}


/**
 * Prints a message on the screen, that userpages from @missingstart up to
 * @missingend are not present in the dump
 *
 * @param missingstart The first page in the range of user pages, that is not
 * present
 * @param missingend   The last page in the range of user pages, thet is not
 * present
 */
static void printmissingpages(long missingstart, long missingend)
{
	long missingcount;

	missingcount = (missingend - missingstart + PAGESIZE()) >> PAGESHIFT();

	if (missingcount > 1) {
		fprintf(fp, "  Missing: %08lx - %08lx [%ld (0x%lx) pages]\n",
			missingstart, missingend, missingcount, missingcount);
	} else {
		fprintf(fp, "  Missing: %08lx\n", missingstart);
	}
}

/** Returns 'true' if the target architecture has a BIG ENDIAN byte order. */
static int big_endian(void)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
return NEED_SWAP();
#else
return !NEED_SWAP();
#endif
}

/**
 * Initializes an appcore context structure.
 *
 * The appcore structure contains architecture specific callback functions and
 * data values.
 *
 * ctx  Pointer to an appcore_context structure to be initialized.
 */
static void init_arch_context(struct appcore_context* ctx)
{
	memset(ctx, 0, sizeof(struct appcore_context));

	if( machine_type("PPC")) {
		ctx->e_machine = EM_PPC;
		ctx->ei_class = ELFCLASS32;
		/* FIXME: Move this to the ppc stuff. */
		ctx->thread_notes = 1;
		ctx->fill_prstatus = fill_prstatus_ppc;
		ctx->fill_prpsinfo = fill_prpsinfo_ppc;
	}

	if(big_endian())
		ctx->ei_data = ELFDATA2MSB;
	else
		ctx->ei_data = ELFDATA2LSB;
}

