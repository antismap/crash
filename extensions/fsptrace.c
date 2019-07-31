#include "defs.h"

int _init(void);
int _fini(void);

void cmd_fsptrace(void);
char *help_fsptrace[];

/* BEGIN: STRUCTS FROM  .../drivers/include/fsptrace.h */

/* Maximum size of component name, needed for struct */
#define TRACE_MAX_COMP_NAME_SIZE 16

/* Structure is put at beginning of all trace buffers */
typedef struct trace_buf_head {
	uint8_t ver;         /* version of this struct (1) */
	uint8_t hdr_len;     /* size of this struct in bytes */
	uint8_t time_flg;    /* meaning of timestamp entry field */
	uint8_t endian_flg;  /* flag for big ('B') or little ('L') endian */
	char comp[TRACE_MAX_COMP_NAME_SIZE];  /* the buffer name */
	uint32_t size;       /* size of buffer, including this struct */
	uint32_t times_wrap; /* how often the buffer wrapped */
	uint32_t next_free;  /* offset of the byte behind the latest entry */
	uint32_t extracted;  /* offset of the yet unread byte, or read-all
				flag */
	uint32_t te_count;   /* trace entry count */
} trace_buf_head_t;

static struct command_table_entry command_table[] = {
	{ "fsptrace", cmd_fsptrace, help_fsptrace, REFRESH_TASK_TABLE },
	{ NULL }
};

int _init(void) /* Register the command set. */
{
	register_extension(command_table);
	return 1;
}

int _fini(void)
{
	return 1;
}


enum FSPTRACE_OPS {
	NONE = 0,
	LIST = 1,
	COMP = 2,
	ALL  = 3,
};

struct fsptrace_opts {
	int op;
	char** comps;
	int comp_count;
	const char* dir;
};

static void do_fsptrace(struct fsptrace_opts * fop );
static void do_listtrace(struct fsptrace_opts * fop );
static void do_dumptrace(struct fsptrace_opts * fo);

/* Implementation of the fsptrace command in crash. */
void cmd_fsptrace(void)
{
	struct fsptrace_opts fo = {0,0,0,"./"};
	char c;
	struct stat data;
	int rc;

	/* parse command options. */
	while ((c = getopt(argcnt, args, "lcad:")) != -1) {
		switch(c) {
			case 'l':
				fo.op = LIST;
				break;
			case 'c':
				fo.op = COMP;
				break;
			case 'a':
				fo.op = ALL;
				break;
			case 'd':
				fo.dir = optarg;
				break;
			default:
				argerrs++;
				break;
		}
	}

	if (argerrs || fo.op == NONE)
		cmd_usage(pc->curcmd, SYNOPSIS);

	/* check 'dir' entry. */
	if (fo.dir) {
		rc = stat(fo.dir, &data);
		if(rc == -1)
			error(FATAL, "Invalid directory: %s (%s)",
			      fo.dir, strerror(errno));
		if(!S_ISDIR(data.st_mode))
			error(FATAL, "Invalid directory: %s (not a directory)",
			      fo.dir);
	}

	if (fo.op == COMP) {
		fo.comps = args + optind;
		fo.comp_count = argcnt - optind;
		if (fo.comp_count <= 0)
			cmd_usage(pc->curcmd, SYNOPSIS);
	}

	do_fsptrace(&fo);
}

char *help_fsptrace[] = {
	"fsptrace",			/* command name */
	"extract fsp-trace data",	/* short description */
	"[-l] [-c COMP ...] [-a] [-d DIR]",
	"  Extracts fsp-trace data from the dump."
	"",
	"  -l       List the names of all trace buffers.",
	"  -c NAME  Dump the named trace buffer.  More than one name may be",
	"           supplied (e.g. \"-c iic sfc\").",
	"  -a       Dump ALL trace buffers.",
	"  -d DIR   Output directory.",
	NULL
};


static char proc_header_line[] = " TD NAME               SIZE V    WRAPPED   TE_COUNT       NEXT\n";

static void do_fsptrace(struct fsptrace_opts * fop )
{
	if( fop->op == LIST )
		do_listtrace(fop);
	else
		do_dumptrace(fop);
}

typedef int (*callback)(trace_buf_head_t*, int idx, uint32_t addr, void* extra);

static int foreach_tracebuf( callback func, void* extra)
{
	int rc = 0;
	uint32_t buf_cnt = 0, i;
	uint32_t addr;
	uint32_t* trace_buffers;
	trace_buf_head_t buf;

	get_symbol_data("buf_cnt", sizeof(uint32_t), &buf_cnt);
	get_symbol_data("trace_buffers", sizeof(uint32_t), &addr);
	trace_buffers = (uint32_t*)GETBUF(buf_cnt * sizeof(uint32_t));

	readmem(addr, KVADDR, trace_buffers,
		buf_cnt * sizeof(uint32_t), "trace_buffers array",
		FAULT_ON_ERROR);
	swap_array(trace_buffers, sizeof(uint32_t), NEED_SWAP(),
		   STRICT_SWAP, buf_cnt);

	for (i=0; i < buf_cnt; i++) {
		if (!trace_buffers[i])
			continue;
		readmem(trace_buffers[i], KVADDR, &buf,
			sizeof(trace_buf_head_t), "trace_buf_head_t",
			FAULT_ON_ERROR);
		rc = (*func)(&buf, i, trace_buffers[i], extra);
		if(rc)
			break;
	}

	FREEBUF(trace_buffers);
	return rc;
}

static int listtrace_cb(trace_buf_head_t * buf, int idx, uint32_t addr,
			void* extra)
{
	/* ENDIAN_SWAP(buf->size); */
	/* ENDIAN_SWAP(buf->times_wrap); */
	/* ENDIAN_SWAP(buf->te_count); */
	/* ENDIAN_SWAP(buf->next_free); */
	fprintf(fp, "%3d %-16.16s %6d %d %10u %10u %10u\n",
		idx, buf->comp, buf->size, buf->ver, buf->times_wrap,
		buf->te_count, buf->next_free);
	return 0;
}

static void do_listtrace(struct fsptrace_opts * fop )
{
	fprintf(fp, "%s", proc_header_line);
	foreach_tracebuf(listtrace_cb,NULL);
}


static int dumptrace_cb(trace_buf_head_t * buf, int idx, uint32_t addr,
			void* extra)
{
	int i, dlen, clen, plen;
	char* tmp, *buffer = NULL, *path = NULL;
	struct fsptrace_opts* fop = (struct fsptrace_opts*)extra;
	FILE* dump;
	const char* fmt = "%s/%s";

	if (fop->op == COMP) {
		for (i = 0; i < fop->comp_count; i++) {
			if(!strcmp(fop->comps[i], buf->comp)) break;
		}
		if( i == fop->comp_count )
			return 0;
	}

	/* Open the file: */
	dlen = strlen(fop->dir);
	clen = strlen(buf->comp);
	plen = dlen + clen + 2;
	path = GETBUF(plen);
	if(dlen > 1 && fop->dir[dlen-1] == '/')
		fmt = "%s%s";
	snprintf(path, plen, fmt, fop->dir, buf->comp);
	dump = fopen(path, "w");

	if (!dump) {
		error(INFO, "Could not open: %s (%s)",
		      path, strerror(errno));
	} else {
		/*ENDIAN_SWAP(buf->size);*/
		fprintf(fp, "Writing: %s (%d)\n", path, buf->size);
		buffer = GETBUF(buf->size);

		readmem(addr, KVADDR, buffer, buf->size,
			"trace_buf_head_t", FAULT_ON_ERROR);
		fwrite(buffer, buf->size, 1, dump);
		fclose(dump);
		FREEBUF(buffer);
	}

	FREEBUF(path);

	if(fop->op == COMP) {
		fop->comp_count -= 1;
		/* If we've found everything, stop the foreach loop: */
		if (!fop->comp_count)
			return 1;
		tmp = fop->comps[fop->comp_count];
		fop->comps[fop->comp_count] = fop->comps[i];
		fop->comps[i] = tmp;
	}
	return 0;
}

static void do_dumptrace(struct fsptrace_opts * fop)
{
	int i;

	foreach_tracebuf(dumptrace_cb,fop);

	if (fop->op == COMP) {
		for( i = 0; i < fop->comp_count; i++ )
		error(INFO, "Missing trace buffer: %s",
		      fop->comps[i]);
	}
}
