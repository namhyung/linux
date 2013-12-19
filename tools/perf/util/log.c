#include <stdio.h>
#include <stdlib.h>
#include "util/debug.h"

#define LINEMAP_GROW  128

struct perf_log perf_log = {
	.seen_newline = true,
};

int perf_log__init(void)
{
	FILE *fp = tmpfile();
	if (fp == NULL)
		return -1;

	perf_log.fp = fp;

	return 0;
}

int perf_log__exit(void)
{
	FILE *fp = perf_log.fp;
	if (fp)
		fclose(fp);

	free(perf_log.linemap);

	perf_log.fp = NULL;
	perf_log.linemap = NULL;
	return 0;
}

static int grow_linemap(struct perf_log *log)
{
	off_t *newmap;
	int newsize = log->nr_alloc + LINEMAP_GROW;

	newmap = realloc(log->linemap, newsize * sizeof(*log->linemap));
	if (newmap == NULL)
		return -1;

	log->nr_alloc = newsize;
	log->linemap = newmap;
	return 0;
}

static int __add_to_linemap(struct perf_log *log, off_t idx)
{
	if (log->lines == log->nr_alloc)
		if (grow_linemap(log) < 0)
			return -1;

	log->linemap[log->lines++] = idx;
	return 0;
}

static void add_to_linemap(struct perf_log *log, const char *msg, off_t base)
{
	const char *pos;

	if (strlen(msg) == 0)
		return;

	if (log->seen_newline) {
		if (__add_to_linemap(log, base) < 0)
			return;
	}

	if ((pos = strchr(msg, '\n')) != NULL) {
		log->seen_newline = true;
		pos++;
		add_to_linemap(log, pos, base + (pos - msg));
	} else {
		log->seen_newline = false;
	}
}

void perf_log__add(const char *msg)
{
	FILE *fp = perf_log.fp;
	off_t offset;
	u32 saved_lines;
	size_t msglen;

	if (fp == NULL)
		return;

	pthread_mutex_lock(&ui__lock);

	offset = ftello(fp);
	saved_lines = perf_log.lines;
	msglen = strlen(msg);

	add_to_linemap(&perf_log, msg, offset);

	if (fwrite(msg, 1, msglen, fp) != msglen) {
		/* restore original offset */
		fseeko(fp, offset, SEEK_SET);
		perf_log.lines = saved_lines;
	}
	pthread_mutex_unlock(&ui__lock);
}

void perf_log__addv(const char *fmt, va_list ap)
{
	char buf[4096];

	if (perf_log.fp == NULL)
		return;

	vsnprintf(buf, sizeof(buf), fmt, ap);
	perf_log__add(buf);
}
