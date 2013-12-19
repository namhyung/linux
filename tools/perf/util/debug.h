/* For debugging general purposes */
#ifndef __PERF_DEBUG_H
#define __PERF_DEBUG_H

#include <stdbool.h>
#include "event.h"
#include "../ui/helpline.h"
#include "../ui/progress.h"
#include "../ui/util.h"

extern int verbose;
extern bool quiet, dump_trace;

int dump_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void trace_event(union perf_event *event);

int ui__error(const char *format, ...) __attribute__((format(printf, 1, 2)));
int ui__warning(const char *format, ...) __attribute__((format(printf, 1, 2)));

void pr_stat(const char *fmt, ...);

struct perf_log {
	FILE *fp;
	off_t *linemap;
	u32 lines;
	u32 nr_alloc;
	bool seen_newline;
};

extern struct perf_log perf_log;

int perf_log__init(void);
int perf_log__exit(void);
void perf_log__add(const char *msg);
void perf_log__addv(const char *fmt, va_list ap);

#endif	/* __PERF_DEBUG_H */
