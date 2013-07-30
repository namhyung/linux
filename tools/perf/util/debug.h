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
void dump_raw_event(void *event, int size);

int ui__error(const char *format, ...) __attribute__((format(printf, 1, 2)));
int ui__warning(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif	/* __PERF_DEBUG_H */
