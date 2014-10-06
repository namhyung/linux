/*
 * mem-malloc.c
 *
 * malloc: stress malloc/free with multi-threads
 *
 * Written by Namhyung Kim <namhyung@kernel.org>
 */

#include "perf.h"
#include "util/util.h"
#include "util/parse-options.h"
#include "bench.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>

#define K 1024

static const char		*length_str	= "100MB";
static size_t			chunk_size	= 32;
static int			iterations	= 3;
static size_t			len;
static int			nr_threads;
static pthread_barrier_t 	barrier;

static const struct option options[] = {
	OPT_STRING('l', "length", &length_str, "100MB",
		    "Specify length of memory to copy. "
		    "Available units: B, KB, MB, GB and TB (upper and lower)"),
	OPT_INTEGER('t', "threads", &nr_threads,
		    "Number of threads to run (default: nr of cpus)"),
	OPT_INTEGER('i', "iterations", &iterations,
		    "repeat malloc/free loop this number of times"),
	OPT_END()
};

static const char * const bench_mem_malloc_usage[] = {
	"perf bench mem malloc <options>",
	NULL
};

static double timeval2double(struct timeval *ts)
{
	return (double)ts->tv_sec +
		(double)ts->tv_usec / (double)1000000;
}

static double do_malloc_immediate_free(bool needs_barrier)
{
	struct timeval tv_start, tv_end, tv_diff;
	size_t sz;
	int i;

	BUG_ON(gettimeofday(&tv_start, NULL));
	for (i = 0; i < iterations; i++) {
		if (needs_barrier)
			pthread_barrier_wait(&barrier);

		for (sz = 0; sz < len; sz += chunk_size)
			free(malloc(chunk_size));
	}
	BUG_ON(gettimeofday(&tv_end, NULL));

	timersub(&tv_end, &tv_start, &tv_diff);
	return (double)((double)len / timeval2double(&tv_diff) * iterations);
}

static double do_malloc_last_free(bool needs_barrier)
{
	struct timeval tv_start, tv_end, tv_diff;
	size_t mapsz, sz;
	int i;
	void *table;
	unsigned long **ptrs;

	mapsz = (len + chunk_size - 1) / chunk_size * sizeof(long);
	table = mmap(NULL, mapsz, PROT_READ|PROT_WRITE,
		     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	BUG_ON(table == MAP_FAILED);

	/* prefault pointer table */
	for (sz = 0; sz < mapsz; sz += 4096)
		*((char *)table + sz) = 0;

	BUG_ON(gettimeofday(&tv_start, NULL));
	for (i = 0 ; i < iterations; i++) {
		if (needs_barrier)
			pthread_barrier_wait(&barrier);

		for (sz = 0, ptrs = table; sz < len; sz += chunk_size, ptrs++)
			*ptrs = malloc(chunk_size);

		for (sz = 0, ptrs = table; sz < len; sz += chunk_size, ptrs++)
			free(*ptrs);
	}
	BUG_ON(gettimeofday(&tv_end, NULL));

	timersub(&tv_end, &tv_start, &tv_diff);
	munmap(table, mapsz);
	return (double)((double)len / timeval2double(&tv_diff) * iterations);
}

struct test_result {
	double 	mif;
	double 	mlf;
};

static void *test_fn(void *arg)
{
	struct test_result *result = arg;

	result->mif = do_malloc_immediate_free(true);
	result->mlf = do_malloc_last_free(true);

	return NULL;
}

static void print_bps(double bps) {
	if (bps < K)
		printf(" %14lf B/Sec", bps);
	else if (bps < K * K)
		printf(" %14lf KB/Sec", bps / K);
	else if (bps < K * K * K)
		printf(" %14lf MB/Sec", bps / K / K);
	else
		printf(" %14lf GB/Sec", bps / K / K / K);
}

static void print_result(double mif, double mlf)
{
	switch (bench_format) {
	case BENCH_FORMAT_DEFAULT:
		print_bps(mif); printf("\t(immediate free)\n");
		print_bps(mlf); printf("\t(last free)\n");
		break;
	case BENCH_FORMAT_SIMPLE:
		printf("%14lf  %14lf\n", mif, mlf);
		break;
	default:
		/* reaching this means there's some disaster: */
		die("unknown format: %d\n", bench_format);
		break;
	}
}

int bench_mem_malloc(int argc, const char **argv,
		     const char *prefix __maybe_unused)
{
	int i;
	pthread_t *thid;
	double base_mif; 	/* malloc immediate free */
	double base_mlf; 	/* malloc last free */
	double avg_mif = 0;
	double avg_mlf = 0;
	struct test_result *args;

	nr_threads = sysconf(_SC_NPROCESSORS_ONLN);

	argc = parse_options(argc, argv, options,
			     bench_mem_malloc_usage, 0);

	len = (size_t)perf_atoll((char *)length_str);

	if ((s64)len <= 0) {
		fprintf(stderr, "Invalid length:%s\n", length_str);
		return 1;
	}

	if (bench_format == BENCH_FORMAT_DEFAULT)
		printf("# Allocating %s Bytes in single thread...\n\n", length_str);

	base_mif = do_malloc_immediate_free(false);
	base_mlf = do_malloc_last_free(false);

	print_result(base_mif, base_mlf);

	if (nr_threads <= 1)
		return 0;

	pthread_barrier_init(&barrier, NULL, nr_threads);

	if (bench_format == BENCH_FORMAT_DEFAULT)
		printf("\n# Allocating %s Bytes for each %d thread...\n\n",
		       length_str, nr_threads);

	thid = calloc(sizeof(*thid), nr_threads);
	args = calloc(sizeof(*args), nr_threads);
	BUG_ON(thid == NULL || args == NULL);

	for (i = 0; i < nr_threads; i++) {
		BUG_ON(pthread_create(&thid[i], NULL, test_fn, &args[i]));
	}

	for (i = 0; i < nr_threads; i++) {
		BUG_ON(pthread_join(thid[i], NULL));
		avg_mif += args[i].mif;
		avg_mlf += args[i].mlf;
	}

	avg_mif /= nr_threads;
	avg_mlf /= nr_threads;

	print_result(avg_mif, avg_mlf);

	free(thid);
	free(args);

	return 0;
}
