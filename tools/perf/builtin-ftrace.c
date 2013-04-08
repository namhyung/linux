/*
 * builtin-ftrace.c
 *
 * Copyright (c) 2013  LG Electronics,  Namhyung Kim <namhyung@kernel.org>
 *
 * Released under the GPL v2.
 */

#include "builtin.h"
#include "perf.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#include "util/debug.h"
#include "util/parse-options.h"
#include "util/evlist.h"
#include "util/target.h"
#include "util/thread_map.h"
#include "util/cpumap.h"


#define DEFAULT_TRACER  "function_graph"

struct perf_ftrace {
	struct perf_evlist *evlist;
	struct perf_target target;
	const char *tracer;
};

static bool done;

static void sig_handler(int sig __maybe_unused)
{
	done = true;
}

static int __write_tracing_file(const char *name, const char *val, bool append)
{
	char *file;
	int fd, ret = -1;
	ssize_t size = strlen(val);
	int flags = O_WRONLY;

	file = get_tracing_file(name);
	if (!file) {
		pr_debug("cannot get tracing file: %s\n", name);
		return -1;
	}

	if (append)
		flags |= O_APPEND;
	else
		flags |= O_TRUNC;

	fd = open(file, flags);
	if (fd < 0) {
		pr_debug("cannot open tracing file: %s\n", name);
		goto out;
	}

	if (write(fd, val, size) == size)
		ret = 0;
	else
		pr_debug("write '%s' to tracing/%s failed\n", val, name);

	close(fd);
out:
	put_tracing_file(file);
	return ret;
}

static int write_tracing_file(const char *name, const char *val)
{
	return __write_tracing_file(name, val, false);
}

static int append_tracing_file(const char *name, const char *val)
{
	return __write_tracing_file(name, val, true);
}

static int reset_tracing_cpu(void);

static int reset_tracing_files(struct perf_ftrace *ftrace __maybe_unused)
{
	if (write_tracing_file("tracing_on", "0") < 0)
		return -1;

	if (write_tracing_file("current_tracer", "nop") < 0)
		return -1;

	if (write_tracing_file("set_ftrace_pid", " ") < 0)
		return -1;

	if (reset_tracing_cpu() < 0)
		return -1;

	return 0;
}

static int set_tracing_pid(struct perf_ftrace *ftrace)
{
	int i;
	char buf[16];

	if (perf_target__has_cpu(&ftrace->target))
		return 0;

	for (i = 0; i < thread_map__nr(ftrace->evlist->threads); i++) {
		scnprintf(buf, sizeof(buf), "%d",
			  ftrace->evlist->threads->map[i]);
		if (append_tracing_file("set_ftrace_pid", buf) < 0)
			return -1;
	}
	return 0;
}

static int set_tracing_cpu(struct perf_ftrace *ftrace)
{
	char *cpumask;
	size_t mask_size;
	int ret;
	int last_cpu;
	struct cpu_map *cpumap = ftrace->evlist->cpus;

	if (!perf_target__has_cpu(&ftrace->target))
		return 0;

	last_cpu = cpumap->map[cpumap->nr - 1];
	mask_size = (last_cpu + 3) / 4 + 1;
	mask_size += last_cpu / 32; /* ',' is needed for every 32th cpus */

	cpumask = malloc(mask_size);
	if (cpumask == NULL) {
		pr_debug("failed to allocate cpu mask\n");
		return -1;
	}

	cpu_map__sprintf(cpumap, cpumask);

	ret = write_tracing_file("tracing_cpumask", cpumask);

	free(cpumask);
	return ret;
}

static int reset_tracing_cpu(void)
{
	char *cpumask;
	size_t mask_size;
	int last_cpu;
	struct cpu_map *cpumap = cpu_map__new(NULL);

	last_cpu = cpumap->map[cpumap->nr - 1];
	mask_size = (last_cpu + 3) / 4 + 1;
	mask_size += last_cpu / 32; /* ',' is needed for every 32th cpus */

	cpumask = malloc(mask_size);
	if (cpumask == NULL) {
		pr_debug("failed to allocate cpu mask\n");
		return -1;
	}

	cpu_map__sprintf(cpumap, cpumask);

	write_tracing_file("tracing_cpumask", cpumask);

	free(cpumask);
	return 0;
}

static int do_ftrace_live(struct perf_ftrace *ftrace)
{
	char *trace_file;
	int trace_fd;
	char buf[4096];
	/* sleep 1ms if no data read */
	struct timespec req = { .tv_nsec = 1000000 };

	signal(SIGINT, sig_handler);
	signal(SIGUSR1, sig_handler);
	signal(SIGCHLD, sig_handler);

	if (reset_tracing_files(ftrace) < 0)
		goto out;

	/* reset ftrace buffer */
	if (write_tracing_file("trace", "0") < 0)
		goto out;

	if (set_tracing_pid(ftrace) < 0) {
		pr_err("failed to set ftrace pid\n");
		goto out_reset;
	}

	if (set_tracing_cpu(ftrace) < 0) {
		pr_err("failed to set tracing cpumask\n");
		goto out_reset;
	}

	if (write_tracing_file("current_tracer", ftrace->tracer) < 0) {
		pr_err("failed to set current_tracer to %s\n", ftrace->tracer);
		goto out_reset;
	}

	trace_file = get_tracing_file("trace_pipe");
	if (!trace_file) {
		pr_err("failed to open trace_pipe\n");
		goto out_reset;
	}

	trace_fd = open(trace_file, O_RDONLY);

	put_tracing_file(trace_file);

	if (trace_fd < 0) {
		pr_err("failed to open trace_pipe\n");
		goto out_reset;
	}

	fcntl(trace_fd, F_SETFL, O_NONBLOCK);

	if (write_tracing_file("tracing_on", "1") < 0) {
		pr_err("can't enable tracing\n");
		goto out_close_fd;
	}

	perf_evlist__start_workload(ftrace->evlist);

	while (!done) {
		int n = read(trace_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				goto sleep;
			else
				break;
		} else if (n == 0) {
sleep:
			clock_nanosleep(CLOCK_MONOTONIC, 0, &req, NULL);
		} else if (fwrite(buf, n, 1, stdout) != 1)
			break;
	}

	write_tracing_file("tracing_on", "0");

	/* read remaining buffer contents */
	while (true) {
		int n = read(trace_fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		if (fwrite(buf, n, 1, stdout) != 1)
			break;
	}

out_close_fd:
	close(trace_fd);
out_reset:
	reset_tracing_files(ftrace);
out:
	return done ? 0 : -1;
}

static int
__cmd_ftrace_live(struct perf_ftrace *ftrace, int argc, const char **argv)
{
	int ret = -1;
	const char * const live_usage[] = {
		"perf ftrace live [<options>] [<command>]",
		"perf ftrace live [<options>] -- <command> [<options>]",
		NULL
	};
	const struct option live_options[] = {
	OPT_STRING('t', "tracer", &ftrace->tracer, "tracer",
		   "tracer to use: function_graph or function"),
	OPT_STRING('p', "pid", &ftrace->target.pid, "pid",
		   "trace on existing process id"),
	OPT_INCR('v', "verbose", &verbose,
		 "be more verbose"),
	OPT_BOOLEAN('a', "all-cpus", &ftrace->target.system_wide,
		    "system-wide collection from all CPUs"),
	OPT_STRING('C', "cpu", &ftrace->target.cpu_list, "cpu",
		    "list of cpus to monitor"),
	OPT_END()
	};

	argc = parse_options(argc, argv, live_options, live_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc && perf_target__none(&ftrace->target))
		usage_with_options(live_usage, live_options);

	ret = perf_target__validate(&ftrace->target);
	if (ret) {
		char errbuf[512];

		perf_target__strerror(&ftrace->target, ret, errbuf, 512);
		pr_err("%s\n", errbuf);
		return -EINVAL;
	}

	ftrace->evlist = perf_evlist__new();
	if (ftrace->evlist == NULL)
		return -ENOMEM;

	ret = perf_evlist__create_maps(ftrace->evlist, &ftrace->target);
	if (ret < 0)
		goto out;

	if (ftrace->tracer == NULL)
		ftrace->tracer = DEFAULT_TRACER;

	if (argc && perf_evlist__prepare_workload(ftrace->evlist,
						  &ftrace->target,
						  argv, false, true) < 0)
		goto out_maps;

	ret = do_ftrace_live(ftrace);

out_maps:
	perf_evlist__delete_maps(ftrace->evlist);
out:
	perf_evlist__delete(ftrace->evlist);

	return ret;
}

int cmd_ftrace(int argc, const char **argv, const char *prefix __maybe_unused)
{
	int ret;
	struct perf_ftrace ftrace = {
		.target = { .uid = UINT_MAX, },
	};
	const char * const ftrace_usage[] = {
		"perf ftrace {live} [<options>] [<command>]",
		"perf ftrace {live} [<options>] -- <command> [<options>]",
		NULL
	};
	const struct option ftrace_options[] = {
	OPT_END()
	};

	argc = parse_options(argc, argv, ftrace_options, ftrace_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc)
		usage_with_options(ftrace_usage, ftrace_options);

	if (geteuid() != 0) {
		pr_err("ftrace only works for root!\n");
		return -1;
	}

	if (strcmp(argv[0], "live") == 0) {
		ret = __cmd_ftrace_live(&ftrace, argc, argv);
	} else {
		usage_with_options(ftrace_usage, ftrace_options);
	}

	return ret;
}
