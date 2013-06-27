/*
 * Builtin check command:  Check current kernel and tools setting
 * and report to user.
 */
#include <sys/utsname.h>
#include <fcntl.h>

#include "perf.h"
#include "builtin.h"
#include "util/cache.h"
#include "util/debug.h"
#include "util/symbol.h"
#include "util/parse-options.h"


static int read_proc_file(const char *filename)
{
	int fd, val = -1000;
	char buf[128];

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		pr_err("Unable to open %s\n", filename);
		return val;
	}

	if (read(fd, buf, sizeof(buf)) < 0)
		pr_err("Unable to read %s\n", filename);
	else
		val = atoi(buf);

	close(fd);
	return val;
}

static void check_kernel(void)
{
	int ret;
	struct utsname uts;
	struct perf_event_attr attr = {
		.size = sizeof(attr),
		.disabled = 1,
		.exclude_kernel = 1,
	};

	/* kernel version */
	ret = uname(&uts);
	if (ret < 0) {
		perror("uname");
		return;
	}

	pr_info("kernel version: %s\n", uts.release);

	/* kptr_restrict */
	ret = read_proc_file("/proc/sys/kernel/kptr_restrict");
	if (ret > 0) {
		pr_warning("/proc/sys/kernel/kptr_restrict is enabled."
			" %s users are not allowed to read kernel symbols.\n",
			ret == 1 ? "unprivileged" : "no");
	} else {
		pr_debug("/proc/sys/kernel/kptr_restrict disabled.\n");
	}

	/* perf_event_paranoid */
	pr_debug("checking /proc/sys/kernel/perf_event_paranoid.\n");
	ret = read_proc_file("/proc/sys/kernel/perf_event_paranoid");
	switch (ret) {
	case -1:
		pr_info("unprivileged users can do everything.\n");
		break;
	case 0:
		pr_info("unprivileged users cannot access to raw tracepoint data.\n");
		break;
	case 1:
		pr_info("unprivileged users cannot do system-wide profiling.\n");
		break;
	case 2:
		pr_info("unprivileged users cannot do kernel profiling.\n");
		break;
	default:
		break;
	}

	/* perf itself, using s/w event */
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	ret = sys_perf_event_open(&attr, 0, -1, -1, 0);
	close(ret);
	if (ret < 0) {
		perror("perf_event_open");
		switch (-ret) {
		case EPERM:
		case EACCES:
			/* check /proc/sys/kernel/paranoid */
		default:
			break;
		}
		return;
	}
	pr_debug("kernel supports perf software event.\n");

	/* h/w event */
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	ret = sys_perf_event_open(&attr, 0, -1, -1, 0);
	close(ret);
	if (ret < 0) {
		perror("perf_event_open");
		return;
	}
	pr_debug("kernel supports perf hardware event.\n");

	/* tracepoint event */
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.config = 20; /* random choice */
	ret = sys_perf_event_open(&attr, 0, -1, -1, 0);
	close(ret);
	if (ret < 0) {
		perror("perf_event_open");
		return;
	}
	pr_debug("kernel supports perf tracepoint event.\n");

	/* hw breakpoint event */
	/* attributes - size, bits */
	/* precise */
}

static void check_tool(void)
{
	/* tool version */
	/* kernel config */
	/* build flags */
	/* libc or pthread */
	/* perfconfig */
}

static void check_file(void)
{
	/* header info */
	/* evlist */
	/* guess command */
	/* build-id */
	/* cross-compile */
}

int cmd_check(int argc, const char **argv, const char *prefix __maybe_unused)
{
	bool do_kernel = true, do_tool = false, do_file = false, do_all = false;
	const char * const check_usage[] = {
		"perf check [<options>]",
		NULL
	};
	struct option check_options[] = {
	OPT_BOOLEAN('a', "all", &do_all, "check kernel, tool and file"),
	OPT_BOOLEAN('k', "kernel", &do_kernel, "check kernel"),
	OPT_BOOLEAN('t', "tool", &do_tool, "check tool"),
	OPT_BOOLEAN('f', "file", &do_file, "check file"),
	OPT_STRING('i', "input", &input_name, "file", "input file name"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_END(),
	};

	argc = parse_options(argc, argv, check_options, check_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc)
		usage_with_options(check_usage, check_options);

	if (do_all)
		do_kernel = do_tool = do_file = true;

	if (!(do_kernel || do_tool || do_file)) {
		pr_warning("You need to set one of -k, -t or -f option.\n");
		return 0;
	}

	symbol__init();

	if (do_kernel)
		check_kernel();
	if (do_tool)
		check_tool();
	if (do_file)
		check_file();

	return 0;
}
