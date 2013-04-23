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
#include <dirent.h>
#include <sys/mman.h>

#include "util/debug.h"
#include "util/parse-options.h"
#include "util/evlist.h"
#include "util/target.h"
#include "util/thread_map.h"
#include "util/cpumap.h"
#include "util/sort.h"
#include "util/trace-event.h"
#include "../lib/traceevent/kbuffer.h"
#include "../lib/traceevent/event-parse.h"


#define DEFAULT_TRACER  "function_graph"
#define DEFAULT_DIRNAME  "perf.data"

struct perf_ftrace {
	struct perf_evlist *evlist;
	struct perf_target target;
	const char *tracer;
	const char *dirname;
	struct pevent *pevent;
	bool show_full_info;
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

static int setup_tracing_files(struct perf_ftrace *ftrace)
{
	int ret = -1;

	if (reset_tracing_files(ftrace) < 0) {
		pr_err("failed to reset tracing files\n");
		goto out;
	}

	/* reset ftrace buffer */
	if (write_tracing_file("trace", "0") < 0) {
		pr_err("failed to reset ftrace buffer\n");
		goto out;
	}

	if (set_tracing_pid(ftrace) < 0) {
		pr_err("failed to set ftrace pid\n");
		goto out;
	}

	if (set_tracing_cpu(ftrace) < 0) {
		pr_err("failed to set tracing cpumask\n");
		goto out;
	}

	if (write_tracing_file("current_tracer", ftrace->tracer) < 0) {
		pr_err("failed to set current_tracer to %s\n", ftrace->tracer);
		goto out;
	}

	ret = 0;
out:
	return ret;
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

	if (setup_tracing_files(ftrace) < 0)
		goto out_reset;

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
	return done ? 0 : -1;
}

static int alloc_ftrace_evsel(struct perf_ftrace *ftrace)
{
	struct perf_evsel *evsel;

	if (!strcmp(ftrace->tracer, "function")) {
		if (perf_evlist__add_newtp(ftrace->evlist, "ftrace",
					   "function", NULL) < 0) {
			pr_err("failed to allocate ftrace event\n");
			return -1;
		}
	} else if (!strcmp(ftrace->tracer, "function_graph")) {
		if (perf_evlist__add_newtp(ftrace->evlist, "ftrace",
					   "funcgraph_entry", NULL) ||
		    perf_evlist__add_newtp(ftrace->evlist, "ftrace",
					   "funcgraph_exit", NULL)) {
			pr_err("failed to allocate ftrace event\n");
			return -1;
		}
	} else {
		pr_err("Not supported tracer: %s\n", ftrace->tracer);
		return -1;
	}

	list_for_each_entry(evsel, &ftrace->evlist->entries, node)
		perf_evsel__set_sample_id(evsel, false);

	perf_evlist__set_id_pos(ftrace->evlist);
	return 0;
}

static void canonicalize_directory_name(const char *name)
{
	char *suffix = strstr(name, ".dir");

	if (suffix) {
		if (suffix[4] == '\0' || suffix[4] == '/')
			*suffix = '\0';
	}
}

static int remove_directory(const char *pathname)
{
	DIR *dir;
	int ret = 0;
	struct dirent *dent;
	char namebuf[PATH_MAX];

	dir = opendir(pathname);
	if (dir == NULL)
		return 0;

	while ((dent = readdir(dir)) != NULL && !ret) {
		struct stat statbuf;

		if (dent->d_name[0] == '.')
			continue;

		scnprintf(namebuf, sizeof(namebuf), "%s/%s",
			  pathname, dent->d_name);

		ret = stat(namebuf, &statbuf);
		if (ret < 0) {
			pr_debug("stat failed\n");
			break;
		}

		if (S_ISREG(statbuf.st_mode))
			ret = unlink(namebuf);
		else if (S_ISDIR(statbuf.st_mode))
			ret = remove_directory(namebuf);
		else {
			pr_debug("unknown file.\n");
			ret = -1;
		}
	}
	closedir(dir);

	if (ret < 0)
		return ret;

	return rmdir(pathname);
}

static int create_perf_header(struct perf_ftrace *ftrace)
{
	int err;
	char buf[PATH_MAX];
	struct stat statbuf;

	canonicalize_directory_name(ftrace->dirname);

	scnprintf(buf, sizeof(buf), "%s.dir", ftrace->dirname);

	if (!stat(buf, &statbuf) && S_ISDIR(statbuf.st_mode)) {
		/* same name already exists - rename to *.old.dir */
		char *old_name = malloc(strlen(buf) + 5);
		if (old_name == NULL)
			return -1;

		scnprintf(old_name, strlen(buf) + 5,
			  "%s.old.dir", ftrace->dirname);

		if (remove_directory(old_name) < 0) {
			perror("rmdir");
			return -1;
		}

		if (rename(buf, old_name) < 0) {
			perror("rename");
			free(old_name);
			return -1;
		}

		free(old_name);
	}

	err = mkdir(buf, 0755);
	if (err < 0) {
		perror("mkdir");
		return -1;
	}

	strcat(buf, "/perf.header");

	err = open(buf, O_RDWR | O_CREAT | O_TRUNC, 0644);
	return err;
}

static void sig_dummy_handler(int sig __maybe_unused)
{
	while (!done)
		continue;
}

enum {
	RECORD_STATE__ERROR = -1,
	RECORD_STATE__INIT,
	RECORD_STATE__READY,
	RECORD_STATE__DONE,
};

struct ftrace_record_arg {
	struct perf_ftrace *ftrace;
	int cpu;
	int state;
	pthread_t id;
	struct list_head node;
};

static int recorder_count;
pthread_cond_t recorder_ready_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t recorder_start_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t recorder_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *record_ftrace_raw_buffer(void *arg)
{
	struct ftrace_record_arg *fra = arg;
	char buf[4096];
	char *trace_file;
	int trace_fd;
	int output_fd;
	off_t byte_written = 0;
	sigset_t sigmask;
	/* sleep 1ms if no data read */
	struct timespec req = { .tv_nsec = 1000000 };

	fra->state = RECORD_STATE__ERROR;

	snprintf(buf, sizeof(buf), "per_cpu/cpu%d/trace_pipe_raw", fra->cpu);

	trace_file = get_tracing_file(buf);
	if (!trace_file) {
		pr_err("failed to get trace_pipe_raw\n");
		goto out;
	}

	trace_fd = open(trace_file, O_RDONLY);

	put_tracing_file(trace_file);

	if (trace_fd < 0) {
		pr_err("failed to open trace_pipe_raw\n");
		goto out;
	}

	snprintf(buf, sizeof(buf), "%s.dir/trace-cpu%d.buf",
		 fra->ftrace->dirname, fra->cpu);

	output_fd = open(buf, O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (output_fd < 0) {
		pr_err("failed to open output file\n");
		goto out_close;
	}

	fra->state = RECORD_STATE__READY;

	/*
	 * block all signals but SIGUSR2.
	 * It'll be used to unblock a recorder to finish.
	 */
	sigfillset(&sigmask);
	sigdelset(&sigmask, SIGUSR2);
	pthread_sigmask(SIG_SETMASK, &sigmask,NULL);

	signal(SIGUSR2, sig_dummy_handler);

	fcntl(trace_fd, F_SETFL, O_NONBLOCK);

	/* Now I'm ready */
	pthread_mutex_lock(&recorder_mutex);
	recorder_count++;
	pthread_cond_signal(&recorder_ready_cond);
	pthread_cond_wait(&recorder_start_cond, &recorder_mutex);
	pthread_mutex_unlock(&recorder_mutex);

	pr_debug2("now recording for cpu%d\n", fra->cpu);

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
		} else if (write(output_fd, buf, n) != n)
			break;

		byte_written += n;
	}

	/* read remaining buffer contents */
	while (true) {
		int n = read(trace_fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				break;
			perror("flush read");
			goto out_close2;
		} else if (n == 0)
			break;

		if (write(output_fd, buf, n) != n) {
			perror("flush write");
			goto out_close2;
		}

		byte_written += n;
	}
	fra->state = RECORD_STATE__DONE;

out_close2:
	close(output_fd);
out_close:
	close(trace_fd);
out:
	if (fra->state == RECORD_STATE__ERROR) {
		/*
		 * We need to update recorder_count in this case also
		 * in order to prevent deadlocking in the main thread.
		 */
		pthread_mutex_lock(&recorder_mutex);
		recorder_count++;
		pthread_cond_signal(&recorder_ready_cond);
		pthread_mutex_unlock(&recorder_mutex);
	}

	pr_debug2("done with %ld bytes\n", (long)byte_written);
	return fra;
}

static void *synthesize_raw_data(struct perf_evsel *evsel)
{
	void *data = NULL;
	u32 data_size;

	if (!strcmp(evsel->tp_format->name, "function")) {
		struct {
			unsigned short common_type;
			unsigned char common_flags;
			unsigned char common_preempt_count;
			int common_pid;
			int common_padding;

			unsigned long ip;
			unsigned long parent_ip;
		} function_format = {
			.common_type = evsel->attr.config,
		};

		data_size = sizeof(function_format);

		data = malloc(data_size + sizeof(u32));
		if (data == NULL)
			return NULL;

		memcpy(data, &data_size, sizeof(data_size));
		memcpy(data + sizeof(data_size), &function_format,
		       sizeof(function_format));
	} else if (!strcmp(evsel->tp_format->name, "funcgraph_entry")) {
		struct {
			unsigned short common_type;
			unsigned char common_flags;
			unsigned char common_preempt_count;
			int common_pid;
			int common_padding;

			unsigned long func;
			int depth;
		} funcgraph_entry_format = {
			.common_type = evsel->attr.config,
		};

		data_size = sizeof(funcgraph_entry_format);

		data = malloc(data_size + sizeof(u32));
		if (data == NULL)
			return NULL;

		memcpy(data, &data_size, sizeof(data_size));
		memcpy(data + sizeof(data_size), &funcgraph_entry_format,
		       sizeof(funcgraph_entry_format));
	}
	return data;
}

static int do_ftrace_record(struct perf_ftrace *ftrace)
{
	int i, err, feat;
	int perf_fd;
	LIST_HEAD(recorders);
	struct perf_session *session;
	struct ftrace_record_arg *fra, *tmp;

	signal(SIGINT, sig_handler);
	signal(SIGUSR1, sig_handler);
	signal(SIGCHLD, sig_handler);

	if (setup_tracing_files(ftrace) < 0)
		goto out_reset;

	alloc_ftrace_evsel(ftrace);

	perf_fd = create_perf_header(ftrace);
	if (perf_fd < 0) {
		pr_err("failed to create perf directory\n");
		goto out_reset;
	}

	/* just use a dummy session for header recording */
	session = zalloc(sizeof(*session));
	if (session == NULL) {
		pr_err("failed to allocate perf session\n");
		goto out_close;
	}
	session->evlist = ftrace->evlist;

	for (feat = HEADER_FIRST_FEATURE; feat < HEADER_LAST_FEATURE; feat++)
		perf_header__set_feat(&session->header, feat);

	perf_header__clear_feat(&session->header, HEADER_BUILD_ID);
	perf_header__clear_feat(&session->header, HEADER_BRANCH_STACK);
	perf_header__clear_feat(&session->header, HEADER_PMU_MAPPINGS);
	perf_header__clear_feat(&session->header, HEADER_GROUP_DESC);

	err = perf_session__write_header(session, ftrace->evlist,
					 perf_fd, false);
	if (err < 0) {
		pr_err("failed to write perf header\n");
		goto out_session;
	}

	/*
	 * We record ftrace's per_cpu buffer so that it'd better having
	 * corresponding cpu maps anyway.
	 */
	if (!perf_target__has_cpu(&ftrace->target)) {
		struct cpu_map *new_map;

		new_map = cpu_map__new(NULL);
		if (new_map == NULL) {
			pr_err("failed to create new cpu map\n");
			goto out_session;
		}

		/* replace existing cpu map */
		cpu_map__delete(ftrace->evlist->cpus);
		ftrace->evlist->cpus = new_map;
	}

	for (i = 0; i < cpu_map__nr(ftrace->evlist->cpus); i++) {
		fra = malloc(sizeof(*fra));
		if (fra == NULL) {
			pr_err("not enough memory!\n");
			goto out_fra;
		}

		fra->ftrace = ftrace;
		fra->cpu = ftrace->evlist->cpus->map[i];
		fra->state = RECORD_STATE__INIT;
		list_add_tail(&fra->node, &recorders);

		err = pthread_create(&fra->id, NULL,
				     record_ftrace_raw_buffer, fra);
		if (err < 0) {
			pr_err("failed to create recorder thread\n");
			goto out_fra;
		}
	}

	/* wait for all recorders ready */
	pthread_mutex_lock(&recorder_mutex);
	while (recorder_count != cpu_map__nr(ftrace->evlist->cpus))
		pthread_cond_wait(&recorder_ready_cond, &recorder_mutex);
	pthread_mutex_unlock(&recorder_mutex);

	list_for_each_entry(fra, &recorders, node) {
		if (fra->state != RECORD_STATE__READY) {
			pr_err("cpu%d: failed to start recorder", fra->cpu);
			goto out_fra;
		}
	}

	if (write_tracing_file("tracing_on", "1") < 0) {
		pr_err("can't enable tracing\n");
		goto out_fra;
	}

	perf_evlist__start_workload(ftrace->evlist);

	pr_debug2("start recording per cpu buffers\n");
	pthread_mutex_lock(&recorder_mutex);
	pthread_cond_broadcast(&recorder_start_cond);
	pthread_mutex_unlock(&recorder_mutex);

	/* wait for signal/finish */
	pause();

	if (write_tracing_file("tracing_on", "0") < 0) {
		pr_err("can't disable tracing\n");
		goto out_fra;
	}

	/* signal recorders to terminate */
	list_for_each_entry(fra, &recorders, node) {
		pr_debug2("killing recorder thread for cpu%d\n", fra->cpu);
		pthread_kill(fra->id, SIGUSR2);
	}

	list_for_each_entry(fra, &recorders, node)
		pthread_join(fra->id, NULL);

	/* synthesize sample data */
	list_for_each_entry(fra, &recorders, node) {
		struct perf_evsel *evsel = perf_evlist__first(ftrace->evlist);
		union perf_event event = {
			.sample = {
				.header = {
					.type = PERF_RECORD_SAMPLE,
					.misc = PERF_RECORD_MISC_KERNEL,
					.size = sizeof(event.sample.header) +
						evsel->sample_size,
				},
			},
		};
		struct perf_sample sample = {
			.cpu = fra->cpu,
			.period = 1,
		};
		void *raw_data;
		u32 raw_size;
		int orig_size;

		if (fra->state != RECORD_STATE__DONE) {
			pr_warning("recorder failed for some reason on cpu%d\n",
				   fra->cpu);
			continue;
		}

		perf_event__synthesize_sample(&event, evsel->attr.sample_type,
					      evsel->attr.sample_regs_user,
					      evsel->attr.read_format,
					      &sample, false);

		raw_data = synthesize_raw_data(evsel);
		if (raw_data == NULL) {
			pr_err("synthesizing raw sample failed\n");
			goto out_fra;
		}

		/*
		 * start of raw data is the size of raw data excluding itself.
		 */
		raw_size = sizeof(u32) + (*(u32 *) raw_data);

		orig_size = event.sample.header.size;
		event.sample.header.size += raw_size;

		err = write(perf_fd, &event.sample, orig_size);
		if (err != orig_size) {
			pr_err("write error occurred\n");
			free(raw_data);
			goto out_fra;
		}

		err = write(perf_fd, raw_data, raw_size);
		free(raw_data);

		if (err != (int)raw_size) {
			pr_err("write error occurred\n");
			goto out_fra;
		}

		session->header.data_size += event.sample.header.size;
	}

	perf_session__write_header(session, ftrace->evlist, perf_fd, true);

out_fra:
	list_for_each_entry_safe(fra, tmp, &recorders, node) {
		list_del(&fra->node);
		free(fra);
	}
out_session:
	free(session);
out_close:
	close(perf_fd);
out_reset:
	reset_tracing_files(ftrace);
	return done ? 0 : -1;
}

static int
function_handler(struct trace_seq *s, struct pevent_record *record,
		 struct event_format *event, void *context __maybe_unused)
{
	struct pevent *pevent = event->pevent;
	unsigned long long function;
	const char *func;

	if (pevent_get_field_val(s, event, "ip", record, &function, 1))
		return trace_seq_putc(s, '!');

	func = pevent_find_function(pevent, function);
	if (func)
		trace_seq_printf(s, "%s <-- ", func);
	else
		trace_seq_printf(s, "0x%llx", function);

	if (pevent_get_field_val(s, event, "parent_ip", record, &function, 1))
		return trace_seq_putc(s, '!');

	func = pevent_find_function(pevent, function);
	if (func)
		trace_seq_printf(s, "%s", func);
	else
		trace_seq_printf(s, "0x%llx", function);

	trace_seq_putc(s, '\n');
	return 0;
}

#define TRACE_GRAPH_INDENT  2

static int
fgraph_ent_handler(struct trace_seq *s, struct pevent_record *record,
		   struct event_format *event, void *context __maybe_unused)
{
	unsigned long long depth;
	unsigned long long val;
	const char *func;
	int i;

	if (pevent_get_field_val(s, event, "depth", record, &depth, 1))
		return trace_seq_putc(s, '!');

	/* Function */
	for (i = 0; i < (int)(depth * TRACE_GRAPH_INDENT); i++)
		trace_seq_putc(s, ' ');

	if (pevent_get_field_val(s, event, "func", record, &val, 1))
		return trace_seq_putc(s, '!');

	func = pevent_find_function(event->pevent, val);

	if (func)
		trace_seq_printf(s, "%s() {", func);
	else
		trace_seq_printf(s, "%llx() {", val);

	trace_seq_putc(s, '\n');
	return 0;
}

static int
fgraph_ret_handler(struct trace_seq *s, struct pevent_record *record,
		   struct event_format *event, void *context __maybe_unused)
{
	unsigned long long depth;
	int i;

	if (pevent_get_field_val(s, event, "depth", record, &depth, 1))
		return trace_seq_putc(s, '!');

	/* Function */
	for (i = 0; i < (int)(depth * TRACE_GRAPH_INDENT); i++)
		trace_seq_putc(s, ' ');

	trace_seq_puts(s, "}\n");
	return 0;
}

struct perf_ftrace_report {
	struct perf_ftrace *ftrace;
	struct perf_tool tool;
};

struct ftrace_report_arg {
	struct list_head node;
	struct pevent_record *record;
	struct kbuffer *kbuf;
	void *map;
	int cpu;
	int fd;
	int done;
	off_t offset;
	off_t size;
};

static LIST_HEAD(ftrace_cpu_buffers);

static int process_sample_event(struct perf_tool *tool,
				union perf_event * event __maybe_unused,
				struct perf_sample *sample,
				struct perf_evsel *evsel __maybe_unused,
				struct machine *machine __maybe_unused)
{
	struct perf_ftrace *ftrace;
	struct perf_ftrace_report *report;
	struct ftrace_report_arg *fra;
	struct stat statbuf;
	enum kbuffer_long_size long_size;
	enum kbuffer_endian endian;
	char buf[PATH_MAX];

	report = container_of(tool, struct perf_ftrace_report, tool);
	ftrace = report->ftrace;

	if (perf_target__has_cpu(&ftrace->target)) {
		int i;
		bool found = false;

		for (i = 0; i < cpu_map__nr(ftrace->evlist->cpus); i++) {
			if ((int)sample->cpu == ftrace->evlist->cpus->map[i]) {
				found = true;
				break;
			}
		}
		if (!found)
			return 0;
	}

	fra = zalloc(sizeof(*fra));
	if (fra == NULL)
		return -1;

	fra->cpu = sample->cpu;

	scnprintf(buf, sizeof(buf), "%s.dir/trace-cpu%d.buf",
		  ftrace->dirname, fra->cpu);

	fra->fd = open(buf, O_RDONLY);
	if (fra->fd < 0)
		goto out;

	if (fstat(fra->fd, &statbuf) < 0)
		goto out_close;

	fra->size = statbuf.st_size;
	if (fra->size == 0) {
		/* skip zero-size buffers */
		close(fra->fd);
		free(fra);
		return 0;
	}

	/*
	 * FIXME: What if pevent->page_size is smaller than current page size?
	 */
	fra->map = mmap(NULL, pevent_get_page_size(ftrace->pevent),
			PROT_READ, MAP_PRIVATE, fra->fd, fra->offset);
	if (fra->map == MAP_FAILED)
		goto out_close;

	fra->offset = 0;

	if (pevent_is_file_bigendian(ftrace->pevent))
		endian = KBUFFER_ENDIAN_BIG;
	else
		endian = KBUFFER_ENDIAN_LITTLE;

	if (pevent_get_long_size(ftrace->pevent) == 8)
		long_size = KBUFFER_LSIZE_8;
	else
		long_size = KBUFFER_LSIZE_4;

	fra->kbuf = kbuffer_alloc(long_size, endian);
	if (fra->kbuf == NULL)
		goto out_unmap;

	if (ftrace->pevent->old_format)
		kbuffer_set_old_format(fra->kbuf);

	kbuffer_load_subbuffer(fra->kbuf, fra->map);

	pr_debug2("setup kbuffer for cpu%d\n", fra->cpu);
	list_add_tail(&fra->node, &ftrace_cpu_buffers);
	return 0;

out_unmap:
	munmap(fra->map, pevent_get_page_size(ftrace->pevent));
out_close:
	close(fra->fd);
out:
	free(fra);
	return -1;
}

static struct pevent_record *
get_next_ftrace_event_record(struct perf_ftrace *ftrace,
			     struct ftrace_report_arg *fra)
{
	struct pevent_record *record;
	unsigned long long ts;
	void *data;

retry:
	data = kbuffer_read_event(fra->kbuf, &ts);
	if (data) {
		record = zalloc(sizeof(*record));
		if (record == NULL) {
			pr_err("memory allocation failure\n");
			return NULL;
		}

		record->ts = ts;
		record->cpu = fra->cpu;
		record->data = data;
		record->size = kbuffer_event_size(fra->kbuf);
		record->record_size = kbuffer_curr_size(fra->kbuf);
		record->offset = kbuffer_curr_offset(fra->kbuf);
		record->missed_events = kbuffer_missed_events(fra->kbuf);
		record->ref_count = 1;

		kbuffer_next_event(fra->kbuf, NULL);
		return record;
	}

	if (fra->done)
		return NULL;

	munmap(fra->map, pevent_get_page_size(ftrace->pevent));
	fra->map = NULL;

	fra->offset += pevent_get_page_size(ftrace->pevent);
	if (fra->offset >= fra->size) {
		/* EOF */
		fra->done = 1;
		return NULL;
	}

	fra->map = mmap(NULL, pevent_get_page_size(ftrace->pevent),
			PROT_READ, MAP_PRIVATE, fra->fd, fra->offset);
	if (fra->map == MAP_FAILED) {
		pr_err("memory mapping failed\n");
		return NULL;
	}

	kbuffer_load_subbuffer(fra->kbuf, fra->map);

	goto retry;
}

static struct pevent_record *
get_ftrace_event_record(struct perf_ftrace *ftrace,
			struct ftrace_report_arg *fra)
{
	if (fra->record == NULL)
		fra->record = get_next_ftrace_event_record(ftrace, fra);

	return fra->record;
}

static struct pevent_record *get_ordered_record(struct perf_ftrace *ftrace)
{
	struct ftrace_report_arg *fra = NULL;
	struct ftrace_report_arg *tmp;
	struct pevent_record *record;
	unsigned long long min_ts = LLONG_MAX;

	list_for_each_entry(tmp, &ftrace_cpu_buffers, node) {
		record = get_ftrace_event_record(ftrace, tmp);
		if (record && record->ts < min_ts) {
			min_ts = record->ts;
			fra = tmp;
		}
	}

	if (fra) {
		record = fra->record;
		fra->record = NULL;
		return record;
	}
	return NULL;
}

static void free_ftrace_report_args(struct perf_ftrace *ftrace)
{
	struct ftrace_report_arg *fra, *tmp;

	list_for_each_entry_safe(fra, tmp, &ftrace_cpu_buffers, node) {
		list_del(&fra->node);

		/* don't care about the errors */
		munmap(fra->map, pevent_get_page_size(ftrace->pevent));
		kbuffer_free(fra->kbuf);
		free(fra->record);
		close(fra->fd);
		free(fra);
	}
}

static int do_ftrace_show(struct perf_ftrace *ftrace)
{
	int ret = 0;
	char buf[PATH_MAX];
	struct perf_session *session;
	struct pevent_record *record;
	struct trace_seq seq;
	struct perf_ftrace_report show = {
		.ftrace = ftrace,
		.tool = {
			.sample = process_sample_event,
		},
	};

	canonicalize_directory_name(ftrace->dirname);

	scnprintf(buf, sizeof(buf), "%s.dir/perf.header", ftrace->dirname);

	session = perf_session__new(buf, O_RDONLY, false, false, &show.tool);
	if (session == NULL) {
		pr_err("failed to create a session\n");
		return -1;
	}

	ftrace->pevent = session->pevent;

	pevent_register_event_handler(ftrace->pevent, -1,
				      "ftrace", "function",
				      function_handler, NULL);
	pevent_register_event_handler(ftrace->pevent, -1,
				      "ftrace", "funcgraph_entry",
				      fgraph_ent_handler, NULL);
	pevent_register_event_handler(ftrace->pevent, -1,
				      "ftrace", "funcgraph_exit",
				      fgraph_ret_handler, NULL);

	if (perf_session__process_events(session, &show.tool) < 0) {
		pr_err("failed to process events\n");
		ret = -1;
		goto out;
	}

	trace_seq_init(&seq);

	record = get_ordered_record(ftrace);
	while (record) {
		int type;
		struct event_format *event;

		type = pevent_data_type(ftrace->pevent, record);
		event = pevent_find_event(ftrace->pevent, type);
		if (!event) {
			pr_warning("no event found for type %d", type);
			continue;
		}

		pevent_print_event(ftrace->pevent, &seq, record);
		trace_seq_do_printf(&seq);

		trace_seq_reset(&seq);

		free(record);
		record = get_ordered_record(ftrace);
	}

	trace_seq_destroy(&seq);

out:
	free_ftrace_report_args(ftrace);
	perf_session__delete(session);
	return ret;
}

struct cmdline_list {
	struct cmdline_list	*next;
	char			*comm;
	int			pid;
};

struct func_list {
	struct func_list	*next;
	unsigned long long	addr;
	char			*func;
	char			*mod;
};

static int do_ftrace_report(struct perf_ftrace *ftrace)
{
	int ret = -1;
	char buf[PATH_MAX];
	unsigned long nr_samples;
	struct perf_session *session;
	struct perf_evsel *evsel;
	struct pevent_record *record;
	struct perf_ftrace_report report = {
		.ftrace = ftrace,
		.tool = {
			.sample = process_sample_event,
		},
	};
	struct cmdline_list *cmdline;
	struct func_list *func;
	struct machine *machine;
	struct dso *dso;

	canonicalize_directory_name(ftrace->dirname);

	scnprintf(buf, sizeof(buf), "%s.dir/perf.header", ftrace->dirname);

	session = perf_session__new(buf, O_RDONLY, false, false, &report.tool);
	if (session == NULL) {
		pr_err("failed to create a session\n");
		return -1;
	}

	ftrace->pevent = session->pevent;

	if (perf_session__process_events(session, &report.tool) < 0) {
		pr_err("failed to process events\n");
		goto out;
	}

	machine = machines__findnew(&session->machines, HOST_KERNEL_ID);

	/* Synthesize thread info from saved cmdlines */
	cmdline = ftrace->pevent->cmdlist;
	while (cmdline) {
		struct thread *thread;

		thread = machine__findnew_thread(machine, cmdline->pid,
						 cmdline->pid);
		if (thread && !thread->comm_set)
			thread__set_comm(thread, cmdline->comm);

		cmdline = cmdline->next;
	}

	/* Synthesize kernel dso and symbol info from saved kallsyms */
	func = ftrace->pevent->funclist;
	while (func) {
		struct symbol *sym;

		scnprintf(buf, sizeof(buf), "[%s]",
			  func->mod ? func->mod : "kernel.kallsyms");

		dso = dso__kernel_findnew(machine, buf, NULL, DSO_TYPE_KERNEL);
		if (dso == NULL) {
			pr_debug("can't find or allocate dso %s\n", buf);
			continue;
		}

		sym = symbol__new(func->addr, 0, STB_GLOBAL, func->func);
		if (sym == NULL) {
			pr_debug("failed to allocate new symbol\n");
			continue;
		}
		symbols__insert(&dso->symbols[MAP__FUNCTION], sym);

		func = func->next;
	}

	/* Generate kernel maps */
	list_for_each_entry(dso, &machine->kernel_dsos, node) {
		struct map *map = map__new2(0, dso, MAP__FUNCTION);
		if (map == NULL) {
			pr_debug("failed to allocate new map\n");
			goto out;
		}

		symbols__fixup_end(&dso->symbols[MAP__FUNCTION]);
		map__fixup_start(map);
		map__fixup_end(map);

		dso__set_loaded(dso, MAP__FUNCTION);

		map_groups__insert(&machine->kmaps, map);
		if (strcmp(dso->name, "[kernel.kallsyms]") == 0)
			machine->vmlinux_maps[MAP__FUNCTION] = map;
	}

	/* FIXME: no need to get ordered */
	record = get_ordered_record(ftrace);
	while (record) {
		int type;
		struct addr_location al;
		union perf_event event = {
			.header = {
				.misc = PERF_RECORD_MISC_KERNEL,
			},
		};
		struct perf_sample sample = {
			.cpu = record->cpu,
			.raw_data = record->data,
			.period = 1,
		};
		struct format_field *field;
		unsigned long long val;

		type = pevent_data_type(ftrace->pevent, record);
		evsel = perf_evlist__find_tracepoint_by_id(session->evlist,
							   type);
		if (evsel == NULL) {
			pr_warning("no event found for type %d\n", type);
			continue;
		}

		sample.pid = pevent_data_pid(ftrace->pevent, record);

		if (!strcmp(perf_evsel__name(evsel), "ftrace:function"))
			field = pevent_find_field(evsel->tp_format, "ip");
		else
			field = pevent_find_field(evsel->tp_format, "func");

		if (pevent_read_number_field(field, record->data, &val) < 0) {
			pr_err("failed to parse function address\n");
			goto out;
		}
		sample.ip = val;

		if (perf_event__preprocess_sample(&event, machine, &al,
						  &sample) < 0) {
			pr_err("problem processing %d event, skipping it.\n",
				event.header.type);
			goto out;
		}

		/* TODO: update sample.period using calltime */
		if (!__hists__add_entry(&evsel->hists, &al, NULL,
					sample.period, 0, 0)) {
			pr_err("failed to add a hist entry\n");
			goto out;
		}

		evsel->hists.stats.total_period += sample.period;
		hists__inc_nr_events(&evsel->hists, PERF_RECORD_SAMPLE);

		free(record);
		record = get_ordered_record(ftrace);
	}
	ret = 0;

	perf_session__fprintf_info(session, stdout, ftrace->show_full_info);

	nr_samples = 0;
	list_for_each_entry(evsel, &session->evlist->entries, node) {
		struct hists *hists = &evsel->hists;

		hists__collapse_resort(hists);
		hists__output_resort(&evsel->hists);
		nr_samples += hists->stats.nr_events[PERF_RECORD_SAMPLE];
	}

	if (nr_samples == 0) {
		pr_warning("The %s file has no samples!\n", session->filename);
		goto out;
	}

	list_for_each_entry(evsel, &session->evlist->entries, node) {
		struct hists *hists = &evsel->hists;
		const char *evname = perf_evsel__name(evsel);
		u64 nr_events = hists->stats.total_period;
		char unit;

		nr_samples = hists->stats.nr_events[PERF_RECORD_SAMPLE];
		nr_samples = convert_unit(nr_samples, &unit);
		fprintf(stdout, "# Samples: %lu%c", nr_samples, unit);
		if (evname != NULL)
			fprintf(stdout, " of event '%s'", evname);

		fprintf(stdout, "\n# Event count (approx.): %" PRIu64, nr_events);
		fprintf(stdout, "\n#\n");

		hists__fprintf(hists, true, 0, 0, 0.0, stdout);
		fprintf(stdout, "\n\n");
	}

out:
	free_ftrace_report_args(ftrace);
	perf_session__delete(session);
	return ret;
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

static int
__cmd_ftrace_record(struct perf_ftrace *ftrace, int argc, const char **argv)
{
	int ret = -1;
	const char * const record_usage[] = {
		"perf ftrace record [<options>] [<command>]",
		"perf ftrace record [<options>] -- <command> [<options>]",
		NULL
	};
	const struct option record_options[] = {
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
	OPT_STRING('o', "output", &ftrace->dirname, "dirname",
		   "input directory name to use (default: perf.data)"),
	OPT_END()
	};

	argc = parse_options(argc, argv, record_options, record_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (!argc && perf_target__none(&ftrace->target))
		usage_with_options(record_usage, record_options);

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

	if (ftrace->dirname == NULL)
		ftrace->dirname = DEFAULT_DIRNAME;

	if (argc && perf_evlist__prepare_workload(ftrace->evlist,
						  &ftrace->target,
						  argv, false, true) < 0)
		goto out_maps;

	ret = do_ftrace_record(ftrace);

out_maps:
	perf_evlist__delete_maps(ftrace->evlist);
out:
	perf_evlist__delete(ftrace->evlist);

	return ret;
}

static int
__cmd_ftrace_show(struct perf_ftrace *ftrace, int argc, const char **argv)
{
	int ret = -1;
	const char * const show_usage[] = {
		"perf ftrace show [<options>]",
		NULL
	};
	const struct option show_options[] = {
	OPT_STRING('i', "input", &ftrace->dirname, "dirname",
		   "input directory name to use (default: perf.data)"),
	OPT_INCR('v', "verbose", &verbose,
		 "be more verbose"),
	OPT_STRING('C', "cpu", &ftrace->target.cpu_list, "cpu",
		    "list of cpus to monitor"),
	OPT_END()
	};

	argc = parse_options(argc, argv, show_options, show_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc)
		usage_with_options(show_usage, show_options);

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

	if (ftrace->dirname == NULL)
		ftrace->dirname = DEFAULT_DIRNAME;

	ret = do_ftrace_show(ftrace);

	perf_evlist__delete_maps(ftrace->evlist);
out:
	perf_evlist__delete(ftrace->evlist);

	return ret;
}

static int
__cmd_ftrace_report(struct perf_ftrace *ftrace, int argc, const char **argv)
{
	int ret = -1;
	const char * const report_usage[] = {
		"perf ftrace report [<options>]",
		NULL
	};
	const struct option report_options[] = {
	OPT_STRING('i', "input", &ftrace->dirname, "dirname",
		   "input directory name to use (default: perf.data)"),
	OPT_INCR('v', "verbose", &verbose,
		 "be more verbose"),
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace,
		    "dump raw trace in ASCII"),
	OPT_STRING('C', "cpu", &ftrace->target.cpu_list, "cpu",
		    "list of cpus to monitor"),
	OPT_STRING('s', "sort", &sort_order, "key[,key2...]",
		   "sort by key(s): pid, comm, dso, symbol, cpu"),
	OPT_BOOLEAN('I', "show-info", &ftrace->show_full_info,
		    "Display extended information like cpu/numa topology"),
	OPT_END()
	};

	argc = parse_options(argc, argv, report_options, report_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc)
		usage_with_options(report_usage, report_options);

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

	if (ftrace->dirname == NULL)
		ftrace->dirname = DEFAULT_DIRNAME;

	perf_hpp__init();

	setup_sorting();

	symbol_conf.exclude_other = false;
	symbol_conf.try_vmlinux_path = false;
	symbol__init();

	ret = do_ftrace_report(ftrace);

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
		"perf ftrace {live|record|show|report} [<options>] [<command>]",
		"perf ftrace {live|record|show|report} [<options>] -- <command> [<options>]",
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
	} else 	if (strncmp(argv[0], "rec", 3) == 0) {
		ret = __cmd_ftrace_record(&ftrace, argc, argv);
	} else 	if (strcmp(argv[0], "show") == 0) {
		ret = __cmd_ftrace_show(&ftrace, argc, argv);
	} else 	if (strncmp(argv[0], "rep", 3) == 0) {
		ret = __cmd_ftrace_report(&ftrace, argc, argv);
	} else {
		usage_with_options(ftrace_usage, ftrace_options);
	}

	return ret;
}
