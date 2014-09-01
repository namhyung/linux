/*
 * builtin-data.c
 *
 * Builtin data command: manipulating data files and directories
 *
 * Copyright (C) 2014, LG Electronics Inc.
 * Copyright (C) 2014, Namhyung Kim  <namhyung@kernel.org>
 */
#include "perf.h"
#include "builtin.h"
#include "util/cache.h"
#include "util/debug.h"
#include "util/parse-options.h"
#include "util/session.h"
#include "util/symbol.h"
#include "util/evlist.h"
#include "util/data.h"

static const char *output_name;

#define FD_HASH_BITS  7
#define FD_HASH_SIZE  (1 << FD_HASH_BITS)
#define FD_HASH_MASK  (FD_HASH_SIZE - 1)

struct data {
	struct perf_tool	tool;
	struct perf_session	*session;
	enum {
		PER_CPU,
		PER_THREAD,
	} mode;
	int 			header_fd;
	u64			header_written;
	struct hlist_head	fd_hash[FD_HASH_SIZE];
	int			fd_hash_nr;
};

struct fdhash_node {
	int			id;
	int			fd;
	struct hlist_node	list;
};

static struct hlist_head *get_hash(struct data *data, int id)
{
	return &data->fd_hash[id % FD_HASH_MASK];
}

static int perf_event__rewrite_header(struct perf_tool *tool,
				      union perf_event *event)
{
	struct data *data = container_of(tool, struct data, tool);
	ssize_t size;

	size = writen(data->header_fd, event, event->header.size);
	if (size < 0)
		return -errno;

	data->header_written += size;
	return 0;
}

static int process_other_events(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample __maybe_unused,
				struct machine *machine __maybe_unused)
{
	return perf_event__rewrite_header(tool, event);
}

static int process_sample_event(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample,
				struct perf_evsel *evsel __maybe_unused,
				struct machine *machine __maybe_unused)
{
	struct data *data = container_of(tool, struct data, tool);
	int id = data->mode == PER_CPU ? sample->cpu : sample->tid;
	int fd = -1;
	char buf[PATH_MAX];
	struct hlist_head *head;
	struct fdhash_node *node;

	head = get_hash(data, id);
	hlist_for_each_entry(node, head, list) {
		if (node->id == id) {
			fd = node->fd;
			break;
		}
	}

	if (fd == -1) {
		scnprintf(buf, sizeof(buf), "%s/perf.data.%d",
			  output_name, data->fd_hash_nr++);

		fd = open(buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
		if (fd < 0) {
			pr_err("cannot open data file: %s: %m\n", buf);
			return -1;
		}

		node = malloc(sizeof(*node));
		if (node == NULL) {
			pr_err("memory allocation failed\n");
			return -1;
		}

		node->id = id;
		node->fd = fd;

		hlist_add_head(&node->list, head);
	}

	return writen(fd, event, event->header.size) > 0 ? 0 : -errno;
}

static int __cmd_data_to_dir(struct data *data)
{
	struct perf_session *session = data->session;
	char *output = NULL;
	char buf[PATH_MAX];
	u64 sample_type;
	int header_fd;
	int i;

	if (perf_header__has_feat(&session->header, HEADER_MULTI_FILE)) {
		pr_err("already converted to directory format\n");
		return -1;
	}

	if (!output_name) {
		if (asprintf(&output, "%s.dir", input_name) < 0) {
			pr_err("memory allocation failed\n");
			return -1;
		}
		output_name = output;
	}

	mkdir(output_name, 0700);

	scnprintf(buf, sizeof(buf), "%s/perf.header", output_name);
	header_fd = open(buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (header_fd < 0) {
		pr_err("cannot open header file: %s: %m\n", buf);
		goto out;
	}

	lseek(header_fd, session->header.data_offset, SEEK_SET);

	sample_type = perf_evlist__combined_sample_type(session->evlist);
	if (sample_type & PERF_SAMPLE_CPU)
		data->mode = PER_CPU;
	else
		data->mode = PER_THREAD;

	pr_debug("splitting data file for %s\n",
		 data->mode == PER_CPU ? "CPUs" : "threads");

	data->header_fd = header_fd;
	perf_session__process_events(session, &data->tool);

	for (i = 0; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *pos;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(pos, tmp, &data->fd_hash[i], list) {
			hlist_del(&pos->list);
			close(pos->fd);
			free(pos);
		}
	}

	session->header.data_size = data->header_written;
	perf_header__set_feat(&session->header, HEADER_MULTI_FILE);
	perf_session__write_header(session, session->evlist, header_fd, false);

	close(header_fd);
out:
	free(output);
	return 0;
}

int cmd_data(int argc, const char **argv, const char *prefix __maybe_unused)
{
	bool force = false;
	struct perf_session *session;
	struct perf_data_file file = {
		.mode  = PERF_DATA_MODE_READ,
	};
	struct data data = {
		.tool = {
			.sample		= process_sample_event,
			.fork		= process_other_events,
			.comm		= process_other_events,
			.exit		= process_other_events,
			.mmap		= process_other_events,
			.mmap2		= process_other_events,
			.lost		= process_other_events,
			.throttle	= process_other_events,
			.unthrottle	= process_other_events,
		},
	};
	const char * const data_usage[] = {
		"perf data to-dir [<options>]",
		NULL
	};
	const struct option data_options[] = {
	OPT_STRING('i', "input", &input_name, "file", "input file/directory name"),
	OPT_STRING('o', "output", &output_name, "file", "output file/directory name"),
	OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
	OPT_INCR('v', "verbose", &verbose, "be more verbose"),
	OPT_END()
	};

	argc = parse_options(argc, argv, data_options, data_usage, 0);
	if (argc == 0)
		usage_with_options(data_usage, data_options);

	file.path = input_name;
	file.force = force;
	session = perf_session__new(&file, false, &data.tool);
	if (session == NULL)
		return -1;

	data.session = session;
	symbol__init(&session->header.env);

	if (!strcmp(argv[0], "to-dir"))
		__cmd_data_to_dir(&data);
	else
		usage_with_options(data_usage, data_options);

	perf_session__delete(session);
	return 0;
}
