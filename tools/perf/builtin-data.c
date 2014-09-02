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

static int convert_to_dir_other_events(struct perf_tool *tool,
				       union perf_event *event,
				       struct perf_sample *sample __maybe_unused,
				       struct machine *machine __maybe_unused)
{
	return perf_event__rewrite_header(tool, event);
}

static int convert_to_dir_sample_event(struct perf_tool *tool,
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
	u64 feat_offset;
	int header_fd;
	int i;
	struct perf_tool todir = {
		.sample		= convert_to_dir_sample_event,
		.fork		= convert_to_dir_other_events,
		.comm		= convert_to_dir_other_events,
		.exit		= convert_to_dir_other_events,
		.mmap		= convert_to_dir_other_events,
		.mmap2		= convert_to_dir_other_events,
		.lost		= convert_to_dir_other_events,
		.throttle	= convert_to_dir_other_events,
		.unthrottle	= convert_to_dir_other_events,
	};

	memcpy(&data->tool, &todir, sizeof(todir));

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

	feat_offset = session->header.feat_offset;
	session->header.data_size = data->header_written;
	perf_header__set_feat(&session->header, HEADER_MULTI_FILE);
	perf_session__write_header(session, session->evlist, header_fd, false);

	lseek(session->file->single_fd, feat_offset, SEEK_SET);
	perf_header__clear_feat(&session->header, HEADER_MULTI_FILE);
	perf_header__copy_feats(&session->header, session->file->single_fd, header_fd);

	close(header_fd);
out:
	free(output);
	return 0;
}

static int dump_other_events(struct perf_tool *tool __maybe_unused,
			     union perf_event *event __maybe_unused,
			     struct perf_sample *sample __maybe_unused,
			     struct machine *machine __maybe_unused)
{
	return 0;
}

static int dump_sample_event(struct perf_tool *tool __maybe_unused,
			     union perf_event *event __maybe_unused,
			     struct perf_sample *sample __maybe_unused,
			     struct perf_evsel *evsel __maybe_unused,
			     struct machine *machine __maybe_unused)
{
	return 0;
}

static int __cmd_data_dump(struct data *data)
{
	struct perf_session *session = data->session;
	int i, fd;
	off_t off, size;
	struct perf_tool dump = {
		.sample		= dump_sample_event,
		.fork		= dump_other_events,
		.comm		= dump_other_events,
		.exit		= dump_other_events,
		.mmap		= dump_other_events,
		.mmap2		= dump_other_events,
		.lost		= dump_other_events,
		.throttle	= dump_other_events,
		.unthrottle	= dump_other_events,
	};

	memcpy(&data->tool, &dump, sizeof(dump));

	setup_pager();

	pr_info("perf header: v%d (need swap: %s)\n",
		session->header.version + 1,
		session->header.needs_swap ? "true" : "false");
	pr_info("data offset: %lx\n", session->header.data_offset);
	pr_info("data length: %lx\n", session->header.data_size);
	pr_info("feat offset: %lx\n", session->header.feat_offset);
	pr_info("feat bitmap: %lx\n", session->header.adds_features[0]);

	off = lseek(session->file->single_fd, 0, SEEK_CUR);
	size = lseek(session->file->single_fd, 0, SEEK_END);
	lseek(session->file->single_fd, off, SEEK_SET);
	__perf_session__process_events(session,
				       session->header.data_offset,
				       session->header.data_size,
				       size,
				       &data->tool);

	printf("\nStats for perf.header\n");
	events_stats__fprintf(&session->stats, stdout);
	memset(&session->stats, 0, sizeof(session->stats));

	for (i = 0; i < session->file->nr_multi; i++) {
		fd = perf_data_file__multi_fd(session->file, i);
		if (fd < 0) {
			pr_err("bad fd for thread %d", i);
			return -1;
		}

		off = lseek(fd, 0, SEEK_CUR);
		size = lseek(fd, 0, SEEK_END);
		lseek(fd, off, SEEK_SET);
		___perf_session__process_events(session, fd, 0, size, size,
						&data->tool);

		printf("\nStats for perf.data.%d\n", i);
		events_stats__fprintf(&session->stats, stdout);
		memset(&session->stats, 0, sizeof(session->stats));
	}

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
			.ordered_events = false,
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
	OPT_BOOLEAN('D', "dump-raw-trace", &dump_trace, "dump raw trace in ASCII"),
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
	else if (!strcmp(argv[0], "dump"))
		__cmd_data_dump(&data);
	else
		usage_with_options(data_usage, data_options);

	perf_session__delete(session);
	return 0;
}
