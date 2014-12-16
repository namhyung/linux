#include <linux/compiler.h>
#include "builtin.h"
#include "perf.h"
#include "debug.h"
#include "session.h"
#include "evlist.h"
#include "parse-options.h"

typedef int (*data_cmd_fn_t)(int argc, const char **argv, const char *prefix);

static const char *output_name;

struct data_cmd {
	const char	*name;
	const char	*summary;
	data_cmd_fn_t	fn;
};

static struct data_cmd data_cmds[];

#define for_each_cmd(cmd) \
	for (cmd = data_cmds; cmd && cmd->name; cmd++)

static const struct option data_options[] = {
	OPT_END()
};

static const char * const data_usage[] = {
	"perf data [<common options>] <command> [<options>]",
	NULL
};

static void print_usage(void)
{
	struct data_cmd *cmd;

	printf("Usage:\n");
	printf("\t%s\n\n", data_usage[0]);
	printf("\tAvailable commands:\n");

	for_each_cmd(cmd) {
		printf("\t %s\t- %s\n", cmd->name, cmd->summary);
	}

	printf("\n");
}

static int data_cmd_split(int argc, const char **argv, const char *prefix);

static struct data_cmd data_cmds[] = {
	{ "split", "split single data file into multi-file", data_cmd_split },
	{ NULL },
};

#define FD_HASH_BITS  7
#define FD_HASH_SIZE  (1 << FD_HASH_BITS)
#define FD_HASH_MASK  (FD_HASH_SIZE - 1)

struct data_split {
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

static struct hlist_head *get_hash(struct data_split *split, int id)
{
	return &split->fd_hash[id % FD_HASH_MASK];
}

static int perf_event__rewrite_header(struct perf_tool *tool,
				      union perf_event *event)
{
	struct data_split *split = container_of(tool, struct data_split, tool);
	ssize_t size;

	size = writen(split->header_fd, event, event->header.size);
	if (size < 0)
		return -errno;

	split->header_written += size;
	return 0;
}

static int split_other_events(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample __maybe_unused,
				struct machine *machine __maybe_unused)
{
	return perf_event__rewrite_header(tool, event);
}

static int split_sample_event(struct perf_tool *tool,
				union perf_event *event,
				struct perf_sample *sample,
				struct perf_evsel *evsel __maybe_unused,
				struct machine *machine __maybe_unused)
{
	struct data_split *split = container_of(tool, struct data_split, tool);
	int id = split->mode == PER_CPU ? sample->cpu : sample->tid;
	int fd = -1;
	char buf[PATH_MAX];
	struct hlist_head *head;
	struct fdhash_node *node;

	head = get_hash(split, id);
	hlist_for_each_entry(node, head, list) {
		if (node->id == id) {
			fd = node->fd;
			break;
		}
	}

	if (fd == -1) {
		scnprintf(buf, sizeof(buf), "%s/perf.data.%d",
			  output_name, split->fd_hash_nr++);

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

static int __data_cmd_split(struct data_split *split)
{
	struct perf_session *session = split->session;
	char *output = NULL;
	char buf[PATH_MAX];
	u64 sample_type;
	int header_fd;
	int ret = -1;
	int i;

	if (!output_name) {
		if (asprintf(&output, "%s.dir", input_name) < 0) {
			pr_err("memory allocation failed\n");
			return -1;
		}
		output_name = output;
	}

	mkdir(output_name, 0700);

	/*
	 * This is necessary to write (copy) build-id table.  After
	 * processing header, dsos list will contain dso which was on
	 * the original build-id table.
	 */
	dsos__hit_all(session);

	scnprintf(buf, sizeof(buf), "%s/perf.header", output_name);
	header_fd = open(buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (header_fd < 0) {
		pr_err("cannot open header file: %s: %m\n", buf);
		goto out;
	}

	lseek(header_fd, session->header.data_offset, SEEK_SET);

	sample_type = perf_evlist__combined_sample_type(session->evlist);
	if (sample_type & PERF_SAMPLE_CPU)
		split->mode = PER_CPU;
	else
		split->mode = PER_THREAD;

	pr_debug("splitting data file for %s\n",
		 split->mode == PER_CPU ? "CPUs" : "threads");

	split->header_fd = header_fd;
	perf_session__process_events(session, &split->tool);

	for (i = 0; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *pos;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(pos, tmp, &split->fd_hash[i], list) {
			hlist_del(&pos->list);
			close(pos->fd);
			free(pos);
		}
	}

	session->header.data_size = split->header_written;
	perf_session__write_header(session, session->evlist, header_fd, true);

	close(header_fd);
	ret = 0;
out:
	free(output);
	return ret;
}

int data_cmd_split(int argc, const char **argv, const char *prefix __maybe_unused)
{
	bool force = false;
	struct perf_session *session;
	struct perf_data_file file = {
		.mode  = PERF_DATA_MODE_READ,
	};
	struct data_split split = {
		.tool = {
			.sample		= split_sample_event,
			.fork		= split_other_events,
			.comm		= split_other_events,
			.exit		= split_other_events,
			.mmap		= split_other_events,
			.mmap2		= split_other_events,
			.lost		= split_other_events,
			.throttle	= split_other_events,
			.unthrottle	= split_other_events,
		},
	};
	const char * const split_usage[] = {
		"perf data split [<options>]",
		NULL
	};
	const struct option split_options[] = {
	OPT_STRING('i', "input", &input_name, "file", "input file name"),
	OPT_STRING('o', "output", &output_name, "file", "output directory name"),
	OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
	OPT_INCR('v', "verbose", &verbose, "be more verbose"),
	OPT_END()
	};

	argc = parse_options(argc, argv, split_options, split_usage, 0);
	if (argc)
		usage_with_options(split_usage, split_options);

	file.path = input_name;
	file.force = force;
	session = perf_session__new(&file, false, &split.tool);
	if (session == NULL)
		return -1;

	split.session = session;
	symbol__init(&session->header.env);

	__data_cmd_split(&split);

	perf_session__delete(session);
	return 0;
}

int cmd_data(int argc, const char **argv, const char *prefix)
{
	struct data_cmd *cmd;
	const char *cmdstr;

	/* No command specified. */
	if (argc < 2)
		goto usage;

	argc = parse_options(argc, argv, data_options, data_usage,
			     PARSE_OPT_STOP_AT_NON_OPTION);
	if (argc < 1)
		goto usage;

	cmdstr = argv[0];

	for_each_cmd(cmd) {
		if (strcmp(cmd->name, cmdstr))
			continue;

		return cmd->fn(argc, argv, prefix);
	}

	pr_err("Unknown command: %s\n", cmdstr);
usage:
	print_usage();
	return -1;
}
