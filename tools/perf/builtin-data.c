#include <linux/compiler.h>
#include "builtin.h"
#include "perf.h"
#include "debug.h"
#include "session.h"
#include "evlist.h"
#include "parse-options.h"
#include "data-convert-bt.h"
#include <sys/mman.h>

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

static const char * const data_subcommands[] = { "convert", NULL };

static const char *data_usage[] = {
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

static int cmd_data_convert(int argc, const char **argv, const char *prefix);
static int data_cmd_index(int argc, const char **argv, const char *prefix);

static struct data_cmd data_cmds[] = {
	{ "convert", "converts data file between formats", cmd_data_convert },
	{ "index", "merge data file and add index", data_cmd_index },
	{ .name = NULL, },
};

static const char * const data_convert_usage[] = {
	"perf data convert [<options>]",
	NULL
};

static int cmd_data_convert(int argc, const char **argv,
			    const char *prefix __maybe_unused)
{
	const char *to_ctf     = NULL;
	bool force = false;
	const struct option options[] = {
		OPT_INCR('v', "verbose", &verbose, "be more verbose"),
		OPT_STRING('i', "input", &input_name, "file", "input file name"),
#ifdef HAVE_LIBBABELTRACE_SUPPORT
		OPT_STRING(0, "to-ctf", &to_ctf, NULL, "Convert to CTF format"),
#endif
		OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
		OPT_END()
	};

#ifndef HAVE_LIBBABELTRACE_SUPPORT
	pr_err("No conversion support compiled in.\n");
	return -1;
#endif

	argc = parse_options(argc, argv, options,
			     data_convert_usage, 0);
	if (argc) {
		usage_with_options(data_convert_usage, options);
		return -1;
	}

	if (to_ctf) {
#ifdef HAVE_LIBBABELTRACE_SUPPORT
		return bt_convert__perf2ctf(input_name, to_ctf, force);
#else
		pr_err("The libbabeltrace support is not compiled in.\n");
		return -1;
#endif
	}

	return 0;
}

#define FD_HASH_BITS  7
#define FD_HASH_SIZE  (1 << FD_HASH_BITS)
#define FD_HASH_MASK  (FD_HASH_SIZE - 1)

struct data_index {
	struct perf_tool	tool;
	struct perf_session	*session;
	enum {
		PER_CPU,
		PER_THREAD,
	} split_mode;
	char			*tmpdir;
	int 			header_fd;
	u64			header_written;
	struct hlist_head	fd_hash[FD_HASH_SIZE];
	int			fd_hash_nr;
	int			output_fd;
};

struct fdhash_node {
	int			id;
	int			fd;
	struct hlist_node	list;
};

static struct hlist_head *get_hash(struct data_index *idx, int id)
{
	return &idx->fd_hash[id % FD_HASH_MASK];
}

static int perf_event__rewrite_header(struct perf_tool *tool,
				      union perf_event *event)
{
	struct data_index *idx = container_of(tool, struct data_index, tool);
	ssize_t size;

	size = writen(idx->header_fd, event, event->header.size);
	if (size < 0)
		return -errno;

	idx->header_written += size;
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
	struct data_index *idx = container_of(tool, struct data_index, tool);
	int id = idx->split_mode == PER_CPU ? sample->cpu : sample->tid;
	int fd = -1;
	char buf[PATH_MAX];
	struct hlist_head *head;
	struct fdhash_node *node;

	head = get_hash(idx, id);
	hlist_for_each_entry(node, head, list) {
		if (node->id == id) {
			fd = node->fd;
			break;
		}
	}

	if (fd == -1) {
		scnprintf(buf, sizeof(buf), "%s/perf.data.%d",
			  idx->tmpdir, idx->fd_hash_nr++);

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

static int split_data_file(struct data_index *idx)
{
	struct perf_session *session = idx->session;
	char buf[PATH_MAX];
	u64 sample_type;
	int header_fd;

	if (asprintf(&idx->tmpdir, "%s.dir", output_name) < 0) {
		pr_err("memory allocation failed\n");
		return -1;
	}

	if (mkdir(idx->tmpdir, 0700) < 0) {
		pr_err("cannot create intermediate directory\n");
		return -1;
	}

	/*
	 * This is necessary to write (copy) build-id table.  After
	 * processing header, dsos list will only contain dso which
	 * was on the original build-id table.
	 */
	dsos__hit_all(session);

	scnprintf(buf, sizeof(buf), "%s/perf.header", idx->tmpdir);
	header_fd = open(buf, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (header_fd < 0) {
		pr_err("cannot open header file: %s: %m\n", buf);
		return -1;
	}

	lseek(header_fd, session->header.data_offset, SEEK_SET);

	sample_type = perf_evlist__combined_sample_type(session->evlist);
	if (sample_type & PERF_SAMPLE_CPU)
		idx->split_mode = PER_CPU;
	else
		idx->split_mode = PER_THREAD;

	pr_debug("splitting data file for %s\n",
		 idx->split_mode == PER_CPU ? "CPUs" : "threads");

	idx->header_fd = header_fd;
	if (perf_session__process_events(session) < 0) {
		pr_err("failed to process events\n");
		return -1;
	}

	return 0;
}

static int build_index_table(struct data_index *idx)
{
	int i, n;
	u64 offset;
	u64 nr_idx = idx->fd_hash_nr + 1;
	struct perf_file_section *sec;
	struct perf_session *session = idx->session;

	sec = calloc(nr_idx, sizeof(*sec));
	if (sec == NULL)
		return -1;

	sec[0].offset = session->header.data_offset;
	sec[0].size   = idx->header_written;

	offset = sec[0].offset + sec[0].size;

	for (i = 0, n = 1; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *node;

		hlist_for_each_entry(node, &idx->fd_hash[i], list) {
			struct stat stbuf;

			if (fstat(node->fd, &stbuf) < 0)
				goto out;

			sec[n].offset = offset;
			sec[n].size   = stbuf.st_size;
			n++;

			offset += stbuf.st_size;
		}
	}

	BUG_ON(n != (int)nr_idx);

	session->header.index = sec;
	session->header.nr_index = nr_idx;

	session->header.data_size = offset - sec[0].offset;
	perf_header__set_feat(&session->header, HEADER_DATA_INDEX);

	perf_session__write_header(session, session->evlist,
				   idx->output_fd, true);
	return 0;

out:
	free(sec);
	return -1;
}

static int cleanup_temp_files(struct data_index *idx)
{
	int i;

	for (i = 0; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *pos;
		struct hlist_node *tmp;

		hlist_for_each_entry_safe(pos, tmp, &idx->fd_hash[i], list) {
			hlist_del(&pos->list);
			close(pos->fd);
			free(pos);
		}
	}
	close(idx->header_fd);

	rm_rf(idx->tmpdir);
	zfree(&idx->tmpdir);
	return 0;
}

static int __data_cmd_index(struct data_index *idx)
{
	struct perf_session *session = idx->session;
	char *output = NULL;
	int ret = -1;
	int i, n;

	if (!output_name) {
		if (asprintf(&output, "%s.out", session->file->path) < 0) {
			pr_err("memory allocation failed\n");
			return -1;
		}

		output_name = output;
	}

	idx->output_fd = open(output_name, O_RDWR|O_CREAT|O_TRUNC, 0600);
	if (idx->output_fd < 0) {
		pr_err("cannot create output file: %s\n", output_name);
		goto out;
	}

	/*
	 * This is necessary to write (copy) build-id table.  After
	 * processing header, dsos list will contain dso which was on
	 * the original build-id table.
	 */
	dsos__hit_all(session);

	if (split_data_file(idx) < 0)
		goto out_clean;

	if (build_index_table(idx) < 0)
		goto out_clean;

	/* copy meta-events */
	if (copyfile_offset(idx->header_fd, session->header.data_offset,
			   idx->output_fd, session->header.data_offset,
			   idx->header_written) < 0)
		goto out_clean;

	/* copy sample events */
	for (i = 0, n = 1; i < FD_HASH_SIZE; i++) {
		struct fdhash_node *node;

		hlist_for_each_entry(node, &idx->fd_hash[i], list) {
			if (copyfile_offset(node->fd, 0, idx->output_fd,
					    session->header.index[n].offset,
					    session->header.index[n].size) < 0)
				goto out_clean;
			n++;
		}
	}
	ret = 0;

out_clean:
	cleanup_temp_files(idx);
	close(idx->output_fd);
out:
	free(output);
	return ret;
}

int data_cmd_index(int argc, const char **argv, const char *prefix __maybe_unused)
{
	bool force = false;
	struct perf_session *session;
	struct perf_data_file file = {
		.mode  = PERF_DATA_MODE_READ,
	};
	struct data_index idx = {
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
			.ordered_events = false,
		},
	};
	const char * const index_usage[] = {
		"perf data index [<options>]",
		NULL
	};
	const struct option index_options[] = {
	OPT_STRING('i', "input", &input_name, "file", "input file name"),
	OPT_STRING('o', "output", &output_name, "file", "output directory name"),
	OPT_BOOLEAN('f', "force", &force, "don't complain, do it"),
	OPT_INCR('v', "verbose", &verbose, "be more verbose"),
	OPT_END()
	};

	argc = parse_options(argc, argv, index_options, index_usage, 0);
	if (argc)
		usage_with_options(index_usage, index_options);

	file.path = input_name;
	file.force = force;
	session = perf_session__new(&file, false, &idx.tool);
	if (session == NULL)
		return -1;

	idx.session = session;
	symbol__init(&session->header.env);

	__data_cmd_index(&idx);

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

	argc = parse_options_subcommand(argc, argv, data_options, data_subcommands, data_usage,
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
