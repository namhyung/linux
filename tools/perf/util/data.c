#include <linux/compiler.h>
#include <linux/kernel.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>

#include "data.h"
#include "util.h"
#include "debug.h"

static bool check_pipe(struct perf_data_file *file)
{
	struct stat st;
	bool is_pipe = false;
	int fd = perf_data_file__is_read(file) ?
		 STDIN_FILENO : STDOUT_FILENO;

	if (!file->path) {
		if (!fstat(fd, &st) && S_ISFIFO(st.st_mode))
			is_pipe = true;
	} else {
		if (!strcmp(file->path, "-"))
			is_pipe = true;
	}

	if (is_pipe)
		file->single_fd = fd;

	return file->is_pipe = is_pipe;
}

static int check_backup(struct perf_data_file *file)
{
	struct stat st;

	if (!stat(file->path, &st) && st.st_size) {
		/* TODO check errors properly */
		char oldname[PATH_MAX];
		bool is_dir = S_ISDIR(st.st_mode);

		snprintf(oldname, sizeof(oldname), "%s.old",
			 file->path);

		if (is_dir)
			rm_rf(oldname);
		else
			unlink(oldname);

		rename(file->path, oldname);
	}

	return 0;
}

static int open_file_read(struct perf_data_file *file)
{
	struct stat st;
	char path[PATH_MAX];
	int fd;
	char sbuf[STRERR_BUFSIZE];

	strcpy(path, file->path);
	if (file->is_multi) {
		if (path__join(path, sizeof(path), file->path, "perf.header") < 0)
			return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		int err = errno;

		pr_err("failed to open %s: %s", file->path,
			strerror_r(err, sbuf, sizeof(sbuf)));
		if (err == ENOENT && !strcmp(file->path, "perf.data"))
			pr_err("  (try 'perf record' first)");
		pr_err("\n");
		return -err;
	}

	if (fstat(fd, &st) < 0)
		goto out_close;

	if (!file->force && st.st_uid && (st.st_uid != geteuid())) {
		pr_err("File %s not owned by current user or root (use -f to override)\n",
		       file->path);
		goto out_close;
	}

	if (!st.st_size) {
		pr_info("zero-sized file (%s), nothing to do!\n",
			file->path);
		goto out_close;
	}

	file->size = st.st_size;
	return fd;

 out_close:
	close(fd);
	return -1;
}

static int open_file_write(struct perf_data_file *file)
{
	int fd;
	char path[PATH_MAX];
	char sbuf[STRERR_BUFSIZE];

	if (check_backup(file))
		return -1;

	strcpy(path, file->path);

	if (file->is_multi) {
		if (mkdir(file->path, S_IRWXU) < 0) {
			pr_err("cannot create data directory `%s': %s\n",
			       file->path, strerror_r(errno, sbuf, sizeof(sbuf)));
			return -1;
		}

		if (path__join(path, sizeof(path), file->path, "perf.header") < 0)
			return -1;
	}

	fd = open(path, O_CREAT|O_RDWR|O_TRUNC, S_IRUSR|S_IWUSR);

	if (fd < 0)
		pr_err("failed to open %s : %s\n", file->path,
			strerror_r(errno, sbuf, sizeof(sbuf)));

	return fd;
}

static int open_file(struct perf_data_file *file)
{
	int fd;

	fd = perf_data_file__is_read(file) ?
	     open_file_read(file) : open_file_write(file);

	file->single_fd = fd;
	return fd < 0 ? -1 : 0;
}

int perf_data_file__open(struct perf_data_file *file)
{
	if (check_pipe(file))
		return 0;

	if (!file->path)
		file->path = file->is_multi ? "perf.data.dir" : "perf.data";

	return open_file(file);
}

static int scandir_filter(const struct dirent *d)
{
	return !prefixcmp(d->d_name, "perf.data.");
}

static int open_file_read_multi(struct perf_data_file *file, int nr)
{
	int i;
	int ret;
	struct dirent **list;
	char path[PATH_MAX];

	nr = scandir(file->path, &list, scandir_filter, versionsort);
	if (nr < 0) {
		ret = -errno;
		pr_err("cannot find multi-data file\n");
		return ret;
	}

	file->multi_fd = malloc(nr * sizeof(int));
	if (file->multi_fd == NULL) {
		free(list);
		return -ENOMEM;
	}

	for (i = 0; i < nr; i++) {
		path__join(path, sizeof(path), file->path, list[i]->d_name);
		ret = open(path, O_RDONLY);
		if (ret < 0)
			goto out_err;

		file->multi_fd[i] = ret;
	}
	file->nr_multi = nr;

	free(list);
	return 0;

out_err:
	while (--i >= 0)
		close(file->multi_fd[i]);

	zfree(&file->multi_fd);
	free(list);
	return ret;
}

static int open_file_write_multi(struct perf_data_file *file, int nr)
{
	int i;
	int ret;
	char path[PATH_MAX];

	file->multi_fd = malloc(nr * sizeof(int));
	if (file->multi_fd == NULL)
		return -ENOMEM;

	for (i = 0; i < nr; i++) {
		scnprintf(path, sizeof(path), "%s/perf.data.%d", file->path, i);
		ret = open(path, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
		if (ret < 0)
			goto out_err;

		file->multi_fd[i] = ret;
	}
	file->nr_multi = nr;

	return 0;

out_err:
	while (--i >= 0)
		close(file->multi_fd[i]);

	zfree(&file->multi_fd);
	return ret;
}

int perf_data_file__open_multi(struct perf_data_file *file, int nr)
{
	int ret;

	if (!file->is_multi)
		return -EINVAL;

	ret = perf_data_file__is_read(file) ?
		open_file_read_multi(file, nr) : open_file_write_multi(file, nr);

	return ret;
}

void perf_data_file__close(struct perf_data_file *file)
{
	if (file->is_multi) {
		int i;

		for (i = 0; i < file->nr_multi; i++)
			close(file->multi_fd[i]);

		zfree(&file->multi_fd);
	}

	close(file->single_fd);
}

ssize_t perf_data_file__write(struct perf_data_file *file,
			      void *buf, size_t size)
{
	return writen(file->single_fd, buf, size);
}

ssize_t perf_data_file__write_multi(struct perf_data_file *file,
				    void *buf, size_t size, int idx)
{
	if (!file->is_multi)
		return -1;

	return writen(file->multi_fd[idx], buf, size);
}
