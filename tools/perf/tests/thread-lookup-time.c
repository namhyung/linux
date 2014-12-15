#include "tests.h"
#include "machine.h"
#include "thread.h"
#include "map.h"
#include "debug.h"

static int thread__print_cb(struct thread *th, void *arg __maybe_unused)
{
	printf("thread: %d, start time: %"PRIu64" %s\n",
	       th->tid, th->start_time,
	       th->dead ? "(dead)" : th->exited ? "(exited)" :
	       th->missing ? "(missing)" : "");
	return 0;
}

static int lookup_with_timestamp(struct machine *machine)
{
	struct thread *t1, *t2, *t3;
	union perf_event fork = {
		.fork = {
			.pid = 0,
			.tid = 0,
			.ppid = 1,
			.ptid = 1,
		},
	};
	struct perf_sample sample = {
		.time = 50000,
	};

	/* start_time is set to 0 */
	t1 = machine__findnew_thread(machine, 0, 0);

	if (verbose > 1) {
		printf("========= after t1 created ==========\n");
		machine__for_each_thread(machine, thread__print_cb, NULL);
	}

	TEST_ASSERT_VAL("wrong start time of old thread", t1->start_time == 0);

	TEST_ASSERT_VAL("cannot find current thread",
			machine__find_thread(machine, 0, 0) == t1);

	TEST_ASSERT_VAL("cannot find current thread with time",
			machine__findnew_thread_time(machine, 0, 0, 10000) == t1);

	/* start_time is overwritten to new value */
	thread__set_comm(t1, "/usr/bin/perf", 20000);

	if (verbose > 1) {
		printf("========= after t1 set comm ==========\n");
		machine__for_each_thread(machine, thread__print_cb, NULL);
	}

	TEST_ASSERT_VAL("failed to update start time", t1->start_time == 20000);

	TEST_ASSERT_VAL("should not find passed thread",
			/* this will create yet another dead thread */
			machine__findnew_thread_time(machine, 0, 0, 10000) != t1);

	TEST_ASSERT_VAL("cannot find overwritten thread with time",
			machine__find_thread_time(machine, 0, 0, 20000) == t1);

	/* now t1 goes to dead thread tree, and create t2 */
	machine__process_fork_event(machine, &fork, &sample);

	if (verbose > 1) {
		printf("========= after t2 forked ==========\n");
		machine__for_each_thread(machine, thread__print_cb, NULL);
	}

	t2 = machine__find_thread(machine, 0, 0);
	TEST_ASSERT_VAL("cannot find current thread", t2 != NULL);

	TEST_ASSERT_VAL("wrong start time of new thread", t2->start_time == 50000);

	TEST_ASSERT_VAL("dead thread cannot be found",
			machine__find_thread_time(machine, 0, 0, 10000) != t1);

	TEST_ASSERT_VAL("cannot find dead thread after new thread",
			machine__find_thread_time(machine, 0, 0, 30000) == t1);

	TEST_ASSERT_VAL("cannot find current thread after new thread",
			machine__find_thread_time(machine, 0, 0, 50000) == t2);

	/* now t2 goes to dead thread tree, and create t3 */
	sample.time = 60000;
	machine__process_fork_event(machine, &fork, &sample);

	if (verbose > 1) {
		printf("========= after t3 forked ==========\n");
		machine__for_each_thread(machine, thread__print_cb, NULL);
	}

	t3 = machine__find_thread(machine, 0, 0);
	TEST_ASSERT_VAL("cannot find current thread", t3 != NULL);

	TEST_ASSERT_VAL("wrong start time of new thread", t3->start_time == 60000);

	TEST_ASSERT_VAL("cannot find dead thread after new thread",
			machine__findnew_thread_time(machine, 0, 0, 30000) == t1);

	TEST_ASSERT_VAL("cannot find dead thread after new thread",
			machine__findnew_thread_time(machine, 0, 0, 50000) == t2);

	TEST_ASSERT_VAL("cannot find current thread after new thread",
			machine__findnew_thread_time(machine, 0, 0, 70000) == t3);

	machine__delete_threads(machine);
	machine__delete_dead_threads(machine);
	machine__delete_missing_threads(machine);
	return 0;
}

static int lookup_without_timestamp(struct machine *machine)
{
	struct thread *t1, *t2, *t3;
	union perf_event fork = {
		.fork = {
			.pid = 0,
			.tid = 0,
			.ppid = 1,
			.ptid = 1,
		},
	};
	struct perf_sample sample = {
		.time = -1ULL,
	};

	t1 = machine__findnew_thread(machine, 0, 0);
	TEST_ASSERT_VAL("cannot find current thread", t1 != NULL);

	TEST_ASSERT_VAL("cannot find new thread with time",
			machine__findnew_thread_time(machine, 0, 0, -1ULL) == t1);

	machine__process_fork_event(machine, &fork, &sample);

	t2 = machine__find_thread(machine, 0, 0);
	TEST_ASSERT_VAL("cannot find current thread", t2 != NULL);

	TEST_ASSERT_VAL("cannot find new thread with time",
			machine__find_thread_time(machine, 0, 0, -1ULL) == t2);

	machine__process_fork_event(machine, &fork, &sample);

	t3 = machine__find_thread(machine, 0, 0);
	TEST_ASSERT_VAL("cannot find current thread", t3 != NULL);

	TEST_ASSERT_VAL("cannot find new thread with time",
			machine__findnew_thread_time(machine, 0, 0, -1ULL) == t3);

	machine__delete_threads(machine);
	machine__delete_dead_threads(machine);
	machine__delete_missing_threads(machine);
	return 0;
}

int test__thread_lookup_time(void)
{
	struct machines machines;
	struct machine *machine;

	/*
	 * This test is to check whether it can retrieve a correct
	 * thread for a given time.  When multi-file data storage is
	 * enabled, those task/comm/mmap events are processed first so
	 * the later sample should find a matching thread properly.
	 */
	machines__init(&machines);
	machine = &machines.host;

	if (lookup_with_timestamp(machine) < 0)
		return -1;

	if (lookup_without_timestamp(machine) < 0)
		return -1;

	machines__exit(&machines);
	return 0;
}
