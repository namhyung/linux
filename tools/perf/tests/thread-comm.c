#include "tests.h"
#include "machine.h"
#include "thread.h"
#include "debug.h"

int test__thread_comm(void)
{
	struct machines machines;
	struct machine *machine;
	struct thread *t;

	/*
	 * This test is to check whether it can retrieve a correct
	 * comm for a given time.  When multi-file data storage is
	 * enabled, those task/comm events are processed first so the
	 * later sample should find a matching comm properly.
	 */
	machines__init(&machines);
	machine = &machines.host;

	t = machine__findnew_thread(machine, 100, 100);
	TEST_ASSERT_VAL("wrong init thread comm",
			!strcmp(thread__comm_str(t), ":100"));

	thread__set_comm(t, "perf-test1", 10000);
	TEST_ASSERT_VAL("failed to override thread comm",
			!strcmp(thread__comm_str(t), "perf-test1"));

	thread__set_comm(t, "perf-test2", 20000);
	thread__set_comm(t, "perf-test3", 30000);
	thread__set_comm(t, "perf-test4", 40000);

	TEST_ASSERT_VAL("failed to find timed comm",
			!strcmp(thread__comm_time_str(t, 20000), "perf-test2"));
	TEST_ASSERT_VAL("failed to find timed comm",
			!strcmp(thread__comm_time_str(t, 35000), "perf-test3"));
	TEST_ASSERT_VAL("failed to find timed comm",
			!strcmp(thread__comm_time_str(t, 50000), "perf-test4"));

	thread__set_comm(t, "perf-test1.5", 15000);
	TEST_ASSERT_VAL("failed to sort timed comm",
			!strcmp(thread__comm_time_str(t, 15000), "perf-test1.5"));

	machine__delete_threads(machine);
	machines__exit(&machines);
	return 0;
}
