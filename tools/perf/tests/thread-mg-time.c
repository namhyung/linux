#include "tests.h"
#include "machine.h"
#include "thread.h"
#include "map.h"
#include "debug.h"

#define PERF_MAP_START  0x40000

int test__thread_mg_time(void)
{
	struct machines machines;
	struct machine *machine;
	struct thread *t;
	struct map_groups *mg;
	struct map *map;
	struct addr_location al = { .map = NULL, };

	/*
	 * This test is to check whether it can retrieve a correct map
	 * for a given time.  When multi-file data storage is enabled,
	 * those task/comm/mmap events are processed first so the
	 * later sample should find a matching comm properly.
	 */
	machines__init(&machines);
	machine = &machines.host;

	t = machine__findnew_thread(machine, 0, 0);
	mg = t->mg;

	map = dso__new_map("/usr/bin/perf");
	map->start = PERF_MAP_START;
	map->end = PERF_MAP_START + 0x1000;

	thread__insert_map(t, map);

	if (verbose > 1)
		map_groups__fprintf(t->mg, stderr);

	thread__find_addr_map(t, PERF_RECORD_MISC_USER, MAP__FUNCTION,
			      PERF_MAP_START, &al);

	TEST_ASSERT_VAL("cannot find mapping for perf", al.map != NULL);
	TEST_ASSERT_VAL("non matched mapping found", al.map == map);
	TEST_ASSERT_VAL("incorrect map groups", al.map->groups == mg);
	TEST_ASSERT_VAL("incorrect map groups", al.map->groups == t->mg);

	thread__find_addr_map_time(t, PERF_RECORD_MISC_USER,
				   MAP__FUNCTION, PERF_MAP_START, &al, -1ULL);

	TEST_ASSERT_VAL("cannot find timed mapping for perf", al.map != NULL);
	TEST_ASSERT_VAL("non matched timed mapping", al.map == map);
	TEST_ASSERT_VAL("incorrect timed map groups", al.map->groups == mg);
	TEST_ASSERT_VAL("incorrect map groups", al.map->groups == t->mg);


	pr_debug("simulate EXEC event (generate new mg)\n");
	__thread__set_comm(t, "perf-test", 10000, true);

	map = dso__new_map("/usr/bin/perf-test");
	map->start = PERF_MAP_START;
	map->end = PERF_MAP_START + 0x2000;

	thread__insert_map(t, map);

	if (verbose > 1)
		map_groups__fprintf(t->mg, stderr);

	thread__find_addr_map(t, PERF_RECORD_MISC_USER, MAP__FUNCTION,
			      PERF_MAP_START + 4, &al);

	TEST_ASSERT_VAL("cannot find mapping for perf-test", al.map != NULL);
	TEST_ASSERT_VAL("invalid mapping found", al.map == map);
	TEST_ASSERT_VAL("incorrect map groups", al.map->groups != mg);
	TEST_ASSERT_VAL("incorrect map groups", al.map->groups == t->mg);

	pr_debug("searching map in the old mag groups\n");
	thread__find_addr_map_time(t, PERF_RECORD_MISC_USER,
				   MAP__FUNCTION, PERF_MAP_START, &al, 5000);

	TEST_ASSERT_VAL("cannot find timed mapping for perf-test", al.map != NULL);
	TEST_ASSERT_VAL("non matched timed mapping", al.map != map);
	TEST_ASSERT_VAL("incorrect timed map groups", al.map->groups == mg);
	TEST_ASSERT_VAL("incorrect map groups", al.map->groups != t->mg);

	machine__delete_threads(machine);
	machines__exit(&machines);
	return 0;
}
