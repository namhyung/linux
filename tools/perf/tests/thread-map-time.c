#include "debug.h"
#include "tests.h"
#include "machine.h"
#include "thread.h"
#include "map.h"

#define PERF_MAP_START  0x40000
#define LIBC_MAP_START  0x80000
#define VDSO_MAP_START  0x7F000

#define NR_MAPS  100

static int lookup_maps(struct map_groups *mg)
{
	struct map *map;
	int i, ret = -1;
	size_t n;
	struct {
		const char *path;
		u64 start;
	} maps[] = {
		{ "/usr/bin/perf",	PERF_MAP_START },
		{ "/usr/lib/libc.so",	LIBC_MAP_START },
		{ "[vdso]",		VDSO_MAP_START },
	};

	/* this is needed to insert/find map by time */
	perf_has_index = true;

	for (n = 0; n < ARRAY_SIZE(maps); n++) {
		for (i = 0; i < NR_MAPS; i++) {
			map = map__new2(maps[n].start, dso__new(maps[n].path),
					MAP__FUNCTION, i * 10000);
			if (map == NULL) {
				pr_debug("memory allocation failed\n");
				goto out;
			}

			map->end = map->start + 0x1000;
			map_groups__insert_by_time(mg, map);
		}
	}

	if (verbose > 1)
		map_groups__fprintf(mg, stderr);

	for (n = 0; n < ARRAY_SIZE(maps); n++) {
		for (i = 0; i < NR_MAPS; i++) {
			u64 timestamp = i * 10000;

			map = map_groups__find_by_time(mg, MAP__FUNCTION,
						       maps[n].start,
						       timestamp);

			TEST_ASSERT_VAL("cannot find map", map);
			TEST_ASSERT_VAL("addr not matched",
					map->start == maps[n].start);
			TEST_ASSERT_VAL("pathname not matched",
					!strcmp(map->dso->name, maps[n].path));
			TEST_ASSERT_VAL("timestamp not matched",
					map->timestamp == timestamp);
		}
	}

	ret = 0;
out:
	return ret;
}

/*
 * This test creates large number of overlapping maps for increasing
 * time and find a map based on timestamp.
 */
int test__thread_map_lookup_time(void)
{
	struct machines machines;
	struct machine *machine;
	struct thread *t;
	int ret;

	machines__init(&machines);
	machine = &machines.host;

	t = machine__findnew_thread(machine, 0, 0);

	ret = lookup_maps(t->mg);

	machine__delete_threads(machine);
	return ret;
}
