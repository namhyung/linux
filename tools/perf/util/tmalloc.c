#include <sys/mman.h>
#include "util/util.h"
#include "util/debug.h"

struct tmalloc_chunk {
	struct tmalloc_chunk	*next;
	size_t			len;
	size_t			cur;
};

static __thread struct tmalloc_chunk *tc;

#define TMALLOC_CHUNK_SIZE  (8 * 1024 * 1024)

void *tmalloc(size_t sz)
{
	void *ptr;
	struct tmalloc_chunk *chunk;

	if (tc == NULL || (tc->cur + sz > tc->len)) {
		ptr = mmap(NULL, TMALLOC_CHUNK_SIZE, PROT_READ|PROT_WRITE,
			   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (ptr == MAP_FAILED) {
			pr_err("map failed for tmalloc\n");
			return NULL;
		}

		chunk = ptr;
		chunk->len = TMALLOC_CHUNK_SIZE;
		chunk->cur = sizeof(*chunk);

		chunk->next = tc;
		tc = chunk;
	}

	ptr = (void *)tc + tc->cur;
	tc->cur += sz;

	return ptr;
}

void *tzalloc(size_t sz)
{
	/* it's already zero-filled */
	return tmalloc(sz);
}

void tfree(void *ptr __maybe_unused)
{
	/* no nothing */
}

void tfree_all(void)
{
	struct tmalloc_chunk *chunk = tc;

	while (chunk) {
		tc = chunk->next;
		munmap(chunk, chunk->len);
		chunk = tc;
	}
}
