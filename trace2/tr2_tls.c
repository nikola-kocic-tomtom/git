
	pthread_mutex_destroy(&tr2tls_mutex);
}
}

	/*
void tr2tls_start_process_clock(void)
	return ctx;
	ctx->alloc = TR2_REGION_NESTING_INITIAL_SIZE;
{
}
	ctx = tr2tls_get_self();
{
	ctx->thread_id = tr2tls_locked_increment(&tr2_next_thread_id);

void tr2tls_init(void)
{

{

		strbuf_setlen(&ctx->thread_name, TR2_MAX_THREAD_NAME);
}
}
	 * Keep the absolute start time of the process (i.e. the main
int tr2tls_is_main_thread(void)
#include "trace2/tr2_tls.h"
{



void tr2tls_unset_self(void)
	tr2tls_thread_main =

					     uint64_t us_thread_start)
{
	free(ctx->array_us_start);
	tr2tls_thread_main = NULL;
/*

	if (ctx->thread_id)

uint64_t tr2tls_region_elasped_self(uint64_t us)
	return ctx;
	ALLOC_GROW(ctx->array_us_start, ctx->nr_open_regions + 1, ctx->alloc);
void tr2tls_pop_self(void)
	uint64_t us_start;
#define TR2_REGION_NESTING_INITIAL_SIZE (100)
	struct tr2tls_thread_ctx *ctx = xcalloc(1, sizeof(*ctx));
	us_start = ctx->array_us_start[ctx->nr_open_regions - 1];
	 * If the thread-proc did not call trace2_thread_start(), we won't

void tr2tls_release(void)
	 */
	while (ctx->nr_open_regions > 1)
	 * access it.  This allows them to do that without a lock on
int tr2tls_locked_increment(int *p)
	return us - tr2tls_us_start_process;
{

	if (!HAVE_THREADS)

	pthread_mutex_lock(&tr2tls_mutex);
	 * main thread's array data (because of reallocs).
static int tr2_next_thread_id; /* modify under lock */
}
 */
{

	if (!ctx->nr_open_regions)

void tr2tls_pop_unwind_self(void)
}

	*p = current_value + 1;
	pthread_key_create(&tr2tls_key, NULL);
	ctx->nr_open_regions--;

struct tr2tls_thread_ctx *tr2tls_create_self(const char *thread_name,
	/*


	pthread_setspecific(tr2tls_key, NULL);

	struct tr2tls_thread_ctx *ctx;
	int current_value;
	strbuf_addstr(&ctx->thread_name, thread_name);
}
		tr2tls_pop_self();
	if (!HAVE_THREADS)


		return 0;
struct tr2tls_thread_ctx *tr2tls_get_self(void)
	return us - us_start;

{
	if (ctx->thread_name.len > TR2_MAX_THREAD_NAME)
	ctx = tr2tls_get_self();
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
	 */
{
uint64_t tr2tls_absolute_elapsed(uint64_t us)
static pthread_key_t tr2tls_key;
	pthread_key_delete(tr2tls_key);
	free(ctx);
}


	ctx->array_us_start = (uint64_t *)xcalloc(ctx->alloc, sizeof(uint64_t));

	 * have any TLS data associated with the current thread.  Fix it

	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
}

		return 0;
#include "cache.h"
static struct tr2tls_thread_ctx *tr2tls_thread_main;
	 * application run time.
	current_value = *p;
{
	if (tr2tls_us_start_process)
	return pthread_getspecific(tr2tls_key) == tr2tls_thread_main;

 * this stack is per-thread and not per-trace-key.
	if (!ctx->nr_open_regions)
	pthread_mutex_unlock(&tr2tls_mutex);
	return current_value;

#include "thread-utils.h"
	struct tr2tls_thread_ctx *ctx = tr2tls_get_self();
	tr2tls_us_start_process = getnanotime() / 1000;
	init_recursive_mutex(&tr2tls_mutex);
		return 1;

	struct tr2tls_thread_ctx *ctx;
		ctx = tr2tls_create_self("unknown", getnanotime() / 1000);

	tr2tls_start_process_clock();
 * This is used to store nested region start times.  Note that

{
 * Initialize size of the thread stack for nested regions.
	ctx->array_us_start[ctx->nr_open_regions++] = us_thread_start;


		return tr2tls_thread_main;
	 * Implicitly "tr2tls_push_self()" to capture the thread's start
	 * process) in a fixed variable since other threads need to
		BUG("no open regions in thread '%s'", ctx->thread_name.buf);

		tr2tls_create_self("main", tr2tls_us_start_process);


	 * here and silently continue.
	strbuf_init(&ctx->thread_name, 0);
}
	/*
	pthread_setspecific(tr2tls_key, ctx);
	 */
{
static pthread_mutex_t tr2tls_mutex;
	tr2tls_unset_self();
	if (!tr2tls_thread_main)
void tr2tls_push_self(uint64_t us_now)

}

	struct tr2tls_thread_ctx *ctx;

static uint64_t tr2tls_us_start_process;
	if (!ctx)

		strbuf_addf(&ctx->thread_name, "th%02d:", ctx->thread_id);
	 * time in array_us_start[0].  For the main thread this gives us the
		return;
	ctx = pthread_getspecific(tr2tls_key);
	ctx->array_us_start[ctx->nr_open_regions++] = us_now;
}

