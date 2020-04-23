#include "trace2/tr2_sid.h"
const char *tr2_sid_get(void)
 * Compute the final component of the SID representing the current process.
 */
 *
		strbuf_addstr(&tr2sid_buf, parent_sid);
	}
 *
 * (This is an abribrary choice.  On most systems pid_t is a 32 bit value,
	return tr2sid_nr_git_parents;

	if (tr2sid_buf.len)
}
 * all events from this process to have a single label (much like a PID).
		const char *p;
				tr2sid_nr_git_parents++;

 */

 * Export this into our environment so that all child processes inherit it.
	if (xgethostname(hostname, sizeof(hostname)))
 * where <process> is a 9 character string containing the least significant
 * This should uniquely identify the process and be a valid filename (to
		return;
 * is an intermediate shell process.)
 * "<yyyymmdd>T<hhmmss>.<fraction>Z-<host>-<process>"

 *    "Localhost" when no hostname.
 *
 * where <host> is a 9 character string:
 *
}
 *    "H<first_8_chars_of_sha1_of_hostname>"
		strbuf_addch(&tr2sid_buf, '/');
#define TR2_ENVVAR_PARENT_SID "GIT_TRACE2_PARENT_SID"

	}
}
	pid_t pid = getpid();
	const char *parent_sid;
int tr2_sid_depth(void)

#include "cache.h"
{
	tr2_sid_append_my_sid_component();
	if (!tr2sid_buf.len)

		strbuf_addch(&tr2sid_buf, 'H');
		tr2sid_nr_git_parents++;
 * for our purposes here.)
	else {
 * length for possible use as a database key.
	char hex[GIT_MAX_HEXSZ + 1];
 *    "P<pid>"
}
	parent_sid = getenv(TR2_ENVVAR_PARENT_SID);
		algo->update_fn(&ctx, hostname, strlen(hostname));
	strbuf_addf(&tr2sid_buf, "-P%08"PRIx32, (uint32_t)pid);

static void tr2_sid_append_my_sid_component(void)
}
		algo->init_fn(&ctx);
	return tr2sid_buf.buf;

static struct strbuf tr2sid_buf = STRBUF_INIT;
static void tr2_sid_compute(void)
	unsigned char hash[GIT_MAX_RAWSZ + 1];
		algo->final_fn(hash, &ctx);
	tr2_tbuf_utc_datetime(&tb_now);

	strbuf_addch(&tr2sid_buf, '-');

		for (p = parent_sid; *p; p++)

		tr2_sid_compute();
	setenv(TR2_ENVVAR_PARENT_SID, tr2sid_buf.buf, 1);

	if (parent_sid && *parent_sid) {
		tr2_sid_compute();
 *
	if (!tr2sid_buf.len)
{
			if (*p == '/')

	struct tr2_tbuf tb_now;
 * so limit doesn't matter.  On larger systems, a truncated value is fine
 *
	strbuf_addstr(&tr2sid_buf, tb_now.buf);
{
 * Compute a "unique" session id (SID) for the current process.  This allows
static int tr2sid_nr_git_parents;
	git_hash_ctx ctx;
{
void tr2_sid_release(void)

 * prefix.  (This lets us track parent/child relationships even if there
	char hostname[HOST_NAME_MAX + 1];
 * Additionally, count the number of nested git processes.
		strbuf_add(&tr2sid_buf, "Localhost", 9);

 * allow writing trace2 data to per-process files).  It should also be fixed
/*
	const struct git_hash_algo *algo = &hash_algos[GIT_HASH_SHA1];
{
		hash_to_hex_algop_r(hex, hash, algo);
 * 32 bits in the process-id.
		strbuf_add(&tr2sid_buf, hex, 8);
	strbuf_release(&tr2sid_buf);
/*
#include "trace2/tr2_tbuf.h"

 * If we were started by another git instance, use our parent's SID as a
