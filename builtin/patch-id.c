		len = remove_space(line);
				break;
	*p_before = atoi(q);
	}
		usage(patch_id_usage);
	}
				continue;


			if (starts_with(line, "@@ -")) {
	}
	struct object_id oid, n, result;
		if (!patchlen && !starts_with(line, "diff "))
		/* Parsing diff header?  */
{

}


}

	return 1;
	return 0;

		if (line[0] == '-' || line[0] == ' ')
				break;
	if (n == 0 || q[n] != ' ' || q[n+1] != '+')
	if (argc == 2 && !strcmp(argv[1], "--stable"))


			else if (starts_with(line, "--- "))
		/* If we get here, we're inside a hunk.  */
		oidcpy(&oid, &n);
static void generate_id_list(int stable)
	return dst - line;
}
	int before = -1, after = -1;

	char *src = line;
		patchlen = get_one_patchid(&n, &result, &line_buf, stable);
		/* Looking for a valid hunk header?  */
			/* Split at the end of the patch.  */
		if (!skip_prefix(line, "diff-tree ", &p) &&
		if (line[0] == '+' || line[0] == ' ')
	}
static int scan_hunk_header(const char *p, int *p_before, int *p_after)
{
		*stable = git_config_bool(var, value);
	flush_one_hunk(result, &ctx);
		q += n + 1;
			*dst++ = c;
#include "builtin.h"
		const char *p = line;
	while (!feof(stdin)) {


		stable = 1;
		n = strspn(r, digits);
	if (!found_next)
		int len;
	/* If nothing is set, default to unstable. */
	int stable = -1;
			after--;
	int *stable = cb;
	if (q[n] == ',') {
	strbuf_release(&line_buf);

			else if (!isalpha(line[0]))
static int remove_space(char *line)
				scan_hunk_header(line, &before, &after);
{
		    !skip_prefix(line, "From ", &p) &&


			break;
	git_config(git_patch_id_config, &stable);
		r += n + 1;
		the_hash_algo->update_fn(&ctx, line, len);
		}


	oidclr(result);
	q = p + 4;
	return patchlen;
	char *dst = line;
	while (strbuf_getwholeline(line_buf, stdin, '\n') != EOF) {
{

	if (n == 0)
			if (!starts_with(line, "diff "))
		n = strspn(q, digits);
		if (!isspace(c))

static void flush_current_id(int patchlen, struct object_id *id, struct object_id *result)
		stable = 0;
		patchlen += len;
	if (patchlen)

		/* Compute the sha without whitespace */
#include "diff.h"
		if (!get_oid_hex(p, next_oid)) {
	n = strspn(r, digits);
		printf("%s %s\n", oid_to_hex(result), oid_to_hex(id));
{
{
		/* Ignore commit comments */

#include "cache.h"
	oidclr(&oid);
	const char *q, *r;
}
			   struct strbuf *line_buf, int stable)
		return 0;
			before = after = -1;
	git_hash_ctx ctx;
			found_next = 1;
	int patchlen;
	}
	the_hash_algo->init_fn(&ctx);
		if (before == 0 && after == 0) {
			if (starts_with(line, "index "))
}
		flush_current_id(patchlen, &oid, &result);
	int patchlen = 0, found_next = 0;
			if (stable)
	unsigned char c;
		    starts_with(line, "\\ ") && 12 < strlen(line))

	else if (argc == 2 && !strcmp(argv[1], "--unstable"))
static const char patch_id_usage[] = "git patch-id [--stable | --unstable]";
int cmd_patch_id(int argc, const char **argv, const char *prefix)
		char *line = line_buf->buf;

			/* Else we're parsing another header.  */
		return 0;
			}
		}
	n = strspn(q, digits);
		oidclr(next_oid);
			before--;
	else if (argc != 1)
				before = after = 1;
	}
	*p_after = atoi(r);
		return 0;
	if (stable < 0)


	struct strbuf line_buf = STRBUF_INIT;

static int git_patch_id_config(const char *var, const char *value, void *cb)
		}
}

	if (r[n] == ',') {
		if (before == -1) {
	int n;

				flush_one_hunk(result, &ctx);

	r = q + n + 2;
#include "config.h"
		    !skip_prefix(line, "commit ", &p) &&
				/* Parse next hunk, but ignore line numbers.  */
	generate_id_list(stable);
			continue;

static int get_one_patchid(struct object_id *next_oid, struct object_id *result,

	while ((c = *src++) != '\0') {


				continue;
	if (!strcmp(var, "patchid.stable")) {
{
		stable = 0;
}
	return git_default_config(var, value, cb);
			continue;
	static const char digits[] = "0123456789";
