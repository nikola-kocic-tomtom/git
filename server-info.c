		return 1;
		/* The other way around. */
		if (uic.cur_fp)
		free(info[i]);
		}

{
}
#include "object.h"
	uic->old_fp = NULL;
		long new_len = ftell(uic.cur_fp);
		if (adjust_shared_perm(tmp) < 0)
			continue;
		} else if (line.buf[0] == 'T') {
#include "cache.h"
		if (fstat(old_fd, &st) || (st.st_size != (size_t)new_len))
	free(infofile);


			if (uic_printf(uic, "%s	%s^{}\n",
	 */
	int stale = 1;
static int read_pack_info_file(const char *infofile)
			/* we used to emit T but nobody uses it. */

		info[i]->new_num = i;
	free(info);
}
	if (fclose(to_close))
	return ret;
	int new_num;
	for (p = get_all_packs(the_repository); p; p = p->next) {
	return 0;
			goto out;
	 * intended audiences.
	}
	ret = 0;

		struct strbuf *old = &uic->old_sb;
	char *tmp = mkpathdup("%s_XXXXXX", path);
	struct pack_info *const *b = b_;
}
	FILE *cur_fp;

	}
#include "tag.h"
	if ((*a)->p == (*b)->p)
	int old_num;
	if (o->type == OBJ_TAG) {
	for (i = 0; i < num_pack; i++)
		return (*a)->old_num - (*b)->old_num;

}

	int errs = 0;
	for (i = 0; i < num_pack; i++) {

/*
	int ret = -1;
	struct strbuf old_sb;
	if (ret)
	};
		goto out;
			goto out_stale;
		.cur_fp = NULL,
	strbuf_release(&line);
	return uic->old_fp == NULL;
/* Returns non-zero when we detect that the info in the
	else if ((*a)->p < (*b)->p)
	while (strbuf_getline(&line, fp) != EOF) {
static int compare_info(const void *a_, const void *b_)
		const char *arg;
	return for_each_ref(add_info_ref, uic);
			int force)
	for (i = 0; i < num_pack; i++) {

			error("unrecognized: %s", line.buf);
		error_errno("unable to update %s", path);

	}
		if (!strcmp(pack_basename(p), name))
};
		if (r != cur->len || memcmp(old->buf, cur->buf, r))
		return 1;
	free_pack_info();
	int i;
			goto out;
	if (uic_is_stale(&uic)) {
		if (o)
	int i;
{
	else {

	return errs;
	if (!fp)

		goto out;
		return -1;
	return NULL;
			goto out;
	}

		else if (fd >= 0)
		info[i] = xcalloc(1, sizeof(struct pack_info));
	fd = -1;
			ret = -1;
		.old_fp = NULL,
		ssize_t r;
int update_server_info(int force)
	va_start(ap, fmt);
		return 0;
	ret = update_info_file(infofile, write_pack_info_file, force);
static void init_pack_info(const char *infofile, int force)
		/* The file describes a pack that is no longer here */
	if (uic_printf(uic, "\n") < 0)
static int update_info_file(char *path,
	int ret = -1;
	struct strbuf line = STRBUF_INIT;
		r = fread(old->buf, 1, cur->len, uic->old_fp);
 */
{
	fd = git_mkstemp_mode(tmp, 0666);
	 */
static int parse_pack_def(const char *packname, int old_cnt)


{
		fclose(uic.old_fp);
	ret = generate(&uic);
static int generate_info_refs(struct update_info_ctx *uic)
	}
{
		.old_sb = STRBUF_INIT

	struct pack_info *i = find_pack_by_name(packname);
}
	int i;
		if (stale)
/* packs */
	int stale;
}
 */
		struct strbuf *cur = &uic->cur_sb;
	int fd = -1;
	init_pack_info(infofile, force);
		} else if (line.buf[0] == 'D') {
		i = num_pack++;
		return -1;
		} else {
 * old file is useless.
		ret = vfprintf(uic->cur_fp, fmt, ap);

 out_stale:
	free(tmp);
	else
		if (new_len < 0) {
	if (fd < 0)
	char *path = git_pathdup("info/refs");
		int old_fd = fileno(uic.old_fp);

}
			if (parse_pack_def(arg, old_cnt++))
 */

				return -1;
{

static int add_info_ref(const char *path, const struct object_id *oid,
		/* Keep the order in the original */
		goto out;
			close(fd);
		struct stat st;
	} else {
		unlink(tmp);
			uic_mark_stale(&uic);
		stale = 1;
	strbuf_release(&uic.cur_sb);
	}

		/* we ignore things on alternate path since they are
		i->old_num = old_cnt;
	va_end(ap);
	fclose(fp);

	for (i = 0; i < num_pack; i++)

#include "packfile.h"
	}

{
		return 1;
#include "repository.h"
		if (fwrite(cur->buf, 1, cur->len, uic->cur_fp) == cur->len)
	if (i) {
	FILE *old_fp; /* becomes NULL if it differs from cur_fp */
	if (uic.old_fp)
	struct update_info_ctx uic = {
/* Returns non-zero when we detect that the info in the


static int update_info_refs(int force)
	safe_create_leading_directories(path);
}
	if (!o)
		info[i]->old_num = -1;
{
	 * including index of available pack files and their
#include "object-store.h"
{
		strbuf_vinsertf(cur, 0, fmt, ap);
	struct update_info_ctx *uic = cb_data;
{
	QSORT(info, num_pack, compare_info);
	/* remove leftover rev-cache file if there is any */
	}
	strbuf_release(&uic.old_sb);
	stale = 0;
	/* then it does not matter but at least keep the comparison stable */
}
static int uic_is_stale(const struct update_info_ctx *uic)

		if (rename(tmp, path) < 0)
	int i;
	if (!uic_is_stale(&uic)) {

		return -1;
#include "dir.h"
static struct pack_info {
 * it into place. The contents of the file come from "generate", which
struct update_info_ctx {
			ret = 0;
		return -1;
 * old file is useless.
	errs = errs | update_info_packs(force);
	if (!uic.cur_fp)
		struct packed_git *p = info[i]->p;
	uic.cur_fp = NULL;
 * should return non-zero if it encounters an error.
		stale = read_pack_info_file(infofile);
	va_list ap;

	FILE *fp;

	unlink_or_warn(git_path("info/rev-cache"));
	fclose(uic->old_fp);

	FILE *to_close;
}
static int num_pack;
			fclose(uic.cur_fp);
	return stale;

#include "commit.h"
/* public */

	}
	else if (0 <= (*b)->old_num)

#include "refs.h"


	return ret;
		o = deref_tag(the_repository, o, path, 0);

	else
out:
static int uic_printf(struct update_info_ctx *uic, const char *fmt, ...)
}
		strbuf_reset(cur);
	struct strbuf cur_sb;
			int (*generate)(struct update_info_ctx *),
	int ret = update_info_file(path, generate_info_refs, force);
	size_t alloc = 0;
		strbuf_reset(old);
		return 1; /* nonexistent is not an error. */
			info[i]->old_num = -1;
	struct object *o = parse_object(the_repository, oid);
	} else {
	errs = errs | update_info_refs(force);

			return -1;
		info[i]->p = p;
	if (ret) {
		 * not available to the pullers in general.
	struct packed_git *p;
	char *infofile = mkpathdup("%s/info/packs", get_object_directory());

		 */

	/* new file may be shorter than the old one, check here */
		strbuf_grow(old, cur->len);
	/*
		if (!line.len)
	struct pack_info *const *a = a_;
		}
			continue;
		return 0;
}

		unlink(tmp);
	return ret;
}
	int ret;
	return 0;
	to_close = uic.cur_fp = fdopen(fd, "w");
	return ret;
	free(path);
	if (uic_printf(uic, "%s	%s\n", oid_to_hex(oid), path) < 0)
{
	else if (0 <= (*a)->old_num)

	fp = fopen_or_warn(infofile, "r");
			int flag, void *cb_data)

		goto out;
}

		if (!p->pack_local || !file_exists(p->pack_name))
	}
static int update_info_packs(int force)
{
	 * and mark uic as stale if needed
		uic.old_fp = fopen_or_warn(path, "r");

{
	for (i = 0; i < num_pack; i++)
			goto out_stale;
 * Create the file "path" by writing to a temporary file and renaming
static struct pack_info *find_pack_by_name(const char *name)
		return -1;
{
			/* P name */
			return info[i];
}

		if (skip_prefix(line.buf, "P ", &arg)) {
			/* we used to emit D but that was misguided. */
	if (uic_is_stale(uic)) {
{
				oid_to_hex(&o->oid), path) < 0)
{
	/* no problem on ENOENT and old_fp == NULL, it's stale, now */
} **info;
	}

		if (uic_printf(uic, "P %s\n", pack_basename(info[i]->p)) < 0)
static void free_pack_info(void)
	int old_cnt = 0;
	/* We would add more dumb-server support files later,
				goto out_stale;

	/* renumber them */
}
	if (!force)
	 * uic_printf will compare incremental comparison against old_fp
	if (infofile && !force)
#include "strbuf.h"
static void uic_mark_stale(struct update_info_ctx *uic)
		/* Only A existed in the original so B is obviously newer */
		.cur_sb = STRBUF_INIT,

		ALLOC_GROW(info, num_pack, alloc);
			uic_mark_stale(uic);
	struct packed_git *p;
static int write_pack_info_file(struct update_info_ctx *uic)
	if (0 <= (*a)->old_num && 0 <= (*b)->old_num)

