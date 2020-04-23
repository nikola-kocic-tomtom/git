	strbuf_addf(base, "%s/", ucd->name);
	int i, len;
		printf("%s\n", ucd->untracked[i]);
	}
	const char *const *a = a_;
int cmd__dump_untracked_cache(int ac, const char **av)
	/* Hack to avoid modifying the untracked cache when we read it */

	       oid_to_hex(&ucd->exclude_oid));
	if (!uc) {
	strbuf_setlen(base, len);
{
		printf("no untracked cache\n");
		fputs(" check_only", stdout);
	printf("core.excludesfile %s\n", oid_to_hex(&uc->ss_excludes_file.oid));
{

	ignore_untracked_cache_config = 1;
	if (read_cache() < 0)
static void dump(struct untracked_cache_dir *ucd, struct strbuf *base)
	printf("\n");

	if (ucd->recurse)
		fputs(" recurse", stdout);
	for (i = 0; i < ucd->dirs_nr; i++)
	return strcmp((*a)->name, (*b)->name);
	if (uc->root)
	printf("%s %s", base->buf,
	struct strbuf base = STRBUF_INIT;
	uc = the_index.untracked;
	len = base->len;
	if (ucd->valid)
	printf("info/exclude %s\n", oid_to_hex(&uc->ss_info_exclude.oid));
	const struct untracked_cache_dir *const *a = a_;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	printf("exclude_per_dir %s\n", uc->exclude_per_dir);
	struct untracked_cache *uc;
	setup_git_directory();
		dump(uc->root, &base);
}
		fputs(" valid", stdout);
}
		die("unable to read index file");
#include "cache.h"
static int compare_dir(const void *a_, const void *b_)
		return 0;
#include "dir.h"

}
static int compare_untracked(const void *a_, const void *b_)
	return 0;
}
		dump(ucd->dirs[i], base);
{
	QSORT(ucd->dirs, ucd->dirs_nr, compare_dir);
	printf("flags %08x\n", uc->dir_flags);
	QSORT(ucd->untracked, ucd->untracked_nr, compare_untracked);
	for (i = 0; i < ucd->untracked_nr; i++)
	const char *const *b = b_;

	return strcmp(*a, *b);
{

	const struct untracked_cache_dir *const *b = b_;
	if (ucd->check_only)
#include "test-tool.h"
