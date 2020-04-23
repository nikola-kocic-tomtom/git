			our = their;
out_free_f2_f1:
		common.ptr = xstrdup("");
	unsigned long size;
				istate, NULL);
		goto out_free_f1;
{
		if (base)
	mmfile_t f1, f2, common;
#include "run-command.h"
	}
	f->size = size;
	free_mmfile(&f1);
		enum object_type type;
	 * modified in the other branch!
static void free_mmfile(mmfile_t *f)
	free_mmfile(&f2);
	if (base) {
	return 0;

	 *
	free(f->ptr);
	*size = res.size;
		goto out_no_mmfile;
#include "object-store.h"
		if (!our)
	mmbuffer_t res;
	merge_status = ll_merge(&res, path, base, NULL,
	 * common ancestor.
		  struct blob *their, unsigned long *size)
	 * There is no need to worry about a label for the
{
	void *buf;
	 * proper warning about removing a file that got
	if (!our || !their) {
	int merge_status;

		return -1;
			return NULL;
	void *res = NULL;
				 unsigned long *size)
	free_mmfile(&common);
}
#include "ll-merge.h"
void *merge_blobs(struct index_state *istate, const char *path,
#include "xdiff-interface.h"
				 mmfile_t *their,
	return res;
				 const char *path,
	 */

	if (fill_mmfile_blob(&f1, our) < 0)
static int fill_mmfile_blob(mmfile_t *f, struct blob *obj)
		common.size = 0;
	return res.ptr;
	 */
static void *three_way_filemerge(struct index_state *istate,
		return -1;
		free(buf);
		return NULL;
{
	}
	} else {
#include "merge-blobs.h"
				 mmfile_t *our,
}
#include "blob.h"

	res = three_way_filemerge(istate, path, &common, &f1, &f2, size);
	 * does not respect the merge.conflictstyle option.
}
	enum object_type type;
				our, ".our", their, ".their",

	 * This function is only used by cmd_merge_tree, which
	if (fill_mmfile_blob(&f2, their) < 0)
		  struct blob *base, struct blob *our,
				 mmfile_t *base,

		return read_object_file(&our->object.oid, &type, size);


out_free_f1:
	if (!buf)
}
	/*
		if (fill_mmfile_blob(&common, base) < 0)

	if (type != OBJ_BLOB) {
	buf = read_object_file(&obj->object.oid, &type, &size);
	 * Removed in either branch?
	if (merge_status < 0)
	}
	/*

	 * NOTE! This depends on the caller having done the
#include "cache.h"
out_no_mmfile:
{
			goto out_free_f2_f1;
	f->ptr = buf;
