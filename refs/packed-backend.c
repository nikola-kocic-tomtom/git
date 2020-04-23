		if (!*r2)
			return (unsigned char)*r1 < (unsigned char)*r2 ? -1 : +1;
			snapshot->peeled = PEELED_TAGS;
			"ref_transaction_prepare");
	snapshot->peeled = PEELED_NONE;
	if (ret) {
	struct packed_ref_store *refs = packed_downcast(
	packed_reflog_expire
	transaction->backend_data = data;
	} else if (mmap_strategy == MMAP_NONE || size <= SMALL_FILE_SIZE) {

	/* The current position in the snapshot's buffer: */
static enum mmap_strategy mmap_strategy = MMAP_TEMPORARY;
#include "../chdir-notify.h"
 * memory holding the contents of the `packed-refs` file with its
}
			/*
					      void *cb_data)
	} else {
 */
 *
	 * If packed-refs is a symlink, we want to overwrite the

	packed_refs_path = get_locked_file_path(&refs->lock);
 * hasn't been changed out from under us, so skip the extra `stat()`
	while (1) {
		return -1;
			    strerror(errno));
			BUG("unterminated line found in packed-refs");
}


	return ret;
	struct stat st;
 * Normally, this will be a mmapped view of the contents of the
				/* The safety check should prevent this. */
			return rec;
	ret = 0;
		}
	packed_transaction_prepare,


	return -1;

		if (iter->eof - p < the_hash_algo->hexsz + 1 ||
	const char *pos;
 * memory and close the file, or free the memory. Then set the buffer
	BUG("packed reference store does not support copying references");
	free(packed_refs_path);
				     struct ref_transaction *transaction,
		die_errno("couldn't stat %s", snapshot->refs->path);
			/*
 * new snapshot is taken.
	packed_delete_refs,
		delete_tempfile(&refs->tempfile);
	const char *p = iter->pos, *eol;
	if (!size) {
				const char *refname, const struct object_id *oid,
 * its reference count incremented.
/*
			error(_("could not delete reference %s: %s"),
	const char *start;
				goto write_error;
		if (!(update->flags & REF_HAVE_NEW))
	size_t i;
	/*
	NULL,
	 * updating the packed references via a transaction.
		return;
		strbuf_addf(err, "unable to close %s: %s", refs->path, strerror(errno));
			if ((update->flags & REF_HAVE_OLD) &&
	packed_reflog_exists,
	 * correctness.
struct ref_store *packed_ref_store_create(const char *path,
	}
	else
					      const char *refname,
	 * ref value.
			 * the update didn't expect an existing value:
	if (iter->snapshot->peeled == PEELED_FULLY ||
		free(data);
	struct object_id oid, peeled;
			iter->base.flags &= ~REF_KNOWS_PEELED;
			"is_packed_transaction_needed");
				if (is_null_oid(&update->old_oid)) {
			 */
	 * that is currently mmapped.
	"packed",
	 * at the mmapped contents of the file. If not, it points at
			      refnames->items[0].string, err.buf);
 * Note that earlier versions of Git used to parse these traits by
	snapshot = get_snapshot(refs);
static int packed_create_reflog(struct ref_store *ref_store,
#define SMALL_FILE_SIZE (32*1024)
	 */
static NORETURN void die_unterminated_line(const char *path,
					 pos, eof - pos);
				     struct strbuf *err)
 *
static const char *find_reference_location(struct snapshot *snapshot,
 * free `*snapshot` and return true; otherwise return false.
		else if (unsorted_string_list_has_string(&traits, "peeled"))
			i++;
	 * Stick the updates in a string list by refname so that we
}

			 * and the reference either didn't exist or we
			string_list_append(&data->updates, update->refname);
{
	struct string_list updates;
	struct snapshot *snapshot;
	/* Nothing to do. */
	out = fdopen_tempfile(refs->tempfile, "w");
static void sort_snapshot(struct snapshot *snapshot)
	if (!out) {
	struct ref_store base;

	if (iter->pos < iter->eof && *iter->pos == '^') {
		 */
 * of `ITER_DONE`.
{
		if (data->own_lock && is_lock_file_locked(&refs->lock)) {
		}
			/*

	/* True iff the transaction owns the packed-refs lock. */
 *   `fully-peeled`:
}
		strbuf_release(&sb);
	unsigned int required_flags = REF_STORE_READ;
 *      All references in the file that can be peeled are peeled.
		refs->snapshot = create_snapshot(refs);
	/*
	base_ref_iterator_init(ref_iterator, &packed_ref_iterator_vtable, 1);
				    struct ref_transaction *transaction,
{
 * Compare a snapshot record at `rec` to the specified NUL-terminated
static int packed_reflog_exists(struct ref_store *ref_store,

	if (ref_iterator_abort(ref_iterator) != ITER_DONE)
 * the whole file during every Git invocation). But we do want to be
	 * to make sure we could read the latest version of
				    struct strbuf *err)


int packed_refs_is_locked(struct ref_store *ref_store)
	if (fd < 0) {

	if (!timeout_configured) {
}
struct snapshot_record {
	 * Initialize records based on a crude estimate of the number

 * to tolerate not detecting the problem, as long as we don't produce
#else
}
}
}
	for (dst = new_buffer, i = 0; i < nr; i++) {
 * Increment the reference count of `*snapshot`.
{
			if (*r2 == '\n')
	int sorted = 0;
		struct string_list traits = STRING_LIST_INIT_NODUP;
			/* Pass the old reference through. */
			int peel_error = peel_object(&update->new_oid,

 *
{
		    ref_type(iter->base.refname) != REF_TYPE_PER_WORKTREE)
	 * Packed refs are already packed. It might be that loose refs
	if (refs->snapshot &&

static int packed_delete_reflog(struct ref_store *ref_store,

	 * of references in the file (we'll grow it below if needed):
{
			 * This is OK; it just means that no


	packed_pack_refs,
	 * always need to find the beginning of a record to do a
		    caller, required_flags, refs->store_flags);
					   flags, msg, &err)) {
}
	const char *start;
#include "../cache.h"
		} else {
		dst += records[i].len;
			return 1;

}
}
			 */
		packed_downcast(ref_store, REF_STORE_WRITE | REF_STORE_MAIN,
	 * from `packed_ref_store::snapshot`, if any. The instance
	const char *r1 = rec + the_hash_algo->hexsz + 1;
static int packed_ref_iterator_peel(struct ref_iterator *ref_iterator,
/*
	if (!is_lock_file_locked(&refs->lock))
					       &update->new_oid,
	snapshot->buf = snapshot->start = snapshot->eof = NULL;
	 * trivial case that references are only being deleted, their
	}

	/*
		const char *prefix, unsigned int flags)
			    !is_null_oid(&update->old_oid)) {
 *
	enum { PEELED_NONE, PEELED_TAGS, PEELED_FULLY } peeled;
	/*
	if (!eol)
	return ret;
 * more traits. We interpret the traits as follows:
	return 0;
					  unsigned int store_flags)
static const char *find_start_of_record(const char *buf, const char *p)
static int packed_for_each_reflog_ent_reverse(struct ref_store *ref_store,
		goto error;
/*
			ref_store,
	 * *before* `refname`.
/*
				      const char *refname,

{

	/*
	if (get_oid_hex(rec, oid))


{
		iter->base.flags |= REF_KNOWS_PEELED;
		 */

	}
	 *    disagrees, we could either let the update go through
		return ITER_DONE;
		snapshot->eof = buf_copy + size;
		if (*r1 != *r2) {
	/*
			      struct string_list *updates,
}
	 * because such a transaction might be executed for the side
	return refs;

}
	 *   contents
	if ((iter->base.flags & REF_KNOWS_PEELED)) {

	struct strbuf sb = STRBUF_INIT;


 * `snapshot->buf` is not known to be sorted. Check whether it is, and
		return 0;
 * refname.
	iter->eof = snapshot->eof;
 * if the reference is not a tag or if it is broken.
	packed_copy_ref,
	string_list_init(&data->updates, 0);
{
 * not a `packed_ref_store`. Also die if `packed_ref_store` doesn't
	return is_lock_file_locked(&refs->lock);
}
 * limitations:
	for_each_string_list_item(item, refnames) {

			} else {
	 * exist), `buf`, `start`, and `eof` are all NULL.

 * perform an illegal memory access.

	 * snapshot is associated:

	 *
	 * `packed_ref_store`) must not be freed.
			ref_store,
{
	}


 * will be added later.
		return 0;

				 last_line, eof - last_line);
	if (refs->snapshot) {
				reflog_expiry_should_prune_fn should_prune_fn,

 *
		struct string_list_item *item =
	static int timeout_value = 1000;
	iter = packed_ref_iterator_begin(&refs->base, "",
 * values are `struct ref_update *`. On error, rollback the tempfile,
 * write an error message to `err`, and return a nonzero value.
 * The record is sought using a binary search, so `snapshot->buf` must
	strbuf_release(&iter->refname_buf);
	    (peeled && fprintf(fh, "^%s\n", oid_to_hex(peeled)) < 0))

	if (ok != ITER_DONE) {
	if (!--snapshot->referrers) {
			die("packed refname is dangerous: %s",
	pos = snapshot->start;

	struct packed_ref_store *refs = packed_downcast(

	 */
			if ((ok = ref_iterator_advance(iter)) != ITER_OK)
	 */
			REF_STORE_READ | REF_STORE_WRITE | REF_STORE_ODB,
	else
	string_list_sort(&data->updates);
	 * can sort them:
				       &oid, &referent, &type) ||
	 * of the lists each time through the loop. When the current


}
	 */
	if (rename_tempfile(&refs->tempfile, packed_refs_path)) {

	base_ref_iterator_free(ref_iterator);
 *
		if (i >= updates->nr) {
		char *tmp, *p, *eol;
	 */
			    &refs->lock,
	 * with the header line):
			struct object_id peeled;
		    !ref_resolves_to_object(iter->base.refname, &iter->oid,

			     snapshot->eof - snapshot->buf);
 *   Neither `peeled` nor `fully-peeled`:
	 * caller wants to optimize away empty transactions, it should


	 */
	const char *pos, *eof, *eol;
	 * loop invariant is described in the next two comments.
	strbuf_addf(&sb, "%s.new", packed_refs_path);
	eof = snapshot->eof;
 * Create a newly-allocated `snapshot` of the `packed-refs` file in
		/*

	const char *eol = memchr(p, '\n', len);
	if (mmap_strategy != MMAP_OK && snapshot->mmapped) {

		} else if (is_null_oid(&update->new_oid)) {
			delete_tempfile(&refs->tempfile);
static int cmp_packed_ref_records(const void *v1, const void *v2)
		if (update->flags & REF_HAVE_OLD)
		BUG("is_packed_transaction_needed() called while unlocked");
		goto cleanup;

static struct ref_iterator_vtable packed_ref_iterator_vtable = {
	fd = open(snapshot->refs->path, O_RDONLY);
		}
 * without totally parsing them. We can do so because the records are
		cmp = cmp_record_to_refname(rec, refname);
		rec = find_start_of_record(lo, mid);
		return !!peel_object(&iter->oid, peeled);
 * call in `stat_validity_check()`. This function does *not* increase
	return 0;
	/*
int packed_refs_lock(struct ref_store *ref_store, int flags, struct strbuf *err)

						    update->refname);
			"packed_refs_is_locked");
		if (eol - pos < the_hash_algo->hexsz + 2)
	packed_delete_reflog,
	 * arbitrary other code is running.
/*
	return ok;
		clear_snapshot_buffer(snapshot);
		/* Store a pointer to update in item->util: */
		 * We don't want to leave the file mmapped, so we are
	packed_for_each_reflog_ent,
	packed_create_symref,
		if (!(iter->flags & DO_FOR_EACH_INCLUDE_BROKEN) &&
	if (snapshot->mmapped) {
		/* refname is not a packed reference. */
		string_list_clear(&traits, 0);
			 * Keep any peeled line together with its
		ref_iterator_abort(iter);
			die_unterminated_line(refs->path,
	 * updates into a single transaction.
			iter->base.flags |= REF_KNOWS_PEELED;
			 * for this reference. Check the old value if
		if (unsorted_string_list_has_string(&traits, "fully-peeled"))
			continue;
	if (ref_store->be != &refs_be_packed)
		}
 * Downcast `ref_store` to `packed_ref_store`. Die if `ref_store` is
#if defined(NO_MMAP)

			 * zeros.
static void packed_transaction_cleanup(struct packed_ref_store *refs,
	if (!load_contents(snapshot))
	}
	 */
	MMAP_OK
				/*
{
	close(fd);

	size_t i;
		 * Regardless of what the file header said, we
					    struct ref_transaction *transaction,
			       const char *refname)
	 * nonzero.
	return 0;
 * LF-terminated, and the refname should start exactly (GIT_SHA1_HEXSZ
			 * There is no old value but there is an
	unsigned int store_flags;
 * sure that we never read past the end of the buffer in memory and
	 * itself and zero or one peel lines that start with '^'. Our
			    refs->path, strerror(errno));
			      const struct object_id *peeled)
{
		memcpy(dst, records[i].start, records[i].len);
{
{
			/*

	snapshot->eof = new_buffer + len;
	}
{
		strbuf_addstr(err, "unable to write packed-refs file: "
	unsigned int flags;
	 */
		die_invalid_line(refs->path, rec, snapshot->eof - rec);

		iter = NULL;
				       struct ref_transaction *transaction)
	char *path;
		return -1;
	iter->base.oid = &iter->oid;
	 * Note that we *don't* skip transactions with zero updates,
static int packed_initial_transaction_commit(struct ref_store *ref_store,
			update = updates->items[i].util;
	int mmapped;
{
static struct packed_ref_store *packed_downcast(struct ref_store *ref_store,
			 * update for this reference. Make sure that

			 * which is equivalent to it being empty,


	 * `packed-refs` file no matter we have just mmap it or not.
	 *
	struct strbuf refname_buf;
			/*
			    const char *logmsg)
{
static void clear_snapshot(struct packed_ref_store *refs)
static int packed_pack_refs(struct ref_store *ref_store, unsigned int flags)
	strbuf_addf(err, "error writing to %s: %s",
	ret = ref_transaction_commit(transaction, &err);
	struct packed_ref_iterator *iter =
	 * setting any nonzero new values, so it still might be able
	MMAP_NONE,
	packed_ref_iterator_begin,
{

			oidclr(&iter->peeled);
	    !isspace(*p++))
		strbuf_addf(err, "error closing file %s: %s",
 *
	 */
 * errors.
				void *policy_cb_data)
}
		nr++;

		errno = ENOENT;
	char *new_buffer, *dst;
			 * We have to actually delete that reference
 * `ITER_DONE`. This function does not free the iterator in the case

 *      References under "refs/tags/", if they *can* be peeled, *are*
		} else if (cmp > 0) {
		pos = eol;
		 */
	 * Since we don't check the references' old_oids, the
			if ((update->flags & REF_HAVE_OLD)) {
		goto write_error;
{

	struct packed_ref_iterator *iter;

			struct object_id peeled;
			return 1;
	 * Neither of these cases will come up in the current code,
 *
	 */
			die_invalid_line(snapshot->refs->path,

			 */
					goto error;

 * existed and was read, or 0 if the file was absent or empty. Die on
	struct snapshot *snapshot;
		if (iter->flags & DO_FOR_EACH_PER_WORKTREE_ONLY &&

	return 0;

	strbuf_init(&iter->refname_buf, 0);

	packed_for_each_reflog_ent_reverse,
	 * already.
 * On the other hand, it can be locked outside of a reference
};
	/*
 * doesn't exist, then return the point where that reference would be


		BUG("write_with_updates() called while unlocked");
				  snapshot->refs->path);
 * its current state and return it. The return value will already have
	}
	/*
	     starts_with(iter->base.refname, "refs/tags/")))
		item->util = update;

	return 0;
	if ((refs->store_flags & required_flags) != required_flags)
			    iter->base.refname);
		bytes_read = read_in_full(fd, snapshot->buf, size);
			       struct strbuf *err)
	 * tempfile.

static int packed_transaction_abort(struct ref_store *ref_store,
	 * of updates is exhausted, leave i set to updates->nr.
/*

}
	struct ref_iterator *ref_iterator;
	packed_ref_iterator_abort
		start = snapshot->start;
 */
	BUG("packed reference store does not support symrefs");
 */
	strbuf_release(&sb);
	ref_iterator = &iter->base;
	/* If the file has a header line, process it: */
	struct lock_file lock;
	for (i = 0; i < transaction->nr; i++) {

	int own_lock;

 *      Probably no references are peeled. But if the file contains a

error:
			ret = 1;
 * Get the `snapshot` for the specified packed_ref_store, creating and
	packed_ref_iterator_peel,
	 * - start -- a pointer to the first byte of actual references
	/*
			 * There is both an old value and an update
			/* The safety check should prevent this. */
				      iter->pos, iter->eof - iter->pos);
 * - It cannot store reflogs.
			 * the update (and don't have to write
	if (sorted)
	/* Is the `packed-refs` file currently mmapped? */

	}
 * be a sorted string list whose keys are the refnames and whose util
				 * the iterator over the unneeded

	 * - buf -- a pointer to the start of the memory

		die_invalid_line(iter->snapshot->refs->path,
}
}
		return;
write_error:

	 */

	 * snapshot is up to date with what is on disk, and re-reads
static int packed_read_raw_ref(struct ref_store *ref_store,
/*
		return lo;

	struct snapshot *snapshot = get_snapshot(refs);
	const char *hi = snapshot->eof;

	const char *r1 = e1->start + the_hash_algo->hexsz + 1;
 */
	struct packed_transaction_backend_data *data = transaction->backend_data;
		snapshot->mmapped = 1;
	if (!refs->tempfile) {


	 */
	size_t len;
				i++;

static void acquire_snapshot(struct snapshot *snapshot)
	struct packed_ref_store *refs =
	return empty_ref_iterator_begin();
	}

	struct ref_transaction *transaction;
	struct ref_iterator base;
	iter->base.refname = iter->refname_buf.buf;
	 *
		ref_iterator = prefix_ref_iterator_begin(ref_iterator, prefix, 0);
 */

	 * A pointer to a the first character of a record whose
		int cmp;
	FILE *out;




 * over it. Instances are garbage collected when their `referrers`
	}

 *

	return 0;
				iter = NULL;
 * The most recent `snapshot`, if available, is referenced by the
	size_t alloc = 0, nr = 0;
/*
		BUG("ref_store is type \"%s\" not \"packed\" in %s",
}
	if (!refnames->nr)
				cmp = +1;
	if (prefix && *prefix)
 */
		if (munmap(snapshot->buf, snapshot->eof - snapshot->buf))

	 */

 * `snapshot` instances are reference counted (via
	}
{
	 * it if not.
		die("unexpected line in %s: %.75s...", path, p);
	const char *r2 = refname;
			i++;
{
{

/*

			/*
		rollback_lock_file(&refs->lock);
	 */
 */
	while (p > buf && (p[-1] != '\n' || p[0] == '^'))
	int ret;
		struct ref_update *update = transaction->updates[i];
		    *p++ != '\n')
 * On the other hand, if we hold the lock, then assume that the file
		snapshot->start = eol + 1;
		    parse_oid_hex(p, &iter->peeled, &p) ||
		if ((update->flags & REF_HAVE_NEW) && !is_null_oid(&update->new_oid))
		return -1;
}
		    get_tempfile_path(refs->tempfile), strerror(errno));
		sorted = unsorted_string_list_has_string(&traits, "sorted");
	int ok;
						    oid_to_hex(&update->old_oid));
 * is used in any necessary error messages.
	packed_ref_iterator_advance,

 * If peeled is non-NULL, write it as the entry's peeled value. On
	 * don't write new content to it, but rather to a separate
	}
		else
 * record start is found, return `buf`.
	/* We need to sort the memory. First we sort the records array: */
			die_errno("error ummapping packed-refs file %s",
		/* The "+ 1" is for the LF character. */
	/*
	 * Now that we hold the `packed-refs` lock, it is important
			cmp = -1;
			       const char *refname, struct object_id *oid,

static struct snapshot *get_snapshot(struct packed_ref_store *refs)
	}
{
		if (*r1 == '\n')
					       iter->oid,
	if ((ok = ref_iterator_advance(iter)) != ITER_OK)
			if ((update->flags & REF_HAVE_NEW)) {
 *
	if (iter->pos == iter->eof)

	struct snapshot *snapshot = xcalloc(1, sizeof(*snapshot));
		unable_to_lock_message(refs->path, errno, err);

			break;
	ret = 0;

	size_t size;
	}

	while (pos < eof) {
	 * 2. It could be that a new value is being set, but that it
	 * Don't use mmap() at all for reading `packed-refs`.

 * A `snapshot` represents one snapshot of a `packed-refs` file.

	 * are packed *into* a packed refs store, but that is done by
/*
					 snapshot->eof - snapshot->buf);
 *      probably not peeled even if they could have been, but if we find
	 *   (i.e., after the header line, if one is present)
					   const char *p, size_t len)
		}
	return 0;

	 * If the `packed-refs` file was already sorted, `buf` points
	if (start == snapshot->eof)
 * + 1) bytes past the beginning of the record.
		refs->snapshot = NULL;
{
{
 * Write an entry to the packed-refs file for the specified refname.
	 * Note that `get_snapshot()` internally checks whether the
		;

	 * What is the peeled state of the `packed-refs` file that
 * Find the place in `snapshot->buf` where the start of the record for
	for (i = 0; i < transaction->nr; i++) {

{
 * This value is set in `base.flags` if the peeled value of the
	if (!is_lock_file_locked(&refs->lock))
 * exist, then return NULL. If `mustexist` is false and the reference
	/*
struct snapshot {
			die_invalid_line(refs->path,

	clear_snapshot(refs);

{
{
	 * heap-allocated memory containing the contents, sorted. If
				goto error;
					       peel_error ? NULL : &peeled))
	 * The transaction isn't checking any old values nor is it
	 * comparison. A "record" here is one line for the reference
	const char *eof = snapshot->eof;
	 * Now make sure that the packed-refs file as it exists in the

	if (*(eof - 1) != '\n' || eof - last_line < the_hash_algo->hexsz + 2)

		/* Stop iteration after we've gone *past* prefix: */
		transaction->backend_data = NULL;
void packed_refs_unlock(struct ref_store *ref_store)

		return 1;

		release_snapshot(snapshot);

		} else {
	int fd;
 * if the `packed-refs` file was not sorted, this might point at heap
 * inserted, or `snapshot->eof` (which might be NULL) if it would be
	ALLOC_GROW(records, len / 80 + 20, alloc);
			       const char *refname, int force_create,
			else
/*
	 * `old_id`. Even if that ever changes, false positives only
	} else {
		if (ref_transaction_delete(transaction, item->string, NULL,
	refs = packed_downcast(ref_store, required_flags, "ref_iterator_begin");
static enum mmap_strategy mmap_strategy = MMAP_NONE;
	 * `update-ref -d` is called and at the same time another
			if (write_packed_entry(out, update->refname,
			/* Have to set a new value -> needed. */
	 * `packed-refs` file contains a value for that reference.
	MMAP_TEMPORARY,
						    "is at %s but expected %s",
#include "../iterator.h"
				reflog_expiry_cleanup_fn cleanup_fn,
	if (hold_lock_file_for_update_timeout(
	}
 * `packed_ref_store`. Its freshness is checked whenever
	 *    old value here and skip the update if it agrees. If it
	new_buffer = xmalloc(len);
}
	 * will not be freed as long as the reference count is
};
	(void)refs; /* We need the check above, but don't use the variable */
 */
 * file. It implements the `ref_store` interface, though it has some
 * if not, sort it into new memory and munmap/free the old storage.
		if (!refs_read_raw_ref(ref_store, update->refname,

 * references.
 *   `sorted`:
#include "packed-backend.h"
}
	} else {
	} else {
		tmp = xmemdupz(snapshot->buf, eol - snapshot->buf);
static int next_record(struct packed_ref_iterator *iter)
	 * effect of ensuring that all of the references are peeled or
 * tempfile, incorporating any changes from `updates`. `updates` must
						const char *caller)
 * Decrease the reference count of `*snapshot`. If it goes to zero,
static int packed_create_symref(struct ref_store *ref_store,


	}
	}
static int packed_ref_iterator_advance(struct ref_iterator *ref_iterator)
{

			    flags, timeout_value) < 0) {
		BUG("packed_refs_unlock() called when not locked");
	 * There is a stat-validity problem might cause `update-ref -d`
	 *
	char *packed_refs_path;
		if (*r1 != *r2)
		struct ref_update *update = transaction->updates[i];

		eol++;
			 */

		 * we suppress it if the reference is broken:
		(struct packed_ref_iterator *)ref_iterator;
		 * definitely know the value of *this* reference. But
}
			 * needed.

		if (refnames->nr == 1)
	iter->flags = flags;
		strbuf_addf(err, "error replacing %s: %s",
	return ref_transaction_commit(transaction, err);
static int load_contents(struct snapshot *snapshot)
	 */
			/*


	transaction->state = REF_TRANSACTION_PREPARED;
static int packed_delete_refs(struct ref_store *ref_store, const char *msg,
}
	const char *lo = snapshot->start;
			ref_store,
	struct packed_ref_store *refs = xcalloc(1, sizeof(*refs));
		} else {
	struct packed_ref_store *refs = packed_downcast(

	 * A back-pointer to the packed_ref_store with which this
 * count goes to zero.
}
 *
	for (i = 0; i < transaction->nr; i++) {
	 * reference name comes *after* `refname`.
 * current reference is known. In that case, `peeled` contains the
	 *    reference.
 *
		struct object_id oid;
		clear_snapshot(refs);
	}
		return snapshot;
	}

 *      (i.e., "peeled" is a no-op if "fully-peeled" is set).

	 * Start with the cheap checks that don't require old
 * `packed-refs` file at the time the snapshot was created. However,
	struct packed_ref_iterator *iter =
 * the snapshot's reference count on behalf of the caller.
				 */
		data->own_lock = 1;
	unsigned int referrers;
	 * `pack-refs --all` process is running.
/*
	struct packed_ref_store *refs;
}
	int ret = TRANSACTION_GENERIC_ERROR;
		die("unterminated line in %s: %.*s", path, (int)len, p);
			goto failure;

	 */

};
	 * this snapshot represents? (This is usually determined from
	 */
	 * is needed if any of the updates is a delete, and the old
	if (prefix && *prefix)

	/*
					      snapshot->buf,
}
					    oid_to_hex(&update->old_oid));
	refs->tempfile = create_tempfile(sb.buf);
		strbuf_addf(err, "unable to create file %s: %s",
		oidclr(&iter->peeled);
		ok = ITER_ERROR;
	else if (eol - p < 80)
			eol = memchr(peeled_start, '\n', eof - peeled_start);
 * by the failing call to `fprintf()`.
		die_unterminated_line(iter->snapshot->refs->path,
			    const char *oldrefname, const char *newrefname,
	/*
{
	strbuf_reset(&iter->refname_buf);

struct packed_ref_store {
						    oid_to_hex(iter->oid),
 * be sorted.
}
};
					   const char *refname, int mustexist)

	 * This could happen with a very small chance when

	snapshot->refs = refs;
	 */
		eol = memchr(pos, '\n', eof - pos);
				goto write_error;
/*
		snapshot->buf = xmalloc(size);
		strbuf_addf(err, "unable to fdopen packed-refs tempfile: %s",
 * inserted at the end of the file. In the latter mode, `refname`
	packed_ref_store_create,
}
	struct packed_ref_store *refs;
	 */
	if (!(flags & DO_FOR_EACH_INCLUDE_BROKEN))


	 */

 */
		}
	    !stat_validity_check(&refs->snapshot->validity, refs->path))
	if (len < 80)
 *
		sort_snapshot(snapshot);
	char *buf, *start, *eof;
	snapshot->referrers++;
		struct ref_store *ref_store,
			 * necessary:
	if (fstat(fd, &st) < 0)

	return 0;

	/*
	 * 1. It could be that the old value is being verified without
			else
		struct ref_update *update = NULL;

	 */
 * Check that `refs->snapshot` (if present) still reflects the
			 * anything).
		/*
		return -1;
}
			 */

			die_invalid_line(iter->snapshot->refs->path,
	get_snapshot(refs);

	 * Temporary file used when rewriting new contents to the
	/*
			sorted = 0;
		 * forced to make a copy now:
}
			 * reference:
	ref_transaction_free(transaction);

/*
			ref_store,
	free(packed_refs_path);
		eol = memchr(snapshot->buf, '\n',
	struct string_list_item *item;
			 * This reference isn't being deleted -> not
{
 * `get_snapshot()` is called; if the existing snapshot is obsolete, a
			 */
	transaction->state = REF_TRANSACTION_CLOSED;
#include "refs-internal.h"
	return 0;
	iter->pos = start;
 * Return a pointer to the start of the record that contains the
	/*
{
		start = find_reference_location(snapshot, prefix, 0);
	while (lo != hi) {
			REF_STORE_READ | REF_STORE_WRITE | REF_STORE_ODB,
			}
		if (!skip_prefix(tmp, "# pack-refs with:", (const char **)&p))
	}
		struct snapshot *snapshot = refs->snapshot;
		close(fd);
	if (!sorted) {
 * error, return a nonzero value and leave errno set at the value left
			"ref_transaction_abort");

		iter->base.flags |= REF_BAD_NAME | REF_ISBROKEN;
}

cleanup:
 *
	/*
 * respect for whether the record is actually required by the current
 * A `ref_store` representing references stored in a `packed-refs`
	if (start == eof)
	clear_snapshot_buffer(snapshot);
	    (iter->snapshot->peeled == PEELED_TAGS &&
 */
				return (unsigned char)*r1 < (unsigned char)*r2 ? -1 : +1;
	packed_transaction_cleanup(refs, transaction);
	struct strbuf err = STRBUF_INIT;
 * Guarantee that minimum level of safety by verifying that the last

	const char *r2 = e2->start + the_hash_algo->hexsz + 1;
	 * ensuring that the `packed-refs` file is sorted. If the

	 * lost the newly commit of a ref, because a new `packed-refs`
		timeout_configured = 1;
 */
	packed_transaction_finish,
	 * We're only going to bother returning false for the common,

	 */
		return -1;
					   &records[nr - 1]) >= 0)
				 iter->pos, iter->eof - iter->pos);
 */
		snapshot->mmapped = 0;
			strbuf_reset(&err);
		if (eol < eof && *eol == '^') {
	return p;
	int sorted = 1;
};
/*

	 * individual updates can't fail, so we can pack all of the
			return 1;

 * doesn't have to be a proper reference name; for example, one could
{
		int cmp;

	packed_init_db,
	free(records);
		if ((iter->base.flags & REF_ISBROKEN)) {
static void validate_snapshot(struct packed_ref_store *refs)
	struct packed_ref_store *refs;
		goto failure;
			/* Have to check the old value -> needed. */
					 iter->pos, iter->eof - iter->pos);
{
	size = xsize_t(st.st_size);
};
	 */
}
			"packed_refs_unlock");
	 */
		 * Reordering the records might have moved a short one
		struct ref_update *update = transaction->updates[i];
					    "reference is missing but expected %s",
		return -1;
 * Write the packed refs from the current snapshot to the packed-refs
		}
	 * reference values to be read:
	packed_transaction_cleanup(refs, transaction);

	base_ref_store_init(ref_store, &refs_be_packed);
		snapshot->buf = xmmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);


#include "../refs.h"
	return p;
}
	 * the new in the order indicated by `records` (not bothering
	len = eof - pos;
		snapshot->mmapped = 0;

			return *r2 == '\n' ? 0 : -1;
	if (!is_lock_file_locked(&refs->lock))
static int packed_init_db(struct ref_store *ref_store, struct strbuf *err)
 * support at least the flags specified in `required_flags`. `caller`
		 * safety again:
		r2++;
				cmp = strcmp(iter->refname, update->refname);
}
 * transaction is done and the new `packed-refs` file is activated.
/*
	 * symlinked-to file, not the symlink itself. Also, put the
	 * The contents of the `packed-refs` file:
	}
		if (cmp < 0) {
		} else if (cmp > 0) {

		oidcpy(peeled, &iter->peeled);
	last_line = find_start_of_record(start, eof - 1);
static int packed_transaction_finish(struct ref_store *ref_store,
				      struct strbuf *err)
	if (close_tempfile_gently(refs->tempfile)) {
	return 0;
		r1++;
		/*
};
#include "../config.h"
	}
				reflog_expiry_prepare_fn prepare_fn,
		const char *mid, *rec;
#elif defined(MMAP_PREVENTS_DELETE)
static int packed_copy_ref(struct ref_store *ref_store,
	/*

static enum mmap_strategy mmap_strategy = MMAP_OK;
			 * which is its state when initialized with
	return 1;
					       peel_error ? NULL : &peeled))
	*type = 0;
	packed_refs_path = get_locked_file_path(&refs->lock);
	 * because the only caller of this function passes to it a
	 * place:
	strbuf_release(&err);
		r2++;
		string_list_split_in_place(&traits, p, ' ', -1);
	 * This is not *quite* a garden-variety binary search, because
failure:
 * Move the iterator to the next record in the snapshot, without
				strbuf_addf(err, "cannot update ref '%s': "
					goto error;
			lo = find_end_of_record(mid, hi);
	verify_buffer_safe(snapshot);
};
	while (1) {
	 *    is identical to the current packed value of the
			ref_store,
/*
		string_list_clear(&data->updates, 0);
{
	chdir_notify_reparent("packed-refs", &refs->path);
 */
	 * The metadata of the `packed-refs` file from which this
 *

 * record in the file is LF-terminated, and that it has at least
		r1++;
	refs->store_flags = store_flags;
				 struct ref_transaction *transaction)
	/*

		if (!cmp) {
	} else {

			"ref_transaction_finish");
	 * old values are not being checked, and the old `packed-refs`
				"packed_refs_lock");
 * Return a pointer to the start of the record following the record
	packed_rename_ref,
			die_errno("couldn't read %s", snapshot->refs->path);
					      each_reflog_ent_fn fn,

struct packed_ref_iterator {
	if (check_refname_format(iter->base.refname, REFNAME_ALLOW_ONELEVEL)) {
			}
		}


	iter = xcalloc(1, sizeof(*iter));
	return ITER_OK;
			 * have already skipped it. So we're done with
	while (iter || i < updates->nr) {
			eol++;
				 * change anything. We're done with it.
 * If the buffer in `snapshot` is active, then either munmap the

	struct ref_store *ref_store = (struct ref_store *)refs;
	*type = REF_ISPACKED;

{
	acquire_snapshot(snapshot);


			if (!iter)
			       const char *refname, const char *target,
}
	 */
	 * theoretically be optimized away:
}
/*

		strbuf_release(&sb);
	const char *last_line;
	 * transaction that only includes `delete` updates with no
}
			       const char *logmsg)
 * correct peeled value for the reference, which might be `null_oid`
#include "../lockfile.h"
	 * thus the enclosing `packed_ref_store`) must not be freed.
		stat_validity_clear(&snapshot->validity);
	if (snapshot->buf < snapshot->eof && *snapshot->buf == '#') {
	 * the data we're searching is made up of records, and we

		if (*r1 == '\n')

 *      trait should typically be written alongside "peeled" for
		packed_downcast(ref_store, REF_STORE_WRITE, "delete_refs");
	if (fprintf(fh, "%s %s\n", oid_to_hex(oid), refname) < 0 ||
	struct packed_ref_iterator *iter =
	} else if ((iter->base.flags & (REF_ISBROKEN | REF_ISSYMREF))) {
	 * timestamp, file size and inode value, but has a changed
		die("unterminated line in %s: %.75s...", path, p);
	char *packed_refs_path;
/*

}
		    errno != ENOENT) {

	strbuf_release(&referent);
	struct packed_ref_store *refs =
			    get_tempfile_path(refs->tempfile),
		return ITER_OK;
	 * We iterate in parallel through the current list of refs and
			      const struct object_id *oid,

	 * file doesn't contain any of those reference(s). This gives
	 * list of refs is exhausted, set iter to NULL. When the list
		die_unterminated_line(path, p, len);
					 DO_FOR_EACH_INCLUDE_BROKEN);
	const char *start = snapshot->start;
		snapshot->buf = snapshot->start = buf_copy;


 * changed (according to its `validity` field) since it was last read.
	i = 0;
			}
	/*
	 * Lock used for the "packed-refs" file. Note that this (and
enum mmap_strategy {
				cmp = +1;


	if (!eol)
}
				}
			    sb.buf, strerror(errno));
	data = xcalloc(1, sizeof(*data));
	/* The path of the "packed-refs" file: */
 *      file for which no peeled value is recorded is not peelable. This

 * (GIT_SHA1_HEXSZ + 1) characters before the LF. Die if either of
	struct packed_ref_store *refs = packed_downcast(
			 * The update wants to delete the reference,

	 * Allocate a new chunk of memory, and copy the old memory to
struct packed_ref_store;
			return *r2 ? -1 : 0;

{
 * an instance from disappearing while an iterator is still iterating
				      each_reflog_ent_fn fn, void *cb_data)
	 * Can use mmap() for reading `packed-refs`, but the file must
	 * to be skipped. Now do the more expensive check: the update
 * - It cannot store symbolic references.
				      const char *p, size_t len)
static const char *find_end_of_record(const char *p, const char *end)
	else
		return -1;
{
			data->own_lock = 0;
		}
		(struct packed_ref_iterator *)ref_iterator;
 * - It does not support reference renaming (though it could).
						    update->refname,
{
				   struct object_id *peeled)
	 * cause an optimization to be missed; they do not affect
static int packed_rename_ref(struct ref_store *ref_store,
	 * there were no contents (e.g., because the file didn't
	ssize_t bytes_read;
	iter->snapshot = snapshot;
	return refs->snapshot;

				 * The update takes precedence. Skip
 * `acquire_snapshot()` and `release_snapshot()`). This is to prevent
 * pointers to NULL.

	const char *eof;
 *
 * search for "refs/replace/" to find the start of any replace
			return 0;
	/*
	}
struct packed_transaction_backend_data {
		clear_snapshot_buffer(snapshot);

					      snapshot->eof - snapshot->buf);
	/*
}
 *
		oidclr(&iter->oid);
 *   `peeled`:

static int packed_reflog_expire(struct ref_store *ref_store,
		return 0;
		BUG("unallowed operation (%s), requires %x, has %x\n",
				item->string, err.buf);
	return 0;

				 */
 */
	 * where you cannot rename a new version of a file onto a file
static NORETURN void die_invalid_line(const char *path,
	 * - eof -- a pointer just past the end of the reference
	snapshot->start = snapshot->buf;
	if (pos == eof)
	return snapshot;
	 * Note that we close the lockfile immediately because we
	 *    setting a new value. In this case, we could verify the
		if (is_tempfile_active(refs->tempfile))
				cmp = -1;
					    iter->flags))
{
/*

	const char *rec;

	 *    error to *our* caller.
		mid = lo + (hi - lo) / 2;
	/*
	strbuf_add(&iter->refname_buf, p, eol - p);
			ref_store,
		free(snapshot->buf);
 * The packfile must be locked before calling this function and will
		if (cmp < 0) {
	 * staging file next to it:
static int packed_for_each_reflog_ent(struct ref_store *ref_store,
	while ((ok = next_record(iter)) == ITER_OK) {
				} else if (!oideq(&update->old_oid, iter->oid)) {
		if (!eol)
	return ref_store;
	}
 * the colon and the trailing space are required.
	}

		die_invalid_line(snapshot->refs->path,
	 *    (the actual commit would re-detect and report the
	if (!is_lock_file_locked(&refs->lock)) {
	/*
	struct packed_ref_store *refs = packed_downcast(
	int ok = ITER_DONE;
	 * So what need to do is clear the snapshot if we hold it
	QSORT(records, nr, cmp_packed_ref_records);
static void verify_buffer_safe(struct snapshot *snapshot)
	packed_transaction_cleanup(refs, transaction);
 *      The references in this file are known to be sorted by refname.
	if (!rec) {
		size_t size = snapshot->eof - snapshot->start;
	int ok;


	/*
static int release_snapshot(struct snapshot *snapshot)
	}
	snapshot->buf = snapshot->start = new_buffer;
	stat_validity_update(&snapshot->validity, fd);
		goto cleanup;
			 */
		if (!refname_is_safe(iter->base.refname))
		verify_buffer_safe(snapshot);
	packed_reflog_iterator_begin,
static void clear_snapshot_buffer(struct snapshot *snapshot)
static int write_with_updates(struct packed_ref_store *refs,
	"# pack-refs with: peeled fully-peeled sorted \n";
	rec = find_reference_location(snapshot, refname, 1);
			/* Now figure out what to use for the new value: */
	struct packed_ref_store *refs = packed_downcast(
	struct packed_ref_store *refs =
			   const char *oldrefname, const char *newrefname,

	BUG("packed reference store does not support reflogs");
struct ref_storage_be refs_be_packed = {
 * character `*p` (which must be within the buffer). If no other

{
 * that contains `*p`. If none is found before `end`, return `end`.
 * the `packed-refs` file into the snapshot. Return 1 if the file
			      struct strbuf *err)
		iter->pos = p;
	struct snapshot_record *records = NULL;
static struct ref_iterator *packed_reflog_iterator_begin(struct ref_store *ref_store)
		/* perhaps other traits later as well */
}
	rollback_lock_file(&refs->lock);
	 * do so itself.
	 */
 *      compatibility with older clients, but we do not require it
		free(tmp);
 *

 */
					    update->refname,

	/*
			if (write_packed_entry(out, iter->refname,
	if (write_with_updates(refs, &data->updates, err))
		(struct packed_ref_iterator *)ref_iterator;
	 * snapshot was created, used to tell if the file has been

		 * to the end of the buffer, so verify the buffer's
#define REF_KNOWS_PEELED 0x40
 * populating it if it hasn't been read before or if the file has been
	    parse_oid_hex(p, &iter->oid, &p) ||
				return 1;
	transaction = ref_store_transaction_begin(ref_store, &err);
 *      peeled in this file. References outside of "refs/tags/" are

			packed_refs_unlock(&refs->base);
	packed_create_reflog,
	}
				if ((ok = ref_iterator_advance(iter)) != ITER_OK)
	 */
	snapshot->eof = snapshot->buf + size;
		return is_null_oid(&iter->peeled) ? -1 : 0;
	 * Now munmap the old buffer and use the sorted buffer in its
	if (!refs->snapshot)
	}
 * transaction. In that case, it remains locked even after the
						    "reference already exists",
			if (!eol)
		git_config_get_int("core.packedrefstimeout", &timeout_value);

	struct snapshot *snapshot;
					 snapshot->buf,
			REF_STORE_READ | REF_STORE_WRITE | REF_STORE_ODB,
						unsigned int required_flags,
static int packed_transaction_prepare(struct ref_store *ref_store,
		return NULL;
{
 */
	 * not remain mmapped. This is the usual option on Windows,
	iter->base.flags = REF_ISPACKED;
	delete_tempfile(&refs->tempfile);
	if (mustexist)
					iter = NULL;
 * But what if the `packed-refs` file contains garbage? We're willing
	 * preceding records all have reference names that come


	eol = memchr(p, '\n', iter->eof - p);
 * An iterator over a snapshot of a `packed-refs` file.
	packed_initial_transaction_commit,
 *      a peeled value for such a reference we will use it.
		if (!eol)
	packed_read_raw_ref,
 * totally garbled output (we can't afford to check the integrity of
			   const char *logmsg)
			REF_STORE_READ | REF_STORE_WRITE,
}

	struct strbuf referent = STRBUF_INIT;
 *
	 * false positives for some other cases that could
			      "error iterating over old contents");
 * Depending on `mmap_strategy`, either mmap or read the contents of
		return -1;

		validate_snapshot(refs);
	packed_transaction_abort,
		ALLOC_GROW(records, nr + 1, alloc);

	struct tempfile *tempfile;
		}



int is_packed_transaction_needed(struct ref_store *ref_store,


 * contents of the `packed-refs` file. If not, clear the snapshot.
	if (iter->eof - p < the_hash_algo->hexsz + 2 ||
	/* The end of the part of the buffer that will be iterated over: */

		required_flags |= REF_STORE_ODB;
	iter->pos = eol + 1;

	}
				      struct ref_transaction *transaction,
 */

					strbuf_addf(err, "cannot update ref '%s': "
 * looking for " trait " in the line. For this reason, the space after

	 *
		p--;
		    ref_store->be->name, caller);
		goto error;
	const struct snapshot_record *e1 = v1, *e2 = v2;
	}
static struct ref_iterator *packed_ref_iterator_begin(
	return ref_iterator;
	 * A pointer to the character at the start of a record whose

	}

	struct packed_transaction_backend_data *data;

	 * "packed-refs" file. Note that this (and thus the enclosing
	}
 */
		p = iter->pos + 1;
 *
	static int timeout_configured = 0;
 *      Inversely (and this is more important), any references in the
	if (fprintf(out, "%s", PACKED_REFS_HEADER) < 0)
	}
	if (ref_update_reject_duplicates(&data->updates, err))
	/* Scratch space for current values: */
	clear_snapshot(refs);
	 * file might has the same on-disk file attributes such as
		if (errno == ENOENT) {
	 * It is OK to leave the `packed-refs` file mmapped while



	if (iter)
				BUG("unterminated peeled line found in packed-refs");
static int packed_ref_iterator_abort(struct ref_iterator *ref_iterator)
	while (++p < end && (p[-1] != '\n' || p[0] == '^'))
static struct snapshot *create_snapshot(struct packed_ref_store *refs)
}
 * `refname` starts. If `mustexist` is true and the reference doesn't
		char *buf_copy = xmalloc(size);
			continue;
			       const char *refname)
	return ret;
		packed_downcast(ref_store, REF_STORE_READ, "read_raw_ref");
			REF_STORE_READ | REF_STORE_WRITE,
			const char *peeled_start = eol;
	 */
 */

						     &peeled);
{
	struct ref_iterator *iter = NULL;

static const char PACKED_REFS_HEADER[] =
		records[nr].len = eol - pos;
			error(_("could not delete references: %s"), err.buf);
		    cmp_packed_ref_records(&records[nr - 2],
		memcpy(buf_copy, snapshot->start, size);
 *
	 * the file's header.)

}
	 *    problem), or come up with a way of reporting such an
			 * "packed-refs" file has been written yet,
			    refs->path,
	 * replaced since we read it.

		    nr > 1 &&
 * remain locked when it is done.

		if (sorted &&

		die("unexpected line in %s: %.*s", path, (int)(eol - p), p);

		free(snapshot);
	if (!is_lock_file_locked(&refs->lock))
}
	else
	return ok;
 * We want to be able to compare mmapped reference records quickly,

	release_snapshot(iter->snapshot);
 *      peeled value for a reference, we will use it.
	BUG("packed reference store does not support renaming references");
}


	 */


		} else {
{
			     struct string_list *refnames, unsigned int flags)
	size_t i;
 * records sorted by refname.


			continue;

 */
	if (!transaction)
	return 0;
	 * locked state is loaded into the snapshot:
	 * the list of updates, processing an entry from at least one
			die_errno("couldn't read %s", snapshot->refs->path);
					    struct strbuf *err)
	 *
	/*


	int ret;
				/*
	if (close_lock_file_gently(&refs->lock)) {
#endif
 */
static int cmp_record_to_refname(const char *rec, const char *refname)
	size_t len, i;
			hi = rec;
	 * if it might still be current; otherwise, NULL.

	struct stat_validity validity;
			warning(_("could not delete reference %s: %s"),
	}
 * The packed-refs header line that we write out. Perhaps other traits
{
			       struct strbuf *referent, unsigned int *type)
{
 * A comment line of the form "# pack-refs with: " may contain zero or
	return ret;
				unsigned int flags,
static int write_packed_entry(FILE *fh, const char *refname,
/*
{
	 */
	 * Count of references to this instance, including the pointer
		unsigned int type;
			 * -> this transaction is needed.
		if (packed_refs_lock(ref_store, 0, err))

			int peel_error = ref_iterator_peel(iter, &peeled);
		return empty_ref_iterator_begin();
	return 0;


		} else {
	if (data) {
	/*
		if (bytes_read < 0 || bytes_read != size)
	/*

	refs->path = xstrdup(path);
	acquire_snapshot(snapshot);
}
			snapshot->peeled = PEELED_FULLY;
		goto failure;
{
	int ret = TRANSACTION_GENERIC_ERROR;
		records[nr].start = pos;


/*
		}

	 *
				 * value.
{
				 * The update doesn't actually want to

cleanup:
 * these checks fails.
 * iteration. Adjust the fields in `iter` and return `ITER_OK` or
	 * A snapshot of the values read from the `packed-refs` file,
					strbuf_addf(err, "cannot update ref '%s': "
			REF_STORE_READ,
			    strerror(errno));
 */
	refs = (struct packed_ref_store *)ref_store;
