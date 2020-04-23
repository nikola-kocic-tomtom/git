{
	}


			 */
	struct diff_queue_struct outq;
				 * Also we do not want to break very
					  * reusing one and two here.
	 * rename/copy can pick the pieces up to match with other
}

				/* deletion of one */
	 */
	 * according to the former definition.
	 * int break_score; we reuse incoming parameter for this.
	if (max_size < MINIMUM_BREAK_SIZE)
				struct diff_filespec *null_one, *null_two;
	 * We will be one extra user of the same src side of the
	*q = outq;
	 * or 0 if we do not.
			/* we already merged this with its peer */
	dp = diff_queue(outq, d->one, c->two);
		 * We do not break anything else.

{
	/*
	 * back together.  The break operation itself happens
	 * files.
				 * small files.
				struct diff_filepair *dp;
	if (diff_populate_filespec(r, src, 0) ||
	struct diff_queue_struct outq;
	for (i = 0; i < q->nr; i++) {
{
			 * we merge them back together.
	d->one->rename_used++;
	 * insert into account at all.  If you start from a 100-line

		struct diff_filepair *p = q->queue[i];
				dp->broken_pair = 1;
	if (DIFF_FILE_VALID(d->two))
				}

	if (DIFF_FILE_VALID(p->one)) {
	 * add 27 lines to it to make a new 30-line file or if you add
			 */
			/* The peer did not survive, so we keep

	*merge_score_p = (int)(src_removed * MAX_SCORE / src->size);
	/* sanity */
	free(q->queue);
	 * paths elsewhere.  Increment to mark that the path stays
		/* this must be a delete half */
				 */
			}
					q->queue[j] = NULL;

			     * is the default.
	 * from the source material".  The clean-up stage will
	/* Compute merge-score, which is "how much is removed
			struct diff_filespec *src,
		d = p; c = pp;

	 * file and delete 97 lines of it, it does not matter if you
				    !strcmp(p->one->path, pp->two->path)) {
	    (literal_added * 20 < src_copied))
	int i, j;
				free(p); /* not diff_free_filepair(), we are
				/* Split this into delete and create */
			diff_q(&outq, p);
			for (j = i + 1; j < q->nr; j++) {
	 * complete rewrite, and if sizable chunk from the original
				struct diff_filepair *pp = q->queue[j];
		die("internal error in merge #4");
	 * 997 lines to it to make a 1000-line file.  Either way what
	DIFF_QUEUE_CLEAR(&outq);
}
	 * The value we return is 1 if we want the pair to be broken,
		/*
	}
	 * purposes of helping later rename/copy, we take both delete
	/* When the filepair has this much edit (insert and delete),
		else if (p->broken_pair &&
		    !strcmp(p->one->path, p->two->path)) {
	 */
	return;
					score = 0;
next:;
	*q = outq;
	 */
			struct diff_filespec *dst,
			diff_q(&outq, p);

		diff_free_filespec_data(p->two);


		diff_q(&outq, p);
				dp->score = score;
	 * subjected to rename/copy, both of them may survive intact,
	 * If the edit is very large, we break this pair so that
		return 0; /* they are the same */
	 * due to lack of suitable rename/copy peer.  Or, the caller
	 *
	 * Either way you did a lot of additions and not a rewrite.
	 * you add 903 lines to it to make a new 1000-line file.
		*merge_score_p = (int)MAX_SCORE;
	 *
		return 0; /* error but caught downstream */
#include "diff.h"
				 * should they survive rename/copy.
		int score;
	if (src->size < src_copied)
			literal_added = 0;
	/* Extent of damage, which counts both inserts and
	free(q->queue);
		return 0; /* we do not break too small filepair */
					/* Peer survived.  Merge them */
	 * of delete and create?
		return 0;
	if (DIFF_FILE_VALID(c->one))
			 struct diff_queue_struct *outq)
static int should_break(struct repository *r,
	 * moving contents from another file, so that rename/copy can
		return 0;
			int *merge_score_p)
				if (score < merge_score)
	    diff_populate_filespec(r, dst, 0))
	 * On the other hand, we would want to ignore inserts for the
	dp->score = p->score;
	 * The score we leave for such a broken filepair uses the
		}
 * Copyright (C) 2005 Junio C Hamano

}
	diff_free_filespec_data(d->two);
		return 0;
	}
	if (!break_score)
	 * This merge happens to catch the latter case.  A merge_score
					merge_broken(p, pp, &outq);
	    oideq(&src->oid, &dst->oid))
		die("internal error in merge #2");
	 * broken pair that have a score lower than given criteria
	 * less than the minimum, after rename/copy runs.
				   &src->cnt_data, &dst->cnt_data,
				dp = diff_queue(&outq, null_two, p->two);
	 */
	 * together).
 */
				/* Set score to 0 for the pair that



	 * broken pair, if it was used as the rename source for other

void diffcore_merge_broken(void)
	 * modification together if the pair did not have more than
	if (!merge_score)
	 * latter definition so that later clean-up stage can find the

			int break_score,
	 * deletes.
		 * We deal only with in-place edit of blobs.
	 * create and delete filepair.  This is to help breaking a
	/* p and pp are broken pairs we want to merge */
		return 0; /* we do not let empty files get renamed */
	 * match it with the other file.
	if (!DIFF_FILE_VALID(d->one))
		struct diff_filepair *p = q->queue[i];
	free(d);
	struct diff_filepair *c = p, *d = pp, *dp;
	if (dst->size < literal_added + src_copied) {
				continue;

	 * existing contents were removed from the file, it is a
	 * file that had too much new stuff added, possibly from
	 * you did was a rewrite of 97%.  On the other hand, if you
		if (!p)
		die("internal error in merge #3");
		    object_type(p->one->mode) == OBJ_BLOB &&
	 *
	*merge_score_p = 0; /* assume no deletion --- "do not break"
			literal_added = dst->size - src_copied;
	if (*merge_score_p > break_score)
					 break_score, &score)) {
void diffcore_break(struct repository *r, int break_score)
	 * pieces that should not have been broken according to the
		merge_score = DEFAULT_MERGE_SCORE;
	}
	 * may be calling us without using rename/copy.  When that
			 !strcmp(p->one->path, p->two->path)) {
	unsigned long src_copied, literal_added, src_removed;
		diff_free_filespec_data(p->one);
		}
	 * not matter how much or how little new material is added to
				diff_free_filespec_blob(p->two);
	merge_score = (break_score >> 16) & 0xFFFF;
				/* creation of two */
	 * of 80% would be a good default value (a broken pair that
			     */
	int merge_score;
	 *
		return 1;

	 * when we return.

	if (S_ISREG(src->mode) != S_ISREG(dst->mode)) {
#include "cache.h"
	/* See comment on DEFAULT_BREAK_SCORE and
	 * it is first considered to be a rewrite and broken into a
	if (!DIFF_FILE_VALID(c->two))
	DIFF_QUEUE_CLEAR(&outq);
			}
			 * it in the output.
				dp->broken_pair = 1;
				diff_free_filespec_blob(p->one);
	/* If you removed a lot without adding new material, that is
	}
				 * needs to be merged back together
	 *
	 */
	/* After a pair is broken according to break_score and
}
		    object_type(p->two->mode) == OBJ_BLOB &&
		return 1; /* even their types are different */
	 */
	unsigned long delta_size, max_size;
	/* Sanity check */
	 * still remains in the result, it is not a rewrite.  It does
	if (src->oid_valid && dst->oid_valid &&


	return 1;
		else
				if (pp->broken_pair &&

	 * the file.
	if (diffcore_count_changes(r, src, dst,
				dp->score = score;

				null_two = alloc_filespec(p->two->path);
	struct diff_queue_struct *q = &diff_queued_diff;
	 */
	 * merge the surviving pair together if the score is
	if (!src->size)
					  */
				    !strcmp(pp->one->path, pp->two->path) &&
	 * different that we are better off recording this as a pair
		 */

	 * There are two criteria used in this algorithm.  For the

	struct diff_queue_struct *q = &diff_queued_diff;
			continue;
static void merge_broken(struct diff_filepair *p,

	break_score = (break_score & 0xFFFF);
	 * pair).  We leave the amount of deletion in *merge_score_p
					goto next;
	max_size = ((src->size > dst->size) ? src->size : dst->size);
	 * latter definition after rename/copy runs, and merge the

	src_removed = src->size - src_copied;
				null_one = alloc_filespec(p->one->path);
	if ((src->size * break_score < src_removed * MAX_SCORE) &&
				   &src_copied, &literal_added))
	 * amount of "edit" required for us to consider breaking the
	 * if you add 3 lines to it to make a new 100-line file or if
	if (delta_size * MAX_SCORE / max_size < break_score)
	int i;
	 * delete 3 lines, keeping 97 lines intact, it does not matter

		src_copied = src->size;
	 *
	diff_free_filespec_data(c->one);
	 * DEFAULT_MERGE_SCORE in diffcore.h
		if (src_copied < dst->size)
	for (i = 0; i < q->nr; i++) {
	/* dst is recorded as a modification of src.  Are they so
/*
#include "diffcore.h"

	 * this much delete.  For this computation, we do not take
			/* If the peer also survived rename/copy, then
	 * pure "complete rewrite" detection.  As long as most of the
	 * happens, we merge the broken pieces back into one
		break_score = DEFAULT_BREAK_SCORE;
	return;
		die("internal error in merge #1");
	 * not really a rewrite.
	    (literal_added * 20 < src_removed) &&
		else

	delta_size = src_removed + literal_added;
	 */
{
		if (DIFF_FILE_VALID(p->one) && DIFF_FILE_VALID(p->two) &&
	free(c);
				dp = diff_queue(&outq, p->one, null_one);
	 * and insert into account and estimate the amount of "edit".
			if (should_break(r, p->one, p->two,
	 * has score lower than merge_score will be merged back
			 struct diff_filepair *pp,
	 * The minimum_edit parameter tells us when to break (the
	 * in the resulting tree.
