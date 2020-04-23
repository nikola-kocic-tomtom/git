	free(mx);
	if (diffcore_count_changes(r, src, dst,
static int score_compare(const void *a_, const void *b_)
static int find_exact_renames(struct diff_options *options)
	if (!options->flags.find_copies_harder)
			 */
		dp->score = score;
		MOVE_ARRAY(rename_src + first + 1, rename_src + first,
		m = &mx[dst_cnt * NUM_CANDIDATE_PER_DST];
 cleanup:
			 *     broken create remains in the output; or
	dst = rename_dst[dst_index].two;
	const struct diff_score *a = a_, *b = b_;
	/* Are we running under -C -C? */
	/*
	hashmap_add(table, &entry->entry);
	/*
	for (i = 0; i < q->nr; i++) {
			 * by one, to indicate ourselves as a user
		if (c1 != c2)
static void insert_file_table(struct repository *r,
		else if (detect_rename == DIFF_DETECT_COPY) {
			 *     out of existence.
	}

				break;
	if (!dst->cnt_data &&
{
	if (!S_ISREG(src->mode) || !S_ISREG(dst->mode))
	 * what percentage of material in dst are from source?

	if (first < rename_dst_nr)
	int rename_limit = options->rename_limit;

			continue;
	default:
	int i, worst;
	stop_progress(&progress);
		if (!--i)
{

static unsigned int hash_filespec(struct repository *r,
	int num_create, dst_cnt;
				   &src->cnt_data, &dst->cnt_data,

		record_rename_pair(mx[i].dst, mx[i].src, mx[i].score);
{
	for (i = 1; i < NUM_CANDIDATE_PER_DST; i++)
 */
		for (j = 0; j < NUM_CANDIDATE_PER_DST; j++)
		rename_count += find_renames(mx, dst_cnt, minimum_score, 1);

		if (c1 == '/')
				(uint64_t)rename_dst_nr * (uint64_t)rename_src_nr);
	if ((num_create <= rename_limit || num_src <= rename_limit) &&
		int cmp = strcmp(two->path, dst->two->path);
			/*
			continue;
	 * only when they are exact matches --- in other words, no edits
	 * Note that base_size == 0 case is handled here already
		}
static void record_rename_pair(int dst_index, int src_index, int score)

	switch (too_many_rename_candidates(num_create, options)) {
			if (score == 2)
			continue; /* dealt with exact match already. */
	int first = find_rename_dst(two);
	if (!minimum_score)
/* Table of rename/copy destinations */
	if (minimum_score == MAX_SCORE)
	if (!src->cnt_data && diff_populate_filespec(r, src, 0))

	 */
	for (num_src = i = 0; i < rename_src_nr; i++) {
	/* is it better than the worst one? */
	last = rename_src_nr;
	    diff_populate_filespec(r, src, CHECK_SIZE_ONLY))
 * 1 if we need to disable inexact rename detection;

	struct diff_score *mx;
		if (!DIFF_FILE_VALID(p->one)) {
							     minimum_score);

		struct diff_filepair *p = q->queue[i];
		struct diff_rename_dst *dst;
				/* broken delete */
		struct diff_filespec *two = rename_dst[i].two;
			pair_to_free = p;
	unsigned int hash = hash_filespec(options->repo, target);
			struct diff_filespec *one = rename_src[j].p->one;
	int i;
	else if (b->dst < 0)
	/* find the worst one */
		renames += find_identical_files(&file_table, i, options);
	hashmap_for_each_entry_from(srcs, p, entry) {
			 * We do not need the text anymore.
	 * dst, and then some edit has been applied to dst.
				   &src_copied, &literal_added))
static int find_rename_dst(struct diff_filespec *two)
		    (mx[i].score < minimum_score))
	case 1:
			diff_free_filespec_blob(two);
		return b->name_score - a->name_score;
static struct diff_rename_src {

		free_filespec(rename_dst[i].two);
		return -1;
	}
	}
		if (source->rename_used && options->detect_rename != DIFF_DETECT_COPY)
	unsigned short score; /* to remember the break score */
				_("Performing inexact rename detection"),
		else if (!DIFF_PAIR_UNMERGED(p) && !DIFF_FILE_VALID(p->two)) {
			break;
			if (source->mode != target->mode)
			if (!DIFF_FILE_VALID(p->two))
	int i, j, rename_count, skip_unmodified = 0;
		return 0;

			       int minimum_score)
			if (dst && dst->pair) {

			else

			 *
	/* All done? */

{

	 * match than anything else; the destination does not even

	/* Add all sources to the hash table in reverse order, because
		}
{
		return 0;
/*
		return -1;
	struct diff_filespec *one = p->one;
	/*
			return src;
					pair_to_free = p;
}
			 */
			       struct diff_filespec *dst,
				  rename_src[i].p->one);
	if (!num_create)
		first = next+1;
	    diff_populate_filespec(r, dst, CHECK_SIZE_ONLY))
	num_create = (rename_dst_nr - rename_count);
	dst->count++;
	first = 0;
#include "diff.h"

		first = next+1;
			 */
	    ((uint64_t)num_create * (uint64_t)num_src
		char c2 = dst->path[--dst_len];
				 */
	 * call into this function in that case.
	hashmap_init(&file_table, NULL, NULL, rename_src_nr);
	for (i = 0; i < rename_dst_nr; i++)
				goto cleanup;


}


		m[worst] = *o;
			 * not been turned into a rename/copy already.
			register_rename_src(p);
		score += basename_same(source, target);
	first = 0;
		return 0;
	int renames = 0;
	for (i = 0; i < q->nr; i++) {
		count++;
	 * Compare them and return how similar they are, representing
	max_size = ((src->size > dst->size) ? src->size : dst->size);
	 * If we already have "cnt_data" filled in, we know it's

#include "progress.h"
	int first, last;
			if (skip_unmodified &&
		else if (!diff_unmodified_pair(p))
					struct file_similarity, entry);

	/* Would we bust the limit if we were running under -C? */
			 */
	 * This basically does a test for the rename matrix not
			this_src.name_score = basename_same(one, two);
			if (pair_to_free)
	struct diff_filespec *two;
 * Find exact renames first.
static int basename_same(struct diff_filespec *src, struct diff_filespec *dst)
			 * Increment the "rename_used" score by
		if (!cmp)
		if (cmp < 0) {
struct diff_score {

	}
			 */
			last = next;
				continue;
	delta_size = max_size - base_size;
	struct diff_filespec *src, *dst;
	base_size = ((src->size < dst->size) ? src->size : dst->size);
	while (src_len && dst_len) {
 */
			worst = i;
	int src_len = strlen(src->path), dst_len = strlen(dst->path);
	/* Free the hash data structure and entries */
}
			}
				diff_q(&outq, p);
			continue;
		progress = start_delayed_progress(

		if (!cmp)
	if (max_size * (MAX_SCORE-minimum_score) < delta_size * MAX_SCORE)
	if (!strcmp(src->path, dst->path))
	int minimum_score = options->rename_score;
			this_src.src = j;

/* Table of rename/copy src files */
			diff_q(&outq, p);
	while (last > first) {
		hash_object_file(r->hash_algo, filespec->data, filespec->size,
	entry->filespec = filespec;
	for (dst_cnt = i = 0; i < rename_dst_nr; i++) {
	}
	struct diff_filespec *filespec;
 *

};

	 * are recorded in rename_dst.  The original list is still in *q.
static int estimate_similarity(struct repository *r,
	 */
	 * all good (avoid checking the size for zero, as that
			 * (2) this is not a broken delete, and rename_dst

			       struct diff_filespec *src,
	return score;
	/* At this point, we have found some renames and copies and they
	 *    num_create * num_src > rename_limit * rename_limit
	FREE_AND_NULL(rename_src);

	case 2:
				  struct diff_filespec *filespec)
	if (first >= 0)
		dp->score = rename_src[src_index].score;
		return 2;
			 *
	 * Calculate how many renames are left (but all the source
}

		goto cleanup;
	 * files still remain as options for rename/copies!)
}
		return 0;
			this_src.score = estimate_similarity(options->repo,
	if (best) {
	hashmap_entry_init(&entry->entry, hash_filespec(r, filespec));
		char c1 = src->path[--src_len];
	     <= (uint64_t)rename_limit * (uint64_t)rename_limit))
			 * delete did not have a matching create to
	 * is a possible size - we really should have a flag to
	return 0;

				continue; /* unmerged */
	int dst; /* index in rename_dst */
		return 0;
	    ((uint64_t)num_create * (uint64_t)num_src
	}
	first = -first - 1;
		break;
			record_if_better(m, &this_src);
static int too_many_rename_candidates(int num_create,
	int src; /* index in rename_src */
				 "blob", &filespec->oid);
	if (!src->cnt_data &&
	if (options->show_rename_progress) {

	diff_debug_queue("done copying original", &outq);
{
 * Copyright (C) 2005 Junio C Hamano
		goto cleanup;
				continue;
				pair_to_free = p;
				p->one->rename_used++;

#include "object-store.h"

		/* Give higher scores to sources that haven't been used already */
		options->degraded_cc_to_c = 1;
	 */
		struct diff_rename_dst *dst = &(rename_dst[next]);
	rename_count += find_renames(mx, dst_cnt, minimum_score, 0);
	struct file_similarity *entry = xmalloc(sizeof(*entry));

	return oidhash(&filespec->oid);

	dp->renamed_pair = 1;
	return renames;
			    diff_unmodified_pair(rename_src[j].p))
	struct hashmap file_table;
		minimum_score = DEFAULT_RENAME_SCORE;
	if (detect_rename == DIFF_DETECT_COPY)
				if (p->one->rename_used)
} *rename_dst;
}
	/* We would not consider edits that change the file size so
	diff_debug_queue("done collapsing", q);
		goto cleanup; /* nothing to do */
	else
		}
	if (rename_dst_nr == 0 || rename_src_nr == 0)
	if (rename_limit <= 0)
 * Returns 0 on success, -1 if we found a duplicate.

}

			/* all the usual ones need to be kept */
			 * We would output this create record if it has

			diff_free_filespec_blob(one);

	 */
	rename_dst[dst_index].pair = dp;
		return 0;
static int rename_dst_nr, rename_dst_alloc;
			p->one->rename_used++;
			 * Once we run estimate_similarity,
	}
 * order (the most similar first).
		for (j = 0; j < rename_src_nr; j++) {

	 * (MAX_SCORE-minimum_score)/MAX_SCORE * min(src->size, dst->size).

	entry->index = index;
			 * (1) this is a broken delete and the counterpart

				int dst_index,
{
}
		}
				diff_q(&outq, p);
	DIFF_QUEUE_CLEAR(&outq);
	if (score_compare(&m[worst], o) > 0)
					" duplicate destination '%s'",
	return (!src_len || src->path[src_len - 1] == '/') &&

		/* False hash collision? */
	 * and the final score computation below would not have a

			best = p;
		struct diff_score *m;
{
			 * one, to indicate ourselves as a user.

	 * We really want to cull the candidates list early
		int cmp = strcmp(one->path, src->p->one->path);
	}
/*
		if (pair_to_free)
		return (0 <= b->dst);

			   rename_dst_nr - first - 1);

			struct diff_score this_src;
		else
	return 1;
	if (first < rename_src_nr)
		int score;
	return count;
		struct diff_filepair *pair_to_free = NULL;
static int rename_src_nr, rename_src_alloc;
	 * drastically.  delta_size must be smaller than
	rename_src_nr = rename_src_alloc = 0;
	if ((num_create <= rename_limit || num_src <= rename_limit) &&
/*
		renames++;
	/* Walk the destinations and find best source match */
					p->two->path);

			struct diff_rename_dst *dst = locate_rename_dst(p->two);
		record_rename_pair(dst_index, best->index, MAX_SCORE);
	FREE_AND_NULL(rename_dst);
			 * If the source is a broken "delete", and
static struct diff_rename_dst {
	return b->score - a->score;

		/* Non-regular files? If so, the modes must match! */
		else if (!DIFF_FILE_VALID(p->one) && DIFF_FILE_VALID(p->two)) {
			      struct diff_filespec *filespec)
{
				continue; /* not interested */
		else if (!options->flags.rename_empty &&
			 is_empty_blob_oid(&p->one->oid))
			if (DIFF_PAIR_BROKEN(p)) {
static int find_identical_files(struct hashmap *srcs,
	struct hashmap_entry entry;

	 * after renaming.
	rename_src[first].score = score;
		if (!copies && rename_src[mx[i].src].p->one->rename_used)
			return next;
	unsigned short score = p->score;
	 */
			 * Deletion
			 * that means the source actually stays.
	 */
				if (dst && dst->pair)
	ALLOC_GROW(rename_dst, rename_dst_nr + 1, rename_dst_alloc);
		num_src++;
		break;
			/* no need to keep unmodified pairs */

	int detect_rename = options->detect_rename;
{
#include "cache.h"
	if (!filespec->oid_valid) {
	struct diff_queue_struct *q = &diff_queued_diff;
			continue;
	src->count++;
	return ofs < 0 ? NULL : &rename_dst[ofs];
	 *
	/* How similar are they?
	rename_count = find_exact_renames(options);
/*
	if (rename_dst[dst_index].pair)
	/* insert to make it at "first" */
}
}
			return 0;
	int score;
			best_score = score;
	if (!dst->cnt_data && diff_populate_filespec(r, dst, 0))

	/* sink the unused ones to the bottom */
			 * they did not really want to get broken,
			continue;
 * 0 if we are under the limit;
		dst = &rename_dst[mx[i].dst];
				/* no matching rename/copy source, so
				  &file_table, i,
			 * Creation
			return 0;
	struct progress *progress = NULL;
	 *
		}
			/*
	options->needed_rename_limit = 0;
	unsigned long max_size, delta_size, base_size, src_copied, literal_added;
 * and then during the second round we try to match
	struct diff_filespec *target = rename_dst[dst_index].two;

		int next = first + ((last - first) >> 1);
				continue;
	return renames;
#include "diffcore.h"

	 */
		skip_unmodified = 1;
		struct diff_filepair *p = q->queue[i];

{
		else if (DIFF_FILE_VALID(p->one) && !DIFF_FILE_VALID(p->two)) {
			 * So we increment the "rename_used" score
			 * begin with.
			      struct hashmap *table, int index,
	 * the score as an integer between 0 and MAX_SCORE.
	int num_src = rename_src_nr;
	}
#define NUM_CANDIDATE_PER_DST 4
};
	if (a->dst < 0)

		return 0;
	 * case we want to say src is renamed to dst or src is copied into
	int i = 100, best_score = -1;
			}
		(!dst_len || dst->path[dst_len - 1] == '/');
		}
			diff_free_filepair(pair_to_free);

	struct diff_filepair *p;
		struct diff_filespec *source = p->filespec;
		if (rename_dst[i].pair)
	for (i = 0; i < dst_cnt * NUM_CANDIDATE_PER_DST; i++) {
			else if (!options->flags.rename_empty &&
		display_progress(progress, (uint64_t)(i+1)*(uint64_t)rename_src_nr);
			}
			else
		if (diff_unmodified_pair(rename_src[i].p))
				diff_q(&outq, dst->pair);
			}
		score = !source->rename_used;
	 *
	}
	 * Need to check that source and destination sizes are

		struct diff_rename_src *src = &(rename_src[next]);
		die("internal error: dst already matched.");

		dst_cnt++;
	for (i = 0; i < rename_dst_nr; i++)
			 * Otherwise, the counterpart broken create
		}
}
		/* Too many identical alternatives? Pick one */
		if (diff_populate_filespec(r, filespec, 0))
			else if (add_rename_dst(p->two) < 0) {
		insert_file_table(options->repo,
{
 * Returns:
	hashmap_free_entries(&file_table, struct file_similarity, entry);
	 * at a newly created file.  They may be quite similar, in which
		goto cleanup;
	/*

/*
					/* counterpart is now rename/copy */
}
	int index;
			continue;
		MOVE_ARRAY(rename_dst + first + 1, rename_dst + first,
			else if (options->single_follow &&

			else {
		}
	/* cost matrix sorted by most to least similar pair */
 */

				struct diff_options *options)
	 * growing larger than a "rename_limit" square matrix, ie:
			this_src.dst = i;
	else
struct file_similarity {
			continue;
	struct diff_queue_struct outq;
	}
	free(q->queue);
	 * divide-by-zero issue.
}

	for (i = rename_src_nr-1; i >= 0; i--)
static struct diff_rename_dst *locate_rename_dst(struct diff_filespec *two)
{
 * We sort the rename similarity matrix with the score, in descending
			 * has been turned into a rename-edit; or
	/* insert to make it at "first" */
	rename_dst_nr++;
			 *
		      two->mode);
	unsigned short score;
	rename_dst[first].two = alloc_filespec(two->path);

		if ((mx[i].dst < 0) ||

				 strcmp(options->single_follow, p->two->path))
		}
	if (a->score == b->score)
	options->needed_rename_limit =
		score = (int)(src_copied * MAX_SCORE / max_size);
		if (score > best_score) {
	rename_src[first].p = p;
				 * record this as a creation.
		if (!oideq(&source->oid, &target->oid))
static struct diff_rename_src *register_rename_src(struct diff_filepair *p)
			/*

	int i, renames = 0;
			last = next;
		score = 0; /* should not happen */
		}
 * cache-dirty entries as well.
			continue; /* already done, either exact or fuzzy. */
		if (!S_ISREG(source->mode) || !S_ISREG(target->mode)) {
	if (!dst->size)
{
}
	*q = outq;
	rename_src_nr++;
			if (p->broken_pair && !p->score)
	/*
	 * When there is an exact match, it is considered a better
				struct diff_rename_dst *dst = locate_rename_dst(p->one);
					pair_to_free = p;
	 * say whether the size is valid or not!)
	last = rename_dst_nr;

		if (cmp < 0) {

{
	struct diff_filepair *dp;
	dp = diff_queue(NULL, src, dst);
		if (DIFF_PAIR_UNMERGED(p)) {
		rename_limit = 32767;
static int add_rename_dst(struct diff_filespec *two)
			   rename_src_nr - first - 1);
				 is_empty_blob_oid(&p->two->oid))

	rename_dst_nr = rename_dst_alloc = 0;
				warning("skipping rename detection, detected"
	 * optionally a file in the destination tree) and dst points

	p = hashmap_get_entry_from_hash(srcs, hash, NULL,
			/*

	     <= (uint64_t)rename_limit * (uint64_t)rename_limit))
	/* Did we only want exact renames? */


			m[j].dst = -1;
	 * filled in before comparing them.
		return 1;
	rename_dst[first].pair = NULL;
 * The first round matches up the up-to-date entries,
	while (last > first) {
	}
	 * later on they will be retrieved in LIFO order.
			 *
		if (score_compare(&m[i], &m[worst]) > 0)

static void record_if_better(struct diff_score m[], struct diff_score *o)
static int find_renames(struct diff_score *mx, int dst_cnt, int minimum_score, int copies)
	src = rename_src[src_index].p->one;
	mx = xcalloc(st_mult(NUM_CANDIDATE_PER_DST, num_create), sizeof(*mx));
			/*
		}
	return &(rename_src[first]);
	int first, last;
	struct file_similarity *p, *best = NULL;
	short name_score;
			 *     does not have a rename/copy to move p->one->path
 */
	 */
	 * with cheap tests in order to avoid doing deltas.
}
				      struct diff_options *options)

	STABLE_QSORT(mx, dst_cnt * NUM_CANDIDATE_PER_DST, score_compare);
	 */
			return 1;
} *rename_src;
 */
	fill_filespec(rename_dst[first].two, &two->oid, two->oid_valid,

	worst = 0;
 * 2 if we would be under the limit if we were given -C instead of -C -C.
							     one, two,
					/* this path remains */
	ALLOC_GROW(rename_src, rename_src_nr + 1, rename_src_alloc);
	return;
	struct diff_filepair *pair;
	 *
			diff_q(&outq, p);
	 */
	src->rename_used++;
	 * Find the best source match for specified destination.
	 *
	/* We deal only with regular files.  Symlink renames are handled
	return -first - 1;
			register_rename_src(p);
		num_src > num_create ? num_src : num_create;

	int ofs = find_rename_dst(two);
		int next = first + ((last - first) >> 1);

	}
}
		if (dst->pair)
		return 0;
	 */
				;
#include "hashmap.h"
			 * We would output this delete record if:
void diffcore_rename(struct diff_options *options)
	/* src points at a file that existed in the original tree (or
	int count = 0, i;
			break; /* there is no more usable pair. */
{
