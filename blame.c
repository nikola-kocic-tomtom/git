			}
	int i, *result, *second_best_result,
		     !(revs->max_age != -1 && commit->date < revs->max_age)))

			ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE);
	 * diff will occur, the currently blamed parts are all that we
				ent->suspect->refcnt);
	return commit_list_count(l);
	if (sb->reverse && sb->revs->first_parent_only) {
	/* Do we have HEAD? */
	commit->date = now;
		found_entry = hashmap_get_entry(&result->map, entry,
			line_blames[i].s_lno = target_idx;
	diff_setup_done(&diff_opts);
		}
	return similarities + line_a - closest_line_a +
			map_line_number_in_b_to_a);
{

			p = diff_queued_diff.queue[i];
 * To keep the length of each row the same, it is padded out with values of -1
		 */
	}
		struct blame_entry *next = head->next;
		}
			for (i = 0, sg = first_scapegoat(revs, commit, sb->reverse);
		 */
	}
			best_idx = fuzzy_matches[i];
	if (!reverse) {
}
static void verify_working_tree_path(struct repository *r,
	 * The actual relation is pretty unimportant as long as it

		/* Calculate the certainty with which this line matches.

	*source = NULL;
 * more complicated to allow performing it with integer operations.
			}
			max_search_distance_a) {
			if (!porigin)
		if (sb->debug) /* sanity */
 * 			 corresponds to the line at start_b.
			second_best_result + offset_b, result + offset_b,
void blame_sort_final(struct blame_scoreboard *sb)
 * \param line_end the end of the string
			e->s_lno = line_blames[i - entry_len + 1].s_lno;
	struct blame_line_tracker *line_blames = NULL;
	diff_opts.output_format = DIFF_FORMAT_NO_OUTPUT;
	 */
		    ent->ignored == next->ignored &&

	if (max_search_distance_a >= length_a)
	 * file_p partially may match that image.
 * the target line range. This is accomplished by matching fingerprints in each
		 * That list must be sorted before we queue_blames().  We defer
		default:
		if (fill_blob_sha1_and_mode(sb->repo, o))

		e = next;
		if (!get_tree_entry(r, commit_oid, path, &blob_oid, &mode) &&
		origin->suspects = toosmall;
			n->next = diffp;
 * in the parent we already tried.
				 - 1) / length_a;
	if (merge_head < 0) {
	const char *final_commit_name = NULL;
{
		else if (sb->copy_score < sb->move_score) {
	pos = index_name_pos(r->index, path, strlen(path));
	queue_blames(sb, porigin, suspects);
	 * fingerprint in A. This means that other lines in B can't also match
	if (is_null_oid(&sb->final->object.oid)) {
	d.dstq = &newdest; d.srcq = &target->suspects;

		 * after most-certain-line-B but are matched with a line in A

	return nl ? nl + 1 : end;
		     i < num_sg && sg;
	/*
			source = &p->next;
		 * We are often adjacent to the next line - only split the blame
		final_commit = find_single_final(sb->revs, NULL);
						  const void *b,
				return;
				return list1;
}
 * The main loop -- while we have blobs with lines whose true origin
		return; /* nothing remains for this target */
		/* ... and the middle part -- parent */
static void dup_entry(struct blame_entry ***queue,
		     sg = sg->next, i++) {
 *
	}

	int i;
static void handle_split(struct blame_scoreboard *sb,
			if (p == o) {
			} else {
			find_copy_in_blob(sb, e, parent, split, &file_p);
		     d->split);
 */
		split[0].s_lno = e->s_lno;
		sb->on_sanity_fail(sb, baa);
 *  bp, cp, dp, ep, -1,
	diff_opts.output_format = DIFF_FORMAT_NO_OUTPUT;
{
		 */
	 * certain line.
static void guess_line_blames(struct blame_origin *parent,
		return p1;
	int num = 0;
				       start_b,
	int pos;
	blame_origin_incref(src->suspect);
			most_certain_line_a + 1 - start_a,
			 * Preemptively drop porigin so we can refresh the

 * \param certainties array of values indicating how strongly a line in B is
}
}
	for (;;) {
		      const char *path,
	 */
	return ((struct blame_entry *)p1)->lno > ((struct blame_entry *)p2)->lno
		if (obj->type != OBJ_COMMIT)
		do_diff_cache(get_commit_tree_oid(parent), &diff_opts);
	if (!name)
	} else {
/*

			continue;
	 * that are no greater than max_search_distance_a lines away from the
			oidcpy(&porigin->blob_oid, &p->one->oid);
	o->commit = commit;
		add_blame_entry(unblamed, &split[2]);
 * of the strings that they represent.
	int chunk_end_lno;
		 * before most-certain-line-B but are matched with a line in A
			name = p->one->path ? p->one->path : p->two->path;
 * ordinary C program, and it is not worth to say it was copied from
	}
				struct blame_entry **toosmall,
	if (o->fingerprints) {
}
 * parent and return an origin structure to represent it.
	parent_tail = append_parent(r, parent_tail, &head_oid);
 * must use detach).
/* A byte pair in a fingerprint. Stores the number of times the byte pair

					continue;
		goto error_out;
			e->ignored = 1;
		if ((p->status == 'R' || p->status == 'C') &&
 * for an origin is also used to pass the blame for the entire file to
	 */
{
	struct blame_entry *ent;
			return;
			decref_split(split);

	origin->file.ptr = buf.buf;
		prio_queue_put(&sb->commits, porigin->commit);
		if (ignore_diffs) {
	int intersection = 0;
 * similar lines. The "certainty" is calculated based on those two
			fingerprints_a + second_half_start_a - start_a,
	struct fingerprint *fingerprints_b,
		for (i = 0; i < diff_queued_diff.nr; i++) {
 * e | q


		*srcq = &diffp->next;
static int prepare_lines(struct blame_scoreboard *sb)
	sb->num_lines = find_line_starts(&sb->lineno, sb->final_buf,
 * a row are the similarities between the line in B and the nearby lines in A.
	int sim, p_idx;

		free_fingerprint(&fingerprints[i]);
/* Distribute collected unsorted blames to the respected sorted lists
	 */
 * Example: if the chunk is 2 lines long in A and 10 lines long in B then the
}
		sb->final_buf = xmemdupz(o->file.ptr, o->file.size);
		porigin->file = origin->file;
		tail = append_parent(r, tail, &oid);
		if (sim < best_sim_val)
		     sg = sg->next, i++) {
	similarity_count = length_b * (max_search_distance_a * 2 + 1);
			     fingerprints_b + most_certain_local_line_b);
 *
 */
		die("No commit to dig up from?");
					  fingerprints_a + start_a,
				struct blame_entry **toosmall,
			      "", &diff_opts);
	/*
 * a | m
		 * lower case. This won't work for multibyte characters but at
	convert_to_git(r->index, path, buf.buf, buf.len, &buf, 0);
			      "", &diff_opts);
		    textconv_object(opt->repo, o->path, o->mode,
		copy_split_if_better(sb, split, potential);
		}
 *			 closest to local_line_b. This must be in the same
 */
		 * Since origin->path is a pathspec, if the parent
	for (pass = 0; pass < 2 - sb->no_whole_file_rename; pass++) {

			struct blame_origin *norigin;
			 */

		return;

}
						  parent_len);

			continue;
	repo_read_index(r);
 * sort according to the suspect line numbers as opposed to the final
	return;
	if (name_p)
		 * a line that matches very well with two lines over matching a
			suspect->guilty = 1;
							 &sb->final_buf_size);
					struct blame_origin *o)
			blame_origin_decref(e->suspect);

				 struct blame_entry *potential)
{
		if (*similarity > best_similarity) {
		    abs(best_sim_idx - t_idx) < abs(p_idx - t_idx))
	xpparam_t xpp = {0};
	if ((opt & PICKAXE_BLAME_COPY_HARDEST)
	cp = blame_nth_line(sb, e->lno);
		*dstq = &samep->next;
static struct blame_origin *find_origin(struct repository *r,
{
 * merge them together.
 * _current_ element.
	handle_split(d->sb, d->ent, d->tlno, d->plno, start_b, d->parent,
			die(_("--reverse --first-parent together require range along first-parent chain"));
{
};
			 */
		}
				blame_origin_decref(porigin);
	o->next = get_blame_suspects(commit);
	/*
			mode = S_IFREG | 0644;
		 * Note ignoredp is not sorted yet, and thus neither is dstq.
 * \param max_search_distance_a maximum distance in lines from the closest line
			break;
		/*
}
	const char *ident;
			if ((p1 = *tail) == NULL) {
		 * worst will match some unrelated characters.
	/* As we know the maximum number of entries in advance, it's
{
static int num_scapegoats(struct rev_info *revs, struct commit *commit, int reverse)
	       local_line_b * (max_search_distance_a * 2 + 1);
					  certainties,
			     struct blame_origin *o, mmfile_t *file,
	for (i = 0; i < revs->pending.nr; i++) {
 *
	/* We use the terminology "A" for the left hand side of the diff AKA
 * \param closest_line_a the index of the line in A that is deemed to be
	fill_origin_blob(&sb->revs->diffopt, parent, &file_p,
				BUG("not unique item in first-parent chain");

				sg_origin[i] = porigin;
 * diff chunk.  If that fails for a line, the second pass tries to match that
}
 * broken into two chunks by 'context.'
	memset(split, 0, sizeof(struct blame_entry [3]));
			   int closest_line_a, int max_search_distance_a)
	 * Now retain records on the target while parts are different

			 &sb->num_read_blob, ignore_diffs);
 * array contains the similarities for a line in B. The similarities stored in



	return make_origin(commit, path);
			blamed->next = suspects;
static int *fuzzy_find_matching_lines(struct blame_origin *parent,
	struct fingerprint *fingerprints_a,
	else if (split[0].suspect) {
		/* The last part -- me */
		porigin->suspects = blame_merge(porigin->suspects, sorted);
			length_a + start_a - second_half_start_a;
	}
 * image line numbers.  The function body is somewhat longish because
	 * max_search_distance_b is an upper bound on the greatest possible
				if (!origin->suspects)
			if (are_lines_adjacent(&line_blames[i],
			p = *source;
			     struct blame_origin *origin, struct blame_origin *porigin)
			small = &p->next;
				mark_parents_uninteresting(commit);
	for (i = 0; i < diff_queued_diff.nr; i++) {

				continue;
 * is still unknown, pick one blob, and allow its lines to pass blames

 */
		return p2;
	const char *end = buf + len;
		}
	blame_origin_incref(e->suspect);
 * fingerprint:
		setup_work_tree();
			certainties, second_best_result, result,
				   struct blame_origin *origin)
		return e->score;

 *	closest_line_a.
	const struct fingerprint_entry *entry_a, *entry_b;
			second_best_similarity = *similarity;
			die("Non commit %s?", revs->pending.objects[i].name);
 * The similarity between two fingerprints is the size of the intersection of
 * start and at the end of the difference region.  Since use of -M and

}

					  compare_blame_suspect);

		file->size = file_size;
	paths[1] = NULL;
	/* The hashmap entry - the hash represents the byte pair in its
		    "author %s\n"
	blame_chunk(&d.dstq, &d.srcq, INT_MAX, d.offset, INT_MAX, 0,
		    oid_to_hex(&parent->commit->object.oid),
		for (i = 0, sg = first_scapegoat(revs, commit, sb->reverse);
	if (invalidate_max > length_b)
					       const char *contents_from)
		}

		/*
}
	struct object_id head_oid;
					 struct blame_entry *tail)
			;
	for (i = 0; i < num_sg; i++) {
		 * examine the second part separately.
		newdest = llist_mergesort(newdest, get_next_blame,
			norigin = get_origin(parent, p->one->path);
	e = reverse_blame(diffp, e);
			       struct blame_origin *parent,
static struct commit *dwim_reverse_initial(struct rev_info *revs,
	int num_ents, i;
				fingerprints_b + local_line_b,
			 * that otherwise are equally similar.
}
		*get_similarity(similarities, most_certain_line_a - start_a,
			second_half_start_a, second_half_start_b,
 * look like this:
			porigin = get_origin(parent, p->one->path);
				fingerprints_a + i) *
	distribute_blame(sb, blames);
					  &map_line_number_in_b_to_a);
		struct blame_entry *next = NULL;
 * The lines in blame_entry after splitting blames many times can become
				hashmap_remove(&a->map, &entry_b->entry, NULL);
 * For debugging -- origin is refcounted, and this asserts that
static void distribute_blame(struct blame_scoreboard *sb, struct blame_entry *blamed)
	if (diffp)
		? 1 : -1;

{

		    ent->s_lno + ent->num_lines == next->s_lno &&
	o->fingerprints = xcalloc(sizeof(struct fingerprint), o->num_lines);
	if (search_start < 0)
			     i < num_sg && sg;
		split[2].s_lno = e->s_lno + (same - e->s_lno);
				  const char *content, const int *line_starts,
 * Append a new blame entry to a given output queue.
	struct fingerprint *fingerprints_a,

 *                              both be compared with the same line in A
}
{
static struct blame_origin *find_rename(struct repository *r,
		}
				       result,
static void fill_origin_fingerprints(struct blame_origin *o)
				  parent_len, line_blames);
	const struct line_number_mapping *map_line_number_in_b_to_a)
			second_best_similarity_index = i;
	dst->next = **queue;
			diffp = n;

#include "blame.h"
 * Returns a pointer to the link pointing to the old head of the small list.
	new_head->next = head;
	**queue = dst;
		else {
			die("unknown line in '%s': %s",
		    start_b + count_b, count_a, d->parent, d->target,
 * actual decision was made in a separate heuristic function, and those answers
		for (i = 0; i < diff_queued_diff.nr; i++) {
					int reverse)
		if (e->s_lno + e->num_lines > tlno) {
			decref_split(split);
		head = next;
	int count;

 */
 * \param length_b number of lines in B for which matching should be done.
		enum object_type type;
			die("More than one commit to dig up from, %s and %s?",
		if (contents_from) {
/* Calculates the similarity between two fingerprints as the size of the
			    unsigned long len)

	 * We carve new entries off the front of e.  Each entry comes from a
 */
}
	struct commit_list **parent_tail, *parent;
	 * origin->blob_sha1 without mucking with its mode or type
	}
	return result ? *result : NULL;
			goto finish;
{
		 * it reaches into it, we need to split it up and

			die("internal error in blame::find_origin (%c)",
	 * parent, and "B" for the right hand side of the diff AKA target. */
static void pass_blame_to_parent(struct blame_scoreboard *sb,
		/* there is a post-chunk part not blamed on parent */
			i + start_b, map_line_number_in_b_to_a) - start_a;
				goto finish;
	struct strbuf line = STRBUF_INIT;

	merge_head = open(git_path_merge_head(r), O_RDONLY);
	sb->copy_score = BLAME_DEFAULT_COPY_SCORE;
	/* Try "find copies harder" on new path if requested;
	for (i = 0; i < same - tlno; i++) {
			 &sb->num_read_blob, 0);
						     &file_size);
	 * the line in A that is closest to its position, and the lines in A
		target_idx = tlno + i;
		 * changes made by the ignored commit.
/* Find the lines in the parent line range that most closely match the lines in
 *		       in B that similarities represents.
			if (porigin && !strcmp(p->one->path, porigin->path))

				      struct blame_origin *target,
			if (l) {
		dup_entry(unblamed, e, &split[0]);
	}
 * Final image line numbers are all different, so we don't need a
 * The blobs of origin and porigin exactly match, so everything
	 */
			line_blames[i].s_lno = best_idx;
		return NULL;
	repo_diff_setup(r, &diff_opts);
	origin->suspects = NULL;
		 */
	 * Pass remaining suspects for ignored commits to their parents.
struct blame_list {
	if (ignoredp) {
				       max_search_distance_a,
			next = ent; /* again */
		hash = c0 | (c1 << 8);
 * origin of dst loses a refcnt.
		 */
 * across file boundary from the parent commit.  porigin is the path
};
		blame_list = xcalloc(num_ents, sizeof(struct blame_list));
		}
 * far, by comparing potential and best_so_far and copying potential into
 * intersection of their multisets, including repeated elements. See
			/* e->s_lno is already in the target's address space. */
	if (o->fingerprints)
 *                   <------------>
 * The similarities are stored in a 2-dimensional array. Each "row" in the
	obj = revs->pending.objects[0].item;
	struct hashmap_entry entry;
				find_move_in_parent(sb, &blametail, &toosmall, origin, porigin);
	return porigin;
	}
 * putting it on a list.
		 * Normalise whitespace to 0, and normalise letters to

	/*
			baa = 1;
#include "diff.h"
	long offset;
 */
		    (!(commit->object.flags & UNINTERESTING) &&
 * string. Whitespace pairs are ignored. Whitespace is converted to '\0'.
		best_sim_val = sim;
 *  cq, dq, eq, -1, -1]
/*
				/* find_move already dealt with this path */
		/*
/*
{
 * offset: add to tlno to get the chunk starting point in the parent
		for (o = get_blame_suspects(porigin->commit); o; o = o->next) {

	int i;
{
 * in split.  Any assigned blame is moved to queue to
{

	n->ignored = e->ignored;
{
	int baa = 0;
		if (!final_commit)
}
			 int tlno, int plno, int same,
				die_errno("cannot open or read '%s'", read_from);
{
	oidclr(&origin->blob_oid);

		}
				oid_to_hex(&ent->suspect->commit->object.oid),
static int handle_split_cb(long start_a, long count_a,
		 * then the lines in order of certainty are X, Y, Z.
}
	       mapping->destination_start;
		diffcore_std(&diff_opts);
	diff_opts.output_format = DIFF_FORMAT_NO_OUTPUT;
				continue;
		}
			struct blame_entry potential[3];
	 * and this code needs to be after diff_setup_done(), which
	*blame_suspects_at(&blame_suspects, commit) = origin;

	 */
 *             <------------------>
}
	int max_search_distance_b,
 */
};
					l->next = p->next;

}
			}
			else if (strbuf_read_file(&buf, read_from, st.st_size) != st.st_size)
			}
 */
		split[i].ignored = e->ignored;
	 * entries that have not yet been tested for blame.  leftover
	}
	struct blame_origin *porigin, **sg_origin = sg_buf;

};
				       similarities,
		if (!origin->suspects)
/*
	struct commit *head_commit;
 * We pass blame from the current commit to its parents.  We keep saying
/*
	else
		result[local_line_b] = start_a + best_similarity_index;
	if (!p1)
		/* Check that the lines in A and B are close enough that there
		split[0].num_lines = tlno - e->s_lno;
static int diff_hunks(mmfile_t *file_a, mmfile_t *file_b,
				pass_whole_blame(sb, origin, porigin);
/*

			int tlno, int offset, int same, int parent_len,
			*source = p;
		 * result needs to be invalidated.
 * 			      similarities may be calculated.
			 * The same path between origin and its parent
				return list1;

			filter_small(sb, &toosmall, &origin->suspects, sb->copy_score);
		sb->final_buf_size = o->file.size;
					same = 1;
 *  -1, an, bn, cn, dn,
		if (ent->suspect->refcnt <= 0) {
 * 				in A for other lines in A for which
			struct blame_entry *split,
	int destination_start, destination_length,
			if (S_ISGITLINK(p->one->mode))
		 * line Y that matches two lines equally with a score of 5,


 * \param fingerprints_b array of fingerprints for the chunk in B
		 */
		if (origin->suspects) {
 *
		get_fingerprint(fingerprints + i, linestart, lineend);
	 * "git blame --reverse ONE..HEAD -- PATH" but only do so
 * similarities.
/*

			}
	for (i = most_certain_local_line_b - 1; i >= invalidate_min; --i) {
		 * slight drawback is that we end up sorting all blame entries
	result = xcalloc(sizeof(int), length_b);

	if (!num_sg)
		       !oideq(&c->object.oid, &sb->final->object.oid)) {
	void *buf = strbuf_detach(sb, &len);
 * \param length_a the length in lines of the chunk in A
		}
	int s_lno;
	int *second_best_result,
	const struct line_number_mapping *mapping)
	int local_line_b,
	int i;
					    i, local_line_b,
		 * is a similarity value for them.
 * -C options may lead to overlapping/duplicate source line number
	if (samep) {
	 * similarity values with that fingerprint.
					break;
{
	if (ignore_diffs)

}
			}
			suspect = suspect->next;
	}

static int compare_blame_final(const void *p1, const void *p2)
		}
static int compare_blame_suspect(const void *p1, const void *p2)
				       fingerprints_a,
	if (diff_hunks(&file_p, &file_o, blame_chunk_cb, &d, sb->xdl_opts))
		char *buf_ptr;
 * 				similarities may be calculated.
{
	struct handle_split_cb_data *d = data;
	fill_origin_blob(&sb->revs->diffopt, target, &file_o,
 * in the various origins.
		closest_local_line_a;
	const char *cp, *ep;
		} while (p1->s_lno <= p2->s_lno);

	int merge_head;
			/* bump to front */

			die_errno("failed to read from stdin");
		/* there is a pre-chunk part not blamed on parent */
				copy_split_if_better(sb, blame_list[j].split,
			*small = p;
 * origin is suspected for can be blamed on the parent.
	diff_flush(&diff_opts);
 * \param map_line_number_in_b_to_a parameter to map_line_number().
		e->s_lno += offset;
static struct blame_origin *get_origin(struct commit *commit, const char *path)
		add_blame_entry(unblamed, &split[2]);

		closest_local_line_a = map_line_number(
{
 */
		while (*tail)
					struct blame_origin *origin)
	 */
			continue;
		result[local_line_b] = -1;
}
}
			;
		diff_tree_oid(get_commit_tree_oid(parent),
		    textconv_object(sb->repo, path, o->mode, &o->blob_oid, 1, (char **) &sb->final_buf,
	for (ent = sb->ent; ent; ent = ent->next) {

 */
{
			    oid_to_hex(&o->blob_oid),
	else
		/*
			     struct fingerprint *t_fps, int t_idx,
static struct commit *find_single_initial(struct rev_info *revs,
					  struct commit_list **tail,
			die("unsupported file type %s", read_from);

	 */
			if (parse_commit(p))
	 * entirety so we don't need to store the byte pair separately.
		do {
	diff_opts.flags.recursive = 1;
	long tlno;
	int parent_slno = tlno + offset;
		sanity_check_refcnt(sb);
 */
			struct blame_entry *n;
		}
	}
	if (most_certain_local_line_b > 0) {
static void set_next_blame(void *p1, void *p2)
}
	if (sb->final && sb->contents_from)
			struct blame_entry *split = blame_list[j].split;
				     struct commit *work_tree, const char *path)
	memset(split, 0, sizeof(struct blame_entry [3]));
		same += ent->s_lno;
		if (!file->ptr)
	}
{
}
		int pos = index_name_pos(r->index, path, len);

	if (opt & PICKAXE_BLAME_COPY) {
		sb->commits.compare = compare_commits_by_commit_date;
	const char *name = NULL;

		/* Should be present exactly once in commit chain */
			 struct blame_entry *sorted)

{
	 * after the blameable portion.
		find_best_line_matches(start_a,
	for (p = buf; p < end; p = get_next_line(p, end))

		found = (struct commit *)obj;
static void decref_split(struct blame_entry *split)

 * the parent.

		*name_p = xstrdup(name);
		found = dwim_reverse_initial(revs, &name);
		if (fuzzy_matches && fuzzy_matches[i] >= 0) {
		/* Always terminate the string with whitespace.
	cache_tree_invalidate_path(r->index, path);
/*
	struct commit *commit = prio_queue_get(&sb->commits);

 * \param similarities 2-dimensional array of similarities between lines in A
	prepare_lines(sb);
	diff_setup_done(&diff_opts);
/*
static void find_copy_in_parent(struct blame_scoreboard *sb,


			if (commit->object.parsed)
		blame_origin_decref(suspect);
	if (s1->s_lno == s2->s_lno)
		FREE_AND_NULL(o->fingerprints);

	 */
{
	init_blame_suspects(&blame_suspects);
	new_head->suspect = o;
	strbuf_addstr(&msg, "tree 0000000000000000000000000000000000000000\n");
		if (!sb->final_buf)
		do {

		if (strbuf_read(&buf, 0, 0) < 0)
	if (is_null_oid(&origin->commit->object.oid))
		return NULL;
void blame_origin_decref(struct blame_origin *o)
		diff_opts.flags.find_copies_harder = 1;
	while (e && e->s_lno < same) {
static void add_blame_entry(struct blame_entry ***queue,
		 * line X that matches only one line with a score of 3,
				if (next) {
		struct blame_entry *next = e->next;
		while (c->parents &&
		die(_("revision walk setup failed"));
		struct object *obj = revs->pending.objects[i].item;
}
	 */
	}

		if (revs->first_parent_only &&
		}
		o = get_blame_suspects(sb->final);
 * than score_min to the front of list *small.
	free(f->entries);
		switch (st.st_mode & S_IFMT) {
	/* Invalidate results that may be affected by the choice of most
	}
	file_o.ptr = (char *) cp;
	if (certainties[local_line_b] != CERTAINTY_NOT_CALCULATED)
 * Then the similarity array will contain:
				continue; /* ignore git links */
		oidcpy(&porigin->blob_oid, &origin->blob_oid);
		if ((p == line_end) || isspace(*p))
		else
define_commit_slab(blame_suspects, struct blame_origin *);
			      struct blame_line_tracker *second)
 * \param similarities 2-dimensional array of similarities between lines in A
 */
			break;
		if (obj->flags & UNINTERESTING)

	if (!porigin->file.ptr && origin->file.ptr) {
	memcpy(e, src, sizeof(*e));
		    commit->parents &&
 * first suspect line number.
			free_commit_list(commit->parents->next);
}
	int *similarities,

		if (obj->type != OBJ_COMMIT)
		struct blame_origin *porigin = sg_origin[i];
	int length_b = same - tlno;

	 * Discard the matches for lines in B that are currently matched with a
			blame_origin_incref(porigin);
	*num_ents_p = num_ents;

{
	 * bottom commits we would reach while traversing as
			if (!origin->suspects)
	struct cache_entry *ce;
static int blame_chunk_cb(long start_a, long count_a,
 * retain a sensible line ordering.
	unsigned score;
		if (!strcmp(o->path, path)) {
		found = (struct commit *) obj;
			fprintf(stderr, "%s in %s has negative refcnt %d\n",
		name = revs->pending.objects[i].name;
	similarities = xcalloc(sizeof(int), similarity_count);

	}
	struct hashmap map;
	 * prepend toosmall to origin->suspects
		 */
		*unblamedtail = NULL;
	*small = oldsmall;
	search_end = closest_local_line_a + max_search_distance_a + 1;
	for (i = 0; i < nr_lines; i++) {
		ent = suspect->suspects;
	struct object *obj;
}

	diff_opts.detect_rename = 0;
{
		free(sg_origin);
			suspects = blamed;
		return commit->parents;
					    origin, sg->item, porigin, opt);
		assert(e->num_lines == entry_len);
		    (result[i] >= most_certain_line_a ||
			     int from, int nr_lines)
	do {
	 * respective pointer value as the primary sorting criterion.
	search_start = closest_local_line_a - max_search_distance_a;
		return NULL;
	struct blame_origin *o, *l;

 * requires writing a link in the _previous_ element, while building
			else
	struct blame_origin *sg_buf[MAXSG];
 *
	for (i = 0; i < 3; i++) {
	struct fingerprint *fingerprints_a = parent->fingerprints;
	int start_a,
		}
static struct blame_entry *blame_merge(struct blame_entry *list1,
	if (start_a - start_b != d->offset)
			break;
			blame_list[i++].ent = e;
 * the commit priority queue of the score board.
static int fingerprint_similarity(struct fingerprint *a, struct fingerprint *b)
	       (mapping->source_length * 2) +
}
 * To allow quick access to the contents of nth line in the
			}
	free(certainties);
/*
			}
		 * the certainty. However we still want to prioritise matching

{
struct fingerprint {

 * examples.
	for (parents = work_tree->parents; parents; parents = parents->next) {
			find_copy_in_parent(sb, &blametail, &toosmall,
	struct hashmap_iter iter;
 * for the lines it is suspected to its parent.  Run diff to find
			}
}
			hashmap_add(&result->map, &entry->entry);
static void get_fingerprint(struct fingerprint *result,
 * c | o
void blame_coalesce(struct blame_scoreboard *sb)
		struct blame_origin *o;
					   &c->parents->item->object, l))
	most_certain_line_a = result[most_certain_local_line_b];

}
 * \param start_b index of the first line in B for which matching should be
			samep = n;
	struct blame_entry *samep = NULL, *diffp = NULL, *ignoredp = NULL;
		if (line_blames[i].is_parent) {
	}
	if (sb->reverse && sb->contents_from)
		*dstq = &ignoredp->next;
}
 * a malloced blame_entry that gets added to the given queue.  The

			 */
		best_similarity_index = 0, second_best_similarity_index = 0;
static int scan_parent_range(struct fingerprint *p_fps,
		     i < num_sg && sg;
		case 'M':
				       certainties,
 * this function directly.
	lineno = *line_starts;
	}
/*
	struct rev_info *revs = sb->revs;
		offset_b = most_certain_local_line_b + 1;
static void copy_split_if_better(struct blame_scoreboard *sb,
		    "committer %s\n\n"

}
 * has an overlap with that range.  it also is known that parent's
static struct blame_entry *split_blame_at(struct blame_entry *e, int len,
			 * Move second half to a new record to be
			if (!DIFF_FILE_VALID(p->one))
	/*
 * closest in terms of its position as a fraction of the length of the chunk.
		entry_a = hashmap_get_entry(&a->map, entry_b, entry, NULL);
	len = strlen(path);
	int max_map_entry_count = 1 + line_end - line_begin;
			*diffp = e;
 * If two blame entries that are next to each other came from
	while (blamed)
			die(_("cannot read blob %s for path %s"),
		/* me and then parent */

		if (blame_entry_score(sb, &potential[1]) <

	o->num_lines = find_line_starts(&line_starts, o->file.ptr,
	}
	int start_a = parent_slno;
	obj = deref_tag(revs->repo, obj, NULL, 0);
		certainties[local_line_b] = best_similarity * 2 -
		}
				if (!porigin)
						     target_idx, 0,
 * We have an origin -- find the path that corresponds to it in its
 */
		die("no such path '%s' in HEAD", path);
		    !strcmp(p->two->path, origin->path)) {
	if (pos >= 0)


	 * Optionally find moves in parents' files.
	for (p_idx = from; p_idx < from + nr_lines; p_idx++) {


	new_head->s_lno = start;
			    o->path);
					struct blame_origin *origin)
					   blame_origin_incref(e->suspect));
			sb->final_buf = read_object_file(&o->blob_oid, &type,
				struct blame_entry ***blamed,
		die("internal error in blame::blame_chunk_cb");
	}
		certainties[local_line_b] = CERTAIN_NOTHING_MATCHES;
			second_best_similarity = best_similarity;
	mmfile_t file_p;
 * Find the lines from parent that are the same as ent so that
	/* Is that sole rev a committish? */
	 */
	const char *p;
	if (!unblamed)
 * It is known that lines between tlno to same came from parent, and e
		obj = deref_tag(revs->repo, obj, NULL, 0);

	invalidate_min = most_certain_local_line_b - max_search_distance_b;
}
					 sb->final_buf_size);
}
 * Any merge of blames happens on lists of blames that arrived via
 */
	if (opt & PICKAXE_BLAME_MOVE) {
	if (toosmall) {
			struct blame_entry ***unblamed,

			die("Non commit %s?", revs->pending.objects[i].name);
		search_start = 0;
	if (!diff_opts.flags.find_copies_harder)
		parse_commit(commit);
						  void *c)
	if (name_p)
			blame_origin_decref(sg_origin[i]);
		struct object_id oid;
	if (!resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &head_oid, NULL))
		}
				       map_line_number_in_b_to_a);
 * This decides which parts of a blame entry go to the parent (added to the
	discard_index(r->index);
		if (best_idx >= 0) {
			 * processed by later chunks
	n->num_lines = e->num_lines - len;
			   long start_b, long count_b, void *data)
					  fingerprints_b + start_b,
					    max_search_distance_a);
	struct diff_options diff_opts;
 */
			tail = &p1->next;
			    sb->copy_score < blame_entry_score(sb, &split[1])) {


 * The first pass checks the blame entry (from the target) against the parent's
 * the string that it represents. Whitespace is added at each end of the
 * Where similarities are denoted either by -1 for invalid, or the
{
	const char *p;
	int start_b,
			found_entry->count += 1;
	for (porigin = get_blame_suspects(parent); porigin; porigin = porigin->next)
					   const char **name_p)
	 * contiguous chunk of lines: adjacent lines from the same origin
		if (e->s_lno + e->num_lines > same) {
{
	 * without being assignable to the parent.

			return blame_origin_incref(o);

 * \param start_a index of the first line in A with which lines in B may be
struct handle_split_cb_data {
			if (!strcmp(name, origin->path))
	    || ((opt & PICKAXE_BLAME_COPY_HARDER)
		do_diff_cache(get_commit_tree_oid(parent), &diff_opts);
				split_blame(blamed, &unblamedtail, split, e);
 * We are looking at a part of the final image represented by
			}
	struct commit *commit;
 * that passes blame to the parent.  Maintain best_so_far the best split so
	struct commit *parent;

	const struct line_number_mapping *map_line_number_in_b_to_a)
	}
		} else {
	/* The number of times the byte pair occurs in the string that the
		 * chunk to the parent */
{
			if (add_decoration(&sb->revs->children,
	/* More invalidating of results that may be affected by the choice of
		die("unable to generate diff (%s -> %s)",
	 * same and diff-tree is fairly efficient about this.
{
		for (j = 0; j < num_ents; j++) {
	int *lineno;

		struct blame_entry **unblamedtail = &unblamed;
	for (i = invalidate_min; i < invalidate_max; ++i) {
	struct blame_origin *target;
	d->offset = start_a + count_a - (start_b + count_b);
	if (!mode) {
			struct blame_origin *parent,
	ce->ce_mode = create_ce_mode(mode);

		struct blame_entry **unblamedtail = &unblamed;

}
			toosmall = NULL;
	struct blame_entry *leftover = NULL;
	repo_read_index(r);
 */
			/*
 * [-1, -1, am, bm, cm,
	/*
	free(second_best_result);

			second_best_similarity_index = best_similarity_index;


				 struct blame_entry *best_so_far,
		else
	ce->ce_flags = create_ce_flags(0);
		max_search_distance_a = length_a ? length_a - 1 : 0;
	struct blame_entry *e, *suspects;
		free_line_fingerprints(o->fingerprints, o->num_lines);
				      int parent_len)
	}
	return blame_list;
}

 * 		       in the chunk.
	while (cp < ep) {
		}
	 * uninteresting.
	int i, best_idx, target_idx;

	const char *linestart, *lineend;
	hashmap_for_each_entry(&b->map, &iter, entry_b,
		lineend = content + line_starts[i + 1];
	int entry_len, nr_lines, i;
 * and a line in B.
		/* Take responsibility for the remaining entries */
}
			die("More than one commit to dig from %s and %s?",
			free(next);
 *
		if (!oideq(&c->object.oid, &sb->final->object.oid))

}
}
	struct blame_origin *parent;
		 * do not care about.
	/* See if the origin->path is different between parent
finish:
	int *result,
}
{
		porigin->suspects = sorted;
		certainties[i] = CERTAINTY_NOT_CALCULATED;
 * 		 freed later using free_fingerprint.
	 */
	sb->num_commits++;
	struct blame_entry *blames, **blametail = &blames;
		if (sb->revs->diffopt.flags.allow_textconv &&
 * We have an origin -- check if the same path exists in the
{

			const char *name;
	return sb->final_buf + sb->lineno[lno];
					o->file.size);
	};
 */
 * 		  done.
	struct blame_entry *newdest = NULL;
		/* Break ties with the closest-to-target line number */
	return &commit_list_insert(parent, tail)->next;

 * \param certainties array of values indicating how strongly a line in B is
				ent->next = sb->ent;
	ecb.priv = cb_data;
		sg_origin = xcalloc(num_sg, sizeof(*sg_origin));
						     &head_oid, 1);
	}
				die_errno("Cannot stat '%s'", contents_from);
	hashmap_iter_init(&b->map, &iter);
 * \param result array of absolute indices in A for the closest match of a line
				    &o->blob_oid, 1, &file->ptr, &file_size))
	return first->is_parent == second->is_parent &&
					ent = next;
	}
	blame_chunk(&d->dstq, &d->srcq, start_b, start_a - start_b,
/*
		most_certain_line_a, most_certain_local_line_b = -1,
	}

				free(o);
			max_search_distance_b,

			next = split_blame_at(e, entry_len,
		    d->ignore_diffs);
			entry->count = 1;
		while (suspect && !suspect->suspects)

	struct blame_entry *unblamed = target->suspects;
{
	 * if it turns out there is nothing to blame the parent for,

			mode = r->index->cache[pos]->ce_mode;
		}
			diffp = e;
}
	return porigin;
		free(o->file.ptr);
		}
	}
		 * "--not A B -- path" without anything positive;
		cp++;
	if (!contents_from || strcmp("-", contents_from)) {
 * \param local_line_b the index of the line in B, relative to the first line

	 * file_o is a part of final image we are annotating.
	if (e->score)
				ent->suspect->path,
		find = pass ? find_rename : find_origin;
	}
		}

			}
 * 		  compared.
				continue;
			if (strbuf_readlink(&buf, read_from, st.st_size) < 0)
			read_from = contents_from;
	while (head) {
		}
	}
			ent->score = 0;

	struct commit *commit = origin->commit;

{
 * \param line_begin the start of the string
						  norigin, potential, &file_p);
	return 0;
			ent->num_lines += next->num_lines;
	}
	struct blame_origin *porigin;
			      struct blame_origin *parent,
		 * line that matches poorly with one line, hence doubling
		**dstq = reverse_blame(samep, **dstq);
 * The callers that add blame to the scoreboard should use
	struct blame_chunk_cb_data *d = data;
 * different parents in a single suspect.  In this case, we want to
		     second_best_result[i] >= most_certain_line_a)) {
		struct blame_entry **tail = &toosmall;
		 * bunch of deletion of files in the directory that we
{
			read_from = path;
	commit = alloc_commit_node(r);
	const struct fingerprint_entry *entry_b;
{
		guess_line_blames(parent, target, tlno, offset, same,
	} else {
#include "cache.h"
					  max_search_distance_b,
static struct blame_list *setup_blame_list(struct blame_entry *unblamed,
		toosmall = filter_small(sb, toosmall, &unblamed, sb->move_score);
 * to its parents. */
	for (parent = commit->parents; parent; parent = parent->next)
{
	free(line_blames);
		 */
	 * we do not want to use diffcore_rename() actually to
		if (!origin->previous) {
 * Example: if the chunk is 10 lines long in A and 2 lines long in B then line
	if (orig)
		line_blames = xcalloc(sizeof(struct blame_line_tracker),
		*orig = o;
 * in reverse order just requires placing the list head into the

		toosmall = filter_small(sb, toosmall, &unblamed, sb->copy_score);

		; /* path is in the index */

			    revs->pending.objects[i].name, name);
					  max_search_distance_a,
			for (;;) {
	 */
		return NULL;
	if (get_tree_entry(r, &origin->commit->object.oid, origin->path, &origin->blob_oid, &origin->mode))
			/* This value will never exceed 10 but assert just in
	blame_origin_incref(o);
{
 *                   <------>
			      int tlno, int offset, int same, int parent_len,
 error_out:
	return -1;
				blame_list[j].ent->next = leftover;

		if (opt->flags.allow_textconv &&
	int ignore_diffs;
	return num;
		return 0;
			c1 = 0;
					    blame_list[j].ent);
					  set_next_blame,
	ce->ce_namelen = len;
		return; /* nothing remains for this target */
		    oid_to_hex(&target->commit->object.oid));
	}
 * get_origin() to obtain shared, refcounted copy instead of calling
		blame_origin_incref(potential[i].suspect);
	/*
		e = next;
		if (certainties[i] > most_certain_line_certainty) {
	mmfile_t file_o;
		 */
	struct blame_entry *split;
		return NULL;
	struct blame_scoreboard *sb;
	if (ent->num_lines <= tlno)

			 * without renaming -- the most common case.
	while (p) {
		const struct object_id *commit_oid = &parents->item->object.oid;
	 * common cases, then we look for renames in the second pass.
	if (!file_p.ptr)
		} while (blamed && blamed->suspect == porigin);
		die(_("--contents and --reverse do not blend well."));
			porigin->mode = p->one->mode;
	/* The rest are the same as the parent */
	const char *paths[2];
			if ((p2 = *tail) == NULL)  {

	return found;
 */
}
	strbuf_addf(&msg,
	}
		     second_best_result[i] <= most_certain_line_a)) {
 * `struct fingerprint` for an explanation of the fingerprint representation.
	free((char *)final_commit_name);
	return ((struct blame_entry *)p)->next;
	repo_diff_setup(sb->repo, &diff_opts);
	size_t len;
	if (sb->reverse && sb->revs->first_parent_only)

			best_idx = scan_parent_range(parent->fingerprints,
					       const char *path,
		 * entry when we have to.
	struct blame_entry *e = **srcq;

			struct blame_origin *porigin = sg_origin[i];
#include "diffcore.h"
/*
			fingerprints_b + offset_b,

 */
	 */
 * line plno corresponds to e's line tlno.

		split[1].lno = e->lno;
 *
	struct blame_entry *n = xcalloc(1, sizeof(struct blame_entry));
			drop_origin_blob(porigin);
 * Note that annotating work tree item never works in the reverse.
	 * most certain line.
 * \param result array of absolute indices in A for the closest match of a line
			continue;
		struct diff_filepair *p = diff_queued_diff.queue[i];
 * The similarity between "cat mat" and "father rather" is 2 because "at" is
	free(similarities);
					    closest_local_line_a,
		/* Pass blame for everything before the differing
					const char **name_p)
		if (i + 1 < nr_lines) {
				max_search_distance_a) = -1;
		fuzzy_find_matching_lines_recurse(
		      xdl_emit_hunk_consume_func_t hunk_func, void *cb_data, int xdl_opts)
			if (lstat(path, &st) < 0)
		porigin = get_origin(parent, origin->path);
	/*
	 * by the choice of most certain line.
				struct commit *parent,
	/* See get_similarity() for details of similarities. */
/*
	memset(sb, 0, sizeof(struct blame_scoreboard));
	sb->move_score = BLAME_DEFAULT_MOVE_SCORE;
 * that of its parent's.
			     sg = sg->next, i++) {
struct blame_origin *get_blame_suspects(struct commit *commit)
	       mapping->destination_length /
 *			 frame of reference as line_a. This value defines
			if (opt->flags.allow_textconv &&
		struct blame_origin *porigin = blamed->suspect;
	struct blame_origin **result;
	/* certainty has already been calculated so no need to redo the work */
/* This contains the data necessary to linearly map a line number in one half
 * If there were no previous blames to that commit, it is entered into
 * fuzzy_find_matching_lines_recurse for details of preserving line ordering.
			blamed = next;
		*tail = p2;
	for (p = buf; p < end; p = get_next_line(p, end))

	struct diff_options diff_opts;
		similarities[i] = -1;
 * Splits a blame entry into two entries at 'len' lines.  The original 'e'
	       first->s_lno + 1 == second->s_lno;
		} while (p1->s_lno <= p2->s_lno);
	/*
	d.target = target;
	decref_split(best_so_far);
	 */
		/*
	int best_sim_idx = -1;
		if (errno == ENOENT)
	}
		 * current record starts before differing portion.  If

 * Process one hunk from the patch between the current suspect for
		obj = deref_tag(revs->repo, obj, NULL, 0);
	}
struct blame_chunk_cb_data {

				goto finish;
			/*

		dup_entry(blamed, e, &split[1]);
		fuzzy_find_matching_lines_recurse(
	diff_opts.flags.recursive = 1;
	}
		}
#define CERTAINTY_NOT_CALCULATED -1
	((struct blame_entry *)p1)->next = p2;
		    parent, target, 0);
	diff_opts.flags.recursive = 1;
	for (p = line_begin; p <= line_end; ++p, c0 = c1) {

	entry_len = 1;
			mmfile_t file_p;
	 */
	if (revs->pending.nr != 1)
				*tail = p2;
		 * or "--contents".

	if (!is_null_oid(&origin->blob_oid))
			/* Did not exist in parent, or type changed */
 * want to transfer ownership of the buffer to the commit (so we
#define CERTAIN_NOTHING_MATCHES -2
		const char *read_from;
			return;
			    git_path_merge_head(r), line.buf);
				       i,

	 * that.

/*
static void blame_chunk(struct blame_entry ***dstq, struct blame_entry ***srcq,
 * 		      matched with some line in A.
		die("no such ref: HEAD");
			filter_small(sb, &toosmall, &origin->suspects, sb->copy_score);
		chunk_end_lno = split[2].lno;
					   int *num_ents_p)
{
	for (e = unblamed, num_ents = 0; e; e = e->next)
	struct handle_split_cb_data d;
}
	struct commit_list *l = first_scapegoat(revs, commit, reverse);
					struct commit *parent,
void assign_blame(struct blame_scoreboard *sb, int opt)

	diff_flush(&diff_opts);
 * After splitting the blame, the origins used by the

	 * usually makes find-copies-harder imply copy detection.
 * fingerprints can be quickly compared to give an indication of the similarity
			length_b + start_b - second_half_start_b;
 * which lines came from parent and pass blame for them.

		 * best_similarity.
	 * from the parent.
			e->suspect = blame_origin_incref(parent);
	clear_pathspec(&diff_opts.pathspec);
	if (!head_commit)
						     parent->num_lines);
	if (!o->file.ptr) {
	for (i = most_certain_local_line_b + 1; i < invalidate_max; ++i) {
 */
{
		}
	origin = make_origin(commit, path);
 * \param start_a the index of the first line of the chunk in A
 * reverse_blame reverses the list given in head, appending tail.
	 */
/*

	diff_flush(&diff_opts);
/* Given a line number in one range, offset and scale it to map it onto the
			    sb->move_score < blame_entry_score(sb, &split[1])) {
		do {
	 * match things up; find_copies_harder is set only to

		for (e = unblamed, i = 0; e; e = e->next)
						/* member name */ entry, NULL);
			struct commit *p = sg->item;
			  struct blame_origin *parent)

}
	obj->flags |= UNINTERESTING;
		*unblamedtail = NULL;
	repo_diff_setup(r, &diff_opts);
	}
 */
	certainties = xcalloc(sizeof(int), length_b);
	if (!diff_queued_diff.nr) {
	int length_a,
	struct fingerprint_entry *entries;
	long plno;
			best_similarity_index = i;
		**tail = &list1;
		    oid_object_info(r, &blob_oid, NULL) == OBJ_BLOB)
 */
		assert(commit == suspect->commit);
	 * Prepend the split off portions: everything after e starts
			if (stat(contents_from, &st) < 0)
	 */
	e->next = **queue;

static struct commit *find_single_final(struct rev_info *revs,


		do_diff_cache(get_commit_tree_oid(parent), &diff_opts);
static int fill_blob_sha1_and_mode(struct repository *r,
	int *second_best_result,
		/* Nobody should have zero or negative refcnt */
static struct commit_list **append_parent(struct repository *r,
	return score;
		die("internal error in blame_origin_decref");

	for (i = 0; i < 3; i++)
		e->next = samep;
		dup_entry(blamed, e, &split[1]);
	else
static void split_overlap(struct blame_entry *split,
			struct commit_list *l = xcalloc(1, sizeof(*l));

	else if (num_sg < ARRAY_SIZE(sg_buf))
				suspect->suspects = NULL;
	}
		      struct blame_entry *dst, struct blame_entry *src)
/* Given a line in B, first calculate its similarities with nearby lines in A
		pass_blame_to_parent(sb, origin, porigin, 0);
		struct blame_origin *(*find)(struct repository *, struct commit *, struct blame_origin *);
	hashmap_free(&f->map);
		if (sim == best_sim_val && best_sim_idx != -1 &&
	 * As we don't know how much of a common stretch after this

	struct commit *found = NULL;
{
#include "refs.h"
			certainties[i] = CERTAINTY_NOT_CALCULATED;


			if (entry_a->count <= entry_b->count)
		blame_origin_incref(porigin);
	sb->ent = llist_mergesort(sb->ent, get_next_blame, set_next_blame,
	int max_search_distance_a = 10, max_search_distance_b;
	int num_ents;
	 * the hashmap manage the memory.
		    blame_entry_score(sb, &best_so_far[1]))

	struct blame_chunk_cb_data d;
 * order right away.  The reason is that building in proper order
 * ent (tlno and same are offset by ent->s_lno).
 * afterwards.  This can be faster than building the list in proper
#include "commit-slab.h"
			most_certain_line_certainty = certainties[i];
		sb->revs->children.name = "children";
		return;
	 * can assign to the parent for now.
	while (commit) {


	else {
		if (ent->suspect == next->suspect &&
	struct blame_entry split[3];
	xpp.flags = xdl_opts;
	struct blame_entry *ent;
			certainties + offset_b,
 * All line numbers are 0-based.

 * For lines target is suspected for, see if we can find code movement
	while (e && e->s_lno < tlno) {


		if (found)

					  length_a, length_b,
			    textconv_object(r, read_from, mode, &null_oid, 0, &buf_ptr, &buf_len))
		    commit->parents->next) {
					set_blame_suspects(o->commit, p->next);
	if (!name)
		    oid_to_hex(&parent->commit->object.oid));
				l->next = o->next;
	 */

		unsigned long file_size;
	}
/* A fingerprint is intended to loosely represent a string, such that two
	append_merge_parents(r, parent_tail);
 * blame_entry e and its parent.  This first blames any unfinished
	 * The first pass looks for unrenamed path to optimize for
			die(_("--reverse and --first-parent together require specified latest commit"));
 *			 where similarities is centered for the line in B.

			int j, same;
{
		} else {
		second_half_length_a =
	if (ignore_diffs && same - tlno > 0) {
	}
			if (split[1].suspect &&
	}
	get_line_fingerprints(o->fingerprints, o->file.ptr, line_starts,
 * This finds the line that we can match with the most confidence, and
					  struct commit *c,
	{
/*
		}
/*
	split[1].suspect = blame_origin_incref(parent);
	if (sb->reverse && sb->revs->first_parent_only) {

	if (!sb->reverse) {
				continue;
	int start_a, int start_b,
		entry_a = hashmap_get_entry(&a->map, entry_b, entry, NULL);
static void fill_origin_blob(struct diff_options *opt,
}
	const char *cp;
	 */
	/* At each iteration, unblamed has a NULL-terminated list of
		local_line_b + start_b, map_line_number_in_b_to_a) - start_a;

static struct commit_list *first_scapegoat(struct rev_info *revs, struct commit *commit,
	/* No matches. */
		/* find one suspect to break down */

			similarities +

	struct blame_origin *parent;
	xdemitconf_t xecfg = {0};
	if (e->s_lno < tlno) {

		 * If current record extends into sameness, need to split.
		fill_origin_fingerprints(o);
		 */
				       struct blame_entry *list2)

 *       <------ent------>
static int are_lines_adjacent(struct blame_line_tracker *first,
		 * This means that if we have
}
	if (is_null_oid(&origin->commit->object.oid))
	if (oidset_contains(&sb->ignore_list, &commit->object.oid)) {
		if (sb->copy_score > sb->move_score)
				die_errno("Cannot lstat '%s'", path);
		     sg = sg->next, i++) {
{
				if (l)
 * \param fingerprints_a mutable array of fingerprints in A. The first element
{

/*
	/* First check any existing origins */
	return o;
 *
	if (sg_buf != sg_origin)
 * parent and return an origin structure to represent it.
		} while (p1->s_lno > p2->s_lno);
			} else {
#include "object-store.h"
}
	 */
		second_half_start_a = most_certain_line_a;
#include "alloc.h"
		search_end = length_a;
		/* In this loop we discard results for lines in B that are
{
 * concatenation of the two lines in the diff being compared.
		if (found_entry) {
					  second_best_result,
		*tail = p1;
		*certainties, *similarities, similarity_count;
	for (i = search_start; i < search_end; ++i) {
{
 * 			     closest match of a line in B.
}

}

		 * If the line matches well with two lines then that reduces
 * \param second_best_result array of absolute indices in A for the second
	       max_search_distance_a);
		 * sorting until after all diff hunks are processed, so that
			    p->status);
		 * that is before most-certain-line-A.
{
	const char *name = NULL;
		int i;
/*
		case S_IFREG:
	handle_split(sb, ent, d.tlno, d.plno, ent->num_lines, parent, split);
	}
					sb->found_guilty_entry(ent, sb->found_guilty_entry_data);
	if (!resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &head_oid, NULL))
	struct blame_entry *e, split[3];
 * 			 corresponds to the line at start_a.

 * three-way comparison here.
			most_certain_local_line_b,

				 struct commit_list **tail)
				*tail = p1;
		return 0;
		best_sim_idx = p_idx;
		/* Reading from stdin */
			  long start_b, long count_b, void *data)
		*name_p = revs->pending.objects[0].name;
	clear_pathspec(&diff_opts.pathspec);
	else
 * 		       and B. See get_similarity() for more details.
	}
}
	return ((line_number - mapping->source_start) * 2 + 1) *
				break;
		blame_list = setup_blame_list(unblamed, &num_ents);
				struct blame_origin *target,
{
 * \param line_a the index of the line in A, in the same frame of reference as
			commit->object.flags |= UNINTERESTING;
		result[i] = -1;
		split[2].num_lines = e->s_lno + e->num_lines - same;
}
			if (o->suspects) {
{
 *
	int max_search_distance_a,
		} else
		most_certain_line_certainty = -1,
		for (i = 0, sg = first_scapegoat(revs, commit, sb->reverse);
	 */
	}
		linestart = content + line_starts[i];
/* Calculate fingerprints for a series of lines.
	}
	if (most_certain_local_line_b + 1 < length_b) {
static struct commit *fake_working_tree_commit(struct repository *r,
	while (!strbuf_getwholeline_fd(&line, merge_head, '\n')) {
		return;
		}
{
 * src typically is on-stack; we want to copy the information in it to
	struct blame_entry *toosmall = NULL;

		for (e = unblamed; e; e = next) {
	struct blame_entry *p1 = list1, *p2 = list2,

 * we can pass blames to it.  file_p has the blob contents for
		if (sg_origin[i]) {
}
	 */

}
}
	} while (unblamed);
	 * to allow for collating suspects, we sort according to the
 * blame the parents.  E.g. "\t\t}\n\t}\n\n" appears everywhere in any
			assert(abs(i - closest_local_line_a) < 1000);
		*name_p = xstrdup_or_null(name);
			*similarity = fingerprint_similarity(
	assert(abs(line_a - closest_line_a) <=
 * last 5 lines will all map onto the second line in the A chunk.
			max_search_distance_b,

		} else {
 * Split e into potentially three parts; before this chunk, the chunk
 */
	/* Turn "ONE" into "ONE..HEAD" then */
			    oid_to_hex(&parent->item->object.oid));
		return;
		blame_origin_decref(e->suspect);
		 */
		      struct blame_origin **orig)
 * where the search range extends beyond the lines in A.
				porigin->suspects = sorted;
}
	drop_origin_blob(origin);

			       struct blame_entry **ignoredp,
	n->unblamable = e->unblamable;
 * Given an origin, prepare mmfile_t structure to be used by the
 * This isn't as simple as passing sb->buf and sb->len, because we
	blamed = llist_mergesort(blamed, get_next_blame, set_next_blame,
 */
			oidcpy(&porigin->blob_oid, &p->one->oid);
 */
}
{
		return (intptr_t)s1->suspect > (intptr_t)s2->suspect ? 1 : -1;
 *
 * 			      in A for other lines in A for which
				       fingerprints_b,
			certainties[i] = CERTAINTY_NOT_CALCULATED;
			max_search_distance_a,
		if (isalnum(ch))
				drop_origin_blob(sg_origin[i]);
				}

	}
	if (porigin->suspects)
	closest_local_line_a = map_line_number(
		diff_tree_oid(get_commit_tree_oid(parent),
	line_starts += first_line;
	}
	}
			for (j = same = 0; j < i; j++)
		**dstq = reverse_blame(ignoredp, **dstq);
static void sanity_check_refcnt(struct blame_scoreboard *sb)
 * if not already calculated, then identify the most similar and second most
			 */
 */
 * that partition. In this way we avoid lines appearing out of order, and
	for (i = 0; i < 3; i++)
		second_half_start_b = start_b + offset_b;
		if (entry_a) {
		if (ent) {
		case S_IFLNK:

	 * If we have bottom, this will mark the ancestors of the
	*lineno = len;
	struct blame_origin *porigin = NULL;
		add_blame_entry(blamed, &split[1]);
		*file = o->file;
	int i;
 * See struct fingerprint for details of fingerprint matching, and
				split_blame(blamed, &unblamedtail, split,
static void fuzzy_find_matching_lines_recurse(
 * present twice in both strings while the similarity between "tim" and "mit"
/*
	else {

	FLEX_ALLOC_STR(o, path, path);
		sim = fingerprint_similarity(&t_fps[t_idx], &p_fps[p_idx]);
	/*
			porigin = find(sb->repo, p, origin);
	e->num_lines = len;
	free(fuzzy_matches);
		struct blame_entry potential[3];
				die_errno("cannot readlink '%s'", read_from);
	max_search_distance_b = ((2 * max_search_distance_a + 1) * length_b
void setup_scoreboard(struct blame_scoreboard *sb,
		}
			die(_("no such path %s in %s"), path, final_commit_name);
};
	struct commit *found = NULL;
 *
			score++;
 *             <------------>
						     target->fingerprints,
 * 			      distance between lines in B such that they will
	origin->file.size = buf.len;
	}
 */
	int *result,
	paths[0] = origin->path;
			die("internal error in blame::find_origin");
		if (o->previous)
struct blame_line_tracker {
	 * unsorted list in the caller anyway.
		&& (!porigin || strcmp(target->path, porigin->path))))
/*
 * call to fill_origin_blob() can use it to locate the data.  blob_sha1
			second_best_similarity;

	second_best_result = xcalloc(sizeof(int), length_b);
				set_blame_suspects(commit, o);
	else
		}
 */
	return s1->s_lno > s2->s_lno ? 1 : -1;
	int i;
		default:
			return blame_origin_incref (porigin);

		for (i = 0, sg = first_scapegoat(revs, commit, sb->reverse);
	if (s1->suspect != s2->suspect)
				e->next = leftover;
	fingerprint_subtract(fingerprints_a + most_certain_line_a - start_a,
 * preallocated to allow storing line_count elements.
		if (!commit->parents && !sb->show_root)
 * The performance is believed to be O(n log n) in the typical case and O(n^2)
		struct blame_entry *suspects = NULL;
}
				decref_split(potential);
	const int max_search_distance_a,
#include "cache-tree.h"
		struct blame_entry *next = e->next;
 * \param local_line_b the index of the line in B, relative to the first line

			 * occur if you ignore back-to-back commits.
	if (search_end > length_a)
 * \param fingerprints_b array of fingerprints in B. The first element
		/* We keep both the best and second best results to allow us to
	struct blame_entry *e;
 * entries before the chunk (which is where target and parent start

			continue;
	}
	struct blame_entry *p = *source;
			if (!origin->suspects)

		porigin->mode = origin->mode;
 * 		      matched with some line in A.
		}
		if (sb->reverse ||
	/*
		/*
		return; /* nothing remains for this target */
			commit->parents->next = NULL;
 * 		       and B. See get_similarity() for more details.
	sb->num_get_patch++;
}
	xdemitcb_t ecb = {NULL};
 * Locate an existing origin or create a new one.
		if (!origin->suspects)
			/* Let's not bother reading from HEAD tree */

		struct diff_filepair *p = NULL;
/* Get a pointer to the element storing the similarity between a line in A
 * Note that the blame entries on the ignoredp list are not necessarily sorted
	struct fingerprint *fingerprints_b = target->fingerprints;
}
	result = blame_suspects_peek(&blame_suspects, commit);

		if (0 <= pos)
	/* Move across elements that are in the unblamable portion */
 *
{
 */
		}
	 */
 * \param result the fingerprint of the string is stored here. This must be
	fuzzy_matches = fuzzy_find_matching_lines(parent, target,
	for (o = get_blame_suspects(commit), l = NULL; o; l = o, o = o->next) {
			    const char *line_end)

			 * closest line) to act as a tie break between lines
	struct blame_entry *e = xmalloc(sizeof(*e));
	cp = blame_nth_line(sb, ent->lno);
	 */
 * same: line number in the target where this chunk ends
		struct blame_entry *ent;
	for (i = 0; i < nr_fingerprints; i++)
 *    <---------preimage----->

	diff_opts.single_follow = origin->path;
			    oid_to_hex(&o->blob_oid),
{
static int map_line_number(int line_number,
			origin->previous = porigin;
/*
 * other range.
{
				goto finish;
	invalidate_max = most_certain_local_line_b + max_search_distance_b + 1;
					  result,
				}
			blame_origin_decref(o->previous);
struct blame_entry *blame_entry_prepend(struct blame_entry *head,
{
		sizeof(struct fingerprint_entry));

}
			break;
			tail = &p1->next;
		split[0].suspect = blame_origin_incref(e->suspect);
 */
 * totally unrelated file in the parent.
		sb->final = fake_working_tree_commit(sb->repo,
static void drop_origin_blob(struct blame_origin *o)

				entry_len++;
 * the parent to detect the case where a child's blob is identical to
			struct blame_entry *n;
	 * DWIM "git blame --reverse ONE -- PATH" as
	return (struct commit *)obj;
 * ranges, all we can rely on from sorting/merging is the order of the
	n->suspect = new_suspect;
	commit->object.parsed = 1;
		split[0].lno = e->lno;
		}
{
		 * that is after most-certain-line-A.
	}
 * \param length_a number of lines in A with which lines in B may be compared.
	else
			intersection += entry_a->count < entry_b->count ?
	ep = blame_nth_line(sb, e->lno + e->num_lines);
	if (!sb->final) {
	/*
	**queue = e;
 * their multisets, including repeated elements. See fingerprint_similarity for

			/* Push new record to samep */
	return 0;
			e->next = *ignoredp;
			die("Cannot read blob %s for path %s",
		/* Steal its file */
		if (!p)
			struct blame_entry *next = blamed->next;
	memcpy(best_so_far, potential, sizeof(struct blame_entry[3]));
		}
	if (split[0].suspect && split[2].suspect) {
	return tail;
		 * The parent covers the entire area; reuse storage for
	}
 * in a pathological case, where n is the number of lines in the target range.
	struct blame_entry *ent, *next;
	for (i = 0, sg = first_scapegoat(revs, commit, sb->reverse);
				 compare_blame_suspect);
	d.ignore_diffs = ignore_diffs;
 * split_overlap() divided an existing blame e into up to three parts
 * b | n
		 * so hold onto it in the meantime.
	return intersection;
 * d | p
/*
 * Prepare a dummy commit that represents the work tree (or staged) item.
	nr_lines = e->num_lines;	/* e changes in the loop */
		 */
#define MAXSG 16
	if (split[1].num_lines < 1)
{
		}
					long start, long end,
	/*
	o->refcnt = 1;
			/* Push new record to diffp */
			  struct blame_entry *e,
			pass_blame_to_parent(sb, origin, porigin, 1);
		o->num_lines = 0;
	 * the boundary.
/* diff chunks are from parent to target */
	drop_origin_fingerprints(o);
/*
		    "Version of %s from %s\n",
		return;
}
static void free_fingerprint(struct fingerprint *f)
	}
		e = next;

	if (num_ents) {
			file->ptr = read_object_file(&o->blob_oid, &type,
{
{
						  tlno, parent_slno, same,
			      struct blame_line_tracker *line_blames)
			/*
 * \param fingerprints_a array of fingerprints for the chunk in A
static void ignore_blame_entry(struct blame_entry *e,
 * allowing repeated elements in a set.

/*
	enum object_type type;
		struct blame_origin *p, *l = NULL;
	pretend_object_file(buf.buf, buf.len, OBJ_BLOB, &origin->blob_oid);
	 * when it makes sense.
			l->item = c;
	int i, invalidate_min, invalidate_max, offset_b,
	for (ent = sb->ent; ent && (next = ent->next); ent = next) {
	int *similarities,
				continue;
	split[1].num_lines = chunk_end_lno - split[1].lno;
				  long first_line, long line_count)
		return;
		second_half_start_a, second_half_start_b,
	if (!sb->repo)
	return best_sim_idx;
 * "parent" (and "porigin"), but what we mean is to find scapegoat to
	return -compare_commits_by_commit_date(a, b, c);
				 struct blame_origin *target,
			start_a, start_b,

/* See `struct fingerprint` for an explanation of what a fingerprint is.

	for (i = 0; i < line_count; ++i) {
	struct blame_origin *origin;
static void free_line_fingerprints(struct fingerprint *fingerprints,
				if (sg_origin[j] &&
	return commit;
		o = get_origin(sb->final, path);
	fill_origin_blob(&sb->revs->diffopt, parent, &file_p,
			map_line_number_in_b_to_a);

				entry_a->count -= entry_b->count;
			blame_origin_decref(next->suspect);
				continue; /* does not exist in parent */
			e->next = diffp;
 */
		/* Ignore whitespace pairs */
				       second_best_result,
 * \param second_best_result array of absolute indices in A for the second
 * uses it as a partition. It then calls itself on the lines on either side of
	/* As the fingerprint in A has changed, discard previously calculated
	if (sb->debug) /* sanity */
		}
}
						     potential);
			oidcpy(&norigin->blob_oid, &p->one->oid);
	result->entries = entry;
 * Another complication is that if a line could map onto many lines in the
		(*num_read_blob)++;
/* Subtracts byte-pair elements in B from A, modifying A in place.
			most_certain_local_line_b = i;
		if (certainties[i] >= 0 &&
			      get_commit_tree_oid(origin->commit),
/*
 *
		memset(sg_buf, 0, sizeof(sg_buf));
		die(_("cannot use --contents with final commit object name"));
	score = 1;
static const char *get_next_line(const char *start, const char *end)
	else
		/* The first part (reuse storage for the existing entry e) */
 * 				in A for other lines in A for which
		 * with this special value so it doesn't get invalidated and
	 * establishes a total order.  Comparing as integers gives us
struct fingerprint_entry {
			return;
		dup_entry(unblamed, e, &split[0]);
		case 'T':

			e->unblamable = 1;
	 * Read the current index, replace the path entry with
				  compare_blame_final);
	const struct blame_entry *s1 = p1, *s2 = p2;
static void drop_origin_fingerprints(struct blame_origin *o)
 */
	 * the same parts of the line in A.

	 */

	if (prepare_revision_walk(sb->revs))
	 * closest line in A.
				leftover = e;
	 */
		goto finish;


{
	int best_sim_val = FINGERPRINT_FILE_THRESHOLD;
			/* scale the similarity by (1000 - distance from
 * 0 in B will map onto line 2 in A, and line 1 in B will map onto line 7 in A.

}
		/* The path is the same as parent */
					break;
		} else if (*similarity > second_best_similarity) {
	}
				i, closest_local_line_a,
 * reflect the split.
	 * forget about the splitting.  !split[1].suspect signals this.
	if (tlno < same) {
	memcpy(ce->name, path, len);
	return sb->num_lines;
	}
		invalidate_min = 0;
		else
	oidcpy(&ce->oid, &origin->blob_oid);
				continue;
			}
	return xdi_diff(file_a, file_b, &xpp, &xecfg, &ecb);
	set_blame_suspects(commit, o);
				continue;
 * very small and trivial, and at some point it becomes pointless to
	 * convenient to store the entries in a single array instead of having
				 struct blame_origin *parent, int ignore_diffs)
	add_pending_object(revs, &head_commit->object, "HEAD");
	 * There must be one and only one negative commit, and it must be
		for (p = get_blame_suspects(o->commit); p; l = p, p = p->next) {
		similarity = get_similarity(similarities,
{
 * up to (but not including) same match preimage.


		     (!strcmp(contents_from, "-") ? "standard input" : contents_from)));
	struct blame_entry **srcq;
		add_blame_entry(blamed, &split[1]);
	if (!potential[1].suspect)
	 * max_search_distance_a means that given a line in B, compare it to
	d.parent = parent;
			    revs->pending.objects[i].name, name);
		strbuf_addf(&msg, "parent %s\n",
	if (name_p)
			max_search_distance_a,
				return list1;
			porigin->mode = p->one->mode;
	unsigned int hash, c0 = 0, c1;
	memcpy(dst, src, sizeof(*src));

	}
		*tail = origin->suspects;
	 */
 * 		 in B.
		add_pending_object(sb->revs, &(sb->final->object), ":");
		/*
 */
 * That allows us to build lists in reverse order, then reverse them
				struct blame_entry *next = ent->next;
static void find_move_in_parent(struct blame_scoreboard *sb,
			 struct blame_origin *parent,
					  struct strbuf *sb)
	}
					 &sb->num_read_blob, 0);
	do {
			n = split_blame_at(e, same - e->s_lno,
	struct commit *final_commit = NULL;
 * occurs in the string that the fingerprint represents.
 * Compute how trivial the lines in the blame_entry are.
			continue;
static void find_copy_in_blob(struct blame_scoreboard *sb,
		split[1].s_lno = plno;

		diff_tree_oid(get_commit_tree_oid(parent),

		/* In this loop we discard results for lines in B that are
{
	/*
	     i < num_sg && sg;
	 * Prepare mmfile that contains only the lines in ent.

/*
	if (!unblamed)

 * line to any part of parent file.  That catches cases where a change was
	set_commit_buffer_from_strbuf(r, commit, &msg);
		 */
		split[1].lno = e->lno + tlno - e->s_lno;

		if (!suspect) {
 * plno is where we are looking at in the preimage.
	queue_blames(sb, parent, newdest);
		do {
	struct hashmap_iter iter;
 * of byte pairs to the count of that byte pair in the string, instead of
				leftover = blame_list[j].ent;
		struct object_id blob_oid;
	 * There is no point in sorting: this ends up on a big
		sb->commits.compare = compare_commits_by_reverse_commit_date;
	free(line_starts);
 *
		unsigned ch = *((unsigned char *)cp);
	return lookup_decoration(&revs->children, &commit->object);
			    path);
		struct blame_entry *next;
			else
		if (found)
			++entry;
			 struct blame_entry *ent,
	return found;
	}
		} else {
{
	}
 * <-------------- final image ---------------------->
			if ((p1 = *tail) == NULL) {
 */
	int is_parent;
}
	FREE_AND_NULL(o->file.ptr);

	 * and origin first.  Most of the time they are the
	blame_origin_decref(dst->suspect);
}


			if (!file_p.ptr)
{

		}
{
static void fingerprint_subtract(struct fingerprint *a, struct fingerprint *b)
		tail = head;
	*queue = &dst->next;
			e->next = *diffp;
		invalidate_max = length_b;
		 * We will use this suspect later in the loop,
	hashmap_for_each_entry(&b->map, &iter, entry_b,
			fill_origin_blob(&sb->revs->diffopt, norigin, &file_p,
		}
		mode = canon_mode(st.st_mode);
		blame_origin_incref(suspect);
 *         ^tlno ^same


}
	}
 * For ease of implementation, the fingerprint is implemented as a map
{
 *         ^plno
		if (hash == 0)
	fuzzy_find_matching_lines_recurse(start_a, start_b,
				strbuf_attach(&buf, buf_ptr, buf_len, buf_len + 1);
	d->plno = start_a + count_a;
				blame_origin_decref(porigin);
 * We are looking at the origin 'target' and aiming to pass blame
 * \param similarities array of similarities between lines in A and B

}
			  int tlno, int plno, int same,
	parent = lookup_commit_reference(r, oid);
}
	unsigned mode;
	for (i = 0; i < revs->pending.nr; i++) {
 */
	int *fuzzy_matches;
}
		       PATHSPEC_ALL_MAGIC & ~PATHSPEC_LITERAL,
	diff_setup_done(&diff_opts);
	new_head->num_lines = end - start;

struct fingerprint_entry;
 *                <---- e ----->
	for (e = suspects; e; e = e->next) {
/*
	d->tlno = start_b + count_b;
 */
	if (baa)
			goto finish;

		 */
		split[1].s_lno = plno + (e->s_lno - tlno);
/*
			      struct blame_entry *ent,
 * contiguous lines in the same origin (i.e. <commit, path> pair),

		else {
		if (blame_entry_score(sb, p) <= score_min) {
	if (obj->type != OBJ_COMMIT)
		if (get_oid_hex(line.buf, &oid))
 */
static int *get_similarity(int *similarities,
		if (entry_a) {
 * Count the number of entries the target is suspected for,
 * destination range then we want to choose the line at the center of those
				int opt)
		name = revs->pending.objects[i].name;
 * parent.
 * first 5 lines in B will map onto the first line in the A chunk, while the
}

 * tlno: line number in the target where this chunk begins
	}
			n->next = samep;
			break;
	n->lno = e->lno + len;

	return n;
 * \param map_line_number_in_b_to_a parameter to map_line_number().
		e->suspect = porigin;
 * Merge the given sorted list of blames into a preexisting origin.
	for (i = 0; i < similarity_count; ++i)
				offset_b * (max_search_distance_a * 2 + 1),
	if (p1->s_lno <= p2->s_lno) {

				struct blame_origin *target,
			      "", &diff_opts);
	 * contains the reversed list of entries that have been tested
}

				o->next = get_blame_suspects(commit);
			struct blame_entry *e)
			struct diff_filepair *p = diff_queued_diff.queue[i];
	*queue = &e->next;

 */
						     &sb->revs->diffopt,
			line_blames[i].is_parent = 1;
				break;
	struct blame_entry *unblamed = target->suspects;
						     path, sb->contents_from);
	ident = fmt_ident("Not Committed Yet", "not.committed.yet",
	}
{
	int i;
		struct stat st;
 */
	n->s_lno = e->s_lno + len;
				   int nr_fingerprints)
{
		 * guess_line_blames() can pick *any* line in the parent.  The
/*
	}
 * on-stack blame_entry should lose one refcnt each.
		 !strcmp(r->index->cache[-1 - pos]->name, path))
		head->next = tail;
	verify_working_tree_path(r, commit, path);
		goto error_out;
			n = split_blame_at(e, tlno - e->s_lno, e->suspect);
	}
		case 'A':
		 */
	parent_tail = &commit->parents;
		die("cannot open '%s' for reading",
static void set_commit_buffer_from_strbuf(struct repository *r,
	 */
	struct blame_entry *new_head = xcalloc(1, sizeof(struct blame_entry));
	set_commit_buffer(r, c, buf, len);

				if (sb->found_guilty_entry)
	**srcq = reverse_blame(diffp, reverse_blame(samep, e));
 * ignoredp list) and which stay with the target (added to the diffp list).  The
	}
		mode = 0;
		/* parent and then me */
/*
	if (same < e->s_lno + e->num_lines) {
 * e->num_lines).  The caller needs to sort out the reference counting for the
	if (length_a <= 0)
			best_similarity = *similarity;

	else {
	xecfg.hunk_func = hunk_func;
			if (sg_origin[i])
	d.offset = 0;
 */
	struct blame_entry *leftover = NULL;
 * 				similarities may be calculated.
	if (fill_fingerprints)
static struct blame_suspects blame_suspects;
		} else {
				sb->ent = suspect->suspects;
	struct commit_list *sg;
{

	int length_a = parent_len;
 */

			pass_blame(sb, suspect, opt);
	target->suspects = reverse_blame(leftover, NULL);
 * Essentially this mapping is a simple linear equation but the calculation is
static void get_line_fingerprints(struct fingerprint *fingerprints,
 * A fingerprint is represented as a multiset of the lower-cased byte pairs in
}



					  similarities,
		if (!porigin)
	if (best_similarity == 0) {

	*blametail = NULL;
	struct line_number_mapping map_line_number_in_b_to_a = {
	/*

			origin->suspects = blame_merge(origin->suspects, toosmall);
			line_blames[i].is_parent = 0;

	return result;
		split[i].unblamable = e->unblamable;
		e->suspect = blame_origin_incref(parent);
struct line_number_mapping {
 * \param max_search_distance_a maximum distance in lines from the closest line
		chunk_end_lno = e->lno + e->num_lines;
		}
	/*
	if (is_null_oid(&target->commit->object.oid))
static void set_blame_suspects(struct commit *commit, struct blame_origin *origin)
		split[2].suspect = blame_origin_incref(e->suspect);
/*
 */
	sb->num_read_blob++;
 */

		num_ents++;
{
	hashmap_init(&result->map, NULL, NULL, max_map_entry_count);
	if (!parent)
		switch (p->status) {
	 * force diff_tree_oid() to feed all filepairs to diff_queue,
}
		struct blame_origin *suspect = get_blame_suspects(commit);
	if (diff_hunks(file_p, &file_o, handle_split_cb, &d, sb->xdl_opts))
	int i, search_start, search_end, closest_local_line_a, *similarity,
	ce = make_empty_cache_entry(r->index, len);

	for (i = 0; i < length_b; ++i) {


	       max_search_distance_a +
 * Fill the blob_sha1 field of an origin if it hasn't, so that later
/*
				find_copy_in_blob(sb, blame_list[j].ent,
 * for the lines in 'e' are in line_blames.  This consumes e, essentially
 * blame_origin, and choosing the best matches that preserve the line ordering.
		num++;
			      get_commit_tree_oid(target->commit),

					  const struct object_id *oid)
static struct blame_entry *reverse_blame(struct blame_entry *head,
 * possibilities.
	int *certainties,
	if (oid_object_info(r, &origin->blob_oid, NULL) != OBJ_BLOB)
static struct blame_entry **filter_small(struct blame_scoreboard *sb,
				    oideq(&sg_origin[j]->blob_oid, &porigin->blob_oid)) {
	else if (-1 - pos < r->index->cache_nr &&
		    (!contents_from ? path :

	struct blame_entry *oldsmall = *small;
 * parent_len: number of lines in the parent chunk
	return small;
/* Move all blame entries from list *source that have a score smaller
			ignore_blame_entry(e, parent, &diffp, &ignoredp,
					 struct blame_entry **small,
	if (invalidate_min < 0)
	memset(&d, 0, sizeof(d));
			sanity_check_refcnt(sb);
	} else {
		/* treat root commit as boundary */
	 * (either the parent or the target).
	}
			 * fingerprints if we use the parent again, which can
					continue;
static struct blame_origin *make_origin(struct commit *commit, const char *path)

			if (!sg_origin[i]->suspects)

};
}
	diffcore_std(&diff_opts);
	head_commit = lookup_commit_reference_gently(revs->repo,
			}

			/* Move second half to a new record */
 */
			      0, o->num_lines);

		}
 * it avoids unnecessary writes.
			      struct blame_entry *split,
	diffcore_std(&diff_opts);
		start_a, length_a, start_b, length_b
	 * with the same line in A according to max_search_distance_a.
static void append_merge_parents(struct repository *r,
		samep = e;
					struct commit *parent,
			tail = &(*tail)->next;
 * For example, the string "Darth   Radar" will be converted to the following
		die("no such commit %s", oid_to_hex(oid));
			if (!porigin)

{
 *  ao, bo, co, do, eo,
			struct blame_origin *target, int ignore_diffs)
		 * won't be recalculated.
			if (split[1].suspect &&
static int find_line_starts(int **line_starts, const char *buf,
					  struct blame_origin *new_suspect)
	if (most_certain_local_line_b == -1)

	else if (!split[0].suspect && !split[2].suspect)
			 * case
				*tail = p2;

 * diff machinery
		queue_blames(sb, porigin, suspects);
	/* Repeat the matching process for lines after the most certain line.
		blame_origin_decref(split[i].suspect);
}
	struct blame_origin *o;
	clear_pathspec(&diff_opts.pathspec);
	samep = NULL;
	diff_opts.detect_rename = DIFF_DETECT_RENAME;
	int start_b = tlno;
	parse_pathspec(&diff_opts.pathspec,
	}
 * we do not underflow.
	 * want to run "diff-index --cached".
	 * distance between lines in B such that they will both be compared
	 */
			   int line_a, int local_line_b,

}
			norigin->mode = p->one->mode;

			ent->next = next->next;
		 * commit had it as a directory, we will see a whole

 * exonerate ourselves.
{
 * 		 in B.
/*
			       struct blame_entry **diffp,
 * consists of len lines, i.e. [e->lno, e->lno + len), and the second part,
	 *
		 * and line Z that matches only one line with a score or 2,
				      int tlno, int parent_slno, int same,
					       struct diff_options *opt,

		*lineno++ = p - buf;
			 */
 * Puts the fingerprints in the fingerprints array, which must have been
			tail = &p2->next;
	 * line in A such that their ordering contradicts the ordering imposed
	struct strbuf msg = STRBUF_INIT;
	}
		sb->final = find_single_final(sb->revs, &final_commit_name);
 * {"\0d", "da", "da", "ar", "ar", "rt", "th", "h\0", "\0r", "ra", "ad", "r\0"}
		filter_small(sb, &toosmall, &origin->suspects, sb->move_score);
		die("unable to generate diff (%s)",
		tlno += ent->s_lno;
			second_half_length_a, second_half_length_b,
			 struct blame_entry *split)

					 unsigned score_min)
	 * bits; we are not going to write this index out -- we just
	new_head->lno = start;
			porigin = get_origin(parent, origin->path);
		; /* path is in the index, unmerged */

			 &sb->num_read_blob, ignore_diffs);
		origin->file.ptr = NULL;
		/* this line definitely doesn't match with anything. Mark it
				return;
			c1 = tolower(*p);
const char *blame_nth_line(struct blame_scoreboard *sb, long lno)
{
static int compare_commits_by_reverse_commit_date(const void *a,

 * This moves the origin to front position in the commit util list.
	file_o.size = blame_nth_line(sb, ent->lno + ent->num_lines) - cp;
		 * do not default to HEAD, but use the working tree
};

		}
			continue;
		 * check at a later stage of the matching process whether the
		if (abs(most_certain_line_a - start_a - closest_local_line_a) >
	else {
	int len;
	}
 * final image, prepare an index in the scoreboard.
	struct fingerprint_entry *found_entry;
	/* remainder, if any, all match the preimage */
	 *
		decref_split(potential);
	struct object_id head_oid;
	close(merge_head);
 * \param max_search_distance_a maximum distance in lines from the closest line
		if (!strcmp(porigin->path, origin->path)) {

 * 			     closest match of a line in B.
	if (best_so_far[1].suspect) {
		source_start, source_length;
		sb->final = find_single_initial(sb->revs, &final_commit_name);

	 * Optionally find copies from parents' files.
	return 0;
	mmfile_t file_p, file_o;
{
	struct diff_options diff_opts;
		 * passed to the parent, including those that are unrelated to
			if (!same)
unsigned blame_entry_score(struct blame_scoreboard *sb, struct blame_entry *e)
 * and prepare a list of entry and the best split.
		suspects = reverse_blame(suspects, NULL);
	struct strbuf buf = STRBUF_INIT;
			struct blame_origin *porigin = sg_origin[i];
 * tlno is where we are looking at in the final image.
static void pass_blame(struct blame_scoreboard *sb, struct blame_origin *origin, int opt)
 * Given a commit and a path in it, create a new origin structure.

				       length_a,

	target->suspects = reverse_blame(leftover, NULL);
	int i;
					 struct blame_entry **source,


		hashmap_entry_init(&entry->entry, hash);
	struct fingerprint_entry *entry = xcalloc(max_map_entry_count,
		return;
 */
	}
	struct blame_entry *ent;
		     i < num_sg && sg;
			start_a + second_best_similarity_index;
 * to be blamed for the parent, and after that portion.
	add_index_entry(r->index, ce,
			if (oideq(&porigin->blob_oid, &origin->blob_oid)) {
				struct blame_origin *porigin = sg_origin[i];
				struct blame_entry ***blamed,
		}
	diffp = NULL;
{
			     int *num_read_blob, int fill_fingerprints)
	 * fingerprint represents.
					entry_a->count : entry_b->count;
	int i;
/*
		second_half_length_b =
			blame_origin_decref(e->suspect);
			WANT_BLANK_IDENT, NULL, 0);
			*ignoredp = e;
				else
	time_t now;
	suspects = origin->suspects;
				entry /* member name */) {
		second_best_result[i] = -1;
	/* Repeat the matching process for lines before the most certain line.
	int length_a, int length_b,
			fingerprints_a, fingerprints_b, similarities,
	return new_head;

		second_half_length_a, second_half_length_b,
	strbuf_release(&line);
				      same - tlno);
	if (!target->suspects)
		if (*similarity == -1) {
		free(blame_list);
			commit->object.flags |= UNINTERESTING;
		o->file = *file;
		split_overlap(potential, ent, tlno, plno, same, parent);
		second_best_result[local_line_b] =
		best_similarity = 0, second_best_similarity = 0,
 * with respect to the parent's line numbers yet.

		    ent->unblamable == next->unblamable) {
			for (j = 0; j < num_ents; j++) {
			      get_commit_tree_oid(origin->commit),
	struct blame_list *blame_list;
	int i, pass, num_sg;

	if (!p2)
	*d.dstq = NULL;
	struct blame_list *blame_list = NULL;
	int *line_starts;
		unsigned long buf_len;
 */
 * See if lines currently target is suspected for can be attributed to
	} while (unblamed);

			blame_origin_decref(norigin);
			continue;
				struct blame_origin *porigin,
		entry_len = 1;
	 * Subtract the most certain line's fingerprint in B from the matched
		struct commit *c = final_commit;
	}

		} else {
	}

	d.sb = sb; d.ent = ent; d.parent = parent; d.split = split;
				entry /* member name */) {
 * differing) on the parent, and then splits blame entries at the
	if (o && --o->refcnt <= 0) {
 */
 * new entry's suspect.
		/*
		sb->revs->children.name = NULL;
{
	for (i = 0; i < length_b; ++i) {
	origin->mode = S_IFINVALID;

		 * e and replace it with the parent.

					       &line_blames[i + 1])) {
		}
}
 * For example, if max_search_distance_a is 2 and the two sides of a diff chunk

	#define FINGERPRINT_FILE_THRESHOLD	10

	struct blame_entry **dstq;
	e->score = score;
 *
	struct rev_info *revs = sb->revs;
		}
	}
			       struct blame_line_tracker *line_blames)
	const char *nl = memchr(start, '\n', end - start);
	assert(!e);
{
		}
		    ident, ident, path,
	/*
	int *certainties,
			      struct blame_origin *target,
		struct object *obj = revs->pending.objects[i].item;
	num_sg = num_scapegoats(revs, commit, sb->reverse);
				(1000 - abs(i - closest_local_line_a));
#include "tag.h"
					  const char **name_p)
		       PATHSPEC_LITERAL_PATH, "", paths);
	     sg = sg->next, i++) {
		    (result[i] <= most_certain_line_a ||
	/*


static void pass_whole_blame(struct blame_scoreboard *sb,
{
			    const char *line_begin,
					   line_blames + e->s_lno - tlno);
static void find_best_line_matches(
			next = e->next;
	struct commit_list *parents;
	/*
	struct fingerprint *fingerprints_b,
				    &sb->final_buf_size))
	ALLOC_ARRAY(*line_starts, num + 1);
			c = c->parents->item;
					      blame_origin_incref(e->suspect));
				struct blame_origin *parent)
		split[2].lno = e->lno + (same - e->s_lno);
 * best_so_far[] and potential[] are both a split of an existing blame_entry
static void queue_blames(struct blame_scoreboard *sb, struct blame_origin *porigin,
 * which is returned, consists of the remainder: [e->lno + len, e->lno +
}
 * bst_so_far as needed.
	time(&now);
void init_scoreboard(struct blame_scoreboard *sb)
static void *get_next_blame(const void *p)

		else
			p = *small;
 * of a diff chunk to the line in the other half of the diff chunk that is
		    git_path_merge_head(r));
	struct fingerprint_entry *entry_a;
	}
#include "mergesort.h"
		BUG("repo is NULL");
 * 			      according to max_search_distance_a.
		unsigned short mode;
	int i, j;

	e->score = 0;
	else {
			commit = prio_queue_get(&sb->commits);
		if (certainties[i] >= 0 &&
 * This also fills origin->mode for corresponding tree path.
			      mmfile_t *file_p)
			    const struct blame_entry *src)
}
static void split_blame(struct blame_entry ***blamed,
 * \param max_search_distance_b an upper bound on the greatest possible
 * is 0.

	struct blame_origin *o;

		if (!(obj->flags & UNINTERESTING))

