
	return;
#include "line-range.h"
	for (i = 0; i < diff->target.nr; i++) {
}
	}
	struct diff_queue_struct outq;
			diff_free_filepair(p);
			continue;
	fprintf(opt->file, "%s%s+++ b/%s%s\n", prefix, c_meta, pair->two->path, c_reset);
		ip->next = p;
{
			    revs->pending.objects[i].name,
	int changed;
}
		}
		cb_data.line_ends = ends;

				 struct diff_filepair *pair,
		free(pairdiff);
	dst->nr = src->nr;
 * Thing(tm).  log -L should be built into the diff pipeline.
 *

				 * b exhausted, or
	if (!pair || !diff)
		if (obj->type != OBJ_COMMIT)
	assert(d->spec && d->spec->data);
void line_log_init(struct rev_info *rev, const char *prefix, struct string_list *args)
		if (!name_part || *name_part != ':' || !name_part[1])
	while (list) {
		if (!changed) {
			   long *lines,
{
static struct line_log_data *
				start = b->ranges[j].end;
{

		end--;
				 char *path,

				range_set_append(out, start, end);
static int process_ranges_arbitrary_commit(struct rev_info *rev, struct commit *commit)
{


/*


			    item->string);
void sort_and_merge_range_set(struct range_set *rs)
		file_parent.size = 0;

	}
	struct diff_ranges *touched = xmalloc(sizeof(*touched));
	int i, changed = 0;
	if (pair->one->oid_valid) {
		while (j < diff->target.nr && src[i].start >= target[j].start) {
		}
	data = spec->data;

		if (strcmp(pathspec->items[i].match, r->path))
static void diff_ranges_release(struct diff_ranges *diff)
		} else {
				/*
		if (p->object.flags & UNINTERESTING)
		range_part = xstrndup(item->string, name_part - item->string);
void range_set_append_unsafe(struct range_set *rs, long a, long b)
}
	return !(a->end <= b->start || b->end <= a->start);
static void range_set_check_invariants(struct range_set *rs)
		add_line_range(rev, parents[i], cand[i]);
static struct diff_filepair *diff_filepair_dup(struct diff_filepair *pair)
		assert(rg->path);
	return changed;

		die("There is no path %s in the commit", spec->path);
	struct line_log_data **cand;
 * Unlike most other functions, this destructively operates on
		rg = rg->next;
		long t_start = range->ranges.ranges[i].start;
	struct range_set tmp;
			rg->pair = diff_filepair_dup(queue->queue[i]);
}
		struct range *new_range;
	unsigned int i, j =  0;

	}
	}
		while (j < diff->target.nr && diff->target.ranges[j].end < t_start)
		return 0;
		}
}
{
		free_line_log_data(old_line);
	struct line_log_data *range = lookup_line_range(rev, commit);
{
				 */
	unsigned int o = 0; /* output cursor */
			 *

		if (!commit->parents || !commit->parents->next)
		printf("\t[%ld,%ld]\t[%ld,%ld]\n",
	unsigned long *ends = NULL;
	range_set_copy(&ret->ranges, &r->ranges);
search_line_log_data(struct line_log_data *list, const char *path,
		FREE_AND_NULL(ends);
	struct line_log_data *p = list;

		pp = &d->next;
 * ranges in the diff that was touched, we remove the latter and add
		cb_data.lines = lines;
	return head;
	if (!r)
		if (rg)
			b = b->next;
		/* different number of pathspec items and ranges */
			j++;


	commit = check_single_commit(rev);
	range_set_release(dst);
		struct diff_filepair *pair = queue->queue[i];
 */
}

			rs->ranges[o].end = rs->ranges[i].end;
}
		else
				print_line(prefix, '-', k, p_ends, pair->one->data,
		dump_diff_hacky_one(rev, range);
	unsigned short mode;
		assert(rs->ranges[i].start < rs->ranges[i].end);
{
}
			 * since that's the commit that caused the
		range = range->next;
		 * Compute parent hunk headers: we know that the diff


		if (i < a->nr && j < b->nr) {

{
			continue;
	} else {
	diff_populate_filespec(rev->diffopt.repo, pair->two, 0);
		if (!p->parents)
			}

	rev->commits = out;
			for (k = diff->parent.ranges[j].start; k < diff->parent.ranges[j].end; k++)

			continue;
struct collect_diff_cbdata {

				       struct line_log_data *range)
	int i;
static int ranges_overlap(struct range *a, struct range *b)
		struct object *obj = revs->pending.objects[i].item;
	struct line_log_data *d;
 * the ranges for which the commit is responsible.
			     struct line_log_data *range)

 */
	struct diff_options *opt = &rev->diffopt;
}
	ALLOC_ARRAY(ends, size);
	while (i < a->nr || j < b->nr) {
	char *prefix = output_prefix(opt);
				 */
	} else {
		nparents = 1;
}
	new_filepair->two = pair->two;
 * In-place pass of sorting and merging the ranges in the range set,
	}
	if (range) {
/*
	const struct range *s = _s;
	struct line_log_data *ret = NULL;
		if (!p_start && !p_end) {
	}
	ALLOC_ARRAY(cand, nparents);
	    const char *prefix, struct string_list *args)
	struct nth_line_cb cb_data;

			/*
			return p;
		}
	struct line_log_data *rg = range;
	for (i = 0; i < rs->nr; i++)
static int collect_diff_cb(long start_a, long count_a,
		assert(rs->ranges[i-1].end < rs->ranges[i].start);


	long lines = 0;
		cb_data.spec = spec;
	return NULL;
static void range_set_shift_diff(struct range_set *out,
	DIFF_QUEUE_CLEAR(&diff_queued_diff);
		if (!(p->object.flags & TREESAME))
		snprintf(buf, 4096, "file %s\n", r->path);
	for_each_string_list_item(item, args) {
		r = next;
{
	while (num < spec->size) {
	}
		p = p->next;
			free(cand);
		else
		parse_pathspec_from_ranges(&opt->pathspec, range);
		if (rs->ranges[i].start == rs->ranges[i].end)
		return 0;
	rs->ranges = NULL;
	return ret;
		}
			range_set_union(&d->ranges, &src->ranges, &src2->ranges);
	add_line_range(rev, commit, range);

					 diff->parent.ranges[i].end);
#include "tag.h"
		long begin = 0, end = 0;
}
}
		if (p->parents && p->parents->next)
	char *begin = get_nth_line(line, ends, data);
		long end = a->ranges[i].end;
			for (; t_cur < diff->target.ranges[j].end && t_cur < t_end; t_cur++)
			if (j == rs->nr)
	old_line = lookup_decoration(&revs->line_log_data, &commit->object);
			; /* empty range */
{
		commit = obj;
		name_part++;
		queue_diffs(range, &rev->diffopt, &diffqueues[i], commit, parents[i]);
	ALLOC_ARRAY(diffqueues, nparents);
				/*
{

	struct range_set tmp1 = RANGE_SET_INIT;

		d->path = xstrdup(src->path);
		dump_diff_hacky(rev, range);
static int same_paths_in_pathspec_and_range(struct pathspec *pathspec,
	}
#include "argv-array.h"
			   long start_b, long count_b,
			 * diff.

		return (char *)data + ends[line] + 1;
			return rewrite_one_ok;
	parse_pathspec(pathspec, 0, PATHSPEC_PREFER_FULL, "", paths);
		die("No commit specified?");
			free_diffqueues(nparents, diffqueues);
}

			*pp = list;
			j++;
	if (pair->one->oid_valid)
			print_line(prefix, ' ', t_cur, t_ends, pair->two->data,
				print_line(prefix, '+', t_cur, t_ends, pair->two->data,
	assert(pair->two->path);
			for (; t_cur < diff->target.ranges[j].start; t_cur++)
static void dump_diff_hacky(struct rev_info *rev, struct line_log_data *range)
				  struct range_set *a, struct range_set *b)
			free(parents);
	while (a || b) {

			range_set_grow(out, 1);
		file_parent.ptr = "";
			out->ranges[out->nr].start = new_range->start;
	FREE_AND_NULL(rs->ranges);
	char *prefix = "";
		*pp = d;


		long t_end = range->ranges.ranges[i].end;
		     struct line_log_data **insertion_point)

}
			struct diff_queue_struct *queue,
			commit_list_append(parents[i], &commit->parents);
static void fill_line_ends(struct repository *r,
}
	struct argv_array array = ARGV_ARRAY_INIT;

	memset(&xecfg, 0, sizeof(xecfg));

	range_set_init(dst, src->nr);
	struct diff_queue_struct *diffqueues;
	assert(d && line <= d->lines);
	/* cannot make an alias of out->ranges: it may change during grow */
static int range_cmp(const void *_r, const void *_s)

	}
	move_diff_queue(queue, &diff_queued_diff);
			else
	for (i = 0; i < range->ranges.nr; i++) {
			else
	return 1;
		p = p->next;
	long p_lines, t_lines;
		if (process_diff_filepair(rev, pair, *range_out, &pairdiff)) {
}
		return (char *)d->spec->data + d->line_ends[line] + 1;
	assert(r);
			   struct diff_filespec *spec,
	diff_tree_oid(parent_tree_oid, tree_oid, "", opt);
static void line_log_data_clear(struct line_log_data *r)

	/* this could be simply 'return r.start-s.start', but for the types */
				 * b:         |----
	fill_line_ends(rev->diffopt.repo, pair->two, &t_lines, &t_ends);
		return (char *)d->spec->data;
	if (opt->detect_rename && diff_might_be_rename()) {
{
	}
		if (!a)
	ends[cur++] = 0;

			src2 = b;
		j_last = j;
}
			return rewrite_one_noparents;
			src = a;
	}

static void diff_ranges_filter_touched(struct diff_ranges *out,
	fprintf(rev->diffopt.file, "%s\n", output_prefix(&rev->diffopt));
		parent = commit->parents->item;
		diff_tree_oid(parent_tree_oid, tree_oid, "", opt);
		range_set_grow(rs, prealloc);
	struct range *src = rs->ranges;
#include "cache.h"
	unsigned int i, j = 0;


	struct line_log_data *r;
			changed = process_ranges_ordinary_commit(rev, commit, range);
						 struct line_log_data *b)
				break;
	return ret;
{

	if (insertion_point)
				 * b:    |--?????
				if (start < b->ranges[j].start)
		if (commit)
		diff_populate_filespec(rev->diffopt.repo, pair->one, 0);
	return 1;
	return ((*diff_out)->parent.nr > 0);
	return 0;
	const char *c_old = diff_get_color(opt->use_color, DIFF_FILE_OLD);
	rs->ranges[rs->nr].start = a;
	parent_tree_oid = parent ? get_commit_tree_oid(parent) : NULL;
	return changed;
		assert(rs->ranges[0].start < rs->ranges[0].end);
		       p_start+1, p_end-p_start, t_start+1, t_end-t_start,
}
			rs->ranges[o].start = rs->ranges[i].start;
					    struct line_log_data *range)
	struct line_log_data *ip;

	assert(r);
/* tack on a _new_ range _at the end_ */
	*lines = cur-1;
			range_set_append(&out->target,
 * Given a diff and the set of interesting ranges, determine all hunks
	range_set_release(&r->ranges);
	dst->ranges = src->ranges;
 */
		range_set_append(&d->diff->target, start_b, start_b + count_b);
#include "userdiff.h"
	for (i = 0; i < rs->nr; i++) {
#include "log-tree.h"
			memcpy(&rg->diff, pairdiff, sizeof(struct diff_ranges));
void range_set_release(struct range_set *rs)
			cmp = 1;
}
				    lines, anchor, &begin, &end,
					 diff->target.ranges[i].end);
		if (!strcmp(rg->path, pair->two->path))
		filter_diffs_for_paths(range, 0);
	while (r) {
	new_filepair->one->count++;
		full_name = prefix_path(prefix, prefix ? strlen(prefix) : 0,
		 * fall in this range.
	}
/*
}

	struct line_log_data *r;
#include "strbuf.h"
		new_line = line_log_data_copy(range);

				 * b: |------|

		found = i;
		num++;
}
		struct line_log_data *src2 = NULL;
		}

	struct range *parent = diff->parent.ranges;
static void free_diffqueues(int n, struct diff_queue_struct *dq)

	free(p_ends);
{
	if (end > begin && end[-1] == '\n') {

	/* NEEDSWORK should apply some heuristics to prevent mismatches */

	free(rg->path);
}
	range_set_move(&rg->ranges, &tmp);
	printf("\tparent\ttarget\n");
		else                       /* a exhausted */
	assert(out->nr == 0);
	cbdata.diff = out;
			   unsigned long **line_ends)
}

				 struct diff_ranges **diff_out)
			if (ra[i].start < rb[j].start)
			struct commit *commit, struct commit *parent)
			if (start >= b->ranges[j].start) {
	range_set_init(&tmp, 0);
/* merge two range sets across files */
		int changed;
}
	assert(a <= b);
	struct range *rb = b->ranges;
	    !same_paths_in_pathspec_and_range(&opt->pathspec, range)) {
	if (rg->ranges.nr == 0)
{
	dst->alloc = src->alloc;
	xecfg.ctxlen = xecfg.interhunkctxlen = 0;
{

}
	int num = 0, size = 50;
		free(r);
{
{
 * Difference of range sets (out = a \ b).  Pass the "interesting"
	int nparents = commit_list_count(commit->parents);
	long cur = 0;

		commit->object.flags |= TREESAME;
 * across the diff.  That is: observe that the target commit takes
		prev = tmp;
		if (j == diff->target.nr || diff->target.ranges[j].start > t_end)
		int cmp = strcmp(p->path, path);
{
	else
			clear_commit_line_range(rev, commit);
	for (i = 0; i < nparents; i++) {
{
	free(diff_queued_diff.queue);
		*pp = p->parents->item;
		line_log_data_clear(r);

			if (keep_deletions)
	diff_ranges_filter_touched(touched, diff, rs);
	*line_ends = ends;
{
		if (src2)
{
	fputs(reset, file);
			anchor = 1;
	       c_reset);
}
{
	xecfg.hunk_func = collect_diff_cb;
	if (!rs)
			cmp = strcmp(a->path, b->path);
{
		struct line_log_data *range = lookup_line_range(rev, commit);
		sort_and_merge_range_set(&p->ranges);

		}
	struct object_id oid;
	memcpy(dst, src, sizeof(struct diff_queue_struct));
			 */
		range_set_append(out, src[i].start+offset, src[i].end+offset);
	} else if (range)
 * its parent side.
	*range_out = line_log_data_copy(range);
			return 0;
}
	}
		r = r->next;
			    revs->pending.objects[found].name);
				- (target[j].end-target[j].start);
				   c_context, c_reset, opt->file);

		struct commit *p = *pp;
	for (i = 0; i < nparents; i++) {


					   c_context, c_reset, opt->file);
#include "line-log.h"
{


	}
{

				 */
			changed++;
	range_set_shift_diff(&tmp2, &tmp1, diff);
			if (!strcmp(rg->path, p->two->path))

	int i;
		else
				    full_name, r->index))
static void range_set_map_across_diff(struct range_set *out,

{
	if (r->start < s->start)
{
	}

			break;
		char *full_name;
		if (o > 0 && rs->ranges[i].start <= rs->ranges[o-1].end) {
 * removed.
			   void *data)
{
/* dst must be uninitialized! */
		struct diff_ranges *pairdiff = NULL;
				 struct range_set *rs,
			end = lines;

				 * b: ------|
		prev->next = tmp;

		dump_range_set(&r->ranges, buf);
		range_set_append_unsafe(&p->ranges, begin, end);
	range_set_init(&r->ranges, 0);
	long lines;

	struct diff_filepair *pair = range->pair;
	struct line_log_data *tmp = NULL, *prev = NULL;
	if (count_b >= 0)
	if (get_tree_entry(r, &commit->object.oid, spec->path, &oid, &mode))
		 */
	const char *c_frag = diff_get_color(opt->use_color, DIFF_FRAGINFO);
 */
	for (r = range; r; r = r->next)
			if (j >= b->nr || end < b->ranges[j].start) {
		parents[i] = p->item;
{
#include "commit.h"

static char *output_prefix(struct diff_options *opt)
		}
int line_log_filter(struct rev_info *rev)

	int found = -1;
	p = xcalloc(1, sizeof(struct line_log_data));


	unsigned long *ends = NULL;
		else if (!b)

line_log_data_copy(struct line_log_data *r)
	if (collect_diff(&file_parent, &file_target, &diff))
		struct line_log_data *rg = NULL;
	}
 * This is also where the ranges are consolidated into canonical form:
	if (!(rev->diffopt.output_format & DIFF_FORMAT_NO_OUTPUT)) {
	queue_diffs(range, &rev->diffopt, &queue, commit, parent);
	p->path = path;
	r = lookup_decoration(&revs->line_log_data, &commit->object);
	if (r->pair)
		if (process_ranges_arbitrary_commit(rev, commit)) {
	if (old_line && range) {
	DIFF_QUEUE_CLEAR(src);
 * Union of range sets (i.e., sets of line numbers).  Used to merge
		 * the line numbers of the first/last hunk(s) that
	if (line == 0)
 * blame for all the + (target-side) ranges.  So for every pair of
	if (count_a >= 0)
					 diff->target.ranges[i].start,
	}

static void dump_range_set(struct range_set *rs, const char *desc)
		}
				rg = rg->next;
{
	REALLOC_ARRAY(ends, cur);
	}
}

		if (!DIFF_FILE_VALID(diff_queued_diff.queue[i]->one)) {
{
			add_line_range(rev, parents[i], cand[i]);
 * 'range'.
{
	free(cand);
		if ((!lines && (begin || end)) || lines < begin)
	}
	struct diff_queue_struct queue;

	/* strings are now owned by pathspec */
			new_range = &rb[j++];
{
	range_set_check_invariants(rs);
	unsigned int i, j = 0;
static struct line_log_data *
static void free_line_log_data(struct line_log_data *r)
			 * trashes the previous one's diff.
/* Either initialization would be fine */
	struct line_log_data *ranges = NULL;
			   struct diff_filespec *spec)
 * of the diff which touch (overlap) at least one of the interesting
	line_log_data_init(ret);
			out->ranges[out->nr].end = new_range->end;
		for (rg = range; rg; rg = rg->next) {
				/*
			   struct line_log_data *range)
	struct line_log_data *old_line = NULL;

	free(parents);
	int i;
	int changed = 0;
	struct diff_ranges *diff = &range->diff;
	/* NEEDSWORK evil merge detection stuff */
static inline int diff_might_be_rename(void)
	for (i = 0; i < diff_queued_diff.nr; i++)
{
	int i, j;

}
		*list = p;
		fill_line_ends(rev->diffopt.repo, pair->one, &p_lines, &p_ends);
	assert(o <= rs->nr);
	 * from the above loop to the parents.
	if (line == 0)
/*
	dst->nr = src->nr;

	struct diff_filespec *spec;
	COPY_ARRAY(dst->ranges, src->ranges, src->nr);
	file_target.ptr = pair->two->data;
			new_range = &ra[i++];
	range_set_release(&rg->ranges);
	DIFF_QUEUE_CLEAR(&outq);
	p = commit->parents;
	memset(&ecb, 0, sizeof(ecb));

	if (diff_populate_filespec(r, spec, 0))
			ends[cur++] = num;
			assert(rg);

			return rewrite_one_ok;
	int i;
	QSORT(rs->ranges, rs->nr, range_cmp);
			p_end = diff->parent.ranges[j_last].end + (t_end-diff->target.ranges[j_last].end);
	struct range *target = diff->target.ranges;
	int i;

		range_set_check_invariants(&d->ranges);
		die("Cannot read blob %s", oid_to_hex(&spec->oid));

				 struct line_log_data *range,

	}
	range_set_difference(&tmp1, rs, &touched->target);
		fputs("\\ No newline at end of file\n", file);
		struct strbuf *sb = opt->output_prefix(opt, opt->output_prefix_data);

				       struct diff_ranges *diff,
	while (p) {
	if (commit->parents)
static int process_ranges_ordinary_commit(struct rev_info *rev, struct commit *commit,
	range_set_init(&diff->target, 0);


			     struct range_set *a, struct range_set *b)
	struct diff_ranges diff;
	return ranges;
		       long line, unsigned long *ends, void *data,
			die("-L argument not 'start,end:file' or ':funcname:file': %s",
	free_line_log_data(r);
				 * a: |-----|
	if (prealloc)
	return xdi_diff(parent, target, &xpp, &xecfg, &ecb);
{
	struct line_log_data *p = search_line_log_data(*list, path, &ip);
/*
	for (i = 0; i < nparents; i++) {

		} else
	}
/*
	struct commit *commit;
			else if (ra[i].end < rb[j].end)

				start = b->ranges[j].end;
 * the "unused function" warning.
	if (opt->detect_rename &&
	if (rs->nr)
static void range_set_union(struct range_set *out,

				diff_q(&outq, p);

				      struct diff_ranges **touched_out)
			p_start = diff->parent.ranges[j].start;
		for (; t_cur < t_end; t_cur++)
		if (cmp < 0) {
	int i;
 * caller needs.
			return 1;
	}
	struct line_log_data *r;
	return 0;

		if (obj->flags & UNINTERESTING)
				diff_free_filepair(p);

	}
	}
	ALLOC_ARRAY(parents, nparents);
	return 1;
}
	if (nparents > 1 && rev->first_parent_only)
	struct object *commit = NULL;
	if (new_line)
	struct range *ra = a->ranges;
		}

static void range_set_difference(struct range_set *out,
{
			out->ranges[out->nr-1].end = new_range->end;


}
	}
	printf("diff ranges %s (%d items):\n", desc, diff->parent.nr);
 * Given a diff and the set of interesting ranges, map the ranges
	while (r) {
static void diff_ranges_init(struct diff_ranges *diff)
	paths = argv_array_detach(&array);
	src->alloc = src->nr = 0;

	if (ip) {
	*touched_out = touched;
				new_range = &rb[j++];
}
			else if (ra[i].start > rb[j].start)
 */




	struct collect_diff_cbdata *d = data;
	while (rg) {

		if (insertion_point && cmp < 0)


	memset(r, 0, sizeof(struct line_log_data));
	if (!had_nl)
		prefix = sb->buf;
	       pair->one->oid_valid ? "a/" : "",
			j_last--;
static struct line_log_data *line_log_data_merge(struct line_log_data *a,
	mmfile_t file_parent, file_target;
		if (ranges_overlap(&diff->target.ranges[i], &rs->ranges[j])) {
		else
	rg->path = xstrdup(pair->one->path);

		fill_line_ends(r, spec, &lines, &ends);
static int process_ranges_merge_commit(struct rev_info *rev, struct commit *commit,
	diff_queued_diff = outq;
}
	range_set_release(&diff->parent);
#include "diff.h"

}
		d = xmalloc(sizeof(struct line_log_data));
}
	range_set_map_across_diff(&tmp, &rg->ranges, &diff, diff_out);
	       pair->one->oid_valid ? pair->one->path : "/dev/null",
static void add_line_range(struct rev_info *revs, struct commit *commit,
	range_set_release(&tmp1);
				 long begin, long end)
		DIFF_QUEUE_CLEAR(&diff_queued_diff);
	}
		*insertion_point = NULL;
	/*
		return;
/*
				 */
		tmp = line_log_data_copy_one(r);
	rs->nr++;
	xpparam_t xpp;
	char buf[4096];
	for (;;) {
};
	assert(pair->two->oid_valid);
		free(path);
		return (char *)data;
	struct commit **parents;
	for (i = 1; i < rs->nr; i++) {

	rs->alloc = rs->nr = 0;

			die("More than one commit to dig from: %s and %s?",
		while (j_last < diff->target.nr && diff->target.ranges[j_last].start < t_end)
 * ranges as 'a' and the target side of the diff as 'b': it removes

	free(paths);
#include "revision.h"
static int process_diff_filepair(struct rev_info *rev,
		free_filespec(spec);
			/*
}
#include "git-compat-util.h"
	for (i = 0; i < rs->nr; i++) {
	struct nth_line_cb *d = data;
	for (i = 0; i < diff_queued_diff.nr; i++) {
			die("Non commit %s?", revs->pending.objects[i].name);
{
		commit = list->item;
{
		else
}
			cmp = -1;
	while (r) {
			return 0;
				/*
	new_filepair->one = pair->one;
			out->nr++;
			j_last++;
}
			o++;
	src->ranges = NULL;
	diff_ranges_init(touched);
			 *
		clear_pathspec(&opt->pathspec);
static void parse_pathspec_from_ranges(struct pathspec *pathspec,
}
					  struct line_log_data *range)

	for (i = 0; i < n; i++)
static int process_all_files(struct line_log_data **range_out,
		if (new_range->start == new_range->end)
	ALLOC_GROW(rs->ranges, rs->nr + extra, rs->alloc);
	assert(out->target.nr == 0);

}
	int i;
		return 0;
	const char **paths;
		/*
static void queue_diffs(struct line_log_data *range,
			src = a;

	range_set_grow(rs, 1);
	if (!changed)
{
			p_start = diff->parent.ranges[j].start - (diff->target.ranges[j].start-t_start);

}
	struct range_set tmp2 = RANGE_SET_INIT;
	if (!commit)
			continue;
		if (!cmp)
int line_log_print(struct rev_info *rev, struct commit *commit)
	*pp = NULL;
			     struct diff_queue_struct *queue,
		return -1;
	return ret;
	diff_ranges_release(&diff);
		fprintf(opt->file, "%s%s@@ -%ld,%ld +%ld,%ld @@%s\n",
				 * a:         |-------
	struct line_log_data *head = NULL, **pp = &head;
		fill_blob_sha1(r, commit, spec);
};
	struct commit *parent = NULL;
		if (end < 1 || lines < end)
	ret = lookup_decoration(&revs->line_log_data, &commit->object);
		add_line_range(rev, parent, parent_range);
}
}
			 * don't follow any other path in history
	rs->alloc = rs->nr = 0;
		       diff->target.ranges[i].end);

{
		} else if (i < a->nr)      /* b exhausted */
				 * a:  ----|
{
		}
 */
	const char *c_meta = diff_get_color(opt->use_color, DIFF_METAINFO);
				 struct diff_ranges *diff)
	return 0;
					   c_new, c_reset, opt->file);
		if (j_last > j)

	char *data = NULL;
{
static struct line_log_data *lookup_line_range(struct rev_info *revs,
	fwrite(begin, 1, end-begin, file);
static void print_line(const char *prefix, char first,
	range_set_append(&p->ranges, begin, end);

static void range_set_grow(struct range_set *rs, size_t extra)
	assert(src != dst);
	struct line_log_data *parent_range;
		rewrite_parents(rev, list->item, line_log_rewrite_one);
			begin = 1;
}
struct nth_line_cb {
		 * So it suffices to shift the start/end according to
			ALLOC_GROW(ends, (cur + 1), size);
				new_range = &rb[j++];
	memset(&xpp, 0, sizeof(xpp));
		spec = alloc_filespec(full_name);
			a = a->next;
			p_start = -1;
	}

 * added/removed in the diff.
	struct object_id *tree_oid, *parent_tree_oid;
		       c_reset);
		return 0;
			range_set_copy(&d->ranges, &src->ranges);
	struct commit *commit = NULL;


}
	free_line_log_data(parent_range);
}

 * overlapping and adjacent ranges are merged, and empty ranges are

{
			j++;
			if (rs->ranges[o-1].end < rs->ranges[i].end)
			a = a->next;
			changed = process_ranges_merge_commit(rev, commit, range);
	for (i = 0; i < diff->parent.nr; i++) {
			to_free = list;
			p_end = -1;
				print_line(prefix, ' ', t_cur, t_ends, pair->two->data,



	const char *c_context = diff_get_color(opt->use_color, DIFF_CONTEXT);
}
	unsigned int i;
	struct commit_list *p;

	return prefix;
		/* must look at the full tree diff to detect renames */
		}
			} else if (end > b->ranges[j].start) {
static void dump_line_log_data(struct line_log_data *r)
			int k;
	putc('\n', file);
 * to establish the invariants when we get the ranges from the user
	unsigned long *line_ends;
		diff_free_filepair(r->pair);
}
	assert(diff->parent.nr == diff->target.nr);
	for (i = 0; i < a->nr; i++) {

 */
		int cmp;

 * NEEDSWORK: manually building a diff here is not the Right
	return new_filepair;
			/* NEEDSWORK leaking like a sieve */
 */
		line_log_data_init(d);
static void range_set_copy(struct range_set *dst, struct range_set *src)
{

		long start = a->ranges[i].start;
	free(dq);
 * ranges in the target.
	char *end = get_nth_line(line+1, ends, data);
		if (t_end > diff->target.ranges[j_last].end)
{
}
	rs->nr = o;
	range_set_init(&diff->parent, 0);
	free_diffqueues(nparents, diffqueues);
		const char *name_part, *range_part;
}


	}
		while (diff->target.ranges[i].start > rs->ranges[j].end) {
	struct line_log_data *new_line = NULL;
	const char *c_new = diff_get_color(opt->use_color, DIFF_FILE_NEW);
	putc(first, file);
{
	struct diff_filepair *new_filepair = xmalloc(sizeof(struct diff_filepair));
{
	unsigned int i;

	range = parse_lines(rev->diffopt.repo, commit, prefix, args);
			/* 	diff_queued_diff.queue[i]->two->path); */
static struct line_log_data *
		long anchor;
		/* Scan ahead to determine the last diff that falls in this range */
				return;
			 * tuck it in the ranges we got as _input_,
		p->next = *list;
	fputs(prefix, file);
/*

{
			struct diff_options *opt,

 */
#endif
		/* Now output a diff hunk for this range */

		return;
	unsigned int i, j = 0;
				rs->ranges[o-1].end = rs->ranges[i].end;

static void dump_diff_ranges(struct diff_ranges *diff, const char *desc)
	/* shrink the array to fit the elements */
}
			return rewrite_one_ok;
	free(t_ends);
					       struct commit *commit)
					 diff->parent.ranges[i].start,

	show_log(rev);

		struct diff_filepair *p = diff_queued_diff.queue[i];
		       diff->target.ranges[i].start,
	}
		had_nl = 1;

	int had_nl = 0;
	if (parent)
		else if (!out->nr || out->ranges[out->nr-1].end < new_range->start) {
	fputs(color, file);
	assert(rs->nr == 0 || rs->ranges[rs->nr-1].end <= a);
static char *get_nth_line(long line, unsigned long *ends, void *data)
		if (t_start < diff->target.ranges[j].start)
			 */

		return;


	clear_commit_line_range(rev, commit);
			while (rg && strcmp(rg->path, pair->two->path))
			range_set_append(&out->parent,
			diff_free_filepair(dq[i].queue[j]);
		       prefix, c_frag,
	return 1;
	for (i = 0; i < revs->pending.nr; i++) {
		p = search_line_log_data(ranges, full_name, NULL);
			/* fprintf(stderr, "diff_might_be_rename found creation of: %s\n", */

}
		} else if (out->ranges[out->nr-1].end < new_range->end) {
		else
		die("unable to generate diff for %s", pair->one->path);
	for (p = ranges; p; p = p->next)
			     struct rev_info *rev,

		while (j < diff->target.nr && diff->target.ranges[j].start < t_end) {
	unsigned int i = 0, j = 0;
				new_range = &ra[i++];
static void range_set_move(struct range_set *dst, struct range_set *src)
	long offset = 0;
 * Check that the ranges are non-empty, sorted and non-overlapping
	if (r->start == s->start)
		} else if (cmp == 0) {
#define RANGE_SET_INIT {0}
			diff_q(&outq, p);
			 * currently each invocation on a merge parent
		       const char *color, const char *reset, FILE *file)
	xdemitconf_t xecfg;
		struct commit_list *to_free = NULL;
}
	for (list = out; list; list = list->next)
	rs->ranges[rs->nr].end = b;
 * them when searches meet at a common ancestor.
 * Note: takes ownership of 'path', which happens to be what the only
	r = r->next;
	return (struct commit *) commit;
}
{
			pp = &list->next;
}
void range_set_init(struct range_set *rs, size_t prealloc)
parse_lines(struct repository *r, struct commit *commit,
	ret->path = xstrdup(r->path);

		file_parent.ptr = pair->one->data;
static void line_log_data_init(struct line_log_data *r)
		 * has the correct line numbers (but not all hunks).
#include "graph.h"
	/* NEEDSWORK leaking like a sieve */
				break;
		else
			src = b;
			    struct diff_queue_struct *src)
{
		printf("\t[%ld,%ld]\n", rs->ranges[i].start, rs->ranges[i].end);
	add_decoration(&revs->line_log_data, &commit->object, NULL);
		struct line_log_data *next = r->next;
				new_range = &ra[i++];
		filter_diffs_for_paths(range, 1);
			b = b->next;
	range_set_union(out, &tmp2, &touched->parent);
		if (data[num] == '\n' || num == spec->size - 1) {
}
		line_log_data_insert(&ranges, full_name, begin, end);
	ret = tmp = prev = line_log_data_copy_one(r);

	new_filepair->two->count++;

		argv_array_push(&array, r->path);
#if 0
static enum rewrite_result line_log_rewrite_one(struct rev_info *rev, struct commit **pp)
		name_part = skip_range_arg(item->string, r->index);
				      struct diff_ranges *diff,
	return changed;
		struct line_log_data *d;
	fprintf(opt->file, "%s%s--- %s%s%s\n", prefix, c_meta,
{
				j++;
	unsigned long *p_ends = NULL, *t_ends = NULL;
	range_set_release(&diff->target);
{
			j++;
	struct diff_ranges *diff;
{
		p->next = ip->next;
	for (i = 0, r = range; i < pathspec->nr && r; i++, r = r->next)
		       diff->parent.ranges[i].start,

}
		list = list->next;
		r = r->next;

	}

		} else {
	if (opt->output_prefix) {
	 * No single parent took the blame.  We add the candidates
				       struct range_set *rs)
		if (!DIFF_FILE_VALID(p->two)) {
/*

			offset += (parent[j].end-parent[j].start)
}
	printf("range set %s (%d items):\n", desc, rs->nr);

	fprintf(opt->file, "%s%sdiff --git a/%s b/%s%s\n", prefix, c_meta, pair->one->path, pair->two->path, c_reset);
			 * NEEDSWORK not enough when we get around to
	file_target.size = pair->two->size;

	if (p) {
					range_set_append(out, start, b->ranges[j].start);
static struct commit *check_single_commit(struct rev_info *revs)
		unsigned int j_last;

static const char *nth_line(void *data, long line)
		add_decoration(&revs->line_log_data, &commit->object, new_line);
	fill_filespec(spec, &oid, 1, mode);
		file_parent.size = pair->one->size;
	if (i < pathspec->nr || r)
	struct line_log_data *range;
}
		if (parse_range_arg(range_part, nth_line, &cb_data,

		clear_pathspec(&opt->pathspec);
#include "xdiff-interface.h"
		free(to_free);
	}
		}
static void dump_diff_hacky_one(struct rev_info *rev, struct line_log_data *range)
 * Adjust the line counts in 'rs' to account for the lines
		long t_cur = t_start;

		for (j = 0; j < dq[i].nr; j++)
	if (!rg)
	tree_oid = get_commit_tree_oid(commit);
			 * doing something interesting with merges;
	while (range) {
	}
	struct commit_list *out = NULL, **pp = &out;
void range_set_append(struct range_set *rs, long a, long b)
		range_set_append(&d->diff->parent, start_a, start_a + count_a);
 */
{
	else
	struct string_list_item *item;
			 * NEEDSWORK tramples over data structures not owned here
		new_line = line_log_data_merge(old_line, range);

					   c_old, c_reset, opt->file);

static void clear_commit_line_range(struct rev_info *revs, struct commit *commit)
#include "decorate.h"

static void fill_blob_sha1(struct repository *r, struct commit *commit,
	}
	const char *c_reset = diff_get_color(opt->use_color, DIFF_RESET);
}
		long p_start, p_end;
		       diff->parent.ranges[i].end,
{
			struct line_log_data *rg = range;
		if (p && p->ranges.nr)
 */
	diff_ranges_init(&diff);
	const struct range *r = _r;
/*
		return;
#include "tree.h"
{


			die("malformed -L argument '%s'", range_part);
{
	range_set_release(&tmp2);
		struct diff_filespec *spec;
		struct line_log_data *src;
{
	}
}

{
		while (start < end) {
		changed = process_all_files(&cand[i], rev, &diffqueues[i], range);
/*
	struct line_log_data *ret = xmalloc(sizeof(*ret));
		diffcore_std(opt);
		cand[i] = NULL;
static void line_log_data_insert(struct line_log_data **list,
	struct line_log_data *p;
	struct line_log_data *ret = NULL;
		}
		obj = deref_tag(revs->repo, obj, NULL, 0);

				 * a:     |--????
static struct line_log_data *line_log_data_copy_one(struct line_log_data *r)
static void filter_diffs_for_paths(struct line_log_data *range, int keep_deletions)
			while (j < b->nr && start >= b->ranges[j].end)
		if (begin < 1)
			 * This parent can take all the blame, so we
	parse_pathspec_from_ranges(&rev->diffopt.pathspec, range);
	struct commit_list *list = rev->commits;
 * These are handy for debugging.  Removing them with #if 0 silences
					name_part);

	for (d = ret; d; d = d->next)
	for (i = 0; i < queue->nr; i++) {
		}
	struct collect_diff_cbdata cbdata = {NULL};
static void move_diff_queue(struct diff_queue_struct *dst,
	xdemitcb_t ecb;
			}

	range_set_append_unsafe(rs, a, b);
			die("file %s has only %lu lines", name_part, lines);

				      struct range_set *rs,
		begin--;
	 */
{
	assert(commit);
			 * Store away the diff for later output.  We
static int collect_diff(mmfile_t *parent, mmfile_t *target, struct diff_ranges *out)
			p_end = diff->parent.ranges[j_last].end;
	changed = process_all_files(&parent_range, rev, &queue, range);
	ecb.priv = &cbdata;


			*insertion_point = p;
			anchor = p->ranges.ranges[p->ranges.nr - 1].end + 1;
#include "blob.h"
				       struct line_log_data *range)
