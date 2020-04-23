		for (i = 0; i <= num_parent; i++) putchar(combine_marker);
			elem->mode = canon_mode(st.st_mode);
	struct diff_options *opt = &rev->diffopt;
				strbuf_addstr(&p->parent[n].path,
			j--;
			if (lline->prev)
			int comment_end = 0;
			elem->mode = canon_mode(st.st_mode);

	int i;
	 */
			  consume_line, &state, &xpp, &xecfg))
	/* find set of paths that everybody touches
		}
			     const char *c_meta, const char *c_reset)
		for (i = 0, p = paths; p; p = p->next, i++)
		printf("%s%s", i ? "," : "", abb);

			else
		if (0 <= fd)
		state->lno++;
		printf("%s\n", c_reset);
					lline->prev->next = lline;

		 */
			*tail = p;
	show_hunks = make_hunks(sline, cnt, num_parent, dense);
		 * that would have come *after* line N
			memset(p->parent, 0,
			 mmfile_t *result_file,
	diffopts.flags.recursive = 1;
			result_size = buf.len;
			 struct userdiff_driver *textconv,
				if (!same_diff)
	if (cnt < i)
			needsep = 1;
			sline[i].flag |= mark;
		}
		return;
		 * to the line after the removed lines,
	xpp.flags = flags;
	saw_cr_at_eol = (len && line[len-1] == '\r');
	 *
				show_line_to_eol(ll->line, -1, c_reset);
}
				elem->mode = canon_mode(S_IFLNK);

		/*

	state->sline[state->nb-1].p_lno[state->n] = state->ob;
 */

	l1 = sline[l1].p_lno[n];
		printf("Binary files differ\n");
	/* Look at each hunk, and if we have changes from only one
	const char *c_reset = diff_get_color(use_color, DIFF_RESET);
	for (i = 0; i < num_parent; i++)
			result_deleted = 1;
			       line_prefix, c_meta, elem->mode);
	paths_head.next = NULL;
	 * paths in curr (linked list) and q->queue[] (array) are
			unsigned long j;
	return path->path;
	printf(" -%lu,%lu", l0, l1-l0-null_context);
		if (type != OBJ_BLOB)
					(la + context) : cnt + 1;
			    DIFF_STATUS_ADDED)
{
	 */
		}
}
	return pair;
		if (i <= j)
	 * mark.  So interesting() would still say false for such context
 * but currently nobody uses it, so this should suffice for now.
/* Lines lost from current parent (before coalescing) */

	}


			for (i = 0; !is_file && i < num_parent; i++)
	struct lline *lost_head, *lost_tail;
					has_interesting = 1;
				else
		sline++;
					  DIFF_FORMAT_NAME |
		for (; len2 > 0 && XDL_ISSPACE(line2[len2 - 1]); len2--);
		for (i = 0; i < num_parent; i++)
		/* lookahead context lines */
			struct rev_info *rev)
		 *
			 */
	sline->plost.lost_tail = lline;
	if (S_ISGITLINK(mode)) {
			done = read_in_full(fd, result, len);
				       elem->parent[i].mode);

			else {
	       saw_cr_at_eol ? "\r" : "");
struct lline {
	free(pair->two);
	}
	unsigned int p_lno, lno;
			if (buffer_is_binary(buf, size))
			baseend = baseend->prev;
};
					result_size = len;
			}
	struct combine_diff_state state;
	char *blob;
	 */
	int line_termination, inter_name_termination, i;
			fputs(line_prefix, stdout);
	quote_two_c_style(&buf, prefix, path, 0);
		 */
					null_context++;
		for (i = 0; i < num_parent; i++) {
				sline[j].flag &= ~mark;
{
	if (show_log_first) {
	for (i = 0, p = paths; p; p = p->next)
	for (i = 0; i < num_paths; i++)
						putchar('-');
}

			else

		int fd = -1;
			(*lenbase)++;
 * find set of paths that everybody touches, assuming diff is run without
				}
	unsigned long parent_map;
}
 * (i.e. diff-files) or the state in HEAD and in the index
	 * "interesting" does not mean interesting(), but marked by
			 long nb, long nn,
	struct userdiff_driver *userdiff;
			for (; len1 > 0 && XDL_ISSPACE(line1[len1]); len1--);
			oidcpy(&p->oid, &q->queue[i]->two->oid);
		ALLOC_ARRAY(o, num_paths);
		printf(" %s ", diff_aligned_abbrev(&p->oid, opt->abbrev));
	for (i = 0; i < origbaselen + 1; i++) {
		show_combined_header(elem, num_parent, dense, rev,
		 * for parent0.
			tail = &p->next;
			}
		len1--;
			/* q->queue[i] not in p->path; skip it */
	if (len < 0)
	}
					combined_all_paths);
			handle_combined_callback(opt, paths, num_parent, num_paths);
		}
	struct combine_diff_path *curr,
	const char *line_prefix = diff_line_prefix(opt);
		while (ll) {
			mode_differs = 1;
			 * paint them interesting because the gap is small.

	dump_quoted_path(dense ? "diff --cc " : "diff --combined ",
		while (lno < hunk_end) {
	}
		 * interesting?  We check if there are only two versions

			 struct sline *sline, unsigned int cnt, int n,
static struct combine_diff_path *find_paths_generic(const struct object_id *oid,
	line_termination = opt->line_termination;
			printf(" %s", diff_aligned_abbrev(&p->parent[i].oid,
			int is_file, i;
		}
	if (!dense)
			*tail = p->next;
	while (i <= cnt)
		abb = find_unique_abbrev(&elem->parent[i].oid,
 * parents are typically from multiple stages during a merge
				is_binary = 1;
	unsigned long mark = (1UL<<num_parent);
	userdiff = userdiff_find_by_path(opt->repo->index, elem->path);
	} else if (textconv) {
	int num_parent;
				fputs(c_context, stdout);
			if ((flags & XDF_IGNORE_WHITESPACE_CHANGE) &&

				     textconv, elem->path, opt->xdl_opts);
			 * are symlinks
	 * Coalesce new lines into base by finding the LCS
		 * no overlap beyond it within context lines.  Paint
	free(parents_oid);
	xpparam_t xpp;
			struct sline *sl = &sline[lno++];
				 */
	/* We have examined up to i-1 and are about to look at i.
				fputs(c_new, stdout);
				while (la && j <= --la) {
	if (base == NULL) {
		}
 * The result (p->elem) is from the working tree and their
#include "commit.h"

			if (ll->parent_map & nmask)
			for (i = 0; i < comment_end; i++)

		} else {
			ll = ll->next;
				write_name_quoted(p->parent[i].path.buf, stdout,
	 * path scanning, which works significantly slower compared to
			ll = (sl->flag & no_pre_delete) ? NULL : sl->lost;
{
	struct commit_list *parent = get_saved_parents(rev, commit);

#include "diff.h"

		 * the trailing edge a bit.
		} else if (directions[i][j] == NEW) {
			elem->mode = 0;

	case '-':
					continue;
			result = strbuf_detach(&buf, NULL);
	lcs = xcalloc(st_add(origbaselen, 1), sizeof(int*));
	int i, show_hunks;

	i = 0;
		while (i <= cnt && !(sline[i].flag & mark))
		 * line in the file.
	if (!(flags & (XDF_IGNORE_WHITESPACE | XDF_IGNORE_WHITESPACE_CHANGE)))

	 *
		unsigned long same_diff;


void diff_tree_combined_merge(const struct commit *commit, int dense,
		unsigned long hunk_end;
		if (added)
	/* fake list head, so worker can assume it is non-NULL */
	if (!S_ISDIR(one->mode) && !S_ISDIR(two->mode))

	if (!show_file_header)
			if (elem->parent[i].status !=
						newend->line, newend->len, flags)) {
	free(lcs);
	free(pair);
			       int i, int j)
	else if (opt->output_format & DIFF_FORMAT_PATCH)

		for (; len1 > 0 && XDL_ISSPACE(line1[len1 - 1]); len1--);
		struct strbuf buf = STRBUF_INIT;
		i = k;

			int j;
			for (j = lno; j < hunk_end; j++)
				if (!context)
	if (num_paths) {


				if (p_mask & sl->flag)
	if (is_binary) {
	unsigned long nmask = (1UL << n);
	parent_file.size = sz;
		       int num_parent,
		       struct rev_info *rev)
						  inter_name_termination);
	int len;
		}
	if (opt->output_format & (DIFF_FORMAT_RAW | DIFF_FORMAT_NAME_STATUS)) {
			if (comment_end)
		return; /* result deleted */
		    filename_changed(p->parent[n].status))
		}

	mmfile_t parent_file;
			    struct rev_info *rev)
	unsigned long sz;

struct combine_diff_state {
		*lenbase = lennew;
			goto again;
	 * TODO some of the filters could be ported to work on
	}
		sline->plost.lost_head = lline;
			struct diff_filespec *df = alloc_filespec(elem->path);
		}
	/* Assign line numbers for this parent.
	}
			for (p = paths; p; p = p->next)
			/* p->path not in q->queue[]; drop it */
{
			if (!is_file)
	 * for deletion hunk at the end.
{
		if (baseend->next)
{
		*size = buf.len;
	struct diff_options *opt = &rev->diffopt;
					 line_prefix, c_meta, c_reset);
	const char *orderfile = opt->orderfile;
	ALLOC_ARRAY(parents_oid, nparent);
		/* j is the first uninteresting line and there is
	sline->p_lno[i] = sline->p_lno[j];
			continue;
			lno++;
				dump_quoted_path("--- ", "", "/dev/null",
		directions[i] = xcalloc(st_add(lennew, 1), sizeof(enum coalesce_direction));
		for (i = 0; i < num_parent; i++)
	pool = xcalloc(st_add(num_parent, 1), sizeof(struct diff_filespec));
			 */
	sline[0].p_lno = xcalloc(st_mult(st_add(cnt, 2), num_parent), sizeof(unsigned long));

enum coalesce_direction { MATCH, BASE, NEW };
		free(tmp);
		}
			if (needsep)
		/* We say it was added if nobody had it */
#include "refs.h"
	if (!working_tree_file)
			 * Even when running with --unified=0, all
	i = 0;
			for (i = 0; i < 40; i++) {

					&size, NULL, NULL);
		if (rev->verbose_header && opt->output_format &&
		fill_filespec(df, oid, 1, mode);
		/*
		userdiff = userdiff_find_by_name("default");
		order_objects(opt->orderfile, path_path, o, num_paths);
/* Lines surviving in the merge result */
		    opt->output_format != DIFF_FORMAT_NO_OUTPUT &&
	 * lines attached to it first).
static struct combine_diff_path *find_paths_multitree(
			 * the loop below in order to show the
{
	 * that are surrounded by interesting() ones.

			if (!(sline[j].flag & mark))
	oidcpy(&pair->two->oid, &p->oid);
			if (lline->next)
			}
}
	enum coalesce_direction **directions;
					   int num_parent)
	if (opt->orderfile && num_paths) {
	if (!bol)
	unsigned long *p_lno;

		    !commit_format_is_empty(rev->commit_format))
				 * same as others?
			sline->flag |= imask;

	}
	return ((sline->flag & all_mask) || sline->lost);
 */
	puts(buf.buf);
		 */
			opt->break_opt != -1	||
			len = strlen(path);
	q.queue = xcalloc(num_paths, sizeof(struct diff_filepair *));
					elem->parent[i].mode,
		if (lstat(elem->path, &st) < 0)
static void dump_quoted_path(const char *head,

	free(directions);
				ll->parent_map |= imask;
				lline->next->prev = lline->prev;
					}
	free(sline[0].p_lno);
				printf("..%06o", elem->mode);
					break;
	/* the overall size of the file (sline[cnt]) */
		for (i = 0; i <= num_parent; i++) putchar(combine_marker);
	if (rev->combined_all_paths) {
		break;
			for (hunk_end = lno + 1; hunk_end <= cnt; hunk_end++)
		p->next = NULL;
static void show_raw_diff(struct combine_diff_path *p, int num_parent, struct rev_info *rev)
		return;
	sline->plost.len++;
	 *
				p_mask <<= 1;
	pair->two = pool;
static int filename_changed(char status)
		return newline;
	if (result_size && result[result_size-1] != '\n')
			result_size = 0;

	if (!state->lost_bucket)
	return has_interesting;
				show_patch_diff(p, num_parent, dense,
	diff_tree_paths(&paths_head, oid, parents_oid, nparent, &base, opt);
		hunk_end = j;
	unsigned long result_size, cnt, lno;
}
	if (opt->flags.allow_textconv)
		return 0;
			break; /* No more interesting hunks */
			 int num_parent, int result_deleted,

	if (!num_parent)
		state->lost_bucket = &state->sline[state->nb];
	i--;
			if (ll->parent_map & jmask)
				printf("%s%s", line_prefix, c_old);
{
	}
		if (lno < cnt && !(sline[lno].flag & nmask))
	return base_name_compare(one->path, strlen(one->path), one->mode,
				ll = ll->next;
				      unsigned long i)
	return i;
	else
				}
			}
	else {
	int result_deleted = 0;
	/* nothing to do, if no parents */
}
	}

		struct lline *ll = sline->lost;
static void handle_combined_callback(struct diff_options *opt,
	unsigned long this_mask = (1UL<<n);
				     line_prefix, mode_differs, 0);

	struct oid_array parents = OID_ARRAY_INIT;
		for (i = 0; i < q->nr; i++) {
	}
	if (result_size && result[result_size-1] != '\n')
		/* we know up to i is to be included.  where does the
	sline = xcalloc(st_add(cnt, 2), sizeof(*sline));
	struct sline *sline; /* survived lines */
		if (hunk_comment) {

}
		free(result);
		unsigned long j, hunk_begin, hunk_end;
		 *       this line appears in the result.
	 * started by showing sline[lno] (possibly showing the lost
				diffcore_order(opt->orderfile);

			for (j = 0; j < num_parent; j++) {
{
		show_log(rev);
						     hunk_begin, j);
			    filename_changed(p->parent[n].status)) {

	while (parent) {
		rlines = hunk_end - lno;
				write_name_quoted(p->path, stdout,

	}
static const char *path_path(void *obj)
	int mode_differs = 0;
	strbuf_release(&base);
	unsigned long nmask;
		j = find_next(sline, mark, i, cnt, 1);
void diff_tree_combined(const struct object_id *oid,
		pair->one[i].mode = p->parent[i].mode;
	struct lline *lline;
			free(p);
			if (rev->combined_all_paths &&
		 * then check the set of parents the result has difference
		oidcpy(&p->parent[n].oid, &q->queue[i]->one->oid);
				lline->next = base;
	 * (counting from 1) for parent N if the final hunk display
			cnt++;
			continue;
	 * deletion, then it is not all that interesting for the
				ll = ll->next;
		    oid_to_hex(parent));
	 *
	const struct oid_array *parents,
			size_t len = xsize_t(st.st_size);
	free(q.queue);
		else {
			       int look_for_uninteresting)
	 *   - Else if we have NEW, insert newend lline into base and
					has_interesting = 1;

	 */
			unsigned long p_mask;
	 * theory, we could end up having only multitree path scanning.
	unsigned long lno, imask, jmask;
				if (!contin)
{

			ll = ll->next;
	if (opt->output_format & DIFF_FORMAT_RAW) {
				hunk_comment = sline[lno].bol;
		show_log(rev);
		}
		blob = strbuf_detach(&buf, NULL);
	int len;
		else {
			/* if symlinks don't work, assume symlink if all parents
			diffopts.output_format = stat_opt;
			char *path = filename_changed(elem->parent[i].status)
	state->ob = ob;
			if (lno < cnt)
			     const char *prefix,

			if (is_file) {
							  opt->abbrev));
			for (i = 0; i < num_parent; i++) {
		}
		 * at:
		int j;
#include "userdiff.h"
		for (i = 0; i < num_parent; i++)
	struct combine_diff_path paths_head;
	clear_pathspec(&diffopts.pathspec);
						   &result_size, NULL, NULL);
			unsigned long size;
};
	show_log_first = !!rev->loginfo && !rev->no_commit_id;
	if (mode_differs) {
				 * lost lines in front of it.
			/* Remove lline from new list and update newend */
		if (XDL_ISSPACE(line1[len1]) || XDL_ISSPACE(line2[len2])) {


			}
		for (j = 1, newend = newline; j < lennew + 1; j++) {
	struct combine_diff_state *state = state_;
	lline->next = NULL;
}
			       sizeof(p->parent[0]) * num_parent);
	}
		for (; len2 > 0 && XDL_ISSPACE(line2[len2 - 1]); len2--);
	       reset,
	else {
				 * is an interesting line after this
	struct diff_filespec *pool;
static int make_hunks(struct sline *sline, unsigned long cnt,
				else if (same_diff != this_diff) {
static unsigned long find_next(struct sline *sline,
		/* deleted blob */
	 * comparing two entries - i.e. they do not apply directly to combine
				printf("%s%06o", i ? "," : "",
		} else if (0 <= (fd = open(elem->path, O_RDONLY))) {
	if (rev->loginfo && !rev->no_commit_id)
			/*
	 * Find next interesting or uninteresting line.  Here,

			while (ll) {
			printf("mode ");
	}
	const struct object_id **parents_oid;
						 line_prefix, c_meta, c_reset);
				  DIFF_FORMAT_NAME |
	opt->output_format = output_format;
				  &elem->parent[j].oid)) {
 * (i.e. diff-index).
			goto deleted_file;
		/* As many colons as there are parents */
		if (stat_opt) {
		/* if showing diff, show it in requested order */
	 * the give_context() function below (i.e. it includes context
static void combine_diff(struct repository *r,
	if (result_deleted)
			p->mode = q->queue[i]->two->mode;
				     &elem->parent[i].oid,
	lline->parent_map = this_mask;
			sline[i].flag &= ~mark;
		if (opt->output_format != DIFF_FORMAT_NO_OUTPUT &&
			       unsigned long i,
	struct diff_queue_struct q;
		has_interesting = 0;
		strbuf_addf(&buf, "Subproject commit %s\n", oid_to_hex(oid));
		if (*cp == '\n') {
			if (oideq(&elem->parent[i].oid,
	for (lno = 0; lno < cnt; lno++) {

	 * some parent, it is interesting.

		/* Paint a few lines before the first interesting line. */
	static struct strbuf buf = STRBUF_INIT;
	lline->prev = sline->plost.lost_tail;
	return blob;
				break;
	int i;
	}
				/* Lost this line from these parents;
		return xcalloc(1, 1);
	return 0;
	 */
	const char *c_old = diff_get_color(use_color, DIFF_FILE_OLD);
}
			 long ob, long on,
	strbuf_init(&base, PATH_MAX);
	state.nmask = nmask;
	 */
	}

/* Lines lost from parent */
	sline[lno].p_lno[n] = p_lno; /* trailer */
		} else if (textconv) {
	struct lline *next, *prev;

			    (!XDL_ISSPACE(line1[len1]) || !XDL_ISSPACE(line2[len2])))
		j = adjust_hunk_tail(sline, all_mask, i, j);
		directions[i][0] = BASE;
		return; /* not in any hunk yet */
				break;
		diff_tree_oid(&parents->oid[i], oid, "", opt);

	free(sline);
				is_file = !S_ISLNK(elem->parent[i].mode);
		 * Even when we have only two versions, if the result does
		parents_oid[i] = &parents->oid[i];
				lline->prev = baseend;
		       int use_color, int result_deleted)
				     &result_file, sline,
	if (!userdiff)
		const char *hunk_comment = NULL;
		else if (opt->output_format & STAT_FORMAT_MASK)


			rlines--; /* pointing at the last delete hunk */
						   elem->path, result, len, &buf, global_conv_flags_eol)) {
	int ch;
			 const struct object_id *parent, unsigned int mode,
	for (i = 0; i < num_parent; i++) {

#define STAT_FORMAT_MASK (DIFF_FORMAT_NUMSTAT \
				}
			putchar(':');

		 *
static void free_combined_pair(struct diff_filepair *pair)
		 *   (-) line, which records from what parents the line
	 * bit (N+1) is used for "do not show deletion before this".
	const char *a_prefix = opt->a_prefix ? opt->a_prefix : "a/";
		else {
				     elem->parent[i].mode,
	unsigned long no_pre_delete = (2UL<<num_parent);
		 * and the result matches one of them.  That is, we look
	char *bol;
			if (this_diff) {
#include "quote.h"
		added = !deleted;
	 * that case which gives us one extra context line.
		if (added)
		if (sline[lno].lost) {
		i = hunk_end;
			 * case.  Compensate.
}
	diffopts.flags.allow_external = 0;
/*
		    orderfile) {
/*
	 */
		is_binary = userdiff->binary;
			if (newend->next)
		p->parent[n].mode = q->queue[i]->one->mode;
				struct lline *tmp = ll;
			i++;
static void show_patch_diff(struct combine_diff_path *elem, int num_parent,
		if (cnt < lno)
	/* bit 0 up to (N-1) are on if the parent has this line (i.e.
		struct lline *lline = newend;

		if (interesting(&sline[i], all_mask))
					free(result);
		 * appear as "the same set of parents" to be "all parents".
	struct combine_diff_path *path = (struct combine_diff_path *)obj;
		k = (j + context < cnt+1) ? j + context : cnt+1;
	if (!len1 && !len2)
						   NULL, NULL);
			sl->plost.lost_head = sl->plost.lost_tail = NULL;
	state->on = on;
						    c_context, c_reset,
		len2--;
			memcpy(p->path, path, len);
				sline[j++].flag |= mark;
void show_combined_diff(struct combine_diff_path *p,

			const struct oid_array *parents,
				 */
{
	/* i points at the first uninteresting line.  If the last line
		 * in the result.  Our lost buckets hang
		struct lline *ll;
			else if (done < len)



		}
			sl->plost.len = 0;
		}
	int num_parent,
				 * who are they?  Are they the same?
		k = find_next(sline, mark, j, cnt, 0);
		i--;
	int i, nparent = parents->nr;
			sline[j++].flag |= mark;
}

	while (i <= cnt) {
				lline->prev->next = lline->next;
		 * different set of parents that the result has differences
			  | DIFF_FORMAT_DIFFSTAT)
			opt->flags.follow_renames	||
	inter_name_termination = '\t';
		paths = find_paths_generic(oid, parents, &diffopts,
	}
	xdemitconf_t xecfg;
			opt->filter;

			result_size = len;

		printf("%06o", p->mode);
	 * parent, or the changes are the same from all but one

	if ((hunk_begin + 1 <= i) && !(sline[i-1].flag & all_mask))
						putchar(' ');
						contin = 1;
			is_file = has_symlinks;
	for (lno = 0,  p_lno = 1; lno <= cnt; lno++) {
		}
			free_filespec(df);
	}
		       int dense,

	 * we did not change it).
			strbuf_addstr(&p->parent[n].path,
	/* If some parents lost lines here, or if we have added to
	for (i = 0; i < num_parent; i++) {
		    ? !(sline[i].flag & mark)
{
		return 1;
			}
	 *
				 * hunk within context span.

}
				/* Look beyond the end to see if there
		       unsigned long cnt, int num_parent,
			free(buf);
	int i, num_paths, needsep, show_log_first, num_parent = parents->nr;

			newend = lline->prev;
			ssize_t done;
	struct diff_options *opt)

		 * Note that this is correct even when N == 0,

				added = 0;
	int combined_all_paths)

		state->sline[state->lno-1].flag |= state->nmask;
		 * in which case the hunk removes the first
		       const struct object_id *oid, unsigned int mode,
				result = grab_blob(opt->repo, &oid, elem->mode,

	struct combine_diff_path *p, **tail = &curr;
	 * uninteresting lines.  Connect such groups to give them a
	lline->len = len;
			i = k;
	strbuf_addstr(&buf, head);

		paths = intersect_paths(paths, i, num_parent,
		cmp = ((i >= q->nr)
	state->nb = nb;
	 * and parent j are the same, so reuse the combined result
		oidcpy(&pair->one[i].oid, &p->parent[i].oid);
#include "diffcore.h"
				 int mode_differs,
	struct diff_filepair *pair;

				la = adjust_hunk_tail(sline, all_mask,
		}
		 *       was removed; this line does not appear in the result.
				     struct combine_diff_path *paths,
		cnt++; /* incomplete line */
static void consume_line(void *state_, char *line, unsigned long len)
		if (sline->flag & jmask)
		if (cnt < i)
	 * diff.
		paths = find_paths_multitree(oid, parents, &diffopts);
	jmask = (1UL<<j);
static int match_string_spaces(const char *line1, int len1,
	 */
 */
	mmfile_t result_file;
			if (cnt < lno)
	unsigned long i;
	/*
static void reuse_combine_diff(struct sline *sline, unsigned long cnt,
		return strcmp(one->path, two->path);
		}
			diffcore_order(orderfile);
		}
				     int num_paths)
	return status == 'R' || status == 'C';
			if (baseend) {
}
				p_lno++; /* '-' means parent had it */
		 * diff(sha1,parent_i) for all i to do the job, specifically

	unsigned long mark = (1UL<<num_parent);
		if (line1[len1] != line2[len2])
};
			const char *path;
}
	}
				strbuf_release(&tmp->parent[i].path);

		}
static struct combine_diff_path *intersect_paths(
		free(directions[i]);
				else if (same_diff != this_diff) {
	 * sline[lno].p_lno[n] records the first line number
static unsigned long context = 3;
{
				if (!(sline[j].flag & (mark-1)))
	copy_pathspec(&diffopts.pathspec, &opt->pathspec);
	int saw_cr_at_eol = 0;
	state.num_parent = num_parent;
static void consume_hunk(void *state_,
	need_generic_pathscan = opt->skip_stat_unmatch	||
		if (cnt < hunk_end)
			p->parent[n].mode = q->queue[i]->one->mode;

		*size = 0;
				      q->queue[i]->one->path);
	/* tell diff_tree to emit paths in sorted (=tree) order */


	oid_array_clear(&parents);
	}
{
	while (len1 > 0 && len2 > 0) {

}
			show_parent_lno(sline, lno, hunk_end, i, null_context);
	for (lno = 0; lno <= cnt; lno++)
		else
		append_lost(state->lost_bucket, state->n, line+1, len-1);
				    struct lline *newline, int lennew,
#include "oid-array.h"
	 * simultaneous all-trees-in-one-go scan in find_paths_multitree().
		 * show stat against the first parent even when doing

	state->lno = state->nb;
	unsigned long all_mask = (1UL<<num_parent) - 1;


	}
{
	return paths_head.next;
				strbuf_init(&p->parent[n].path, 0);
		for (; len1 > 0 && XDL_ISSPACE(line1[len1 - 1]); len1--);
static int give_context(struct sline *sline, unsigned long cnt, int num_parent)
		}
		show_log(rev);
			} else {
	case '+':
		printf("%s\n", c_reset);
	unsigned long i;
	}
		die("unable to generate combined diff for %s",
				directions[i][j] = NEW;


				this_diff = ll->parent_map;

			/* Add lline to base list */
			p_lno++; /* no '+' means parent had it */
	struct diff_options *opt = &rev->diffopt;
		if (S_ISLNK(st.st_mode)) {
	opt->format_callback(&q, opt, opt->format_callback_data);
				ll = ll->next;
}

				die_errno("read error '%s'", elem->path);
	}
		if (k < j + context) {
			i++;
	 * Diffcore transformations are bound to diff_filespec and logic
			p = o[i].obj;
	}
	q.nr = num_paths;


			for (; len2 > 0 && XDL_ISSPACE(line2[len2]); len2--);
			}
	while ((p = *tail) != NULL) {

		return;
{
		diffcore_std(opt);
			i--;


			 * we do not want to show the resulting line
		 */
			for (j = 0; j < num_parent; j++)
			lline = newend;
		}

			newend = newend->prev;
					same_diff = this_diff;
		directions[0][j] = NEW;

			combine_diff(opt->repo,
				struct strbuf buf = STRBUF_INIT;
	diffopts = *opt;

			o[i].obj = p;
			else
	for (i = 1, baseend = base; i < origbaselen + 1; i++) {
	unsigned long mark = (1UL<<num_parent);
		*size = fill_textconv(r, textconv, df, &blob);
		 * combined diff.
		show_raw_diff(p, num_parent, rev);

	int i, num_parent = parents->nr;
		state->lost_bucket = &state->sline[state->nb-1];

		return (len1 == len2 && !memcmp(line1, line2, len1));
	for (i = 0; i < num_parent; i++) {
		deleted_file:
		       const char *path)
		if (sline[lno].plost.lost_head) {
	return base;

		for (i = 0; i < num_parent; i++)
		       ? -1 : compare_paths(p, q->queue[i]->two));
		}
	struct lline *baseend, *newend = NULL;
	printf("%s%sindex ", line_prefix, c_meta);
	int i;
	 * If some of such transformations is requested - we launch generic
		for (i = 0; i < num_paths - 1; i++) {
		unsigned long j = (context < i) ? (i - context) : 0;

			lno++;
static struct lline *coalesce_lines(struct lline *base, int *lenbase,
	has_interesting = give_context(sline, cnt, num_parent);
		 * from, that means we have more than two versions.
	unsigned long lno = 0;
	result_file.ptr = result;
		unsigned long k;
			printf("%s%snew file mode %06o",
static void show_line_to_eol(const char *line, int len, const char *reset)
		if (opt->output_format & (DIFF_FORMAT_RAW |
		printf(" +%lu,%lu ", lno+1, rlines);
			baseend->parent_map |= 1<<parent;
		pair->one[i].has_more_entries = 1;
			path = q->queue[i]->two->path;
}
}
			struct lline *ll;
				 int dense,
			int dense,
	int is_binary;
	int added = 0;
			if (lline->next)
		free(lcs[i]);
				/*

	if (flags & XDF_WHITESPACE_FLAGS) {
		for (i = 0; i < num_parent; i++)

		i++;
{
			     const char *line_prefix,
		 * After passing the above "two versions" test, that would
		blob = read_object_file(oid, &type, size);
				 * This sline was here to hang the
	 *
		/* Consume remaining spaces */

	}

				     int num_parent,
		if (!context) {
	pair->two->path = p->path;
	q.alloc = num_paths;
			   opt->use_color, result_deleted);
			      struct rev_info *rev)
	 */
	unsigned int lno;
	/* At this point, baseend and newend point to the end of each lists */
			 * lines in the hunk needs to be processed in
 * rename/copy detection, etc, comparing all trees simultaneously (= faster).
				if (convert_to_git(rev->diffopt.repo->index,
				sline[j].flag |= no_pre_delete;

				? elem->parent[i].path.buf : elem->path;
	state.lno = 1;
	}

	 * we output '-' line and then unmodified sline[i-1] itself in
	struct plost plost;
	const char *c_frag = diff_get_color(use_color, DIFF_FRAGINFO);
			diff_tree_oid(&parents->oid[0], oid, "", &diffopts);
		oid_array_append(&parents, &parent->item->object.oid);
		while (j < k)
	return curr;
		for (i = 0; added && i < num_parent; i++)
				free(tmp);
	diff_tree_combined(&commit->object.oid, &parents, dense, rev);
		q.queue[i++] = combined_pair(p, num_parent);
			if (!(sl->flag & (mark-1))) {

		 * interesting.  In such a case, we would have all '+' line.
	/* We matched full line1 and line2 */
	enum object_type type;
	memset(&xpp, 0, sizeof(xpp));
						0, rev);
{
			 const char *funcline, long funclen)
	sline[0].bol = result;
	} else {
{
	if (line[len-1] == '\n')
		}

	const char *c_func = diff_get_color(use_color, DIFF_FUNCINFO);
	 *   consume newend
			if (deleted)
			if (match_string_spaces(baseend->line, baseend->len,
				lcs[i][j] = lcs[i - 1][j - 1] + 1;
}
	}
	for (i = 0; i < origbaselen + 1; i++)

		}
			 * deletion recorded in lost_head.  However,
	for (num_paths = 0, p = paths; p; p = p->next)
			struct strbuf buf = STRBUF_INIT;
			while (ll && !has_interesting) {
			  const struct diff_filespec *two)
			/* This hunk is not that interesting after all */
{
						 line_prefix, c_meta, c_reset);
	 * We first start from what the interesting() function says,
static void append_lost(struct sline *sline, int n, const char *line, int len)
{
	return paths;
	struct diff_options *opt = &rev->diffopt;
		for (i = 0; !is_binary && i < num_parent; i++) {
	int i, j, origbaselen = *lenbase;
		while (lno <= cnt && !(sline[lno].flag & mark)) {
	 * lines but they are treated as "interesting" in the end.
				 int num_parent,
	while (i != 0 || j != 0) {
	 * and mark them with "mark", and paint context lines with the
		return give_context(sline, cnt, num_parent);
				 two->path, strlen(two->path), two->mode);
	again:
					break;
	if (!n) {
			if (elem->parent[i].status == DIFF_STATUS_ADDED)
	unsigned long all_mask = (1UL<<num_parent) - 1;
			char *buf;
		 */
	int abbrev = opt->flags.full_index ? the_hash_algo->hexsz : DEFAULT_ABBREV;

	for (i = 0; i < nparent; i++)
		p->parent[n].status = q->queue[i]->status;
	FLEX_ALLOC_MEM(lline, line, line, len);
		free(lline);
					putchar(' ');
			opt->output_format = stat_opt;
			(opt->pickaxe_opts & DIFF_PICKAXE_KINDS_MASK)	||
	result_file.size = result_size;
				for (j = 0; j < num_parent; j++) {
			if (hunk_comment_line(sline[lno].bol))
		if (elem->parent[i].mode != elem->mode) {
	} else if (is_null_oid(oid)) {
		stat_opt = opt->output_format & STAT_FORMAT_MASK;
				putchar(hunk_comment[i]);
					putchar('+');
				die("early EOF '%s'", elem->path);

		parent = parent->next;
	struct userdiff_driver *textconv = NULL;
	needsep = 0;
			 */

	}
			break;

	if (textconv)
			diffcore_std(&diffopts);
			else
{
			} else if (lcs[i][j - 1] >= lcs[i - 1][j]) {
			       const char *line2, int len2,
	}
				return 0;

	/* We have already examined parent j and we know parent i
	directions = xcalloc(st_add(origbaselen, 1), sizeof(enum coalesce_direction*));
			}
	return 1;
					   rev->combined_all_paths);
				continue;
	const char *abb;
		unsigned long null_context = 0;
		free(o);
static char combine_marker = '@';
	if (rev->loginfo && !rev->no_commit_id)
				directions[i][j] = MATCH;
		return; /* result deleted */
		struct stat st;
			sline[j++].flag |= mark;
	 * - Then reverse read the direction structure:
			i--;
			break;
		}
		unsigned long rlines;
			printf("%s%c", diff_line_prefix(opt),
	strbuf_reset(&buf);
}
			    int dense, int working_tree_file,
			i++;
		struct diff_filespec *df = alloc_filespec(path);
			else
	 * - Compute the LCS

		dump_quoted_path("+++ ", "", "/dev/null",
	if (deleted)
	 * - Create the table to run dynamic programming
			struct lline *lline;
		sline[lno+1].p_lno = sline[lno].p_lno + num_parent;
		sline->p_lno[i] = sline->p_lno[j];

		hunk_begin = i;
	 * NOTE please keep this semantically in sync with diffcore_std()
		 * from, from all lines.  If there are lines that has
	else if (userdiff->binary != -1)
	const char *c_meta = diff_get_color_opt(opt, DIFF_METAINFO);
					 line_prefix, c_meta, c_reset);
		pair->one[i].oid_valid = !is_null_oid(&p->parent[i].oid);
			if (diff_unmodified_pair(q->queue[i]))
			if (!(sline[j].flag & mark)) {
			struct lline *ll = sline[j].lost;
			       opt->line_termination);
				base = lline;
		}

	}
{
	 * of the hunk was interesting only because it has some
			}
struct plost {
	if (need_generic_pathscan) {
		printf("%s", line_prefix);
			sl->lost = coalesce_lines(sl->lost, &sl->lenlost,
		for (i = 0; i < num_parent; i++)
	abb = find_unique_abbrev(&elem->oid, abbrev);
		state->sline[state->nb-1].p_lno =

	struct combine_diff_path *paths = NULL;
				lcs[i][j] = lcs[i][j - 1];
		p = o[num_paths-1].obj;
			opt->output_format = DIFF_FORMAT_NO_OUTPUT;
	struct sline *lost_bucket;
	state.n = n;
			  | DIFF_FORMAT_SUMMARY \

				if (!isspace(ch))
			return i;
		show_combined_header(elem, num_parent, dense, rev,
				lline->next->prev = lline;

		/* Show sha1's */
/* Coalesce new lines into base by finding LCS */
	 * both sorted in the tree order.
static int hunk_comment_line(const char *bol)


		}
static struct diff_filepair *combined_pair(struct combine_diff_path *p,
	}
					 abbrev);
static void show_parent_lno(struct sline *sline, unsigned long l0, unsigned long l1, int n, unsigned long null_context)
	free(parent_file.ptr);
{
		for (j = i + 1; j <= cnt; j++) {
	for (i = 0; i < num_parent; i++) {
	}
		if (directions[i][j] == MATCH) {
				       opt->line_termination);
		else
	while (paths) {
				 const char *line_prefix,
#include "object-store.h"
		 * next uninteresting one start?
			  | DIFF_FORMAT_DIRSTAT \
	if (opt->output_format & (DIFF_FORMAT_RAW |
			if (elem->mode)

	int i;
			return 0;
				if (!same_diff)
		else if (opt->output_format & DIFF_FORMAT_CALLBACK)
				 int show_file_header)
			 "", elem->path, line_prefix, c_meta, c_reset);
	int has_interesting = 0;
#include "cache.h"
		}
			opt->detect_rename	||
{
	pair->two->oid_valid = !is_null_oid(&p->oid);
					if (sline[la].flag & mark) {
	pair->one[num_parent - 1].has_more_entries = 0;
/*
		}


	 * bit of context.
			       unsigned long mark,

		if (!state->nb)
	 */
#include "xdiff-interface.h"
				     line_prefix, mode_differs, 1);
	struct combine_diff_path *p, *paths;
}
static int compare_paths(const struct combine_diff_path *one,
			p->path = (char *) &(p->parent[num_parent]);
	strbuf_addstr(&buf, line_prefix);
	memset(&state, 0, sizeof(state));


			oidcpy(&p->parent[n].oid, &q->queue[i]->one->oid);
	/* Even p_lno[cnt+1] is valid -- that is for the end line number
 * A combine_diff_path expresses N parents on the LHS against 1 merge
		show_patch_diff(p, num_parent, dense, 1, rev);
		       unsigned long *size, struct userdiff_driver *textconv,
				     cnt, i, num_parent, result_deleted,
			       unsigned long cnt,
	l0 = sline[l0].p_lno[n];
		 * NOTE generic case also handles --stat, as it computes
			baseend = baseend->next;
	unsigned long flag;
				if (!ch || ch == '\n')

		diff_flush(opt);
/* find set of paths that every parent touches */
#include "revision.h"
static char *grab_blob(struct repository *r,
	}
			  | DIFF_FORMAT_SHORTSTAT \
	}
}
#include "blob.h"
						    c_func);
			}
	 * parent, mark that uninteresting.
	int ob, on, nb, nn;
	memset(&xecfg, 0, sizeof(xecfg));
	if (!line_termination)
	if (xdi_diff_outf(&parent_file, result_file, consume_hunk,
{
		/*
static int interesting(struct sline *sline, unsigned long all_mask)
	j--;
		free_filespec(df);
			p->next = o[i+1].obj;
			putchar(p->parent[i].status);
#include "xdiff/xmacros.h"
	for (i = 0; i < origbaselen + 1; i++)
				printf("%s%sdeleted file ",
static unsigned long adjust_hunk_tail(struct sline *sline,
			}
				printf("%s%c", diff_line_prefix(opt),
			 * with all blank context markers in such a

		if (opt->output_format & DIFF_FORMAT_PATCH) {
	pair = xmalloc(sizeof(*pair));
				sline[lno].bol = cp + 1;
	state->nn = nn;
			p->parent[n].status = q->queue[i]->status;
		is_binary = buffer_is_binary(result, result_size);
	if (flags & XDF_IGNORE_WHITESPACE) {
	 *   - If we have MATCH, assign parent to base flag, and consume

{
	printf("%.*s%s%s\n", len - saw_cr_at_eol, line,
		while (ll) {
	strbuf_addstr(&buf, c_reset);
				directions[i][j] = BASE;
	if (result_deleted)

	for (lno = 0; lno <= cnt; lno++) {

					  DIFF_FORMAT_NAME_STATUS)) {
					result = strbuf_detach(&buf, &len);
	while (i <= cnt) {
	newend = newline;
			if (done < 0)
	int **lcs;
	}


{
			result_size = fill_textconv(opt->repo, textconv, df, &result);
			struct sline *sl = &sline[lno];
	 *   both baseend and newend
	free(result);

						  sl->plost.len, n, flags);

	/* Accumulated and coalesced lost lines */
		}
				show_raw_diff(p, num_parent, rev);
			for (p = paths; p; p = p->next)
			 const char *path, long flags)
	 */
		dump_sline(sline, line_prefix, cnt, num_parent,
			}
}
 * In the future, we might want to add more data to combine_diff_path
	const char *line_prefix = diff_line_prefix(opt);
};
		/* How many lines would this sline advance the p_lno? */
	}



				unsigned long la; /* lookahead */
		lline->prev->next = lline;
	}
	/* D(A,P1...Pn) = D(A,P1) ^ ... ^ D(A,Pn)  (wrt paths) */
				if (!(sline[hunk_end].flag & mark))
	int deleted = 0;
				j = la;
	opt->orderfile = orderfile;
	}
	if (newline == NULL)

	return (isalpha(ch) || ch == '_' || ch == '$');
		 */
		printf("%s%s", line_prefix, c_frag);
 * side and 1 entry on the "two" side.
				    filename_changed(p->parent[j].status))
	if (state->nn == 0) {
			/* If not a fake symlink, apply filters, e.g. autocrlf */
	 * NOTE
			/* k is interesting and [j,k) are not, but
			needsep = 1;
{
		}
	}
		else

		 * when doing combined diff.
				      unsigned long hunk_begin,
		return 0;
		while (j < i) {
			int len;

		paths = o[0].obj;
	for (j = 1; j < lennew + 1; j++)
}
				 */
		if (*cp == '\n')
 * Diff stat formats which we always compute solely against the first parent.
			    filename_changed(tmp->parent[i].status))
			state->nb = 1;
	 * purpose of giving trailing context lines.  This is because
		if (rev->combined_all_paths) {
}
}
	/*
	struct lline *lost;
		len--;
		 * show stat against the first parent even
			p->path[len] = 0;
			result = xmallocz(len);
			struct object_id oid;

			       long flags)
	struct diff_queue_struct *q = &diff_queued_diff;
				       line_prefix, c_meta);
			close(fd);
	int lenlost;

	/* Read the result of merge first */
		lcs[i] = xcalloc(st_add(lennew, 1), sizeof(int));

		if (cmp < 0) {
			for (j = hunk_begin; j < hunk_end; j++)
			buf = grab_blob(opt->repo,

	opt->orderfile = NULL;
		    : (sline[i].flag & mark))
			sline[lno].len = cp - sline[lno].bol;
						  sl->plost.lost_head,
				error_errno("readlink(%s)", elem->path);
}
			}
					&elem->parent[i].oid,

	struct combine_diff_state *state = state_;
			while (j < k)
			die("object '%s' is not a blob!", oid_to_hex(oid));

		/* Coalesce new lines */
			baseend = baseend->prev;
{
{
	imask = (1UL<<i);

		}
		 * not match any of the parents, the it should be considered
 */
{
				lcs[i][j] = lcs[i - 1][j];
			}
	switch (line[0]) {
			show_line_to_eol(sl->bol, sl->len, c_reset);
	pair->one = pool + 1;
				int contin = 0;
			if (filename_changed(p->parent[i].status))
	int len;

		else
				 */
	pair->two->mode = p->mode;
	i = find_next(sline, mark, 0, cnt, 0);
			diff_flush(&diffopts);
			p->next = NULL;

			struct lline *ll = sline[lno].lost;
		sline[cnt-1].len = result_size - (sline[cnt-1].bol - result);
			printf("%06o ", p->parent[i].mode);

						   elem->mode, &result_size,
		same_diff = 0;
		break;
	for (lno = 0, cp = result; cp < result + result_size; cp++) {
				 struct rev_info *rev,
				      unsigned long all_mask,
static void dump_sline(struct sline *sline, const char *line_prefix,

	if (lline->prev)
		putchar(inter_name_termination);

	char line[FLEX_ARRAY];
	char *result, *cp;

{
			fill_filespec(df, &null_oid, 0, st.st_mode);
	const char *c_reset = diff_get_color_opt(opt, DIFF_RESET);
			xcalloc(state->num_parent, sizeof(unsigned long));
					same_diff = this_diff;
 * so that we can fill fields we are ignoring (most notably, size) here,
					break;
			     const char *path,
	int n,
	/* order paths according to diffcore_order */
				/* This has some changes.  Is it the
}
	int n;
	printf("..%s%s\n", abb, c_reset);

				newline = lline->next;
			unsigned long this_diff = sline[j].flag & all_mask;
			result = xcalloc(1, 1);
	const struct object_id *oid, const struct oid_array *parents,
	parent_file.ptr = grab_blob(r, parent, mode, &sz, textconv, path);
				    comment_end = i;
					strbuf_release(&p->parent[j].path);
}
	while (1) {
		int stat_opt = output_format & STAT_FORMAT_MASK;
				    unsigned long parent, long flags)
	if (!state->sline[state->nb-1].p_lno)
		sline[lno].p_lno[n] = p_lno;
		for (j = 0; j < i; j++) {
		num_paths++;
	struct diff_options diffopts;
		int stat_opt;
		return base;
				 line_prefix, c_meta, c_reset);
	const char *c_context = diff_get_color(use_color, DIFF_CONTEXT);

		tail = &p->next;
	/* Two groups of interesting lines may have a short gap of
				return;
			p_mask = 1;
	state.sline = sline;
		if (i == 0 && stat_opt)
		struct combine_diff_path *tmp = paths;
	struct sline *sline;

						break;
		textconv = userdiff_get_textconv(opt->repo, userdiff);
			if (resolve_gitlink_ref(elem->path, "HEAD", &oid) < 0)
			j--;
	context = opt->context;
	 * lines that are not interesting to interesting() function
				if (lline->prev)
	int combined_all_paths)
	} else {
}
	}
			}
		pair->one[i].path = p->path;
	if (show_hunks || mode_differs || working_tree_file) {
		if (combined_all_paths &&

		/* Used by diff-tree to read from the working tree */
	int i, j, cmp;
		paths = paths->next;
		inter_name_termination = 0;
	/* find out number of surviving paths */
				lline->next = baseend->next;

	const char *c_new = diff_get_color(use_color, DIFF_FILE_NEW);
	for (i = 0; i <= cnt; i++) {
				 line_prefix, c_meta, c_reset);
		return curr;
	 */
		/* @@ -X,Y +N,0 @@ removed Y lines
		 *   (+) line, which records lines added to which parents;
	 * combine_diff_paths - i.e. all functionality that skips paths, so in

	write_name_quoted(p->path, stdout, line_termination);

			}
				la = (la + context < cnt + 1) ?
						  inter_name_termination);
	strbuf_addstr(&buf, c_meta);
		}
				newend = newend->next;
struct sline {
			dump_quoted_path("--- ", a_prefix, elem->path,
				if (combined_all_paths &&
	ch = *bol & 0xff;

	opt->output_format = DIFF_FORMAT_NO_OUTPUT;
		} else if (S_ISDIR(st.st_mode)) {
	int output_format = opt->output_format;
	for (i = 0; i < num_parent; i++) {
	unsigned long no_pre_delete = (2UL<<num_parent);
		       int num_parent, int dense)
		is_binary = 0;
				reuse_combine_diff(sline, cnt, i, j);
		result = grab_blob(opt->repo, &elem->oid, elem->mode, &result_size,
			rlines -= null_context;
		ll = sline[lno].lost;
				  DIFF_FORMAT_NAME_STATUS))

	for (cnt = 0, cp = result; cp < result + result_size; cp++) {
	}
	 *
				dump_quoted_path("--- ", a_prefix, path,
		dump_quoted_path("+++ ", b_prefix, elem->path,
				   textconv, elem->path);
		if (cmp > 0) {
	struct combine_diff_path *p;
		if (cnt < j)
	 * of parent j for parent i.
	else
				int ch = hunk_comment[i] & 0xff;
}
				printf("%s%s %s%s", c_reset,
					break;
#include "log-tree.h"

				}
				result = grab_blob(opt->repo, &elem->oid,
			if (opt->orderfile)
			while (ll) {
	return i;
	}
		newend = newend->next;
	struct diff_options *opt,
	int need_generic_pathscan;
			if (combined_all_paths &&
	struct diff_options *opt = &rev->diffopt;
		free_combined_pair(q.queue[i]);
		/* [i..hunk_end) are interesting.  Now is it really
			dump_quoted_path("--- ", "", "/dev/null",
			p = xmalloc(combine_diff_path_size(num_parent, len));
		if (!has_interesting && same_diff != all_mask) {
			break; /* the rest are all interesting */
					else
	else {
 *
	 *   - Else if we have BASE, consume baseend
		/* Show the modes */
 * result. Synthesize a diff_filepair that has N entries on the "one"
		len = strlen(line);
		struct obj_order *o;

	 * bit N is used for "interesting" lines, including context.
	} else {
}
			if (strbuf_readlink(&buf, elem->path, st.st_size) < 0) {
static void show_combined_header(struct combine_diff_path *elem,

	const char *b_prefix = opt->b_prefix ? opt->b_prefix : "b/";

					if (ll->parent_map & (1UL<<j))
	struct strbuf base;


					      q->queue[i]->one->path);
				}
		}
	/* Clean things up */
		deleted = !elem->mode;
/*
	}
		for (j = i; j < hunk_end && !has_interesting; j++) {
		if (look_for_uninteresting
		 */
	while (newend) {
