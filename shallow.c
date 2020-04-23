void assign_shallow_commits_to_refs(struct shallow_info *info,
	if (write_shallow_commits(&sb, 0, extra)) {
#include "commit-reach.h"
	memset(bitmap, 0, bitmap_size);
	fd = hold_lock_file_for_update(shallow_lock,
		die("shallow file has changed since we read it");
	}
		struct object *o = &p->item->object;
	for (i = 0; i < nr; i++)
		    close_tempfile_gently(temp) < 0)
		return get_tempfile_path(temp);
			struct commit_graft *graft;
 *
	is_repository_shallow(the_repository); /* make sure shallows are read */
int delayed_reachability_test(struct shallow_info *si, int c)
	free(pi.pools);
{
				c->object.flags |= shallow_flag;
			if (memcmp(tmp, *refs, bitmap_size)) {
		rollback_lock_file(&shallow_lock);
	for_each_ref(mark_uninteresting, NULL);
	struct strbuf sb = STRBUF_INIT;
						       si->nr_commits,
	for (p = result; p; p = p->next) {
			     const char **alternate_shallow_file,
	return 0;
		commit->object.flags |= not_shallow_flag;
				int *ref_status)
	while (commit || i < heads->nr || stack.nr) {
			if (!*depth_slot) {


	 * set at this point. But better be safe than sorry.
			    oid_to_hex(&c->object.oid));

			continue;
						    int shallow_flag,
				struct ref_bitmap *ref_bitmap,
{
				       LOCK_DIE_ON_ERROR);
	struct commit **commits;
		 * unreachable shallow commits are not removed from
	struct commit_depth depths;
				   const struct oid_array *extra,
				update_refstatus(ref_status, info->ref->nr, *bitmap);

			for (i = 0; i < bitmap_nr; i++)
	struct commit_array ca;
	info->shallow = sa;
		for (p = c->parents; p; p = p->next) {
	strbuf_release(&sb);
		bitmap = ref_bitmap_at(ref_bitmap, c);
	 * NEEDSWORK: This function updates
	trace_printf_key(&trace_shallow, "shallow: prepare_shallow_info\n");
/*

		if (write_in_full(fd, sb.buf, sb.len) < 0)
		shallow[nr_shallow++] = info->ours[i];
	repo_init_revisions(the_repository, &revs, NULL);

	}
		else
		       unsigned int id)
struct trace_key trace_shallow = TRACE_KEY_INIT(SHALLOW);
	int dst, i, j;
	nr = get_max_object_index();
/*
		packet_buf_write(data->out, "shallow %s", hex);
	 */

	/*
 */

			int **depth_slot = commit_depth_at(&depths, p->item);
	for_each_commit_graft(write_one_shallow, &data);
	 * is_repository_shallow() sees empty string as "no shallow
		for (j = 0; j < bitmap_nr; j++)
	int i = 0, cur_depth = 0;
	struct object_id *oid = info->shallow->oid;
			continue;
	int count;
	struct write_shallow_data *data = cb_data;
	for (i = 0; i < extra->nr; i++) {
			    oid_to_hex(&c->object.oid));
		if (size > POOL_SIZE)
				cur_depth = **commit_depth_at(&depths, commit);
 * bitmaps. The n-th bit set in the m-th bitmap if ref[n] needs the
	if (ref_status)
	struct commit_list *result = NULL;
		if (write_in_full(fd, sb.buf, sb.len) < 0)
	return r->parsed_objects->is_shallow;
		strbuf_addch(data->out, '\n');
 * are marked with shallow_flag. The list of border/shallow commits
				commit = p->item;
{
 * TODO: use "int" elemtype instead of "int *" when/if commit-slab
			continue;
	for (i = 0; i < ref->nr; i++)

				break;
	ca->commits[ca->nr] = lookup_commit_reference_gently(the_repository,
		}
struct commit_list *get_shallow_commits(struct object_array *heads, int depth,
	if (r->parsed_objects->is_shallow >= 0)
#include "repository.h"
		if (i != dst)
 * mark_reachable_objects() should have been run prior to this and all
{


	 * have to go down to the current shallow commits.
	check_shallow_file_for_update(the_repository);
static uint32_t *paint_alloc(struct paint_info *info)

		if (!c || !(c->object.flags & SEEN)) {
	if (!info->pool_count || size > info->end - info->free) {
	 * both flags set can confuse the caller.
	struct paint_info pi;
}
	return register_commit_graft(r, graft, 0);
}
static void show_commit(struct commit *commit, void *data)
	struct commit_graft *graft =
	check_shallow_file_for_update(the_repository);
 * reachable commits marked as "SEEN", except when quick_prune is non-zero,
	}
	for (p = not_shallow_list; p; p = p->next) {
	struct object_id *oid = info->shallow->oid;
				struct ref_bitmap *ref_bitmap,
	for (i = 0; i < sa->nr; i++) {
	struct commit *commit = NULL;
 * commits that do not exist (any longer).
		if (has_object_file(sa->oid + i)) {
	if (!stat_validity_check(r->parsed_objects->shallow_stat,
}

	if (prepare_revision_walk(&revs))
	}
	struct commit *c = lookup_commit_reference_gently(the_repository, oid,
 * info->ref must be initialized before calling this function.
			}
	if (!not_shallow_list)
			} else {
			info->ours[dst] = info->ours[i];

void prune_shallow(unsigned options)
		strbuf_addstr(out, oid_to_hex(extra->oid + i));
		}
{
	for (i = dst = 0; i < info->nr_theirs; i++) {
	struct object_array stack = OBJECT_ARRAY_INIT;


	 */
};
	struct rev_info revs;
		}
	}
		si->reachable[c] = in_merge_bases_many(commit,
				memcpy(*refs, tmp, bitmap_size);
static void update_refstatus(int *ref_status, int nr, uint32_t *bitmap)
	unsigned nr_bits;
				break;
			} else {

	trace_printf_key(&trace_shallow, "shallow: assign_shallow_commits_to_refs\n");
		c->object.flags |= BOTTOM;
	if (graft->nr_parent == -1)
	unsigned flags = SEEN_ONLY;
	data.out = out;
	}
void advertise_shallow_grafts(int fd)
							     oid, 1);
	 * "--not --all" to cut short the traversal if new refs
		bitmap = ref_bitmap_at(ref_bitmap, c);
{
	if (!is_repository_shallow(the_repository))
	int fd;
	oidcpy(&graft->oid, oid);
	return 0;
	memset(info, 0, sizeof(*info));

 * in which case lines are excised from the shallow file if they refer to
		if (i != dst)
		if (get_oid_hex(buf, &oid))
{
	}
{
		*alternate_shallow_file = get_lock_file_path(shallow_lock);


		if (bitmap[i / 32] & (1U << (i % 32)))
		for (j = 0; j < depths.slab_size; j++)
	}
	}
	 * commit A is processed first, then commit B, whose parent is
		if ((depth != INFINITE_DEPTH && cur_depth >= depth) ||
		   int flags, void *cb_data)
}
	struct commit_graft *graft;


	if (r->parsed_objects->alternate_shallow_file && !override)
		return;
}
	info->nr_theirs = dst;
	free(info->ours);
	 * connect to old refs. If not (e.g. force ref updates) it'll

	stat_validity_update(r->parsed_objects->shallow_stat, fileno(fp));
	if (commit && commit->object.parsed)
				continue;
		 * "ours" and "theirs". The user is supposed to run
 * If used is not NULL, it's an array of info->shallow->nr
	free(ca.commits);
};
	 * r->parsed_objects->{is_shallow,shallow_stat} as a side effect but
	}
		struct commit_list *p;
 * Step 6(+7), associate shallow commits with new refs
		*alternate_shallow_file = "";
		BUG("is_repository_shallow must not be called before set_alternate_shallow_file");
		 */
		}
/* (Delayed) step 7, reachability test at commit level */
			if (data->flags & VERBOSE)
#include "pkt-line.h"
{
		for (j = 0; j < bitmap_nr; j++)
	free_commit_list(not_shallow_list);
	 * there is no corresponding function to clear them when the shallow
	}
 */
	 */
		return 0;
		     (graft = lookup_commit_graft(the_repository, &commit->object.oid)) != NULL &&
static void check_shallow_file_for_update(struct repository *r)
	/* Remove unreachable shallow commits from "theirs" */
#include "tag.h"
				commit = (struct commit *)

	FILE *fp;
				       git_path_shallow(the_repository),
			graft = lookup_commit_graft(the_repository,
	return result;
	free(shallow);
}

}
	 */
	struct strbuf sb = STRBUF_INIT;
	clear_ref_bitmap(&pi.ref_bitmap);
	if (r->parsed_objects->is_shallow == -1)
	for (i = 0; i < nr; i++) {

	if (!sa)
		commit->parents = NULL;
		BUG("shallow must be initialized by now");
			    /* Step 7, reachability test at commit level */
			commit->object.flags |= shallow_flag;
	if (!ref_status)


define_commit_slab(commit_depth, int *);
			si->nr_commits = ca.nr;
	ALLOC_ARRAY(info->ours, sa->nr);
		if (!depths.slab[i])
 *
}
	 */
				*refs = paint_alloc(info);
	clear_object_flags(both_flags);

				*depth_slot = xmalloc(sizeof(int));
	if (data->flags & QUICK) {
	graft->nr_parent = -1;
	struct commit_list *head = NULL;
	 * A, later. If NOT_SHALLOW on A is cleared at step 1, B
		for (p = commit->parents, commit = NULL; p; p = p->next) {
				break;
	return 0;
	free(tmp);
		stat_validity_clear(r->parsed_objects->shallow_stat);
define_commit_slab(ref_bitmap, uint32_t *);
		ca->nr++;
	}
		return data.count;
	head_ref(add_ref, &ca);
			die("bad shallow line: %s", buf);
#define VERBOSE   2
		die("revision walk setup failed");
 * except border ones are marked with not_shallow_flag. Border commits
			}
				int *ref_status);
	for_each_ref(add_ref, &ca);
	 * shallow file should be used. We could just open it and it
 * are also returned.
 */
	int *shallow, nr_shallow = 0;
	clear_commit_depth(&depths);
	void *p;
 *
				    uint32_t **used, int *ref_status)
			c->object.flags |= SEEN;
static void paint_down(struct paint_info *info, const struct object_id *oid,
{
	 * SHALLOW (excluded) and NOT_SHALLOW (included) should not be
	if (si->need_reachability_test[c]) {
					*depth_slot = xmalloc(sizeof(int));
			head_ref(add_ref, &ca);
				   unsigned flags)
	/*
static void post_assign_shallow(struct shallow_info *info,


static int advertise_shallow_grafts_cb(const struct commit_graft *graft, void *cb)
	for (i = 0; i < pi.pool_count; i++)
	info->nr_ours = dst;

	bitmap = paint_alloc(info);
	if (options & PRUNE_SHOW_ONLY) {
		si->need_reachability_test[c] = 0;
		register_shallow(r, &oid);

{
				cur_depth = 0;
	unsigned flags;
			}
		}
	for_each_commit_graft(advertise_shallow_grafts_cb, &fd);
	unsigned nr = DIV_ROUND_UP(info->nr_bits, 32);
	/*
	 * will likely fail. But let's do an explicit check instead.
			dst++;
{
			uint32_t **map = ref_bitmap_at(&pi.ref_bitmap, c);
{
void setup_alternate_shallow(struct lock_file *shallow_lock,
{
	}

		write_shallow_commits_1(&sb, 0, NULL, flags);

				**depth_slot = cur_depth;

	} else
	data->count++;
}
				commit = (struct commit *)
	info->nr_theirs = dst;
						  heads->objects[i++].item,
			if (graft && graft->nr_parent < 0)
		 * and "theirs" any more.

#include "object-store.h"
		if (o && o->type == OBJ_COMMIT)
			info->theirs[dst] = info->theirs[i];
	struct ref_bitmap ref_bitmap;
 * is not NULL it's an array of ref->nr ints. ref_status[i] is true if

	if (r->parsed_objects->is_shallow != -1)
{
		uint32_t **refs = ref_bitmap_at(&info->ref_bitmap, c);
				tmp[i] |= bitmap[i];
		struct commit_list *p;
}
	struct commit *commit = lookup_commit(the_repository, oid);
#include "cache.h"
	 * fetch-pack sets '--shallow-file ""' as an indicator that no
		strbuf_addstr(data->out, hex);
{
	/* Mark potential bottoms so we won't go out of bound */
	memset(&pi, 0, sizeof(pi));

	return write_shallow_commits_1(out, use_pack_protocol, extra, 0);
		if (write_in_full(temp->fd, sb.buf, sb.len) < 0 ||
	r->parsed_objects->is_shallow = 1;
			o->flags &= ~not_shallow_flag;

				update_refstatus(ref_status, info->ref->nr, *bitmap);
		if (c->object.flags & (SEEN | UNINTERESTING))
{
 * Step 2, clean "ours" based on .git/shallow
		if (has_object_file(oid + info->theirs[i]))
						       si->commits);
		die("no commits selected for shallow requests");
struct paint_info {
		struct commit *c = lookup_commit(the_repository, &graft->oid);
						 &oid[shallow[i]]);
							  1);
		info->pool_count++;
	}
		 * step 7 on every ref separately and not trust "ours"
	struct commit_list *result = NULL, *p;
	ALLOC_GROW(ca->commits, ca->nr + 1, ca->alloc);
			    size);
#include "diff.h"
	}
	}
			}

		 * shallow file".
 * UNINTERESTING or BOTTOM is hit. Set the id-th bit in ref_bitmap for
	char **pools;
		}
			return 0;
		c = lookup_commit(the_repository, &oid[info->theirs[i]]);
				 git_path_shallow(r)))
	 * Prepare the commit graph to track what refs can reach what
				cur_depth = **commit_depth_at(&depths, commit);

	 * file is updated.
		unlink(git_path_shallow(the_repository));
 */
/*
		struct object *o = get_indexed_object(i);
{
		memset(ref_status, 0, sizeof(*ref_status) * info->ref->nr);
			memset(&ca, 0, sizeof(ca));
	 */
}
				**depth_slot = cur_depth;
			}
		strbuf_release(&sb);
}
		}
 * all walked commits.
	data.count = 0;
	int i;
 * info->theirs.
		commit_lock_file(&shallow_lock);
		return 0;
	unsigned int i;
	/*
}
	unsigned size = nr * sizeof(uint32_t);
	fclose(fp);
				printf("Removing %s from .git/shallow\n",
}
	char buf[1024];
			die("unable to parse commit %s",
 */
	 */
			*refs = bitmap;
		}
	commit_list_insert(commit, data);
	int nr, alloc;

{
	if (options & PRUNE_QUICK)
			}
		if (i != dst)
	if (graft->nr_parent != -1)
	for (i = 0; i < depths.slab_count; i++) {
	unsigned int i, nr;
			commit_list_insert(p->item, &head);
 * Given a commit SHA-1, walk down to parents until either SEEN,
	int fd = *(int *)cb;
}
				       git_path_shallow(the_repository),
	data.use_pack_protocol = use_pack_protocol;
		if (parse_commit(c))
		if (parse_commit(c))
const char *setup_temporary_shallow(const struct oid_array *extra)
void clear_shallow_info(struct shallow_info *info)
		 */
		if (c->object.flags & BOTTOM)
	 * mark border commits SHALLOW + NOT_SHALLOW.
	struct tempfile *temp;
	for (i = dst = 0; i < info->nr_theirs; i++) {
		     graft->nr_parent < 0)) {
	const char *hex = oid_to_hex(&graft->oid);
#include "tempfile.h"
	const char *path = r->parsed_objects->alternate_shallow_file;
	}
	int fd;
				if (cur_depth >= **depth_slot)
				       LOCK_DIE_ON_ERROR);
			if (p->item->object.flags & SEEN)
	if (used) {
				commit_list_insert(c, &result);
	init_ref_bitmap(&pi.ref_bitmap);
		struct commit *c = p->item;
			if (i < heads->nr) {
void set_alternate_shallow_file(struct repository *r, const char *path, int override)
	return data.count;
	for (p = not_shallow_list; p; p = p->next)
	free(r->parsed_objects->alternate_shallow_file);
	return si->reachable[c];
			if (bitmap[0][j]) {
		strbuf_addch(out, '\n');
	struct oid_array *ref = info->ref;
							       oid, 1);
				used[shallow[i]] = xmemdupz(*map, bitmap_size);
	if (!c)
		struct object *o = get_indexed_object(i);
static int write_one_shallow(const struct commit_graft *graft, void *cb_data)
	char *free, *end;
	else {

	r->parsed_objects->alternate_shallow_file = xstrdup_or_null(path);
			    !in_merge_bases_many(c, ca.nr, ca.commits)) {
	 * Now we can clean up NOT_SHALLOW on border commits. Having
		/*
			si->commits = ca.commits;
}
	}
struct commit_list *get_shallow_commits_by_rev_list(int ac, const char **av,
{
	int bitmap_nr = DIV_ROUND_UP(info->nr_bits, 32);
	/* Remove unreachable shallow commits from "ours" */

		if (!has_object_file(&graft->oid))
 */
}
		paint_down(&pi, ref->oid + i, i);
	setup_revisions(ac, av, &revs, NULL);
	int use_pack_protocol;

	int bitmap_nr = DIV_ROUND_UP(info->ref->nr, 32);
		if (!commit) {
static void post_assign_shallow(struct shallow_info *info,

		struct commit *c = pop_commit(&head);
						  NULL, 0);
		path = git_path_shallow(r);
#define QUICK 4
	int i;

	}
}
	bitmap[id / 32] |= (1U << (id % 32));
			}
	return result;
			if (*map)
		parse_commit_or_die(commit);
		packet_write_fmt(fd, "shallow %s\n", oid_to_hex(&graft->oid));
 * m-th shallow commit from info->shallow.
	return p;


#include "commit-slab.h"
		return;
 */
				if (!commit || commit->object.type != OBJ_COMMIT) {
	commit_list_insert(c, &head);
					object_array_pop(&stack);
		c = lookup_commit(the_repository, &oid[info->ours[i]]);
		return r->parsed_objects->is_shallow;

			struct commit_array ca;
}

			commit_list_insert(commit, &result);
	nr = get_max_object_index();
		for (i = 0; i < nr_shallow; i++) {
			BUG("pool size too small for %d in paint_alloc()",
}

/*
		flags |= VERBOSE;
						      &si->shallow->oid[c]);
 * supports a "valid" flag.
	memset(&ca, 0, sizeof(ca));
	/* Mark all reachable commits as NOT_SHALLOW */
	ALLOC_ARRAY(info->theirs, sa->nr);
	/*
/*
#define POOL_SIZE (512 * 1024)
struct write_shallow_data {
{
	ALLOC_ARRAY(shallow, info->nr_ours + info->nr_theirs);
	 */

	head_ref(mark_uninteresting, NULL);
			info->theirs[dst] = info->theirs[i];
	info->free += size;
}
				dst++;
			commit = NULL;
		if (!*bitmap)
	struct commit_array *ca = cb_data;
	p = info->free;
	struct lock_file shallow_lock = LOCK_INIT;
{
	size_t bitmap_size = st_mult(sizeof(uint32_t), bitmap_nr);
	for (i = 0; i < info->nr_theirs; i++)
	struct commit_list *not_shallow_list = NULL;
	}
/*
						    &sa->oid[i]);
		memset(used, 0, sizeof(*used) * info->shallow->nr);
	if (data->use_pack_protocol)
	for (i = dst = 0; i < info->nr_ours; i++) {
				       oid_to_hex(&c->object.oid));
/*
		return;
		if (!o || o->type != OBJ_COMMIT)
			      int flags, void *cb_data)
}
	strbuf_release(&sb);
	 * (new) shallow commits.
	trace_printf_key(&trace_shallow, "shallow: post_assign_shallow\n");
 * Step 1, split sender shallow commits into "ours" and "theirs"
		strbuf_release(&sb);
		 * is_repository_shallow() sees empty string as "no
		return;


#include "revision.h"
void remove_nonexistent_theirs_shallow(struct shallow_info *info)
#include "refs.h"
		return r->parsed_objects->is_shallow;
	struct object_id *oid = info->shallow->oid;
		else {

struct commit_array {
};
		if (!*bitmap)
		/*
{
/* Step 4, remove non-existent ones in "theirs" after getting the pack */
		post_assign_shallow(info, &pi.ref_bitmap, ref_status);
		free(pi.pools[i]);
	while (head) {
{

int is_repository_shallow(struct repository *r)
						    int not_shallow_flag)
			info->theirs[info->nr_theirs++] = i;
			continue;
	return "";
	if (!path)
			die("unable to parse commit %s",

		data.count++;
			continue;
		int j;

	 * We cannot clear NOT_SHALLOW right now. Imagine border


						NULL, &stack);
		    (is_repository_shallow(the_repository) && !commit->parents &&
			die_errno("failed to write to %s",
	int both_flags = shallow_flag | not_shallow_flag;
#include "lockfile.h"
					deref_tag(the_repository,
		cur_depth++;

void prepare_shallow_info(struct shallow_info *info, struct oid_array *sa)

		struct commit *c = lookup_commit(the_repository,
			return 0;

			info->ours[info->nr_ours++] = i;
		shallow[nr_shallow++] = info->theirs[i];
		if (!si->commits) {
			continue;
	/*
{
 * the ref needs some shallow commits from either info->ours or
	} else
		o->flags &= ~(UNINTERESTING | BOTTOM | SEEN);
				  get_lock_file_path(&shallow_lock));
	if (ca->commits[ca->nr])
		info->pools[info->pool_count - 1] = info->free;
static int add_ref(const char *refname, const struct object_id *oid,
			die_errno("failed to write to %s",
	} else {
		if ((o->flags & both_flags) == both_flags)

		xmalloc(sizeof(struct commit_graft));
#include "oid-array.h"
				int **depth_slot;

	init_commit_depth(&depths);
			continue;



					continue;
}
}

			memcpy(tmp, *refs, bitmap_size);
		if (*refs == NULL)
		struct object_id oid;
		for (parent = c->parents; parent; parent = parent->next)
				if (!*depth_slot)

	mark_parents_uninteresting(commit);
{

#include "commit.h"
			die_errno("failed to write to %s",
	traverse_commit_list(&revs, show_commit, NULL, &not_shallow_list);
	commit->object.flags |= UNINTERESTING;
	uint32_t **bitmap;
			o->flags &= ~SEEN;
	for (i = 0; i < nr; i++) {
		info->end = info->free + POOL_SIZE;
	if (!extra)
		REALLOC_ARRAY(info->pools, info->pool_count);
		int bitmap_size = DIV_ROUND_UP(pi.nr_bits, 32) * sizeof(uint32_t);
				continue;
		} else
				  get_lock_file_path(shallow_lock));
	int i, dst;
		struct commit *commit = lookup_commit(the_repository,
	struct write_shallow_data data;
	}
			if (bitmap[0][j] &&

			if (!(parent->item->object.flags & not_shallow_flag)) {
				}

	}

	uint32_t *bitmap;
	 * itself is considered border at step 2, which is incorrect.
		int shallow_flag, int not_shallow_flag)
	if (write_shallow_commits(&sb, 0, extra)) {
				dst++;
	struct commit *c;
	unsigned pool_count;
	trace_printf_key(&trace_shallow, "shallow: remove_nonexistent_theirs_shallow\n");
					continue;


				depth_slot = commit_depth_at(&depths, commit);
			for_each_ref(add_ref, &ca);
					commit = NULL;
				**depth_slot = 0;
		p->item->object.flags |= not_shallow_flag;
	for (i = 0; i < nr_shallow; i++) {
 * Step 7, reachability test on "ours" at commit level
		return;
		struct commit_list *parent;
	if (!commit)
	struct strbuf sb = STRBUF_INIT;
	unsigned int i, nr;
 * If used is NULL, "ours" and "theirs" are updated. And if ref_status
			free(depths.slab[i][j]);
	/*
		r->parsed_objects->is_shallow = 0;
	save_commit_buffer = 0;
	/*
		info->free = xmalloc(POOL_SIZE);
	for (i = 0; i < info->nr_ours; i++)
	struct commit *commit = lookup_commit_reference_gently(the_repository,
}
	fd = hold_lock_file_for_update(&shallow_lock,
				  get_tempfile_path(temp));
	pi.nr_bits = ref->nr;
#define SEEN_ONLY 1
	free(info->theirs);
			     const struct oid_array *extra)
	return 0;

int write_shallow_commits(struct strbuf *out, int use_pack_protocol,
			  const struct oid_array *extra)
int register_shallow(struct repository *r, const struct object_id *oid)

	 * file".
	} else if (data->flags & SEEN_ONLY) {
							       &oid[shallow[i]]);

		flags |= QUICK;
static int mark_uninteresting(const char *refname, const struct object_id *oid,
}
			else {
	struct strbuf *out;
			ref_status[i]++;
	if (!*path || (fp = fopen(path, "r")) == NULL) {
		return;
	tmp = xmalloc(bitmap_size);
 * Given rev-list arguments, run rev-list. All reachable commits
	uint32_t *tmp; /* to be freed before return */

#include "list-objects.h"
				add_object_array(&p->item->object,
		temp = xmks_tempfile(git_path("shallow_XXXXXX"));
			const struct commit *c = lookup_commit(the_repository,
	while (fgets(buf, sizeof(buf), fp)) {
			if (p->next)

static int write_shallow_commits_1(struct strbuf *out, int use_pack_protocol,
	data.flags = flags;

		/* XXX check "UNINTERESTING" from pack bitmaps if available */
	if (write_shallow_commits_1(&sb, 0, NULL, flags)) {
#include "remote.h"
