			/*
		return combine_notes_cat_sort_uniq;
		/* else: t->ref points to nothing, assume root/orphan commit */
				die("Failed to find/parse commit %s", t->ref);
			 struct notes_tree *t,
				   struct notes_rewrite_cfg *c,
	c->refs_from_env = 0;
{
		if (!read_ref(t->ref, &parent_oid)) {
	for (i = 0; c->trees[i]; i++)
	if (commit_tree(msg, msg_len, &tree_oid, parents, result_oid, NULL,
			 */
	} else if (!c->refs_from_env && !strcmp(k, "notes.rewriteref")) {
			error(_("Bad notes.rewriteMode value: '%s'"), v);
#include "config.h"
struct notes_rewrite_cfg *init_copy_notes_for_rewrite(const char *cmd)
		   UPDATE_REFS_DIE_ON_ERR);
	else
	free(c->trees);
		commit_notes(r, c->trees[i], msg);
		if (starts_with(v, "refs/notes/"))
		c->mode_from_env = 1;
	return 0;
void commit_notes(struct repository *r, struct notes_tree *t, const char *msg)
	int ret = 0;
	int i;
	const char *rewrite_mode_env = getenv(GIT_NOTES_REWRITE_MODE_ENVIRONMENT);
		string_list_clear(c->refs, 0);
	else if (!strcmp(v, "ours"))
	c->cmd = cmd;
			commit_list_insert(parent, &parents);
			 struct commit_list *parents,
	else if (!strcasecmp(v, "concatenate"))
	else if (!strcasecmp(v, "cat_sort_uniq"))

	}
		die("Failed to write notes tree to database");
	}
}

	for (i = 0; c->trees[i]; i++) {
		if (!v)
int copy_note_for_rewrite(struct notes_rewrite_cfg *c,
		struct object_id parent_oid;
#include "refs.h"

	if (!t->dirty)
		return 0;
}
	free(c);
	return 0;
		t = &default_notes_tree;
		if (!c->combine)

#include "cache.h"
	if (rewrite_mode_env) {
		c->combine = parse_combine_notes_fn(v);
		c->enabled = git_config_bool(k, v);
	if (!strcmp(v, "manual"))
void create_notes_commit(struct repository *r,
			 struct object_id *result_oid)
		*s = NOTES_MERGE_RESOLVE_OURS;
	if (starts_with(k, "notes.rewrite.") && !strcmp(k+14, c->cmd)) {
		return NULL;
		*s = NOTES_MERGE_RESOLVE_CAT_SORT_UNIQ;
	c->refs = xcalloc(1, sizeof(struct string_list));

	struct strbuf buf = STRBUF_INIT;
	c->refs->strdup_strings = 1;

	else if (!strcmp(v, "cat_sort_uniq"))
		die(_("Cannot commit uninitialized/unreferenced notes tree"));
			string_list_add_refs_by_glob(c->refs, v);
		}

		return combine_notes_concatenate;
		free(c);
	struct object_id tree_oid;
{
	else if (!strcmp(v, "union"))
	else

}
		die("Failed to commit notes tree to database");

			 * its value.
	c->enabled = 1;
#include "repository.h"
	return c;
			return 1;
	}
		*s = NOTES_MERGE_RESOLVE_UNION;
	}
	struct notes_rewrite_cfg *c = cb;
		return 0;
{
	strbuf_release(&buf);
	free(c->refs);
	c->trees = load_notes_trees(c->refs, NOTES_INIT_WRITABLE);

		c->refs_from_env = 1;
			  const struct object_id *from_obj, const struct object_id *to_obj)
		free(c->refs);
}
	assert(t->initialized);
	else if (!strcmp(v, "theirs"))
	strbuf_insertstr(&buf, 0, "notes: ");
	return ret;
		}
					rewrite_mode_env);
	} else if (!c->mode_from_env && !strcmp(k, "notes.rewritemode")) {

	const char *rewrite_refs_env = getenv(GIT_NOTES_REWRITE_REF_ENVIRONMENT);
		 * underlying for_each_glob_ref */
		free_notes(c->trees[i]);
		return; /* don't have to commit an unchanged tree */
	git_config(notes_rewrite_config, c);
	struct object_id commit_oid;
	c->mode_from_env = 0;
{
		/* note that a refs/ prefix is implied in the

}
static int notes_rewrite_config(const char *k, const char *v, void *cb)
	/* Prepare commit message and reflog message */
		/* Deduce parent commit from t->ref */
static combine_notes_fn parse_combine_notes_fn(const char *v)


	if (!t->initialized || !t->update_ref || !*t->update_ref)
		return -1;
	if (write_notes_tree(t, &tree_oid))
	strbuf_complete_line(&buf);
		string_list_add_refs_from_colon_sep(c->refs, rewrite_refs_env);
			 const char *msg, size_t msg_len,
		return NULL;
	}
		*s = NOTES_MERGE_RESOLVE_THEIRS;
			struct commit *parent = lookup_commit(r, &parent_oid);
				   const char *msg)
int parse_notes_merge_strategy(const char *v, enum notes_merge_strategy *s)
		if (!c->combine) {

			warning(_("Refusing to rewrite notes in %s"
			NULL))
		else
{
	if (!parents) {
				" (outside of refs/notes/)"), v);
		return combine_notes_overwrite;
	create_notes_commit(r, t, NULL, buf.buf, buf.len, &commit_oid);
	if (!c->enabled || !c->refs->nr) {
	strbuf_addstr(&buf, msg);
	if (!t)
			error(_("Bad %s value: '%s'"), GIT_NOTES_REWRITE_MODE_ENVIRONMENT,
	}
	string_list_clear(c->refs, 0);
#include "notes-utils.h"
		return 0;
		c->combine = parse_combine_notes_fn(rewrite_mode_env);
	if (rewrite_refs_env) {
			 * TRANSLATORS: The first %s is the name of
			if (parse_commit(parent))
		return combine_notes_ignore;

}
		*s = NOTES_MERGE_RESOLVE_MANUAL;
			return config_error_nonbool(k);
			 * the environment variable, the second %s is
}
{
	update_ref(buf.buf, t->update_ref, &commit_oid, NULL, 0,
{
	struct notes_rewrite_cfg *c = xmalloc(sizeof(struct notes_rewrite_cfg));
void finish_copy_notes_for_rewrite(struct repository *r,
{
#include "commit.h"

}
	c->combine = combine_notes_concatenate;


		ret = copy_note(c->trees[i], from_obj, to_obj, 1, c->combine) || ret;
	int i;
	if (!strcasecmp(v, "overwrite"))
	else if (!strcasecmp(v, "ignore"))
