		if (explicit_tracking) {
{
	if (!is_bare_repository() && head && !strcmp(head, ref->buf))

		break;
					  _("Branch '%s' set up to track remote branch '%s' from '%s'."),
 * config.
			ret = error(_("HEAD of working tree %s is not updated"),
 * Check if a branch 'name' can be created as a new branch; die otherwise.
			continue;
	switch (dwim_ref(start_name, strlen(start_name), &oid, &real_ref)) {
			continue;
	    branch, wt->path);
}
 * to infer the settings for branch.<new_ref>.{remote,merge} from the
	struct refspec_item query;
	char *v = NULL;

				advise(_(upstream_advice));
			tracking->remote = remote->name;
					  local, shortname, origin);
{
	struct strbuf key = STRBUF_INIT;
		setup_tracking(ref.buf + 11, real_ref, track, quiet);
	unlink(git_path_merge_msg(r));
"After fixing the error cause you may try to fix up\n"
	if ((track == BRANCH_TRACK_OVERRIDE || clobber_head_ok)

	memset(&query, 0, sizeof(struct refspec_item));
			msg = xstrfmt("branch: Reset to %s", start_name);
	switch (autorebase) {
/*
			return;
}
			local);
static void setup_tracking(const char *new_ref, const char *orig_ref,
	error(_("Unable to write upstream branch configuration"));
			msg = xstrfmt("branch: Created from %s", start_name);
				exit(1);
"If you are planning on basing your work on an upstream\n"
int replace_each_worktree_head_symref(const char *oldref, const char *newref,
	struct refspec_item spec;
	struct tracking tracking;
	for (i = 0; worktrees[i]; i++) {
		transaction = ref_transaction_begin(&err);
	return !remote_find_tracking(remote, &query);
int validate_new_branchname(const char *name, struct strbuf *ref, int force)
}
static const char upstream_not_branch[] =
		free(msg);
		switch (track) {
			free(tracking->spec.src);
		warning(_("Not setting branch %s as its own upstream."),
}

			else
		strbuf_addf(&key, "branch.%s.rebase", local);
		default:

	if (rebasing) {
	}
#include "branch.h"
{
static const char upstream_missing[] =
			if (advice_set_upstream_failure) {
	const struct worktree *wt;
	if (!tracking.matches)
	    ? validate_branchname(name, &ref)
		else
	unlink(git_path_merge_head(r));
	memset(&tracking, 0, sizeof(tracking));
{
	case AUTOREBASE_LOCAL:

		if (!starts_with(real_ref, "refs/heads/") &&
		exit(-1);
{
	int ret = 0;
				printf_ln(rebasing ?
	return ref_exists(ref->buf);
					  _("Branch '%s' set up to track local branch '%s' by rebasing.") :
}

}
	    : validate_new_branchname(name, &ref, force)) {
void die_if_checked_out(const char *branch, int ignore_current_worktree)
{
	if (track == BRANCH_TRACK_EXPLICIT || track == BRANCH_TRACK_OVERRIDE)
				      const char *logmsg)
	const char *shortname = NULL;
	}
	unlink(git_path_squash_msg(r));

	if (for_each_remote(find_tracked_branch, &tracking))
	strbuf_addstr(buf, v);
#include "worktree.h"
		return 0;

{
int read_branch_desc(struct strbuf *buf, const char *branch_name)
		} else {
 */

	int matches;
	if (reflog)
}

		    orig_ref);
{
	die(_("'%s' is already checked out at '%s'"),

					  _("Branch '%s' set up to track remote branch '%s' from '%s' by rebasing.") :
		    ref_transaction_commit(transaction, &err))
};
	strbuf_release(&key);
/*
			die("%s", err.buf);
"If you are planning to push out a new local branch that\n"
		return 0;
		ref_transaction_free(transaction);

		if (git_config_set_gently(key.buf, "true") < 0)
	case AUTOREBASE_NEVER:
}
		strbuf_release(&err);
			      tracking.src ? tracking.src : orig_ref) < 0)

	if (!dont_change_ref) {
		die(_("Cannot force update the current branch."));
	}


			FREE_AND_NULL(tracking->src);
			die(_(upstream_missing), start_name);
		/* Not branching from any existing branch */
#include "sequencer.h"
	sequencer_post_commit_cleanup(r, verbose);
	int forcing = 0;
{
	const char *head;

	}

"\"git branch --set-upstream-to=%s%s%s\".");
	strbuf_release(&name);
		return;
	char *tracking_branch = cb_data;
	    && !origin) {
	}
		die(_("Ambiguous object name: '%s'."), start_name);
		die(_("'%s' is not a valid branch name."), name);
	if (flag & BRANCH_CONFIG_VERBOSE) {
 */
	return 0;
		die(_("Not a valid object name: '%s'."), start_name);
		if (shortname) {
	}
	oidcpy(&oid, &commit->object.oid);
					  local, shortname);
				real_ref = NULL;
 */
		}
			if (explicit_tracking)
		}
	strbuf_addf(&key, "branch.%s.merge", local);
"\n"
		    ref->buf + strlen("refs/heads/"));
	struct tracking *tracking = priv;
	strbuf_reset(&key);

	char *src;
				printf_ln(rebasing ?
{

	if (git_config_set_gently(key.buf, origin ? origin : ".") < 0)
static int validate_remote_tracking_branch(char *ref)
			if (origin)
		}

		}
	if (git_config_get_string(name.buf, &v)) {

static int find_tracked_branch(struct remote *remote, void *priv)
{
"the remote tracking information by invoking\n"
		return 1;
	strbuf_release(&ref);
		break;
		if (!worktrees[i]->head_ref)
		return -1;

		/* Unique completion -- good, only if it is a real branch */
 * Return 1 if the named branch already exists; return 0 otherwise.
	skip_prefix(branch, "refs/heads/", &branch);
	int explicit_tracking = 0;
				die(_(upstream_not_branch), start_name);
N_("Cannot setup tracking information; starting point '%s' is not a branch.");
static int check_tracking_branch(struct remote *remote, void *cb_data)
	case 1:
		if (!force)

		break;
	int rebasing = should_setup_rebase(origin);
	if (!force)
	if (!remote_find_tracking(remote, &tracking->spec)) {
		if (strcmp(oldref, worktrees[i]->head_ref))

	case AUTOREBASE_REMOTE:
out_err:
static const char upstream_advice[] =


		   int force, int clobber_head_ok, int reflog,
					  _("Branch '%s' set up to track remote ref '%s'."),
	remove_merge_branch_state(r);



#include "config.h"
 * Check if 'name' can be a valid name for a branch; die otherwise.
	free_worktrees(worktrees);
	return ret;
		die(_("Not tracking: ambiguous information for ref %s"),
		die(_("A branch named '%s' already exists."),
	return 0;
		if (!transaction ||
		die(_("Not a valid branch point: '%s'."), start_name);
		goto out_err;
		case BRANCH_TRACK_OVERRIDE:
	free(real_ref);

	int i;
	strbuf_addf(&key, "branch.%s.remote", local);

	struct object_id oid;

	}
		explicit_tracking = 1;
	struct strbuf ref = STRBUF_INIT;
				    worktrees[i]->path);
		if (refs_create_symref(refs, "HEAD", newref, logmsg))
	unlink(git_path_merge_rr(r));
"\"git push -u\" to set the upstream config as you push.");
					  _("Branch '%s' set up to track local ref '%s'."),
					  _("Branch '%s' set up to track remote ref '%s' by rebasing.") :
 * Fill ref with the full refname for the branch.
	if (skip_prefix(remote, "refs/heads/", &shortname)
				error(_(upstream_missing), start_name);
			break;
"run \"git fetch\" to retrieve it.\n"
static const char tracking_advice[] =
			dont_change_ref = 1;
	struct strbuf name = STRBUF_INIT;
	return 0;
			   enum branch_track track, int quiet)
	default:
					   &oid, forcing ? NULL : &null_oid,
	if (tracking.matches > 1)
		if (++tracking->matches == 1) {
{
	advise(_(tracking_advice),
					  _("Branch '%s' set up to track local ref '%s' by rebasing.") :
 * Return 1 if the named branch already exists; return 0 otherwise.
	return 0;
	return 1;


#include "refs.h"
				printf_ln(rebasing ?
	if (!wt || (ignore_current_worktree && wt->is_current))
}

			if (origin)

			goto out_err;
	wt = find_shared_symref("HEAD", branch);
		    validate_remote_tracking_branch(real_ref)) {
				printf_ln(rebasing ?
		    ref_transaction_update(transaction, ref.buf,
	}
	}
	case 0:
	struct worktree **worktrees = get_worktrees(0);
N_("\n"
		tracking->spec.src = NULL;

		if (explicit_tracking)

	head = resolve_ref_unsafe("HEAD", 0, NULL, NULL);
	if ((commit = lookup_commit_reference(r, &oid)) == NULL)
			die(_(upstream_not_branch), start_name);
			forcing = 1;
		struct strbuf err = STRBUF_INIT;
	int dont_change_ref = 0;
{
		return 0;
#include "commit.h"
	       origin ? "/" : "",
	if (install_branch_config(config_flags, new_ref, tracking.remote,
		strbuf_release(&name);
					  _("Branch '%s' set up to track local branch '%s'."),
					   0, msg, &err) ||
}
	if (get_oid_mb(start_name, &oid)) {
	strbuf_addf(&name, "branch.%s.description", branch_name);


/*
			tracking->src = tracking->spec.src;
		struct ref_transaction *transaction;
	case AUTOREBASE_ALWAYS:
	struct commit *commit;
	       shortname ? shortname : remote);
		}


}
		   const char *name, const char *start_name,
{
void remove_branch_state(struct repository *r, int verbose)
N_("the requested upstream branch '%s' does not exist");
	       origin ? origin : "",
#include "git-compat-util.h"
"will track its remote counterpart, you may want to use\n"
	}
		strbuf_reset(&key);
		log_all_ref_updates = LOG_REFS_NORMAL;
	int config_flags = quiet ? 0 : BRANCH_CONFIG_VERBOSE;
	    && !strcmp(local, shortname)
	if (strbuf_check_branch_ref(ref, name))
}
		case BRANCH_TRACK_EXPLICIT:

	if (!validate_branchname(name, ref))

	if (git_config_set_gently(key.buf, remote) < 0)
		refs = get_worktree_ref_store(worktrees[i]);
			else
void remove_merge_branch_state(struct repository *r)
			else
#include "remote.h"
	strbuf_release(&key);
int install_branch_config(int flag, const char *local, const char *origin, const char *remote)
			continue;
		char *msg;
	return !for_each_remote(check_tracking_branch, ref);

					  local, remote);

		   int quiet, enum branch_track track)
	unlink(git_path_merge_mode(r));
		return origin != NULL;
			}

		return origin == NULL;
static int should_setup_rebase(const char *origin)
 * This is called when new_ref is branched off of orig_ref, and tries

	}
					  local, remote);
	char *real_ref;
		case BRANCH_TRACK_ALWAYS:
#include "refspec.h"
	free(v);
	free(tracking.src);
	tracking.spec.dst = (char *)orig_ref;
#include "cache.h"
void create_branch(struct repository *r,

struct tracking {

 * Fill ref with the full refname for the branch.
}
}



N_("\n"
		if (forcing)
"branch that already exists at the remote, you may need to\n"
	real_ref = NULL;
	return -1;
 * 'force' can be used when it is OK for the named branch already exists.
	const char *remote;
		if (worktrees[i]->is_detached)
	query.dst = tracking_branch;
		return;
		} else {
	if (real_ref && track)
		goto out_err;
int validate_branchname(const char *name, struct strbuf *ref)
		else
		struct ref_store *refs;
