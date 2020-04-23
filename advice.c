			 "as appropriate to mark resolution and make a commit."));
	[ADVICE_IMPLICIT_IDENTITY]			= { "implicitIdentity", 1 },
};

	{ "setUpstreamFailure", &advice_set_upstream_failure },
		return advice_setting[ADVICE_PUSH_UPDATE_REJECTED].enabled &&
int advice_push_fetch_first = 1;
		int slot = parse_advise_color_slot(slot_name);
	/* make this an alias for backward compatibility */
{
	{ "graftFileDeprecated", &advice_graft_file_deprecated },
		list_config_item(list, prefix, advice_setting[i].key);
void list_config_advices(struct string_list *list, const char *prefix)
	[ADVICE_PUSH_UPDATE_REJECTED]			= { "pushUpdateRejected", 1 },
int advice_waiting_for_editor = 1;
		       advice_setting[ADVICE_PUSH_UPDATE_REJECTED_ALIAS].enabled;
int advice_commit_before_merge = 1;
	"do so (now or later) by using -c with the switch command. Example:\n"
	{ "detachedHead", &advice_detached_head },
}
	ADVICE_COLOR_HINT = 1,
{
	{ "submoduleAlternateErrorStrategyDie", &advice_submodule_alternate_error_strategy_die },
		 * Message used both when 'git commit' fails and when
	{ "pushNonFastForward", &advice_push_update_rejected }
	{ "checkoutAmbiguousRemoteBranchName", &advice_checkout_ambiguous_remote_branch_name },
	else if (!strcmp(me, "commit"))
	strbuf_release(&buf);
int advice_push_update_rejected = 1;
void NORETURN die_conclude_merge(void)


{
		error(_("Committing is not possible because you have unmerged files."));
	error(_("You have not concluded your merge (MERGE_HEAD exists)."));
	[ADVICE_AM_WORK_DIR] 				= { "amWorkDir", 1 },
	int *preference;
	"You are in 'detached HEAD' state. You can look around, make experimental\n"
	}
		return ADVICE_COLOR_RESET;
	vadvise(advice, 1, advice_setting[type].key, params);
	"Or undo this operation with:\n"
		advise(_("Please, commit your changes before merging."));
			return 0;
	"\n"
		advice_setting[i].enabled = git_config_bool(var, value);
	for (i = 0; i < ARRAY_SIZE(advice_setting); i++)
		return advice_setting[type].enabled;
		if (strcasecmp(k, advice_config[i].name))
	if (want_color_stderr(advice_use_color))
	for (i = 0; i < ARRAY_SIZE(advice_setting); i++) {
			advise_get_color(ADVICE_COLOR_RESET));
			np++;
	[ADVICE_STATUS_AHEAD_BEHIND_WARNING]		= { "statusAheadBehindWarning", 1 },
	const char *key;
	{ "addEmbeddedRepo", &advice_add_embedded_repo },
	const char *fmt =
int advice_detached_head = 1;


} advice_config[] = {
	fprintf(stderr, fmt, new_name);
static const char turn_off_instructions[] =
		error(_("Reverting is not possible because you have unmerged files."));

	return -1;
int advice_add_ignored_file = 1;
	{ "rmHints", &advice_rm_hints },
{
	die(_("Exiting because of an unresolved conflict."));
{
			advise_get_color(ADVICE_COLOR_HINT),
void NORETURN die_resolve_conflict(const char *me)
	[ADVICE_RESOLVE_CONFLICT]			= { "resolveConflict", 1 },
	[ADVICE_NESTED_TAG]				= { "nestedTag", 1 },
int advice_status_u_option = 1;
	if (!strcmp(var, "color.advice")) {
void advise_if_enabled(enum advice_type type, const char *advice, ...)
	{ "commitBeforeMerge", &advice_commit_before_merge },
	{ "pushNonFFCurrent", &advice_push_non_ff_current },

int advice_graft_file_deprecated = 1;
	if (!advice_enabled(type))
static void vadvise(const char *advice, int display_instructions,
	"changes and commit them, and you can discard any commits you make in this\n"
}
		error(_("Pulling is not possible because you have unmerged files."));
static const char *advise_get_color(enum color_advice ix)

	{ "objectNameWarning", &advice_object_name_warning },
	{ "statusUoption", &advice_status_u_option },
	[ADVICE_SET_UPSTREAM_FAILURE]			= { "setUpstreamFailure", 1 },
{
		return color_parse(value, advice_colors[slot]);

void advise(const char *advice, ...)
	[ADVICE_STATUS_HINTS]				= { "statusHints", 1 },
	{ "amWorkDir", &advice_amworkdir },
int advice_push_unqualified_ref_name = 1;
	"\n"
}
static int parse_advise_color_slot(const char *slot)
		return advice_colors[ix];
	{ "pushUnqualifiedRefName", &advice_push_unqualified_ref_name },
	if (!strcasecmp(slot, "hint"))
#include "cache.h"

int advice_sequencer_in_use = 1;
	"\n"
	[ADVICE_PUSH_NEEDS_FORCE]			= { "pushNeedsForce", 1 },
	[ADVICE_PUSH_ALREADY_EXISTS]			= { "pushAlreadyExists", 1 },
	strbuf_vaddf(&buf, advice, params);
static struct {
	{ "waitingForEditor", &advice_waiting_for_editor },
	else if (!strcmp(me, "revert"))
		error(_("Cherry-picking is not possible because you have unmerged files."));
	{ "sequencerInUse", &advice_sequencer_in_use },


		error(_("Merging is not possible because you have unmerged files."));
} advice_setting[] = {
	[ADVICE_SUBMODULE_ALTERNATE_ERROR_STRATEGY_DIE] = { "submoduleAlternateErrorStrategyDie", 1 },
	va_end(params);
{
{
int advice_resolve_conflict = 1;
	}
	[ADVICE_CHECKOUT_AMBIGUOUS_REMOTE_BRANCH_NAME] 	= { "checkoutAmbiguousRemoteBranchName", 1 },
			continue;
N_("\n"
	int enabled;
		return ADVICE_COLOR_HINT;
		if (slot < 0)
	ADVICE_COLOR_RESET = 0,
	GIT_COLOR_YELLOW,	/* HINT */
}
	{ "resetQuiet", &advice_reset_quiet_warning },
#include "help.h"
}
#include "color.h"
	"\n"
	[ADVICE_STATUS_U_OPTION]			= { "statusUoption", 1 },
	va_list params;

	struct strbuf buf = STRBUF_INIT;
	return 0;
	"Turn off this advice by setting config variable advice.detachedHead to false\n\n");


	else if (!strcmp(me, "merge"))

	"  git switch -c <new-branch-name>\n"
void detach_advice(const char *new_name)
	[ADVICE_COMMIT_BEFORE_MERGE]			= { "commitBeforeMerge", 1 },
	va_end(params);
int advice_rm_hints = 1;
	if (skip_prefix(var, "color.advice.", &slot_name)) {
int advice_push_non_ff_matching = 1;
	"\n"
	{ "pushUpdateRejected", &advice_push_update_rejected },
	const char *name;
		np = strchrnul(cp, '\n');
}
	[ADVICE_SEQUENCER_IN_USE]			= { "sequencerInUse", 1 },

	[ADVICE_WAITING_FOR_EDITOR]			= { "waitingForEditor", 1 },
	if (display_instructions)
		 */
	_("Note: switching to '%s'.\n"
			return config_error_nonbool(var);
	va_start(params, advice);
		*advice_config[i].preference = git_config_bool(var, value);
{
			(int)(np - cp), cp,
	{ "statusHints", &advice_status_hints },
	[ADVICE_OBJECT_NAME_WARNING]			= { "objectNameWarning", 1 },
	/* make this an alias for backward compatibility */
}
	}
	const char *k, *slot_name;

		break;
int advice_fetch_show_forced_updates = 1;
	vadvise(advice, 0, "", params);
	[ADVICE_PUSH_NON_FF_CURRENT]			= { "pushNonFFCurrent", 1 },
	{ "pushAlreadyExists", &advice_push_already_exists },

	[ADVICE_PUSH_UPDATE_REJECTED_ALIAS]		= { "pushNonFastForward", 1 },
}
	if (!strcmp(me, "cherry-pick"))
enum color_advice {
};
		advise(_("Fix them up in the work tree, and then use 'git add/rm <file>'\n"
	{ "pushNeedsForce", &advice_push_needs_force },
	{ "addEmptyPathspec", &advice_add_empty_pathspec },
}
	[ADVICE_ADD_EMBEDDED_REPO]			= { "addEmbeddedRepo", 1 },



	[ADVICE_PUSH_FETCH_FIRST]			= { "pushFetchFirst", 1 },
	{ "statusAheadBehindWarning", &advice_status_ahead_behind_warning },
	return -1;
	if (!skip_prefix(var, "advice.", &k))
	int i;
		 * other commands doing a merge do.
	{ "resolveConflict", &advice_resolve_conflict },

	else if (!strcmp(me, "pull"))
int advice_push_non_ff_current = 1;

		if (!value)
		/*
int advice_reset_quiet_warning = 1;
	[ADVICE_FETCH_SHOW_FORCED_UPDATES]		= { "fetchShowForcedUpdates", 1 },
int advice_add_embedded_repo = 1;
			continue;
int git_default_advice_config(const char *var, const char *value)
	"  git switch -\n"
int error_resolve_conflict(const char *me)
	{ "pushFetchFirst", &advice_push_fetch_first },
	[ADVICE_IGNORED_HOOK]				= { "ignoredHook", 1 },

	{ "fetchShowForcedUpdates", &advice_fetch_show_forced_updates },
	[ADVICE_RESET_QUIET_WARNING]			= { "resetQuiet", 1 },
		return;
int advice_push_already_exists = 1;
	va_list params;
#include "config.h"
		return 0;
	if (advice_resolve_conflict)
int advice_push_needs_force = 1;
int advice_add_empty_pathspec = 1;
	va_start(params, advice);
{
	[ADVICE_RM_HINTS]				= { "rmHints", 1 },
{
int advice_set_upstream_failure = 1;
		    const char *key, va_list params)
	for (cp = buf.buf; *cp; cp = np) {
			me);

	default:
	const char *cp, *np;
	}
   "Disable this message with \"git config advice.%s false\"");

		if (*np)
static struct {

int advice_submodule_alternate_error_strategy_die = 1;
int advice_enabled(enum advice_type type)
	}

	error_resolve_conflict(me);
	}
		return 0;
int advice_amworkdir = 1;
		advice_use_color = git_config_colorbool(var, value);
	[ADVICE_GRAFT_FILE_DEPRECATED]			= { "graftFileDeprecated", 1 },
	{ "addIgnoredFile", &advice_add_ignored_file },
int advice_status_hints = 1;
static int advice_use_color = -1;
{
		fprintf(stderr,	_("%shint: %.*s%s\n"),
	return "";

}
	"If you want to create a new branch to retain commits you create, you may\n"
	[ADVICE_DETACHED_HEAD]				= { "detachedHead", 1 },
		error(_("It is not possible to %s because you have unmerged files."),


};
static char advice_colors[][COLOR_MAXLEN] = {
int advice_ignored_hook = 1;
int advice_object_name_warning = 1;
	{ "ignoredHook", &advice_ignored_hook },
int advice_checkout_ambiguous_remote_branch_name = 1;
	case ADVICE_PUSH_UPDATE_REJECTED:
	else
	die(_("Exiting because of unfinished merge."));
	int i;
	[ADVICE_PUSH_UNQUALIFIED_REF_NAME]		= { "pushUnqualifiedRefName", 1 },
	{ "pushNonFFMatching", &advice_push_non_ff_matching },
	[ADVICE_PUSH_NON_FF_MATCHING]			= { "pushNonFFMatching", 1 },
	if (advice_resolve_conflict)
	if (!strcasecmp(slot, "reset"))
int advice_status_ahead_behind_warning = 1;
};
}
}
		strbuf_addf(&buf, turn_off_instructions, key);
	GIT_COLOR_RESET,
	{ "implicitIdentity", &advice_implicit_identity },
	"\n"

		return 0;

	for (i = 0; i < ARRAY_SIZE(advice_config); i++) {
int advice_implicit_identity = 1;

		if (strcasecmp(k, advice_setting[i].key))
	switch(type) {
	"state without impacting any branches by switching back to a branch.\n"
