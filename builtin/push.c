
	   "counterpart. Check out this branch and integrate the remote changes\n"

				    query.force ? "+" : "",
{
	 * upstream to a non-branch, we should probably be showing
	if (!advice_push_fetch_first || !advice_push_update_rejected)
				     TRANS_OPT_RECEIVEPACK, receivepack);
	if (!branch)
	if (!push_refspec->nr && !(flags & TRANSPORT_PUSH_ALL)) {
	 * mode. If the user is doing something crazy like setting
}
	   "    git push %s HEAD:<name-of-remote-branch>\n");
		OPT_SET_INT('4', "ipv4", &family, N_("use IPv4 addresses only"),
	struct string_list *push_options;
	      "%s"),
	   "See the 'Note about fast-forwards' in 'git push --help' for details.");
	advise(_(message_advice_pull_before_push));
	int i, errs;
	      "the name of your current branch.  To push to the upstream branch\n"
			struct strbuf buf = STRBUF_INIT;
		    "    git push <name>\n"));
	if (deleterefs && argc < 2)
#include "submodule-config.h"

		return remote->pushurl_nr;
		    "and then push using the remote name\n"

		die(_("No configured push destination.\n"
		? &push_options_cmdline
{
	else if (arg)
			if (deleterefs)
	const char *branch_name;
	   "'git pull ...') before pushing again.\n"
	} else if (reject_reasons & REJECT_ALREADY_EXISTS) {

static int deleterefs;
	}
		break;

	}
static int option_parse_recurse_submodules(const struct option *opt,

	int triangular = is_workflow_triangular(remote);
	PUSH_COLOR_ERROR = 1
static int git_push_config(const char *k, const char *v, void *cb)
	 * push.default.
#include "run-command.h"
}
				   const char *arg, int unset)

				set_push_cert_flags(flags, SEND_PACK_PUSH_CERT_NEVER);
	   "not have locally. This is usually caused by another repository pushing\n"
static int parse_push_color_slot(const char *slot)
#include "transport.h"
		if (push_with_options(transport, push_refspec, flags))
{
	url_nr = push_url_of_remote(remote, &url);
		    "    git remote add <name> <url>\n"
	const char *advice_maybe = "";
}
	if (!is_empty_cas(&cas)) {
	if (push_options->nr)
	strbuf_addf(&refspec, "%s:%s", branch->refname, branch->refname);
		OPT_BIT(0, "atomic", &flags, N_("request atomic transaction on remote side"), TRANSPORT_PUSH_ATOMIC),
#include "color.h"
		OPT_BIT( 0,  "porcelain", &flags, N_("machine-readable output"), TRANSPORT_PUSH_PORCELAIN),
			else
#include "send-pack.h"
static const char message_detached_head_die[] =
	for (i = 0; i < nr; i++) {
		      "your current branch '%s', without telling me what to push\n"
	rc = do_push(repo, flags, push_options, remote);
	}
#include "cache.h"
		: &push_options_config);
	      "\n"
			PARSE_OPT_OPTARG, option_parse_recurse_submodules },

static NORETURN void die_push_simple(struct branch *branch,
		break;
		return;

	skip_prefix(short_upstream, "refs/heads/", &short_upstream);
	if (simple) {
	trace2_region_enter("push", "transport_push", the_repository);
		if (tags)
	N_("Updates were rejected because the remote contains work that you do\n"
	case SEND_PACK_PUSH_CERT_ALWAYS:
static int progress = -1;
		return color_parse(v, push_colors[slot]);
		setup_push_upstream(remote, branch, triangular, 0);
		    "To push the current branch and set the remote as upstream, use\n"
	case SEND_PACK_PUSH_CERT_NEVER:
			return config_error_nonbool(k);
{
				set_push_cert_flags(flags, SEND_PACK_PUSH_CERT_ALWAYS);
/*
	if (rc == -1)
int cmd_push(int argc, const char **argv, const char *prefix)
static void setup_default_push_refspecs(struct remote *remote)
				TRANSPORT_FAMILY_IPV4),
}
	switch (push_default) {
		OPT_BIT('u', "set-upstream", &flags, N_("set upstream for git pull/status"),
}
	return !!errs;

		    branch->name);
	   "to the same ref. You may want to first integrate the remote changes\n"
	advise(_(message_advice_ref_needs_force));
		int val = git_config_bool(k, v) ?
			struct strbuf buf = STRBUF_INIT;
		if (flags & TRANSPORT_PUSH_OPTIONS)
			die(_("push options must not have new line characters"));
		memset(&query, 0, sizeof(struct refspec_item));
	int url_nr;
		if (!v)
		advice_maybe = _("\n"
static const char message_advice_pull_before_push[] =
{
		return;

	PUSH_COLOR_RESET = 0,
	int flags = 0;
	refspec_append(&rs, refspec.buf);
		if (strcmp(branch->refname, branch->merge[0]->src))

		if (!strcmp("tag", ref)) {
		die(_(message_detached_head_die), remote->name);
static int push_url_of_remote(struct remote *remote, const char ***url_p)
		break;
					set_push_cert_flags(flags, SEND_PACK_PUSH_CERT_IF_ASKED);
	if (reject_reasons & REJECT_NON_FF_HEAD) {
		{ OPTION_CALLBACK,
			strbuf_addf(&delref, ":%s", ref);
static int verbosity;
static const char message_advice_ref_needs_force[] =
	   "(e.g. 'git pull ...') before pushing again.\n"
		    remote->name,
static struct push_cas_option cas;
	   "without using the '--force' option.\n");
enum color_push {
		{ OPTION_CALLBACK, 0, "recurse-submodules", &recurse_submodules, "(check|on-demand|no)",
				/* lazily grab remote and local_refs */
	 */
{
		break;
	} else if (reject_reasons & REJECT_FETCH_FIRST) {
	die(_("The upstream branch of your current branch does not match\n"
	if (recurse_submodules == RECURSE_SUBMODULES_CHECK)
		*flags |= TRANSPORT_PUSH_CERT_IF_ASKED;
}
		if (strchr(item->string, '\n'))
		    "\n"
			if (push_with_options(transport, push_refspec, flags))
	int push_cert = -1;
		query.src = matched->name;
 * "git push"
	argc = parse_options(argc, argv, prefix, options, push_usage, 0);
#include "remote.h"
		*recurse_submodules = RECURSE_SUBMODULES_OFF;
			if (flags & TRANSPORT_PUSH_OPTIONS)
	advise(_(message_advice_ref_already_exists));
		die(_("The current branch %s has multiple upstream branches, "
		fprintf(stderr, "%s", push_get_color(PUSH_COLOR_ERROR));
}
		advise_ref_fetch_first();

	} else if (!strcmp(k, "push.gpgsign")) {
}
	int rc;

	transport_set_option(transport, TRANS_OPT_THIN, thin ? "yes" : NULL);
	N_("Updates were rejected because a pushed branch tip is behind its remote\n"
			TRANSPORT_PUSH_FOLLOW_TAGS),
	if (!strcmp(k, "push.followtags")) {
		if (triangular)
	}

		OPT_BOOL(0, "progress", &progress, N_("force progress reporting")),
				TRANSPORT_FAMILY_IPV6),
	N_("You cannot update a remote ref that points at a non-commit object,\n"
static void advise_ref_already_exists(void)
	int i;
	struct strbuf refspec = STRBUF_INIT;
	if (flags & TRANSPORT_PUSH_ALL) {
		return push_colors[ix];
		return ref;
	if (triangular)
		break;
		refspec_append(&rs, "refs/tags/*");
	if (remote->push.nr) {
		else
}
	if (flags & TRANSPORT_PUSH_MIRROR) {
			die("underlying transport does not support --%s option",
	} else if (reject_reasons & REJECT_NEEDS_FORCE) {
				local_refs = get_local_heads();
		struct transport *transport =
	const char *slot_name;
	    skip_prefix(matched->name, "refs/heads/", &branch_name)) {
		struct branch *branch = branch_get(branch_name);
		advise_pull_before_push();
	default:

				die(_("tag shorthand without <tag>"));
		return 0;

			transport_get(remote, NULL);
		}
static struct refspec rs = REFSPEC_INIT_PUSH;
				break;
				if (value && !strcasecmp(value, "if-asked"))
			    CAS_OPT_NAME);
static void set_refspecs(const char **refs, int nr, const char *repo)
	 * as the ambiguity would be on the remote side, not what
				 "see push.default in 'git help config'.");

}
}
		recurse_submodules = val;
				 "To choose either option permanently, "

	}
			}
	return "";
	   "See the 'Note about fast-forwards' in 'git push --help' for details.");
{
	if (err != 0) {

		    "\n"
		    branch->name,
		    "\n"
	struct refspec *push_refspec = &rs;
};
	/* Does "ref" uniquely name our ref? */
		die(_("The current branch %s has no upstream branch.\n"
		if (!v)
	if (verbosity > 0)
static const char message_advice_ref_already_exists[] =
		OPT_BIT(0, "prune", &flags, N_("prune locally removed refs"),
				string_list_clear(&push_options_config, 0);
		  0, "signed", &push_cert, "(yes|no|if-asked)", N_("GPG sign the push"),
		flags |= TRANSPORT_PUSH_OPTIONS;
			setup_push_upstream(remote, branch, triangular, 1);
	struct option options[] = {
		} else if (!(flags & TRANSPORT_PUSH_MIRROR))
	packet_trace_identity("push");
			    (TRANSPORT_PUSH_MIRROR|TRANSPORT_PUSH_FORCE)),
	struct ref *local_refs = NULL;

	if (remote->mirror)
	status = git_gpg_config(k, v, NULL);
static void advise_pull_before_push(void)
}
			return strbuf_detach(&buf, NULL);
	   "(e.g., 'git pull ...') before pushing again.\n"
	refspec_append(&rs, refspec.buf);
				errs++;
{
			setup_default_push_refspecs(remote);
		}
	}
		OPT__VERBOSITY(&verbosity),
		return;

			switch (git_parse_maybe_bool(value)) {
	else
	struct string_list push_options_cmdline = STRING_LIST_INIT_DUP;
			setup_push_current(remote, branch);
		if (tags)
		OPT_BOOL( 0 , "tags", &tags, N_("push tags (can't be used with --all or --mirror)")),
		die(_("--delete doesn't make sense without any refs"));
}
				remote = remote_get(repo);
	else if (recurse_submodules == RECURSE_SUBMODULES_ON_DEMAND)
}
	GIT_COLOR_RESET,
		const char *value;
		die(_("You didn't specify any refspecs to push, and "
		setup_push_current(remote, branch);
	}


	const struct string_list_item *item;


{
		die("%s missing parameter", opt->long_name);
		*flags &= ~TRANSPORT_PUSH_CERT_IF_ASKED;
	   "See the 'Note about fast-forwards' in 'git push --help' for details.");
static int push_with_options(struct transport *transport, struct refspec *rs,
			ref = strbuf_detach(&delref, NULL);
	};
{
#include "parse-options.h"

	} else {
		    "Either specify the URL from the command-line or configure a remote repository using\n"
			else
	if (!advice_push_non_ff_matching || !advice_push_update_rejected)
	} else if (!strcmp(k, "submodule.recurse")) {
		else
static int is_workflow_triangular(struct remote *remote)
		if (argc >= 2)
		die(_("--all and --mirror are incompatible"));
			die(_("--mirror can't be combined with refspecs"));
		OPT_END()
	 * we have locally. Plus, this is supposed to be the simple
	    remote->name, short_upstream,
	if (push_default == PUSH_DEFAULT_UPSTREAM &&
	int *flags = cb;
	N_("Updates were rejected because the tag already exists in the remote.");
			     rs, flags, &reject_reasons);
	}
	      "    git push %s HEAD:%s\n"
{
{
	struct ref *matched = NULL;
static void advise_ref_needs_force(void)
		OPT_SET_INT('6', "ipv6", &family, N_("use IPv6 addresses only"),
	if (remote->pushurl_nr) {

	for_each_string_list_item(item, push_options)
	err |= transport_disconnect(transport);
		die(_(message_detached_head_die), remote->name);
	int status;


{
static void advise_checkout_pull_push(void)
	if (url_nr) {
	if (unset)
		}

				    ref, branch->merge[0]->src);
static const char *map_refspec(const char *ref,
		break;
	case PUSH_DEFAULT_NOTHING:
static int push_use_color = -1;
{
		OPT_BIT( 0 , "all", &flags, N_("push all refs"), TRANSPORT_PUSH_ALL),
		if (branch->merge_nr == 1 && branch->merge[0]->src) {
		   const struct string_list *push_options,
		break;
				break;

		const char *value;

		if (!transport->smart_options)
	if (!strcasecmp(slot, "reset"))
		OPT_BOOL_F( 0 , "thin", &thin, N_("use thin pack"), PARSE_OPT_NOCOMPLETE),
		repo = argv[0];
}
	}
#include "refspec.h"
	const char *short_upstream = branch->merge[0]->src;

	if ((flags & TRANSPORT_PUSH_ALL) && (flags & TRANSPORT_PUSH_MIRROR))
		int slot = parse_push_color_slot(slot_name);
	      "\n"
			if (!remote) {
		    "    git push --set-upstream %s %s\n"),
}
	remote = pushremote_get(repo);
			die(_("--mirror and --tags are incompatible"));
	}
	if (!remote) {
	NULL,

static void setup_push_current(struct remote *remote, struct branch *branch)
		if (!git_config_get_value("push.recursesubmodules", &value))
{

			ref = refs[i];
	int tags = 0;
	*url_p = remote->url;
		return status;

	} else if (skip_prefix(k, "color.push.", &slot_name)) {
				else
		if (!query_refspecs(&remote->push, &query) && query.dst) {
		refspec_append(&rs, ref);
			strbuf_addf(&buf, "%s:%s",
		flags |= TRANSPORT_RECURSE_SUBMODULES_CHECK;
#include "config.h"
	struct strbuf refspec = STRBUF_INIT;
			transport->push_options = push_options;
		    "push.default is \"nothing\"."));
				int triangular, int simple)

		OPT_STRING_LIST('o', "push-option", &push_options_cmdline, N_("server-specific"), N_("option to transmit")),
		return;
{
	case PUSH_DEFAULT_UPSTREAM:
	const char **url;
				string_list_append(&push_options_config, v);
	}
		/* Additional safety */
	case PUSH_DEFAULT_UNSPECIFIED:
		  0, CAS_OPT_NAME, &cas, N_("<refname>:<expect>"),
{
		if (repo)
#include "refs.h"
		transport->smart_options->cas = &cas;
		const char *ref = refs[i];
		OPT_BIT(0, "no-verify", &flags, N_("bypass pre-push hook"), TRANSPORT_PUSH_NO_HOOK),
		  PARSE_OPT_OPTARG | PARSE_OPT_LITERAL_ARGHELP, parseopt_push_cas_option },
			N_("control recursive pushing of submodules"),
	if (!branch->merge_nr || !branch->merge || !branch->remote_name)
	}

		push_use_color = git_config_colorbool(k, v);
	if (argc > 0) {
			RECURSE_SUBMODULES_ON_DEMAND : RECURSE_SUBMODULES_OFF;

static int do_push(const char *repo, int flags,
		fprintf(stderr, _("Pushing to %s\n"), transport->url);
static char push_colors[][COLOR_MAXLEN] = {

	case PUSH_DEFAULT_SIMPLE:
			default:
	}
		return;
		}
		OPT_STRING( 0 , "repo", &repo, N_("repository"), N_("repository")),
		OPT_BIT('n' , "dry-run", &flags, N_("dry run"), TRANSPORT_PUSH_DRY_RUN),
	    remote->name, advice_maybe);
			     int flags)
	else if (recurse_submodules == RECURSE_SUBMODULES_ONLY)
	if (!strcasecmp(slot, "error"))

	GIT_COLOR_RED,	/* ERROR */

{
				transport->push_options = push_options;
static struct string_list push_options_config = STRING_LIST_INIT_DUP;
		return PUSH_COLOR_RESET;
			if (strchr(ref, ':'))
			       struct remote *remote, struct ref *local_refs)
}
	if (!branch)
				strbuf_addf(&tagref, ":refs/tags/%s", ref);

	if (status)
	 */
static enum transport_family family;
	if (!err)
		advise_checkout_pull_push();
	if (branch->merge_nr != 1)
		if (remote->push.nr) {
		      "to update which remote branch."),
	if (receivepack)

	if (!advice_push_already_exists || !advice_push_update_rejected)
	push_options = (push_options_cmdline.nr
			die(_("--all can't be combined with refspecs"));
	advise(_(message_advice_ref_fetch_first));
	advise(_(message_advice_checkout_pull_push));
}
#include "builtin.h"
				     struct remote *remote)
		die(_("You are pushing to remote '%s', which is not the upstream of\n"
	 * There's no point in using shorten_unambiguous_ref here,
	string_list_clear(&push_options_cmdline, 0);
	case PUSH_DEFAULT_CURRENT:
	   "or update a remote ref to make it point at a non-commit object,\n"
static void set_push_cert_flags(int *flags, int v)


	   "\n"

		flags |= TRANSPORT_RECURSE_SUBMODULES_ON_DEMAND;
	   "its remote counterpart. Integrate the remote changes (e.g.\n"
		OPT_STRING( 0 , "receive-pack", &receivepack, "receive-pack", N_("receive pack program")),
};
{
}
			}
	return git_default_config(k, v, NULL);

	      "\n"
			case 1:
	set_push_cert_flags(&flags, push_cert);
	} else if (!strcmp(k, "push.recursesubmodules")) {
	case SEND_PACK_PUSH_CERT_IF_ASKED:

};
			die_push_simple(branch, remote);
	/*
		    remote->name, branch->name);

	}
	N_("git push [<options>] [<repository> [<refspec>...]]"),
	 * them the big ugly fully qualified ref.
		refspec_append(&rs, ":");
			ref = strbuf_detach(&tagref, NULL);
		OPT_STRING( 0 , "exec", &receivepack, "receive-pack", N_("receive pack program")),
	else
	const char *repo = NULL;	/* default repository */
		*flags &= ~(TRANSPORT_PUSH_CERT_ALWAYS | TRANSPORT_PUSH_CERT_IF_ASKED);
		flags |= (TRANSPORT_PUSH_MIRROR|TRANSPORT_PUSH_FORCE);
	}
	switch (v) {
	case PUSH_DEFAULT_MATCHING:

		transport_set_option(transport,
			if (!*v)
			return strbuf_detach(&buf, NULL);
		else
	if (push_default == PUSH_DEFAULT_UNSPECIFIED)

		if (!git_config_get_value("push.gpgsign", &value)) {
			recurse_submodules = parse_push_recurse_submodules_arg(k, value);
	}
static int thin = 1;
				    query.src, query.dst);
		struct refspec_item query;
static void advise_ref_fetch_first(void)
	transport_set_verbosity(transport, verbosity, progress);
		break;
			die(_("--all and --tags are incompatible"));

		OPT_BOOL('d', "delete", &deleterefs, N_("delete refs")),
		error(_("failed to push some refs to '%s'"), transport->url);

	      "    git push %s HEAD\n"

			return config_error_nonbool(k);
	return ref;
		return 0;
			*flags |= TRANSPORT_PUSH_FOLLOW_TAGS;
	transport->family = family;
	if (count_refspec_match(ref, local_refs, &matched) != 1)
	git_config(git_push_config, &flags);
	      "To push to the branch of the same name on the remote, use\n"
		   struct remote *remote)
		}
 */
		die(_("--delete is incompatible with --all, --mirror and --tags"));
	return -1;
			struct strbuf tagref = STRBUF_INIT;
	trace2_region_leave("push", "transport_push", the_repository);

	N_("You are not currently on a branch.\n"
			TRANSPORT_PUSH_SET_UPSTREAM),
		  N_("require old value of ref to be at this value"),
	strbuf_addf(&refspec, "%s:%s", branch->refname, branch->merge[0]->src);
static void setup_push_upstream(struct remote *remote, struct branch *branch,
	unsigned int reject_reasons;
		usage_with_options(push_usage, options);
		return 0;
	err = transport_push(the_repository, transport,
	} else if (reject_reasons & REJECT_NON_FF_OTHER) {
		*flags |= TRANSPORT_PUSH_CERT_ALWAYS;

		*url_p = remote->pushurl;
		{ OPTION_CALLBACK,
			errs++;
		    "refusing to push."), branch->name);
		if (argc >= 2)
	   "To push the history leading to the current (detached HEAD)\n"
		for (i = 0; i < url_nr; i++) {
#include "submodule.h"
	return (fetch_remote && fetch_remote != remote);
	struct remote *fetch_remote = remote_get(NULL);
			*flags &= ~TRANSPORT_PUSH_FOLLOW_TAGS;
	   "state now, use\n"
	      "on the remote, use\n"
				strbuf_addf(&tagref, "refs/tags/%s", ref);

			ref = map_refspec(ref, remote, local_refs);

	return 1;
		*recurse_submodules = parse_push_recurse_submodules_arg(opt->long_name, arg);
		fprintf(stderr, "%s", push_get_color(PUSH_COLOR_RESET));
	return remote->url_nr;

	errs = 0;


	string_list_clear(&push_options_config, 0);
static int recurse_submodules = RECURSE_SUBMODULES_DEFAULT;
		*flags &= ~TRANSPORT_PUSH_CERT_ALWAYS;
			case 0:
static const char message_advice_checkout_pull_push[] =
		  PARSE_OPT_OPTARG, option_parse_push_signed },
		return PUSH_COLOR_ERROR;
			die(_("bad repository '%s'"), repo);
		    "\n"
		set_refspecs(argv + 1, argc - 1, repo);

}

		if (slot < 0)
static const char message_advice_ref_fetch_first[] =
			struct strbuf delref = STRBUF_INIT;
	} else if (!strcmp(k, "color.push")) {
			if (nr <= ++i)
	N_("Updates were rejected because the tip of your current branch is behind\n"

	if (want_color_stderr(push_use_color))

	struct branch *branch = branch_get(NULL);
}
		flags |= TRANSPORT_RECURSE_SUBMODULES_ONLY;
			return 0;
	int *recurse_submodules = opt->value;
		} else if (deleterefs) {
	if (!advice_push_needs_force || !advice_push_update_rejected)
				transport_get(remote, url[i]);
		return 0;
	if (!advice_push_non_ff_current || !advice_push_update_rejected)


			push_refspec = &remote->push;
	return 0;
static const char *push_get_color(enum color_push ix)

	/*
	}
		} else if (!strchr(ref, ':')) {
static const char *receivepack;

				die(_("--delete only accepts plain target ref names"));
	} else if (!strcmp(k, "push.pushoption")) {
	int err;
	if (deleterefs && (tags || (flags & (TRANSPORT_PUSH_ALL | TRANSPORT_PUSH_MIRROR))))
		OPT_BIT(0, "follow-tags", &flags, N_("push missing but relevant tags"),
{

	 * Don't show advice for people who explicitly set
		if (git_config_bool(k, v))
			TRANSPORT_PUSH_PRUNE),
	if (tags)


		OPT_BIT( 0 , "mirror", &flags, N_("mirror all refs"),
	struct remote *remote;
static const char * const push_usage[] = {
{
					return error("Invalid value for '%s'", k);
		return rc;
			struct transport *transport =
		OPT_BIT('f', "force", &flags, N_("force updates"), TRANSPORT_PUSH_FORCE),

		advise_ref_already_exists();
	struct remote *remote = NULL;
		advise_ref_needs_force();
			strbuf_addf(&buf, "%s%s:%s",
