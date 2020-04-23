
	if (others.nr)
	if (skip_prefix(name, "git-", &new_name))
	string_list_sort(&keys);
		}
	struct string_list *similar_refs;
int is_in_cmdlist(struct cmdnames *c, const char *s)
	int i;
	}
	for (e = slot_expansions; e->prefix; e++)
#include "cache.h"
{
{
			path = colon + 1;
	for (i = 0; i < keys.nr; i++) {
	{ CAT_worktree, N_("work on the current change (see also: git help everyday)") },

		fprintf_ln(stderr,
				break;
{
		putchar('\n');
	 * about layout strategy and stuff
	struct category_description catdesc[] = {


{

	int build_options = 0;

static struct cmdnames aliases;
	for (i = 0; i < ARRAY_SIZE(command_list); i++) {
			aliases[i].name = alias_list.items[i].string;
	DIR *dir = opendir(path);
		die(_("unsupported command listing type '%s'"), cat);
			   cmd);
		for (i = 0; i < alias_list.nr; i++) {

			size_t len = strlen(cmds[i].name);

			continue;
				e->fn(&keys, e->prefix);
		return;
}
	}

{
	int i;
	print_cmd_by_category(main_categories, &longest);
	}

}
				continue;

	};
	 */

	print_cmd_by_category(catdesc, NULL);
		strip_suffix(ent, ".exe", &entlen);
	 * always enable column display, we only consult column.*
	}
	return similar_refs;
	putchar('\n');
		   struct cmdnames *main_cmds, struct cmdnames *other_cmds)

		      best_similarity == main_cmds.names[n]->len);
	extract_cmds(&cmds, mask);
	};
{
	 * with external projects that rely on the output of "git version".
	int ci, cj, ei;

			       git_built_from_commit_string);
	struct similar_ref_cb ref_cb;

	const char * const usage[] = {

			printf("built from commit: %s\n",
			longest = len;



			continue;
		if (wildcard && !tag)
		putchar('\n');
	for_each_ref(append_similar_ref, &ref_cb);
static int cmd_name_cmp(const void *elem1, const void *elem2)
	struct cmdname *a = *(struct cmdname **)a_;

		die(_("Uh oh. Your system reports no Git commands at all."));

{
			      int flags, void *cb_data)

				     "you meant '%s'."),

	memset(&other_cmds, 0, sizeof(other_cmds));
		add_cmdname(&aliases, p, strlen(p));
	}
		for (i = 0; i < suggested_refs.nr; i++)
	}
			      "\nThe most similar commands are",
			   Q_("\nThe most similar command is",
	struct string_list suggested_refs = guess_refs(ref);


		entlen = strlen(ent);
static void print_command_list(const struct cmdname_help *cmds,
		{ CAT_guide, N_("The common Git guides are:") },
	ref_cb.similar_refs = &similar_refs;
		ALLOC_ARRAY(aliases, alias_list.nr + 1);
		return;
static int levenshtein_compare(const void *p1, const void *p2)
	puts(_("These are common Git commands used in various situations:"));

	if (alias_list.nr) {
}
		printf("\n%s\n", _("Command aliases"));
	/*
static int cmdname_compare(const void *a_, const void *b_)

		const char *p = strchrnul(cmd_list, ' ');

				break;


			printf("no commit associated with this build\n");

	struct cmdname_help *cmds;

		{ "color.diff", "<slot>", list_config_color_diff_slots },

		}
		/* prefix matches with everything? that is too ambiguous */
		wildcard = strchr(var, '*');
	printf("git version %s\n", git_version_string);
	}
		return new_name;

	return name;
	struct slot_expansion *e;
static void print_cmd_by_category(const struct category_description *catdesc,
}
	struct cmdname_help *aliases;
		if (cmds[i].category & mask) {
	FREE_AND_NULL(old->names);


	ref_cb.base_ref = ref;
	struct string_list similar_refs = STRING_LIST_INIT_DUP;
{
			if (!exec_path || strcmp(path, exec_path))
	fprintf_ln(stderr, _("git: '%s' is not a git command. See 'git --help'."), cmd);
#include "exec-cmd.h"

			n++;

		cmds[nr] = *cmd;
	if (main_cmds.cnt <= n) {
		}
}
	return 0;
	 * Always show the version, even if other options are given.
	clean_cmdnames(&main_cmds);
	if (git_config_get_string_const("completion.commands", &cmd_list))
		strbuf_release(&sb);
	while (*cmd_list) {
	QSORT(main_cmds.names, main_cmds.cnt, cmdname_compare);
	exclude_cmds(other_cmds, main_cmds);
	strbuf_release(&buf);
	for (p = config_name_list; *p; p++) {
	memset(&aliases, 0, sizeof(aliases));
	struct column_options copts;
	void (*fn)(struct string_list *list, const char *prefix);
		const char *exec_path = git_exec_path();

}
void list_config_help(int for_human)
	for (i = j = 1; i < cmds->cnt; i++) {
		QSORT(main_cmds->names, main_cmds->cnt, cmdname_compare);
		printf("   %s\n", others.items[i].string);
				main_cmds.names[i]->len = 0;
	}
{
			return 1;
	if (!prefix)
			continue;
		cmp = strcmp(cmds->names[ci]->name, excludes->names[ei]->name);

		 * for some reason exec'ing it gave us ENOENT; probably
		free(aliases);
		{ "color.grep", "<slot>", list_config_color_grep_slots },
	exit(1);
		while (1) {
			cut = tag;
	int i, longest;
	clean_cmdnames(&other_cmds);
				   assumed);


			fprintf(stderr, "\t%s\n", suggested_refs.items[i].string);
	const char *p;
		while (common_cmds[n].name &&
			   const char *cat)
static int append_similar_ref(const char *refname, const struct object_id *oid,

		OPT_BOOL(0, "build-options", &build_options,
			free(cmds->names[i]);



#define SIMILARITY_FLOOR 7
		cmds->names[cj++] = cmds->names[ci++];
}
		 * git-completion.bash to handle
		if (for_human) {
			if (longest > len)
	int i;
				   _("Continuing under the assumption that "
		string_list_append(list, drop_prefix(cmd->name, cmd->category));
	if (suggested_refs.nr > 0) {

		if (common_cmds[n].name && !cmp) {
	if (skip_prefix(var, "alias.", &var))
			continue;
			puts(var);
		 * it's a bad interpreter in the #! line.
}
	ALLOC_GROW(cmds->names, cmds->cnt + 1, cmds->alloc);
		if (longest < len)
	return strcmp(e1->name, e2->name);
	/*

	}
		struct cmdname_help *cmd = command_list + i;
		best_similarity = SIMILARITY_FLOOR + 1;
			cut = wildcard;

#include "version.h"
	QSORT(main_cmds.names, main_cmds.cnt, levenshtein_compare);
	cmds->names[cmds->cnt++] = ent;
			    e->prefix, e->placeholder);
	if (category == CAT_guide && skip_prefix(name, "git", &new_name))
		main_cmds.names[i]->len =
};
	int i;
#include "levenshtein.h"
	free(cmds->names);
		uniq(other_cmds);
	const char *cmd_list;
	int i;
static void extract_cmds(struct cmdname_help **p_cmds, uint32_t mask)
		 * An exact match means we have the command, but

			printf("   %s   ", cmds[i].name);
	cmds[nr].name = NULL;
		uint32_t mask = catdesc[i].category;
void list_common_cmds_help(void)
static void list_commands_in_dir(struct cmdnames *cmds,

void add_cmdname(struct cmdnames *cmds, const char *name, int len)


	}


	add_cmd_list(&main_cmds, &aliases);
		OPT_END()

	const char **p;
		} else if (cmp > 0)
void list_cmds_by_category(struct string_list *list,
					 shorten_unambiguous_ref(refname, 1));
{

	{ 0, NULL }
	}
	cmds->alloc = 0;
{
		struct cmdnames *main_cmds,
	for (i = 0; i < main_cmds.cnt; i++)
		print_command_list(cmds, mask, longest);

	{ CAT_purehelpers, N_("Low-level Commands / Internal Helpers") },
	copts.padding = 2;

	read_early_config(git_unknown_cmd_config, NULL);
					 const char *path,
		print_command_list(aliases, 1, longest);
	const char *base_ref;

{
	int i;


	QSORT(cmds, nr, cmd_name_cmp);
			 "also print build options"),
				mput_char(' ', longest - len);
	return 0;
		const char *ent;

	load_command_list("git-", &main_cmds, &other_cmds);
				/* Give prefix match a very good score */

		else {
{

}
}
	for (i = 0; i < cmds->cnt; ++i)
		fprintf_ln(stderr,
			   Q_("\nDid you mean this?",
		tag = strchr(var, '<');
	return 0;
		if (!strcmp(cat, category_names[i])) {
void list_cmds_by_config(struct string_list *list)
		if (cmp < 0)
}
		else if (!wildcard && tag)
			strbuf_addf(&sb, "%s.%s", e->prefix, e->placeholder);
}

}
			string_list_append(&keys, var);
			}

	*p_cmds = cmds;
	if (starts_with(refname, "refs/remotes/") &&
		/*
				   (float)autocorrect/10.0, assumed);
	cmds->cnt = j;
	exit(1);

	cmds->cnt = 0;
static int git_unknown_cmd_config(const char *var, const char *value, void *cb)
	}

}

			string_list_remove(list, sb.buf + 1, 0);
static struct category_description common_categories[] = {
	struct cmdname_help *cmds;
		aliases[alias_list.nr].name = NULL;
			aliases[i].category = 1;


		size_t entlen;
		printf("\n%s\n", _(desc));
	closedir(dir);
void list_commands(unsigned int colopts,
			longest = strlen(cmds[i].name);
		printf_ln(_("available git commands in '%s'"), exec_path);
#include "command-list.h"
	N_("'%s' appears to be a git command, but we were not\n"
	struct cmdname *ent;
			ei++;
	strbuf_addf(&buf, "%s/", path);
		const char *var = *p;

{
		return new_name;
		strbuf_addstr(&buf, de->d_name);
	len = buf.len;
			fprintf(stderr, "\t%s\n", main_cmds.names[i]->name);
		/* count all the most similar ones */
				e->found++;
		else
	int i, n, best_similarity = 0;
		     (n < main_cmds.cnt &&
	add_cmd_list(&main_cmds, &other_cmds);
		{ "advice", "*", list_config_advices },

	 * The format of this string should be kept stable for compatibility
	struct string_list alias_list = STRING_LIST_INIT_DUP;
	struct option options[] = {
void list_all_other_cmds(struct string_list *list)
			ei++;
	int i, nr = 0;
		struct strbuf sb = STRBUF_INIT;
	string_list_clear(&alias_list, 1);
		for (best_similarity = main_cmds.names[n++]->len;
#include "string-list.h"
	for (i = 0; cmds[i].name; i++, nr++) {
		{ "color.status", "<slot>", list_config_color_status_slots },
			break;

	int i, n = ARRAY_SIZE(command_list);
	uint32_t category;
void list_all_cmds_help(void)
	for (i = 0; i < cmds->cnt; i++)
	string_list_clear(&suggested_refs, 0);
	if (!strcmp(var, "help.autocorrect"))

		uniq(main_cmds);
	if (exec_path) {
			     "which does not exist."),
	int len;
			levenshtein(cmd, candidate, 0, 2, 1, 3) + 1;

	struct string_list list = STRING_LIST_INIT_NODUP;
	}
			fprintf_ln(stderr,
	argc = parse_options(argc, argv, prefix, options, usage, 0);
	uint32_t cat_id = 0;
static int autocorrect;
	}
	char *branch = strrchr(refname, '/') + 1;
		printf("cpu: %s\n", GIT_HOST_CPU);
	return 0;

static void pretty_print_cmdnames(struct cmdnames *cmds, unsigned int colopts)
		const char *assumed = main_cmds.names[0]->name;
		 * We may produce duplicates, but that's up to
	{ CAT_plumbingmanipulators, N_("Low-level Commands / Manipulators") },
		putchar('\n');
			strbuf_reset(&sb);
	const char *env_path = getenv("PATH");
}
	if (build_options) {
		 */
	/* Also use aliases for command lookup */
			string_list_insert(list, sb.buf);

struct similar_ref_cb {
#include "run-command.h"
#define SIMILAR_ENOUGH(x) ((x) < SIMILARITY_FLOOR)
const char *help_unknown_cmd(const char *cmd)
		N_("git version [<options>]"),
	 */
		const char *var = keys.items[i].string;
		if (!skip_prefix(de->d_name, prefix, &ent))
	for (i = 0, n = 0; i < main_cmds.cnt; i++) {
	uint32_t mask = 0;

}
	for (i = 0; i < n; i++) {
static uint32_t common_mask =

				*colon = 0;
			n++; /* use the entry from common_cmds[] */
		strbuf_release(&sb);
		for (e = slot_expansions; e->prefix; e++) {
void list_all_main_cmds(struct string_list *list)
}
	ALLOC_ARRAY(cmds, ARRAY_SIZE(command_list) + 1);
{
			aliases[i].help = alias_list.items[i].util;
{
	/* skip and count prefix matches */
	}
		const char *wildcard, *tag, *cut;


	if (!main_cmds.cnt)
	} else {
	int l2 = (*c2)->len;
	while ((de = readdir(dir)) != NULL) {
		const char *candidate = main_cmds.names[i]->name;
	const char *s1 = (*c1)->name, *s2 = (*c2)->name;
	{ CAT_init, N_("start a working area (see also: git help tutorial)") },
	struct cmdnames main_cmds, other_cmds;
	int cmp;
			   _("WARNING: You called a Git command named '%s', "
		 */

}
	if (longest_p)

		while (*p == ' ')
	string_list_clear(&list, 0);
	{ CAT_synchingrepositories, N_("Low-level Commands / Syncing Repositories") },
	ent->len = len;
}
				list_commands_in_dir(other_cmds, path, prefix);
	{ CAT_history, N_("grow, mark and tweak your common history") },
	while (ci < cmds->cnt && ei < excludes->cnt) {
		return assumed;
	for (i = 0; i < others.nr; i++)
		strbuf_add(&sb, cmd_list, p - cmd_list);
			puts(var);
		}

			fprintf_ln(stderr,
		printf("sizeof-size_t: %d\n", (int)sizeof(size_t));
	int l1 = (*c1)->len;
	if (!cmds->cnt)
	ALLOC_GROW(cmds->names, cmds->cnt + old->cnt, cmds->alloc);
};
		size_t len = strlen(alias_list.items[i].string);
		pretty_print_cmdnames(main_cmds, colopts);
	string_list_sort(&alias_list);
			p++;

#include "column.h"
		{ "color.decorate", "<slot>", list_config_color_decorate_slots },
	clean_cmdnames(&main_cmds);
	int i;
	const char *prefix;
		printf_ln(_("git commands available from elsewhere on your $PATH"));
		struct cmdnames *other_cmds)
	}
{
		}
void list_common_guides_help(void)
		for (i = 0; i < n; i++)
		free(cmds->names[i]);
	string_list_remove_duplicates(list, 0);
		if (!strcmp(candidate, cmd))
	for (i = 0; i < old->cnt; i++)
	    !strcmp(branch, cb->base_ref))

{
	}
{
		else

		add_cmdname(cmds, ent, entlen);
		pretty_print_cmdnames(other_cmds, colopts);
	struct string_list keys = STRING_LIST_INIT_DUP;
		/* Does the candidate appear in common_cmds list? */
		cmds->names[cmds->cnt++] = old->names[i];

	/* This abuses cmdname->len for levenshtein distance */


		{ "color.remote", "<slot>", list_config_color_sideband_slots },
}
	memset(&main_cmds, 0, sizeof(main_cmds));


	if (!cat_id)
		if (!wildcard && !tag) {


		path = paths = xstrdup(env_path);
	cmds->cnt = cj;
		if (autocorrect < 0)
			; /* still counting */
	memset(&copts, 0, sizeof(copts));
		return;

	while (ci < cmds->cnt)
	struct cmdnames main_cmds, other_cmds;
	const char *placeholder;
		cmds[nr].name = drop_prefix(cmd->name, cmd->category);


		*longest_p = longest;
		}
	print_cmd_by_category(common_categories, NULL);
		cmd_list = p;
}

}
NORETURN void help_unknown_ref(const char *ref, const char *cmd,

	if (!dir)
		printf("%.*s\n", (int)(cut - var), var);
	struct slot_expansion slot_expansions[] = {
					 const char *prefix)
	struct string_list others = STRING_LIST_INIT_DUP;
	int longest = 0;
		if (!is_executable(buf.buf))
			puts(_(cmds[i].help));
{
#include "builtin.h"
}
	print_columns(&list, colopts, &copts);
		if (sb.buf[0] == '-')

{
	for (n = 0; n < main_cmds.cnt && !main_cmds.names[n]->len; n++)
			BUG("slot_expansion %s.%s is not used",
}
{

	if (main_cmds->cnt) {
struct category_description {
			free(cmds->names[ci++]);
	{ CAT_ancillaryinterrogators, N_("Ancillary Commands / Interrogators") },
		const char *desc = catdesc[i].desc;
	CAT_history | CAT_remote;
#include "help.h"
}
	fprintf_ln(stderr, _("%s: %s - %s"), cmd, ref, error);
	list_all_other_cmds(&others);
#include "config.h"

	if (other_cmds->cnt) {
static void clean_cmdnames(struct cmdnames *cmds)

/* An empirically derived magic number */
		{ "fsck", "<msg-id>", list_config_fsck_msg_ids },
				  int *longest_p)
			if (!colon)
	int i, nr = 0;
			cat_id = 1UL << i;
	}
void exclude_cmds(struct cmdnames *cmds, struct cmdnames *excludes)
		}
	{ CAT_plumbinginterrogators, N_("Low-level Commands / Interrogators") },
	"able to execute it. Maybe git-%s is broken?");
	{ CAT_mainporcelain, N_("Main Porcelain Commands") },
			cmds->names[j++] = cmds->names[i];
	struct dirent *de;

	struct string_list *list = data;
		if (!(cmd->category & cat_id))
		; /* still counting */

			continue;
#include "parse-options.h"
}
	const char *new_name;
{
		}
		if (!strcmp(s, c->names[i]->name))
	const struct cmdname *const *c1 = p1, *const *c2 = p2;
		int cmp = 0; /* avoid compiler stupidity */
	if (skip_prefix(var, "alias.", &p))
		putchar('\n');
static const char *drop_prefix(const char *name, uint32_t category)

{
		BUG("empty command_list[] is a sign of broken generate-cmdlist.sh");
	load_command_list("git-", &main_cmds, &other_cmds);

			      "\nDid you mean one of these?",

		NULL
				     "assuming that you meant '%s'."),
}

	string_list_clear(&others, 0);
		prefix = "git-";
static int get_alias(const char *var, const char *value, void *data)
{


		string_list_append(list, other_cmds.names[i]->name);
		list_commands_in_dir(main_cmds, exec_path, prefix);
	return strcmp(a->name, b->name);
};
	clean_cmdnames(&other_cmds);
		if (!e->prefix)
			continue;
struct slot_expansion {
			if ((colon = strchr(path, PATH_SEP)))
static void add_cmd_list(struct cmdnames *cmds, struct cmdnames *old)
		char *paths, *path, *colon;
	FREE_AND_NULL(common_cmds);
		string_list_append_nodup(cb->similar_refs,
			      suggested_refs.nr));
{
			if (!strcasecmp(var, sb.buf)) {
		main_cmds.names[0] = NULL;
		fprintf_ln(stderr,
	const char *desc;
	}
		const struct cmdname_help *cmd = command_list + i;
		       (cmp = strcmp(common_cmds[n].name, candidate)) < 0)
		{ "color.branch", "<slot>", list_config_color_branch_slots },
		{ 0, NULL }
		clean_cmdnames(&main_cmds);
	}
			/* Yes, this is one of the common commands */
#include "refs.h"
	{ CAT_info, N_("examine the history and state (see also: git help revisions)") },
	for (i = 0; catdesc[i].desc; i++) {
	load_command_list("git-", &main_cmds, &other_cmds);

	memset(&other_cmds, 0, sizeof(other_cmds));
	free(cmds);
		struct strbuf sb = STRBUF_INIT;
		{ NULL, NULL, NULL }
			       const char *error)
	return git_default_config(var, value, cb);

{
	int i, j;

int cmd_version(int argc, const char **argv, const char *prefix)

	uniq(&main_cmds);
		{ "color.interactive", "<slot>", list_config_color_interactive_slots },
	int i;
	}
	ci = cj = ei = 0;
		printf("\n%s\n", _("External commands"));

	struct cmdname_help *common_cmds;
}
		/* NEEDSWORK: also save and output GIT-BUILD_OPTIONS? */
static void uniq(struct cmdnames *cmds)
	{ CAT_ancillarymanipulators, N_("Ancillary Commands / Manipulators") },
	int i;

		free(paths);
		string_list_append(list, var)->util = xstrdup(value);
		strbuf_setlen(&buf, len);
{
	struct cmdname *b = *(struct cmdname **)b_;
{
	struct similar_ref_cb *cb = (struct similar_ref_cb *)(cb_data);
	FLEX_ALLOC_MEM(ent, name, name, len);
	string_list_clear(&keys, 0);

	}
		QSORT(other_cmds->names, other_cmds->cnt, cmdname_compare);
	const struct cmdname_help *e1 = elem1;
	memset(&main_cmds, 0, sizeof(main_cmds));
		if (!strcmp(cmds->names[i]->name, cmds->names[j-1]->name))
}
	for (i = 0; i < other_cmds.cnt; i++)
	for (i = 0; category_names[i]; i++) {
			sleep_millisec(autocorrect * 100);

	const struct cmdname_help *e2 = elem2;

		if (longest < strlen(cmds[i].name))
	memset(&main_cmds, 0, sizeof(main_cmds));
	}
	old->cnt = 0;
}
	const char *exec_path = git_exec_path();


		if (git_built_from_commit_string[0])
	struct cmdnames main_cmds, other_cmds;
	}
	git_config(get_alias, &alias_list);

	/* A remote branch of the same name is deemed similar */
	{ CAT_foreignscminterface, N_("Interacting with Others") },
	CAT_init | CAT_worktree | CAT_info |
static struct category_description main_categories[] = {
void load_command_list(const char *prefix,
		     n++)
	for (i = 0; i < c->cnt; i++)
	{ 0, NULL }
		else
		autocorrect = git_config_int(var,value);
	for (i = 0; cmds[i].name; i++) {
	colopts = (colopts & ~COL_ENABLE_MASK) | COL_ENABLED;
	memset(&other_cmds, 0, sizeof(other_cmds));
		string_list_append(&list, cmds->names[i]->name);
		/*

			cut = wildcard < tag ? wildcard : tag;
	 *
{
		else
			}
	};
			       uint32_t mask, int longest)
	int found;
	{ CAT_remote, N_("collaborate (see also: git help workflows)") },
		printf("sizeof-long: %d\n", (int)sizeof(long));
		mask |= catdesc[i].category;
		if (!(cmd->category & mask))
{
			   n));
	for (i = 0; i < alias_list.nr; i++) {
}
			cmds->names[cj++] = cmds->names[ci++];
	string_list_sort(list);
	extract_cmds(&common_cmds, common_mask);
		}
		string_list_append(list, main_cmds.names[i]->name);
	};
	if (SIMILAR_ENOUGH(best_similarity)) {
{
		else if (cmp == 0) {
	return l1 != l2 ? l1 - l2 : strcmp(s1, s2);

	copts.indent = "  ";
	if (env_path) {
			if (starts_with(candidate, cmd)) {
				   _("Continuing in %0.1f seconds, "
	for (i = 0; catdesc[i].desc; i++)


};
	if (autocorrect && n == 1 && SIMILAR_ENOUGH(best_similarity)) {
			die(_(bad_interpreter_advice), cmd, cmd);
	struct strbuf buf = STRBUF_INIT;
static struct string_list guess_refs(const char *ref)
		if (!e->found)

};
		nr++;
}
		{ "receive.fsck", "<msg-id>", list_config_fsck_msg_ids },
	printf_ln(_("See 'git help <command>' to read about a specific subcommand"));
static const char bad_interpreter_advice[] =
	if (ARRAY_SIZE(command_list) == 0)

