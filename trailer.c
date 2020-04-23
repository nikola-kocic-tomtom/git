 * The separator-starts-line case (in which this function returns 0) is
{
				      struct list_head *new_trailer_head)
static int same_token(struct trailer_item *a, struct arg_item *b)
		conf->command = xstrdup(value);
static int find_same_and_apply_arg(struct list_head *head,
	return 0;
	list_add_tail(&new_item->list, arg_head);
					strbuf_addch(out, '\n');
		}

	for (pos = is_reverse ? (head)->prev : (head)->next; \
		nr++;
	struct arg_item *item;
	const char *nl = strchrnul(str, '\n');
					 NULL,
			if (conf)

	dst->command = xstrdup_or_null(src->command);
	const char *trailer_item, *variable_name;
	case MISSING_DO_NOTHING:
		}
{
}
				      separator_pos);
		return 0;
		if (conf->command)
	const char *name;

	else if (!strcasecmp("add", value))
	info->trailer_start = str + trailer_start;
{
}

						   value) < 0)
			parse_trailer(&tok, &val, &conf, tr->text,
	char *value;
			char *tok_buf = strbuf_detach(tok, NULL);
				     &item->conf, NULL);
			print_tok_val(outfile, item->token, item->value);
	dst->key = xstrdup_or_null(src->key);
	enum trailer_if_missing if_missing;
	 * of the last line anyway.

	 * (excluding the terminating newline) and token is NULL.
}
	case TRAILER_WHERE:
	git_config(git_trailer_default_config, NULL);
		if (item->conf.command)
	strbuf_release(&filename_template);
		patch_start = find_patch_start(str);

		const char **p;
	char **last = NULL;
	struct strbuf buf = STRBUF_INIT;
	variable_name = strrchr(trailer_item, '.');
	trailer_start = find_trailer_start(str, trailer_end);
	if (!opts->only_input) {
		*item = WHERE_BEFORE;
		else
	char *token;
{
		apply_item_command(in_tok, arg_tok);

		*item = WHERE_DEFAULT;
	if (opts->in_place)
	new_item->token = arg_tok->token;
	return info.trailer_end - str;
		break;


	}
	struct conf_info conf;
{
	for (c = line; *c; c++) {
		if (!strcasecmp(item->conf.name, name))
	if (file) {
	/* Print the lines after the trailers as is */
	int middle = (where == WHERE_AFTER) || (where == WHERE_BEFORE);
	free(item);
};
		add_arg_to_input_list(on_tok, arg_tok);
	}
#include "tempfile.h"
		return -1;
	return item->conf.name;
	*dst = *src;
		type = trailer_config_items[i].type;

		BUG("trailer.c: unhandled value %d",
	list_for_each(pos, head) {

		ssize_t separator_pos = find_separator(trailer, separators);
	if (configured)
			continue;
		if (strbuf_read(sb, fileno(stdin), 0) < 0)
{
	trailer_lines = strbuf_split_buf(str + trailer_start,
static char *apply_command(const char *command, const char *arg)
			list_for_each(pos, &conf_head) {
	if (!name)
		item = list_entry(pos, struct trailer_item, list);
	while (len > 0 && !isalnum(token[len - 1]))
	char *command;
	if (stat(file, &st))
	FILE *outfile = stdout;
	conf = &item->conf;
	trailer_info_release(&info);
		apply_item_command(in_tok, arg_tok);
		*item = EXISTS_REPLACE;
	new_item->token = tok;

 * location of the separator. Otherwise, return -1.  The optional whitespace
 * Return the position of the first trailer line or len if there are no
		free_trailer_item(in_tok);
#include "cache.h"
				 const struct process_trailer_options *opts)
		fprintf(outfile, "%s%c %s\n", tok, separators[0], val);
		return 0;
	/*
		return -1;

		}
		if (new_trailer_item->if_exists != EXISTS_DEFAULT)
}
static FILE *create_in_place_tempfile(const char *file)
}
static char *separators = ":";
 * "Bug" and <separator> is "#".
	const char *ptr = strstr(sb->buf, a);
static int after_or_end(enum trailer_where where)
	struct strbuf val = STRBUF_INIT;
	if (conf)

		break;
 * is no patch in the message.
	duplicate_conf(&new_item->conf, conf);
		char c = val->buf[i++];

			warning(_("unknown value '%s' for key '%s'"), value, conf_key);
	 * considered continuations of that trailer), and added to
		return;
				continue;
		strbuf_add(out, info->trailer_start,

	if (!variable_name)
#include "config.h"
			else
		*item = EXISTS_DEFAULT;
#include "trailer.h"
	ssize_t end_of_title, l;
		free_trailer_item(list_entry(pos, struct trailer_item, list));
	return 0;
}
{
		conf->key = xstrdup(value);

static void add_arg_item(struct list_head *arg_head, char *tok, char *val,
	if (!tok) {

		fwrite(sb.buf + trailer_end, 1, sb.len - trailer_end, outfile);
		return;

	tok_len = token_len_without_separator(tok->buf, tok->len);
	struct strbuf cmd = STRBUF_INIT;
	enum trailer_info_type type;
	new_item->value = arg_tok->value;

				     conf, tr);

 * distinguished from the non-well-formed-line case (in which this function

					recognized_prefix = 1;
			strbuf_addstr(tok, token_from_item(item, tok_buf));
	if (!variable_name) {
	struct trailer_item *new_item = xcalloc(sizeof(*new_item), 1);
		strbuf_trim(val);
}
		list_add(&to_add->list, &on_tok->list);
	struct list_head *pos;
	 * In command-line arguments, '=' is accepted (in addition to the
		break;
	ensure_configured();
 * separator_pos must not be 0, since the token cannot be an empty string.
		return;
	if (ll < 0)

	trailers_tempfile = xmks_tempfile_m(filename_template.buf, st.st_mode);
	struct arg_item *item;
		if (check_if_different(in_tok, arg_tok, 1, head))
			non_trailer_lines += possible_continuation_lines;
			continue;

				if (token_matches_item(bol, item,
	free(cl_separators);
		strbuf_trim(tok);
	{ "command", TRAILER_COMMAND },


		if (token_matches_item(tok->buf, item, tok_len)) {
	struct list_head *pos;
			      int check_all,
{
}
			continue;

	/* Default config must be setup first */
			new_item->conf.if_exists = new_trailer_item->if_exists;

		if (!strcmp(trailer_item, "where")) {
}
	size_t i;
			 const struct new_trailer_item *new_trailer_item)
		return tok;
		return 0;
	}
			strbuf_addch(&out, ' ');
 * returns -1) because some callers of this function need such a distinction.
	 */
static void ensure_configured(void)
		if (skip_prefix(s, "---", &v) && isspace(*v))
	 * separators that are defined).
	if (!opts->only_trailers && !info.blank_line_before_trailer)
	else if (!strcasecmp("add", value))
	/* output goes back to val as if we modified it in-place */
static int check_if_different(struct trailer_item *in_tok,
	default_conf_info.if_missing = MISSING_ADD;
}
	strbuf_release(&sb);

			list_entry(pos, struct new_trailer_item, list);
	case TRAILER_IF_EXISTS:
		in_tok = list_entry(next_head, struct trailer_item, list);
	trailer_end = process_input_file(outfile, sb.buf, &head, opts);
{
		}
					value, conf_key);
}
		list_del(pos);
	switch (arg_tok->conf.if_exists) {
			strbuf_release(&val);
		}
			       list);
		break;
	}
	}
	}
			? &trailer_strings[nr]
	/* Add an arg item for each trailer on the command line */
		to_add = trailer_from_arg(arg_tok);
	}


	return !*s || *s == '\n';

	/* Create temporary file in the same directory as the original */
static void unfold_value(struct strbuf *val)
		return -1;
};
		strbuf_replace(&cmd, TRAILER_ARG_STRING, arg);
	}
				 const char *str,
 * Return the position of the start of the patch or the length of str if there
	free(info->trailers);
 *
	while (i < val->len) {
int trailer_set_if_exists(enum trailer_if_exists *item, const char *value)

					     char *val)
		      const struct process_trailer_options *opts,
	return 0;
		break;
				if (!opts->separator)
{
static void free_trailer_item(struct trailer_item *item)
		/*
		process_trailers_lists(&head, &arg_head);
	const char *argv[] = {NULL, NULL};

	if (!c)
static void duplicate_conf(struct conf_info *dst, const struct conf_info *src)

		if (trailer_set_if_missing(&conf->if_missing, value))

			possible_continuation_lines = 0;
			add_arg_item(arg_head,
	ssize_t ll = last_line(buf, len);
		if (!same_token(in_tok, arg_tok))
			non_trailer_lines += possible_continuation_lines;
static void parse_trailer(struct strbuf *tok, struct strbuf *val,
static ssize_t last_line(const char *buf, size_t len)
			    trailer_lines * 3 >= non_trailer_lines)
	struct strbuf out = STRBUF_INIT;

	i = 0;
}
		break;

}
				     xstrdup(token_from_item(item, NULL)),

		fprintf(outfile, "%s\n", val);
	case EXISTS_REPLACE:
	list_for_each(pos, &conf_head) {

static int token_matches_item(const char *tok, struct arg_item *item, size_t tok_len)
	 */

	/*
				trailer_lines++;
	struct list_head *next_head;
		next_head = after_or_end(where) ? in_tok->list.prev
	i = len - 2;
	else if (!strcasecmp("after", value))

		ALLOC_GROW(trailer_strings, nr + 1, alloc);
static int same_trailer(struct trailer_item *a, struct arg_item *b)
		} else if (!opts->only_trailers) {
{

	default:
	struct strbuf tok = STRBUF_INIT;

	return !strncasecmp(a->token, b->token, min_len);
	for (i = 0; i < info.trailer_nr; i++) {
		return 0;
struct trailer_item {
static void free_all(struct list_head *head)
			if (only_spaces)


			*last = strbuf_detach(&sb, NULL);
		return 1;
	int possible_continuation_lines = 0;
}
	if (!a->token)
	return result;
	info->blank_line_before_trailer = ends_with_blank_line(str,
				const struct process_trailer_options *opts)
 */
static void add_arg_to_input_list(struct trailer_item *on_tok,
static size_t find_trailer_start(const char *buf, size_t len)

	struct trailer_item *item;
	case TRAILER_COMMAND:
/*
			list_add_tail(&to_add->list, head);

			free_arg_item(arg_tok);
				warning(_("unknown value '%s' for key '%s'"),
			return item;
/*
static size_t process_input_file(FILE *outfile,
	/* Empty lines may have left us with whitespace cruft at the edges */


	enum trailer_where where;
			return s[i];
	char **trailer_strings = NULL;
static int ends_with_blank_line(const char *buf, size_t len)
 * Obtain the token, value, and conf from the given trailer.
/*
	char *result;
	format_trailer_info(out, &info, opts);
			break;
		patch_start = strlen(str);
{
	default:

		      const struct process_trailer_options *opts)

	/* Add an arg item for each configured trailer with a command */

static const char *git_generated_prefixes[] = {
enum trailer_info_type { TRAILER_KEY, TRAILER_COMMAND, TRAILER_WHERE,
		*item = WHERE_AFTER;
static void apply_item_command(struct trailer_item *in_tok, struct arg_item *arg_tok)
	return item->conf.key ? !strncasecmp(tok, item->conf.key, tok_len) : 0;
		    arg_tok->conf.if_exists);

{


	 * reset to 0 if we encounter a trailer (since those lines are to be
static struct trailer_item *trailer_from_arg(struct arg_item *arg_tok)
	info->trailer_end = str + trailer_end;
	FILE *outfile;
	size_t a_len, b_len, min_len;
	int patch_start, trailer_end, trailer_start;

			non_trailer_lines++;
		char *trailer = info->trailers[i];
	ensure_configured();
		ssize_t separator_pos;


	return 0;


	for (l = last_line(buf, len);
	 * blank line before a set of non-blank lines that (i) are all
	free(item->conf.name);
{
				goto continue_outer_loop;
		*item = EXISTS_ADD;
}
	} else {
}

				  struct arg_item *arg_tok)
	/* The first paragraph is the title and cannot be trailers */
	size_t origlen = out->len;
	free(item->conf.key);
	struct strbuf filename_template = STRBUF_INIT;
			strbuf_addch(&out, c);
		strbuf_add(tok, trailer, separator_pos);

		if (rename_tempfile(&trailers_tempfile, file))

	size_t i;
/*
{
	dst->name = xstrdup_or_null(src->name);
	struct trailer_item *to_add = trailer_from_arg(arg_tok);
	}
	if (strchr(separators, c))
	if (tok)
		const char *arg;
{
	struct list_head *pos, *p;
			}
	struct list_head *pos;
	 * Skip the last character (in addition to the null terminator),
}

static ssize_t find_separator(const char *line, const char *separators)
}
	list_for_each(pos, &conf_head) {

	const char *s;
	struct trailer_item *start_tok;
			if (trailer_set_if_missing(&default_conf_info.if_missing,
}
				i++;
	else
 * is allowed there primarily to allow things like "Bug #43" where <token> is
					value, conf_key);

	 * are to be considered non-trailers).
			possible_continuation_lines++;
	size_t tok_len;
	switch (arg_tok->conf.if_missing) {
		} else if (!strcmp(trailer_item, "ifexists")) {
continue_outer_loop:
static struct trailer_item *add_trailer_item(struct list_head *head, char *tok,
							       trailer_start);
		apply_item_command(in_tok, arg_tok);
	if (separator_pos != -1) {

		if (trailer_set_where(&conf->where, value))

			new_item->conf.where = new_trailer_item->where;
	strbuf_addstr(&cmd, command);

			continue;
			 const struct conf_info *conf,
}
		applied = find_same_and_apply_arg(head, arg_tok);

	end_of_title = s - buf;
	char *key;
	if (!opts->only_trailers && !opts->unfold && !opts->filter && !opts->separator) {
static void format_trailer_info(struct strbuf *out,
		strbuf_trim(&buf);

	/*

	else
static void apply_arg_if_missing(struct list_head *head,

	if (item->conf.key)
	if (ptr)
	 */


		ssize_t separator_pos = find_separator(tr->text, cl_separators);
		die(_("file %s is not a regular file"), file);


				return next_line(bol) - buf;
	trailer_info_release(&info);

	/* Print lines before the trailers as is */
	"(cherry picked from commit ",
	ssize_t i;
				unfold_value(&val);
	if (list_empty(head))

		 */
	default:
			: NULL;
 */
	     l >= end_of_title;
			struct strbuf sb = STRBUF_INIT;
		if (!applied)

		where = arg_tok->conf.where;
};
			possible_continuation_lines = 0;
		    (!opts->only_trailers || item->token))
			       struct trailer_item,
{
	}
#include "string-list.h"
		break;

	if (!opts->only_trailers)

				 const struct process_trailer_options *opts)
	}
		return 1;
	     l = last_line(buf, l)) {
			      struct arg_item *arg_tok,

			strbuf_strip_suffix(&val, "\n");
/* Return the position of the end of the trailers. */
	struct strbuf tok = STRBUF_INIT;
	return !strcasecmp(a->value, b->value);
void format_trailers_from_commit(struct strbuf *out, const char *msg,
				struct arg_item *arg_tok,
	struct list_head list;

			warning(_("more than one %s"), conf_key);
	a_len = token_len_without_separator(a->token, strlen(a->token));
	else if (!strcasecmp("doNothing", value))
	 * consists of at least 25% trailers.
{
			list_add(&to_add->list, head);
			if (recognized_prefix &&
static void process_trailers_lists(struct list_head *head,

		int separator_pos;
	case MISSING_ADD:
{
	int whitespace_found = 0;
				arg = xstrdup(in_tok->value);
	free(name);
	free(item->value);

	for (; i >= 0; i--) {
{


 * If separator_pos is -1, interpret the whole trailer as a token.
	}
	struct trailer_info info;
				      separator_pos);
static void read_input_file(struct strbuf *sb, const char *file)
			strbuf_addstr(out, trailer);
					 '\n',
{
	int i;
	list_for_each_safe(pos, p, head) {
		if (bol[0] == comment_line_char) {
	if (!opts->only_trailers)
		separator_pos = find_separator(bol, separators);
	{ "ifexists", TRAILER_IF_EXISTS },
			}
			struct strbuf tok = STRBUF_INIT;
{
}
	trailer_info_get(&info, str, opts);
				if (!opts->value_only)
{
static const char *next_line(const char *str)
	LIST_HEAD(head);
 */
{
		return 0;
	return s - str;
		*item = MISSING_DEFAULT;
}
			 const struct conf_info **conf, const char *trailer,
		s++;
}
}
	size_t trailer_end;
	strbuf_release(&out);
	new_item->value = val;
	 * because if the last character is a newline, it is considered as part
static void free_arg_item(struct arg_item *item)
		*item = EXISTS_DO_NOTHING;
	cp.no_stdin = 1;
			die_errno(_("could not read input file '%s'"), file);
		arg_tok->value = apply_command(arg_tok->conf.command, arg);
			warning(_("unknown value '%s' for key '%s'"), value, conf_key);
			die_errno(_("could not read from stdin"));
	if (!strncasecmp(tok, item->conf.name, tok_len))
	struct trailer_info info;
			return i + 1;
			if (recognized_prefix)
	strbuf_release(&cmd);
static struct {
	else if (!strcasecmp("addIfDifferent", value))
	start_tok = list_entry(backwards ? head->prev : head->next,
#include "commit.h"
	size_t nr = 0, alloc = 0;
				     xstrdup(""),
			error(_("empty trailer token in trailer '%.*s'"),
			if (trailer_set_if_exists(&default_conf_info.if_exists,
				arg = xstrdup("");
	struct arg_item *arg_tok;

{
}
			break;
	const char *trailer_item, *variable_name;
		error(_("running trailer command '%s' failed"), cmd.buf);

			struct list_head *pos;
		*item = EXISTS_ADD_IF_DIFFERENT_NEIGHBOR;
		on_tok = middle ? in_tok : start_tok;
		*conf = &default_conf_info;
		if (separator_pos >= 1 && !isspace(bol[0])) {
			if (opts->unfold)
	return -1;


		if ((!opts->trim_empty || strlen(item->value) > 0) &&
}
	}
	trailer_info_get(&info, msg, opts);
{
	enum trailer_where where;
			add_arg_item(arg_head,
	}
	}
	}
			parse_trailer(&tok, &val, NULL, trailer,
	}
			if (opts->separator) {
				item = list_entry(pos, struct arg_item, list);
	return is_blank_line(buf + ll);
		*item = MISSING_DO_NOTHING;
		pos = is_reverse ? pos->prev : pos->next)
}
	}
		else
	const char *c;
		    arg_tok->conf.if_missing);
				   struct arg_item *arg_tok)
		add_arg_to_input_list(on_tok, arg_tok);
			non_trailer_lines += possible_continuation_lines;
	tail = strrchr(file, '/');
struct conf_info {
 * 13, stripping the trailing punctuation but retaining
			possible_continuation_lines = 0;
	return item;
{
{

		} else {
			arg = arg_tok->value;
			}
	char *cl_separators = xstrfmt("=%s", separators);
		if (conf->key)
		 * we have to check those before this one
}
	return '\0';

						: in_tok->list.next;
		outfile = create_in_place_tempfile(file);
		result = xstrdup("");
	if (capture_command(&cp, &buf, 1024)) {

				struct list_head *head)
	 */
			warning(_("more than one %s"), conf_key);
	struct child_process cp = CHILD_PROCESS_INIT;
	strbuf_swap(&out, val);
			strbuf_trim(&sb);
		if (strcmp(trailer_config_items[i].name, variable_name))
			 ssize_t separator_pos)
			}
	else if (!strcasecmp("before", value))
	}
	argv[0] = cmd.buf;
}
static struct arg_item *get_conf_item(const char *name)
	switch (type) {
	struct trailer_item *new_item = xcalloc(sizeof(*new_item), 1);

	for (i = 0; i < info->trailer_nr; i++)
{
						       separator_pos)) {
			else if (trailer_lines && !non_trailer_lines)
	strbuf_grow(&out, val->len);

{
		}
		item = list_entry(pos, struct arg_item, list);
{
{
 * Copyright (c) 2013, 2014 Christian Couder <chriscool@tuxfamily.org>
	}
		arg_tok = list_entry(pos, struct arg_item, list);
	struct list_head *pos, *p;
	else if (!strcasecmp("replace", value))
static int git_trailer_default_config(const char *conf_key, const char *value, void *cb)
		      const struct process_trailer_options *opts)
static size_t find_trailer_end(const char *buf, size_t len)

		in_tok = list_entry(pos, struct trailer_item, list);

		strbuf_addstr(tok, trailer);
	}
		process_command_line_args(&arg_head, new_trailer_head);
		if (same_trailer(in_tok, arg_tok))
			add_trailer_item(head,
	for (i = 0; i < ARRAY_SIZE(trailer_config_items); i++) {
					strbuf_addbuf(out, opts->separator);
		if (c == '\n') {
	duplicate_conf(&item->conf, &default_conf_info);

{
		if (buf[i] == '\n')
		result = strbuf_detach(&buf, NULL);
}
{
		die(_("file %s is not writable by user"), file);
		trailer_strings[nr] = strbuf_detach(*ptr, NULL);
		free_arg_item(arg_tok);
		item = list_entry(pos, struct arg_item, list);
	strbuf_addstr(&filename_template, "git-interpret-trailers-XXXXXX");

	arg_tok->token = arg_tok->value = NULL;
		if (new_trailer_item->if_missing != MISSING_DEFAULT)
}
			      struct list_head *head)
	int i;
	list_add_tail(&item->list, &conf_head);
					      value) < 0)

	const char *s = str;
}
			if (starts_with(bol, *p)) {
	/*
{
			return s - str;
		} else if (!strcmp(trailer_item, "ifmissing")) {
	if (!outfile)
	return (where == WHERE_AFTER) || (where == WHERE_END);
	strbuf_trim(&out);

	struct conf_info *conf;
	char *name = NULL;
 */
	/* If we want the whole block untouched, we can take the fast path. */
		break;
				strbuf_addbuf(out, opts->separator);
	list_for_each_safe(pos, p, arg_head) {
		return 0;
	for (i = strlen(s) - 1; i >= 0; i--)
	if (!S_ISREG(st.st_mode))
	list_for_each(pos, new_trailer_head) {
	struct strbuf val = STRBUF_INIT;
	size_t i;
	 * If this is not a trailer line, the line is stored in value
		pos != (head); \
		char *trailer = info.trailers[i];
					value, conf_key);
		only_spaces = 0;
			add_arg_to_input_list(on_tok, arg_tok);
		free(info->trailers[i]);
		strbuf_splice(sb, ptr - sb->buf, strlen(a), b, strlen(b));

	}
	struct arg_item *new_item = xcalloc(sizeof(*new_item), 1);
	else if (!strcasecmp("doNothing", value))
	variable_name = strrchr(trailer_item, '.');
}
	else if (!strcasecmp("addIfDifferentNeighbor", value))
	"Signed-off-by: ",
	case EXISTS_ADD_IF_DIFFERENT_NEIGHBOR:
{
				struct trailer_item *on_tok,

}
		strbuf_addstr(val, trailer + separator_pos + 1);
	}
	free_arg_item(arg_tok);

	int recognized_prefix = 0, trailer_lines = 0, non_trailer_lines = 0;
/* Iterate over the elements of the list. */
	cp.use_shell = 1;
}
	case EXISTS_ADD_IF_DIFFERENT:
				strbuf_addbuf(out, &val);
} trailer_config_items[] = {
static const char *token_from_item(struct arg_item *item, char *tok)
		 * if we want to add a trailer after another one,
				if (opts->unfold)
			warning(_("unknown value '%s' for key '%s'"), value, conf_key);
		list_add_tail(&to_add->list, &on_tok->list);
 * trailers.
	struct arg_item *item;
	free(item->token);
				possible_continuation_lines = 0;

	if (arg)
		if (is_blank_line(bol)) {
		BUG("trailer.c: unhandled value %d",
		*item = EXISTS_ADD_IF_DIFFERENT;

#include "run-command.h"
	if (!(st.st_mode & S_IWUSR))
	return outfile;
		*item = WHERE_END;

	b_len = token_len_without_separator(b->token, strlen(b->token));
			whitespace_found = 1;


	return new_item;
			strbuf_addstr(&sb, tr->text);
	c = last_non_space_char(tok);
	{ "key", TRAILER_KEY },
static inline int is_blank_line(const char *str)
			 TRAILER_IF_EXISTS, TRAILER_IF_MISSING };


{
	free_all(&head);
			if (trailer_set_where(&default_conf_info.where,
		die_errno(_("could not stat %s"), file);
{
		} else if (isspace(bol[0]))
				warning(_("unknown value '%s' for key '%s'"),
		apply_arg_if_exists(in_tok, arg_tok, on_tok, head);
	item->conf.name = xstrdup(name);
		;
{
	return new_item;
	if (new_trailer_item) {
			return len;


			break;
	struct list_head *pos;
		free((char *)arg);
	trailer_end = find_trailer_end(str, patch_start);
 * Return the length of the string not including any final
static struct tempfile *trailers_tempfile;
	}
};
 * internal punctuation.
	if (len == 1)
void trailer_info_get(struct trailer_info *info, const char *str,
	return 0;
	for (i = 0; i < info->trailer_nr; i++) {
	for (ptr = trailer_lines; *ptr; ptr++) {
		} else {
	else
		}
		int applied = 0;
		return item->conf.key;
}
		} else {
		if (check_if_different(on_tok, arg_tok, 0, head))
		strbuf_add(&filename_template, file, tail - file + 1);
}
			struct strbuf sb = STRBUF_INIT;
		if (separator_pos == 0) {
				strbuf_rtrim(out);
		break;
		apply_item_command(in_tok, arg_tok);
	free(item->conf.command);
	 */

	if (opts->in_place)
			strbuf_attach(&sb, *last, strlen(*last), strlen(*last));
{
		struct new_trailer_item *tr =
	git_config(git_trailer_config, NULL);
	list_for_each(pos, &conf_head) {
{
	struct trailer_item *to_add;
		break;

}
				*conf = &item->conf;
				     strbuf_detach(&tok, NULL),
	char *value;
	new_item->value = val;
 *
	if (!value)
		if (arg_tok->value && arg_tok->value[0]) {
		if (last && isspace((*ptr)->buf[0])) {

					 strbuf_detach(&tok, NULL),
{
static struct conf_info default_conf_info;
			}
	if (opts->no_divider)
{

		return 0;
			strbuf_addstr(&val, trailer);
		len--;
				warning(_("unknown value '%s' for key '%s'"),
			strbuf_release(&tok);

		LIST_HEAD(arg_head);
	char *token;
			separators = xstrdup(value);
}
void process_trailers(const char *file,
	/* Item does not already exists, create it */
		if (separator_pos >= 1) {
		      struct list_head *new_trailer_head)
			return c - line;
	 * Number of possible continuation lines encountered. This will be
				 struct list_head *head,

	else
	case TRAILER_IF_MISSING:

					break;
{
}

	new_item->token = tok;

					 trailer_end - trailer_start,
		for (p = git_generated_prefixes; *p; p++) {
			if (opts->separator && out->len != origlen) {

				if (opts->separator && out->len != origlen)
	return 0;
	variable_name++;
			strbuf_addbuf(&sb, *ptr);
	{ "ifmissing", TRAILER_IF_MISSING }
		separator_pos = find_separator(trailer, separators);
				     strbuf_detach(&val, NULL),
		if (!whitespace_found && (isalnum(*c) || *c == '-'))
/*
	if (tail != NULL)

		if (after_or_end(where))
			continue;
			free_arg_item(arg_tok);
	case EXISTS_ADD:
		if (s[0] == comment_line_char)
	cp.argv = argv;
	default_conf_info.where = WHERE_END;
static void print_all(FILE *outfile, struct list_head *head,
	struct list_head *pos;
{
	/*

		} else if (!strcmp(trailer_item, "separators")) {
	int only_spaces = 1;
			continue;
		break;
			   info->trailer_end - info->trailer_start);
			      (int) sb.len, sb.buf);
static size_t find_patch_start(const char *str)
					strbuf_addf(out, "%s: ", tok.buf);
{
		if (separator_pos >= 1) {
		if (trailer[0] == comment_line_char)
	while (*s && *s != '\n' && isspace(*s))
 */
 * punctuation. E.g., the input "Signed-off-by:" would return
	const struct conf_info *conf;

		const char *bol = buf + l;
		return 0;
}
				recognized_prefix = 1;
struct arg_item {
	list_for_each_dir(pos, head, backwards) {
	/* Print the lines before the trailers */
		}
	enum trailer_if_exists if_exists;
			continue;
	if (!value)
	item = get_conf_item(name);
}
	}
 * If the given line is of the form
				return next_line(bol) - buf;
		}
		fwrite(str, 1, info.trailer_start - str, outfile);
				continue;

					unfold_value(&val);
static int same_value(struct trailer_item *a, struct arg_item *b)
	if (len == 0)
		}
	if (!skip_prefix(conf_key, "trailer.", &trailer_item))
		if (next_head == head)
	struct strbuf **trailer_lines, **ptr;
 * Return the position of the start of the last line. If len is 0, return -1.
						  value) < 0)
		strbuf_trim(tok);
		*item = WHERE_START;
	configured = 1;
	}
}
	/* Lookup if the token matches something in the config */
		fprintf(outfile, "\n");
	const char *s;
#include "list.h"
	if (aoe)
	for (s = buf; s < buf + len; s = next_line(s)) {
					 strbuf_detach(&val, NULL));

	else if (!strcasecmp("start", value))
	struct trailer_item *on_tok;
	else if (!strcasecmp("end", value))

static char last_non_space_char(const char *s)
void trailer_info_release(struct trailer_info *info)
int trailer_set_where(enum trailer_where *item, const char *value)
	const char *tail;
	struct stat st;
}
	struct strbuf sb = STRBUF_INIT;
}
	default_conf_info.if_exists = EXISTS_ADD_IF_DIFFERENT_NEIGHBOR;
	if (arg_tok->conf.command) {
	free(item);
	}
{
{
	enum trailer_where where = arg_tok->conf.where;
	enum trailer_where where = arg_tok->conf.where;
	enum trailer_info_type type;
{
		last = find_separator(trailer_strings[nr], separators) >= 1
		free_arg_item(arg_tok);
	cp.env = local_repo_env;
		if (is_blank_line(s))
	else
		if (new_trailer_item->where != WHERE_DEFAULT)
			strbuf_release(&sb);
static void print_tok_val(FILE *outfile, const char *tok, const char *val)
		BUG("trailer.c: unhandled type %d", type);
	return same_token(a, b) && same_value(a, b);
	return 0;

	 * Get the start of the trailers by looking starting from the end for a
	list_add_tail(&new_item->list, head);
		*item = MISSING_ADD;
	min_len = (a_len > b_len) ? b_len : a_len;
	read_input_file(&sb, file);
		item = list_entry(pos, struct arg_item, list);
}
					 0);
		if (!isspace(s[i]))

			new_item->conf.if_missing = new_trailer_item->if_missing;
			if (in_tok && in_tok->value)
		break;
			parse_trailer(&tok, &val, NULL, trailer, separator_pos);
#define TRAILER_ARG_STRING "$ARG"
{
					 strbuf_detach(&val, NULL));
				}
	NULL
	}
			die_errno(_("could not rename temporary file to %s"), file);
			return 0;
			apply_arg_if_missing(head, arg_tok);
/*
		strbuf_release(&buf);
 */
	} else {
{
		else {
		if (c != line && (*c == ' ' || *c == '\t')) {
static void apply_arg_if_exists(struct trailer_item *in_tok,

};

}
			continue;
	struct arg_item *item;
	if (!skip_prefix(conf_key, "trailer.", &trailer_item))
	return len;
		}
	else

			if (!opts->filter || opts->filter(&tok, opts->filter_data)) {
		list_del(pos);

			/* Collapse continuation down to a single space. */
	info->trailer_nr = nr;
	int aoe = after_or_end(arg_tok->conf.where);

}
static LIST_HEAD(conf_head);
	} while (check_all);
	char *name;
static inline void strbuf_replace(struct strbuf *sb, const char *a, const char *b)
	} else {
{
	free(item->token);
	outfile = fdopen_tempfile(trailers_tempfile, "w");
		break;
	case TRAILER_KEY:

	 * trailers, or (ii) contains at least one Git-generated trailer and

	}
}
			add_arg_to_input_list(on_tok, arg_tok);
	if (!value)
}
	 * non_trailer_lines if we encounter a non-trailer (since those lines
	do {
		return;


			add_trailer_item(head,
				const struct trailer_info *info,

	size_t i;
}
		fprintf(outfile, "%s%s\n", tok, val);
		list_del(&in_tok->list);
static int git_trailer_config(const char *conf_key, const char *value, void *cb)


		return -1;
		else
	free(item->value);
/*
	/* Look up item with same name */
			free(tok_buf);
				 struct arg_item *arg_tok)
		}

	return len;
		name = xstrndup(trailer_item,  variable_name - trailer_item - 1);
		apply_item_command(NULL, arg_tok);
#define list_for_each_dir(pos, head, is_reverse) \
			trailer_lines++;

		if (trailer_set_if_exists(&conf->if_exists, value))
static void process_command_line_args(struct list_head *arg_head,
 */
		break;
	strbuf_list_free(trailer_lines);
			while (i < val->len && isspace(val->buf[i]))
	print_all(outfile, &head, opts);
static int configured;
		if (strchr(separators, *c))

	info->trailers = trailer_strings;
			struct strbuf val = STRBUF_INIT;
	struct list_head list;
				struct arg_item *item;
	case EXISTS_DO_NOTHING:
}
	struct trailer_item *in_tok;
		die_errno(_("could not open temporary file"));
 * "<token><optional whitespace><separator>..." or "<separator>...", return the
	return nl + !!*nl;
	for (s = str; *s; s = next_line(s)) {
		if (strbuf_read_file(sb, file, 0) < 0)
		const char *v;
static size_t token_len_without_separator(const char *token, size_t len)
	int backwards = after_or_end(where);

	char c;
		} else if (!opts->only_trailers) {
	{ "where", TRAILER_WHERE },
				   struct list_head *arg_head)
 *
		}
	return 1;
	}
	item = xcalloc(sizeof(*item), 1);
	return len - ignore_non_trailer(buf, len);
int trailer_set_if_missing(enum trailer_if_missing *item, const char *value)
