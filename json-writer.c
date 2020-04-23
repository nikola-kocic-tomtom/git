		else if (c == '\b')
		else if (c == '\f')
	jw->need_comma = 0;
	int k;
{
	if (jw->pretty)
{
		strbuf_addbuf(&jw->json, &sb);
}
void jw_array_bool(struct json_writer *jw, int value)
}
		if (ch == '\n')
	maybe_add_comma(jw);
static void indent_pretty(struct json_writer *jw)
			strbuf_addstr(out, "\\b");
		char ch = jw->json.buf[k];
{
	jw_object_begin(jw, jw->pretty);
		strbuf_addstr(&jw->json, "  ");
	maybe_add_comma(jw);
 * Assert that the top of the open-stack is an array.
	return !jw->open_stack.len;
static void assert_in_object(const struct json_writer *jw, const char *key)
	array_common(jw);
{
	append_quoted_string(&jw->json, value);
	begin(jw, '[', pretty);
	strbuf_release(&jw->open_stack);
		strbuf_addch(&jw->json, '\n');
			strbuf_addchars(sb, ' ', indent);

		indent_pretty(jw);

static void maybe_add_comma(struct json_writer *jw)
	append_quoted_string(&jw->json, value);
 */
		return;
void jw_end(struct json_writer *jw)
void jw_array_double(struct json_writer *jw, int precision, double value)
void jw_array_true(struct json_writer *jw)

 */
{
static void append_quoted_string(struct strbuf *out, const char *in)

/*
void jw_array_false(struct json_writer *jw)
		jw_object_false(jw, key);
 * Assert that the top of the open-stack is an object.
			strbuf_addf(out, "\\u%04x", c);
		kill_indent(&sb, value);

static void fmt_double(struct json_writer *jw, int precision,
	strbuf_addstr(&jw->json, "null");
		strbuf_release(&fmt);
	if (!jw->open_stack.len)
	strbuf_addstr(&jw->json, "true");
	append_sub_jw(jw, value);
{
		else if (c < 0x20)
{


	if (jw->open_stack.buf[jw->open_stack.len - 1] != '{')
	assert_in_object(jw, key);
		strbuf_addf(&jw->json, fmt.buf, value);
	strbuf_addstr(&jw->json, "null");

}
{
			      double value)
static void assert_in_array(const struct json_writer *jw)
	if (jw->open_stack.buf[jw->open_stack.len - 1] != '[')
}
void jw_array_argc_argv(struct json_writer *jw, int argc, const char **argv)
	 * for this debug-ish feature.)

	strbuf_reset(sb);
	if (jw->pretty && jw->open_stack.len && value->pretty) {
		strbuf_addch(&jw->json, '\n');
}

		return;
}
		BUG("json-writer: array: missing jw_array_begin()");
	object_common(jw, key);
int jw_is_terminated(const struct json_writer *jw)
	} else {
{
{
void jw_array_null(struct json_writer *jw)
	array_common(jw);

	}
 * open object or array).
{
 */
		strbuf_addch(&jw->json, ']');
		BUG("json-writer: object: missing jw_end(): '%s'",
	unsigned char c;
		strbuf_addch(sb, ch);
	 *
}

{
}
/*
void jw_object_null(struct json_writer *jw, const char *key)

		BUG("json-writer: too many jw_end(): '%s'", jw->json.buf);
			continue;

	/*
	}
}
	array_common(jw);
	if (jw->pretty) {
{

	if (!jw->open_stack.len)
/*

		strbuf_addf(&jw->json, "%f", value);
	 * If the super is compact, and the sub_jw is pretty, convert

void jw_array_inline_begin_object(struct json_writer *jw)
	strbuf_addstr(&jw->json, "false");
static void increase_indent(struct strbuf *sb,
			continue;
void jw_object_bool(struct json_writer *jw, const char *key, int value)
}
}

 * Append JSON-quoted version of the given string to 'out'.
	char ch_open;
{
	if (ch_open == '{')

		      double value)
	assert_in_array(jw);


	append_sub_jw(jw, value);
		jw->need_comma = 1;

		jw_array_true(jw);
}
	fmt_double(jw, precision, value);
	int eat_it = 0;
		strbuf_addch(&jw->json, ',');
}
		strbuf_addch(&jw->json, ' ');
			eat_it = 1;
	for (k = 0; k < jw->json.len; k++) {




	array_common(jw);
}
{
	strbuf_release(&jw->json);
	begin(jw, '{', pretty);
{
void jw_object_string(struct json_writer *jw, const char *key, const char *value)
{
void jw_release(struct json_writer *jw)
{
	 * If both are compact, keep the sub_jw compact.
	}
{
}
	int k;
		else if (c == '\r')
{
		BUG("json-writer: object: missing jw_object_begin(): '%s'", key);
static void assert_is_terminated(const struct json_writer *jw)
	append_quoted_string(&jw->json, key);
}
	strbuf_addf(&jw->json, "%"PRIdMAX, value);
 */
static void kill_indent(struct strbuf *sb,
void jw_object_false(struct json_writer *jw, const char *key)
	strbuf_init(&jw->json, 0);
{
		strbuf_addch(&jw->json, '\n');
	}
	strbuf_setlen(&jw->open_stack, len);

}
	if (jw->pretty) {
#include "cache.h"
void jw_init(struct json_writer *jw)

	while (*argv)
			strbuf_addstr(out, "\\\\");
	jw->need_comma = 1;
			strbuf_addstr(out, "\\t");
{

		increase_indent(&sb, value, jw->open_stack.len * 2);
static void begin(struct json_writer *jw, char ch_open, int pretty)
	strbuf_addch(&jw->json, ':');
}

	strbuf_reset(sb);
{
/*
			const struct json_writer *jw)
{
void jw_object_inline_begin_array(struct json_writer *jw, const char *key)
 */
		strbuf_addch(&jw->json, '}');
		struct strbuf sb = STRBUF_INIT;
		else
			strbuf_addstr(out, "\\\"");
 * Assert that the given JSON object or JSON array has been properly
	array_common(jw);
{
		    jw->json.buf);
static void append_sub_jw(struct json_writer *jw,
		strbuf_addf(&fmt, "%%.%df", precision);
	if (jw->open_stack.len)

	for (k = 0; k < argc; k++)
{

	int k;
{
		indent_pretty(jw);
	strbuf_addstr(&jw->json, "false");
	 *
/*
		else if (c == '\t')
	jw->pretty = 0;
	}
	strbuf_addf(&jw->json, "%"PRIdMAX, value);
		strbuf_release(&sb);
	if (!jw->open_stack.len)
}

	assert_is_terminated(value);



	jw->pretty = pretty;
		jw_array_string(jw, *argv++);
void jw_array_intmax(struct json_writer *jw, intmax_t value)

 * Add comma if we have already seen a member at this level.
	if (jw->pretty) {
	array_common(jw);
void jw_object_begin(struct json_writer *jw, int pretty)
void jw_array_inline_begin_array(struct json_writer *jw)
}
void jw_array_string(struct json_writer *jw, const char *value)

	strbuf_init(&jw->open_stack, 0);

	int len;
		else if (c == '\\')

}
	while ((c = *in++) != '\0') {
	strbuf_addch(&jw->json, ch_open);

}
}
}
/*
		jw_array_string(jw, argv[k]);
	}
	else
		struct strbuf sb = STRBUF_INIT;
	array_common(jw);
	for (k = 0; k < jw->json.len; k++) {
			strbuf_addch(out, c);
	}
}

		if (ch == '\n') {
#include "json-writer.h"
	array_common(jw);
}

		indent_pretty(jw);
}

{
		char ch = jw->json.buf[k];
		if (eat_it && ch == ' ')
}
	 */
{
	object_common(jw, key);
	object_common(jw, key);
	 * If both are pretty, increase the indentation of the sub_jw
			strbuf_addstr(out, "\\f");
}
	strbuf_addstr(&jw->json, "true");
			    const struct json_writer *jw,
void jw_array_begin(struct json_writer *jw, int pretty)
{
void jw_object_double(struct json_writer *jw, const char *key, int precision,

	len = jw->open_stack.len - 1;
 */
		struct strbuf fmt = STRBUF_INIT;
 * as-is onto the given JSON data.
}
 * Begin an object or array (either top-level or nested within the currently

void jw_object_intmax(struct json_writer *jw, const char *key, intmax_t value)
	}
	 *
 * terminated.  (Has closing bracket.)
		BUG("json-writer: array: not in array");
	else
		strbuf_release(&sb);
	object_common(jw, key);
void jw_array_argv(struct json_writer *jw, const char **argv)

		if (c == '"')
	strbuf_addbuf(&jw->json, &value->json);
}
{
	object_common(jw, key);
	array_common(jw);
	object_common(jw, key);
}
	jw_array_begin(jw, jw->pretty);
	}
/*
	object_common(jw, key);
void jw_object_true(struct json_writer *jw, const char *key)
	else
	 * the sub_jw to compact.

	fmt_double(jw, precision, value);
{
void jw_object_inline_begin_object(struct json_writer *jw, const char *key)
		else if (c == '\n')
{
		jw_array_false(jw);
	if (precision < 0) {
	if (!jw->pretty && value->pretty) {
{
 */


}
			  const struct json_writer *value)

	jw->need_comma = 0;
		strbuf_addch(sb, ch);
	ch_open = jw->open_stack.buf[len];

}
}
}
	else
}
	 * If the super is pretty, but the sub_jw is compact, leave the

	for (k = 0; k < jw->open_stack.len; k++)

	 * to better fit under the super.
		BUG("json-writer: object: not in object: '%s'", key);


		strbuf_addbuf(&jw->json, &sb);
		eat_it = 0;
	if (jw->need_comma)
}
	strbuf_addch(out, '"');
	int k;
 * Append existing (properly terminated) JSON sub-data (object or array)
{
			strbuf_addstr(out, "\\n");
			    int indent)
void jw_object_sub_jw(struct json_writer *jw, const char *key,
	object_common(jw, key);
	if (value)
		      const struct json_writer *value)
		}
	 * sub_jw compact.  (We don't want to parse and rebuild the sub_jw
static void object_common(struct json_writer *jw, const char *key)


		jw_object_true(jw, key);
	strbuf_addch(out, '"');

}
{

}
	jw_array_begin(jw, jw->pretty);
static void array_common(struct json_writer *jw)
	if (value)
{
}
	assert_is_terminated(value);
{

void jw_array_sub_jw(struct json_writer *jw, const struct json_writer *value)
			strbuf_addstr(out, "\\r");

{
	strbuf_addch(&jw->open_stack, ch_open);
	jw_object_begin(jw, jw->pretty);
	object_common(jw, key);
{
{

