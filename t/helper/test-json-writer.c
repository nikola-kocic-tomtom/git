			get_i(line_nr, &i_value);
		jw_object_true(&obj4, "t");

			jw_array_intmax(&inline2, 4);
	("{\n"
static const char *pretty_arr3 = ("[\n"

static const char *expect_arr1 = "[\"abc\",42,true]";
				  "}");
		jw_object_sub_jw(&mixed1, "obj1", &obj1);
		}
	jw_array_begin(&inline2, pretty);
	jw_end(&obj4);
		else if (!strcmp(verb, "object-false")) {
	*s_in = strtok(NULL, " ");
		intmax_t i_value;
			jw_object_inline_begin_array(&jw, key);
{
	len = strlen(buf);
	int len;
	 "    2\n"
	}
	{

	jw_array_begin(&arr1, pretty);
static void make_obj6(int pretty)


static void make_arr1(int pretty)
	get_s(line_nr, &s);
 * When super is pretty, a compact sub (obj1) is kept compact and a pretty
	printf("error[%s]: observed '%s' expected '%s'\n",
static void get_s(int line_nr, char **s_in)

				  "  \"t\": true,\n"
{


	{
		jw_object_intmax(&obj3, "a", 0);
	 "}");
				  "  \"c\": 0\n"
	p(arr3);
{
		die("expected first line to be 'object' or 'array'");

	{
		}
			get_s(line_nr, &key);
{
		else if (!strcmp(verb, "array-object"))
/*
			get_s(line_nr, &key);

	make_arr1(1); /* arr1 is pretty */
	 "  \"arr1\": [\n"
	printf("%s\n", jw.json.buf);
		}
	*s_in = strtod(s, &endptr);
	}
	jw_array_begin(&arr2, pretty);
		jw_array_intmax(&arr3, 0x7fffffffffffffffULL);
static struct json_writer obj6 = JSON_WRITER_INIT;


	jw_init(&obj3);
			get_s(line_nr, &s_value);

	make_obj1(0); /* obj1 is compact */

				  "  \"a\": \"abc\",\n"

		char c = buf[len - 1];
static struct json_writer arr4 = JSON_WRITER_INIT;
	jw_end(&arr4);
		else if (!strcmp(verb, "array-true"))
				  "  \"abc\",\n"
	argv++;
	t(obj4);
		jw_array_intmax(&arr3, 0xffffffff);

	 "  ]\n"


				  "  0,\n"
}
	/* mixed forms */
	t(obj5);
				  "  \"c\": 9223372036854775807\n"

			get_s(line_nr, &key);
		}
	}
{
				  "]");
	t(inline2);
		jw_object_begin(&jw, pretty);
static const char *expect_arr2 = "[-1,2147483647,0]";
	t(obj1);
	 "  {\n"
	char *s;
	while (*buf == ' ' || *buf == '\t')
	t(arr4);

			get_s(line_nr, &key);
		jw_array_string(&arr1, "abc");

	}
	/* comptact (canonical) forms */
static struct json_writer obj5 = JSON_WRITER_INIT;

	"[[1,2],[3,4],{\"a\":\"abc\"}]";
	else
		}
	 "    \"abc\",\n"
static const char *pretty_obj2 = ("{\n"
	 "    \"abc\",\n"
				  "  \"b\": 2147483647,\n"
	p(arr2);
		jw_object_string(&obj1, "a", "abc");
			get_s(line_nr, &key);
		if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
		jw_object_sub_jw(&mixed1, "arr1", &arr1);
	p(obj3);
		jw_object_intmax(&obj1, "b", 42);
	 "  \"obj1\": {\n"
	 "    \"a\": \"abc\"\n"
	}

	jw_end(&arr2);
#define t(v) do { make_##v(0); cmp(#v, &v, expect_##v); } while (0)

	}
			get_d(line_nr, &d_value);
	 "  }\n"
	jw_object_begin(&obj1, pretty);
	jw_end(&arr3);
		jw_end(&inline1);
	t(obj3);


	("[\n"
		}
		}
		}
static const char *pretty_obj3 = ("{\n"
	jw_object_begin(&inline1, pretty);
}
static char *pretty_inline1 =
/*
		die("line[%d]: expected: <s>", line_nr);
	if (*endptr || errno == ERANGE)
		jw_array_intmax(&arr2, 0x7fffffff);
	t(nest1);
}

	jw_init(&arr4);
		jw_object_sub_jw(&nest1, "obj1", &obj1);
 * sub (arr1) is re-indented.
	exit(1);
}
		jw_object_sub_jw(&nest1, "arr1", &arr1);

	{
		jw_array_begin(&jw, pretty);
	jw_init(&inline2);
	}
		else if (!strcmp(verb, "object-true")) {

static void get_i(int line_nr, intmax_t *s_in)
}
				  "}");
			jw_array_true(&jw);
}
static struct json_writer arr3 = JSON_WRITER_INIT;
		{
}
		}
}
			get_s(line_nr, &key);
}
static struct json_writer nest1 = JSON_WRITER_INIT;
static struct json_writer arr1 = JSON_WRITER_INIT;
	jw_end(&arr1);
			jw_object_double(&jw, key, i_value, d_value);
 */
static void make_obj2(int pretty)
static int unit_tests(void)
	if (*endptr || errno == ERANGE)

		}
		jw_end(&inline1);
static struct json_writer mixed1 = JSON_WRITER_INIT;
		jw_array_inline_begin_array(&inline2);
	jw_array_begin(&arr4, pretty);
		jw_object_false(&obj4, "f");
			jw_object_true(&jw, key);
	return buf;
		{
{
		}
		buf++;
	{
	jw_object_begin(&obj6, pretty);

static struct json_writer arr2 = JSON_WRITER_INIT;
	jw_end(&nest1);
	 "    42,\n"

			jw_object_true(&inline1, "c");
	{

		jw_object_inline_begin_array(&inline1, "arr1");
				  "  9223372036854775807\n"
{
static const char *expect_arr4 = "[true,false,null]";
		char *verb;
	char *line;
		jw_array_intmax(&arr2, 0);
			jw_array_null(&jw);

		jw_array_intmax(&arr3, 0);

			jw_object_string(&inline2, "a", "abc");
	p(obj2);
	strbuf_release(&jw.json);
				  "]");
				  "]");
	 "  },\n"
				  "  \"n\": null\n"
	t(obj2);
	}
	jw_end(&obj3);
		{
	 "  ],\n"
		else if (!strcmp(verb, "object-string")) {
static void cmp(const char *test, const struct json_writer *jw, const char *exp)
		else
	jw_object_begin(&obj3, pretty);
	 "    1,\n"
	 "  \"obj1\": {\"a\":\"abc\",\"b\":42,\"c\":true},\n"
	jw_init(&obj1);
static char *pretty_inline2 =
		jw_object_true(&obj1, "c");
	jw_end(&inline1);

	p(inline1);
				  "  null\n"


	 "    42,\n"
	int line_nr = 0;
	{
		jw_array_intmax(&arr1, 42);
		return 0;
		jw_object_intmax(&obj3, "b", 0xffffffff);
		}
	jw_init(&arr2);
	}
	}

	p(inline2);

			jw_array_string(&jw, s_value);
		else if (!strcmp(verb, "array-string")) {
{
			pretty = 1;
}
{
	p(obj4);
static void make_obj1(int pretty)
 */
	while (len > 0) {
	return scripted();
				  "}");
		return NULL;
		else if (!strcmp(verb, "object-object")) {
	jw_init(&obj2);
static const char *pretty_obj1 = ("{\n"
static const char *expect_obj1 = "{\"a\":\"abc\",\"b\":42,\"c\":true}";

	if (!strcmp(jw->json.buf, exp))
	jw_end(&inline2);
	 "    \"b\": 42,\n"
			jw_array_double(&jw, i_value, d_value);
			jw_array_inline_begin_array(&jw);

	jw_end(&obj6);
	{
static const char *pretty_arr2 = ("[\n"
			jw_array_intmax(&inline2, 3);

		jw_end(&inline2);
		jw_object_null(&obj4, "n");
{
static struct json_writer obj4 = JSON_WRITER_INIT;
				  "  \"a\": -1,\n"
		else if (!strcmp(verb, "array-int")) {
		die("line[%d]: invalid float value", line_nr);
	}
	}
				  "  \"c\": true\n"
		jw_array_true(&arr1);
		jw_object_inline_begin_object(&inline1, "obj1");



	p(mixed1);
	if (!line)
			jw_object_string(&inline1, "a", "abc");

}
		jw_end(&inline2);
}
		else if (!strcmp(verb, "array-array"))
				  "  2147483647,\n"
		}
	jw_end(&mixed1);
		die("json not terminated: '%s'", jw.json.buf);
		else if (!strcmp(verb, "object-array")) {
{
	char *endptr;
			jw_array_intmax(&jw, i_value);
}

 * These tests also demonstrate how to use the jw_ API.
	}
		char *s_value;
	else if (!strcmp(line, "array"))
	jw_object_begin(&mixed1, pretty);
				  "  \"b\": 4294967295,\n"
 * Run some basic regression tests with some known patterns.
			jw_array_intmax(&inline2, 2);
			buf[--len] = 0;
		jw_end(&inline2);
	 "\"arr1\":[\"abc\",42,true]}");
			jw_object_false(&jw, key);
			get_s(line_nr, &s_value);
static void make_obj3(int pretty)
	{
	t(arr2);
static const char *pretty_mixed1 =
		jw_object_intmax(&obj2, "a", -1);
		jw_object_intmax(&obj2, "c", 0);
			jw_array_false(&jw);
	 "  \"arr1\": [\n"
	struct json_writer jw = JSON_WRITER_INIT;
	jw_object_begin(&obj2, pretty);
		double d_value;
				  "  true\n"
		else if (!strcmp(verb, "object-double")) {
 * pretty).
	jw_object_begin(&obj5, pretty);
static const char *expect_obj2 = "{\"a\":-1,\"b\":2147483647,\"c\":0}";
static char *expect_inline2 =

		else if (!strcmp(verb, "array-null"))
#include "cache.h"
static const char *expect_obj5 = "{\"abc\\tdef\":\"abc\\\\def\"}";
		jw_object_intmax(&obj2, "b", 0x7fffffff);

static struct json_writer obj2 = JSON_WRITER_INIT;
	p(obj1);
	{
	jw_init(&inline1);
		return;
			get_s(line_nr, &key);
	 "  [\n"
	t(mixed1);
	 "}");
	t(obj6);
 */
		jw_array_null(&arr4);
		jw_array_false(&arr4);

#define p(v) do { make_##v(1); cmp(#v, &v, pretty_##v); } while (0)
static const char *expect_obj3 = "{\"a\":0,\"b\":4294967295,\"c\":9223372036854775807}";
			jw_object_intmax(&inline1, "b", 42);

			get_i(line_nr, &i_value);
static void make_mixed1(int pretty)
{
	 "    true\n"
		}
				  "  \"a\": 0,\n"

static void make_nest1(int pretty)
				  "  -1,\n"
		else if (!strcmp(verb, "array-false"))
			get_i(line_nr, &i_value);
			return unit_tests();
				  "]");

#define MAX_LINE_LENGTH (64 * 1024)
	if (!fgets(buf, buf_size, stdin))

static void make_arr2(int pretty)
	{
static char *get_trimmed_line(char *buf, int buf_size)
static struct json_writer obj3 = JSON_WRITER_INIT;
static void make_inline1(int pretty)
			jw_array_string(&inline1, "abc");

		{
			jw_end(&jw);
			jw_object_null(&jw, key);
	t(arr1);
		jw_array_inline_begin_object(&inline2);
{
{
}
static char *expect_nest1 =
/*
	       test, jw->json.buf, exp);

	jw_array_begin(&arr3, pretty);
static void make_arr4(int pretty)
			get_s(line_nr, &key);
	p(arr4);
	"{\"obj1\":{\"a\":\"abc\",\"b\":42,\"c\":true},\"arr1\":[\"abc\",42,true]}";
		die("line[%d]: invalid integer value", line_nr);
static int pretty;
	}
}
			jw_array_intmax(&inline1, 42);
		}
	("{\n"
	*s_in = strtol(s, &endptr, 10);
			jw_object_string(&jw, key, s_value);
		verb = strtok(line, " ");
static const char *expect_obj6 = "{\"a\":3.14}";
static const char *expect_obj4 = "{\"t\":true,\"f\":false,\"n\":null}";
static char *expect_inline1 =

static struct json_writer inline2 = JSON_WRITER_INIT;

	p(arr1);
		jw_array_inline_begin_array(&inline2);
	jw_init(&mixed1);
	return 0;
	 "  ],\n"
	 "    \"c\": true\n"
	t(inline1);
{
	 "]");
	jw_init(&arr3);
	if (!strcmp(line, "object"))

	jw_init(&arr1);
static void make_obj5(int pretty)
	}
	jw_end(&obj1);
}


	jw_init(&arr1);
	{

}
		line_nr++;
	while ((line = get_trimmed_line(buf, MAX_LINE_LENGTH)) != NULL) {
	jw_init(&obj1);
static void make_inline2(int pretty)
	{
	line = get_trimmed_line(buf, MAX_LINE_LENGTH);
			get_d(line_nr, &d_value);
			die("unrecognized token: '%s'", verb);
	 "    4\n"
 * When super is compact, we expect subs to be compacted (even if originally
		jw_object_double(&obj6, "a", 2, 3.14159);
	jw_object_begin(&nest1, pretty);
				  "  true,\n"
}
static struct json_writer obj1 = JSON_WRITER_INIT;
	/* pretty forms */
	get_s(line_nr, &s);
static void make_obj4(int pretty)
static const char *pretty_arr4 = ("[\n"
		if (!strcmp(argv[0], "-u") || !strcmp(argv[0], "--unit"))
	 "  ]\n"
{
				  "  0\n"
#include "test-tool.h"
				  "  false,\n"
#include "json-writer.h"
				  "  \"f\": false,\n"
			jw_object_intmax(&jw, key, i_value);
{
static void make_arr3(int pretty)

	char *endptr;
	jw_end(&obj2);

{
}


		if (!strcmp(argv[0], "-p") || !strcmp(argv[0], "--pretty"))
static int scripted(void)
			break;
	 "    true\n"
			get_i(line_nr, &i_value);
	jw_end(&obj5);

		else if (!strcmp(verb, "object-null")) {
		else
}
}
{
static struct json_writer inline1 = JSON_WRITER_INIT;
	if (!jw_is_terminated(&jw))
				  "  4294967295,\n"
	argc--; /* skip over "json-writer" arg */
		jw_array_intmax(&arr2, -1);
	if (!*s_in)
int cmd__json_writer(int argc, const char **argv)
		else if (!strcmp(verb, "array-double")) {
{
		char *key;
{
		jw_object_intmax(&obj3, "c", 0x7fffffffffffffffULL);
		}
		jw_array_true(&arr4);
		if (!strcmp(verb, "end")) {
				  "  \"b\": 42,\n"
static const char *expect_mixed1 =
			jw_object_inline_begin_object(&jw, key);
	{
	if (argc > 0 && argv[0][0] == '-') {
	t(arr3);
		jw_object_string(&obj5, "abc" "\x09" "def", "abc" "\\" "def");
static void get_d(int line_nr, double *s_in)
		else if (!strcmp(verb, "object-int")) {
}

{
			jw_array_intmax(&inline2, 1);
				  "}");
static const char *pretty_obj4 = ("{\n"
		}
	 "    3,\n"
	}
	char *s;
	"{\"obj1\":{\"a\":\"abc\",\"b\":42,\"c\":true},\"arr1\":[\"abc\",42,true]}";
	 "    \"a\": \"abc\",\n"
	("{\"obj1\":{\"a\":\"abc\",\"b\":42,\"c\":true},"


				  "  42,\n"
			jw_array_inline_begin_object(&jw);
		{
	jw_object_begin(&obj4, pretty);




	 "  [\n"
	jw_init(&obj4);
	}
static const char *pretty_arr1 = ("[\n"
	return 0;

	char buf[MAX_LINE_LENGTH];
			jw_array_true(&inline1);
static const char *expect_arr3 = "[0,4294967295,9223372036854775807]";
