
		timestamp_t t;
"  test-tool date approxidate [date]...\n"
	parse_date_format(format, &mode);
		return sizeof(time_t) == 8 ? 0 : 1;
}
#include "test-tool.h"
static void show_dates(const char **argv, const char *format)
{
static void parse_dates(const char **argv)
	else if (skip_prefix(*argv, "show:", &x))
		printf("%s -> %s\n", *argv, buf.buf);
	printf("%lf\n", seconds);
}
}
			printf("%s -> bad\n", *argv);
		time_t t = atoi(*argv);
}
	}
"  test-tool date parse [date]...\n"
		show_relative_dates(argv+1);
		show_dates(argv+1, x);
	else if (!strcmp(*argv, "parse"))
		int tz;
	for (; *argv; argv++) {
		tz = atoi(arg);
"  test-tool date is64bit\n"
{
		t = parse_timestamp(*argv, &arg, 10);

	strbuf_release(&buf);
static void show_human_dates(const char **argv)
		 * Do not use our normal timestamp parsing here, as the point
		show_human_dates(argv+1);
		timestamp_t t;

			       *argv, show_date(t, tz, DATE_MODE(ISO8601)));

	for (; *argv; argv++) {
	const char *x;
"  test-tool date getnanos [start-nanos]\n"
	argv++;
		strbuf_reset(&result);
}
	}
		parse_approx_timestamp(argv+1);
	}
		getnanos(argv+1);
static void parse_approx_timestamp(const char **argv)
	struct strbuf buf = STRBUF_INIT;
static void getnanos(const char **argv)
		 * is to test the formatting code in isolation.
static const char *usage_msg = "\n"
		seconds -= strtod(*argv, NULL);
	if (*argv)
	for (; *argv; argv++) {
	else
	strbuf_release(&result);
{
	else if (!strcmp(*argv, "time_t-is64bit"))
		t = approxidate_relative(*argv);

		parse_dates(argv+1);

	struct strbuf result = STRBUF_INIT;
	else if (!strcmp(*argv, "human"))
	struct date_mode mode;
	else if (!strcmp(*argv, "timestamp"))
		while (*arg == ' ')
		time_t t = atoi(*argv);
		parse_date(*argv, &result);



		char *arg;
"  test-tool date show:<format> [time_t]...\n"
		printf("%s -> %s\n", *argv, show_date(t, 0, DATE_MODE(HUMAN)));
		/*
	}
			printf("%s -> %s\n",
		printf("%s -> %"PRItime"\n", *argv, t);
{
{
	double seconds = getnanotime() / 1.0e9;
	else if (!strcmp(*argv, "is64bit"))
		 */
"  test-tool date human [time_t]...\n"
"  test-tool date relative [time_t]...\n"
}

"  test-tool date timestamp [date]...\n"
		timestamp_t t;
		printf("%s -> %s\n", *argv, show_date(t, 0, DATE_MODE(ISO8601)));
		usage(usage_msg);


static void parse_approxidate(const char **argv)
}
		int tz;
		timestamp_t t;

		if (sscanf(result.buf, "%"PRItime" %d", &t, &tz) == 2)
	if (!*argv)
		parse_approxidate(argv+1);

	}
		t = approxidate_relative(*argv);
#include "cache.h"
		show_date_relative(t, &buf);
		else
		printf("%s -> %s\n", *argv, show_date(t, tz, &mode));
		usage(usage_msg);
static void show_relative_dates(const char **argv)
{

	else if (!strcmp(*argv, "getnanos"))
	if (!strcmp(*argv, "relative"))
int cmd__date(int argc, const char **argv)

{
	for (; *argv; argv++) {
"  test-tool date time_t-is64bit\n";
		return sizeof(timestamp_t) == 8 ? 0 : 1;
{
	return 0;
			arg++;
	}
	for (; *argv; argv++) {

}
	for (; *argv; argv++) {
	else if (!strcmp(*argv, "approxidate"))
