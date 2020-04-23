	}

	 * for 20 lines, or "-L <something>,-5" for 5 lines ending at
{

		while (begin++ < lines) {
			     void *data, long lines, long begin, long *ret)


		return spec;
	*term = 0;
		die("-L parameter '%s': %s", pattern, errbuf);
	if (anchor > lines)
	if (*arg)
	if (isalpha(*bol) || *bol == '_' || *bol == '$')
	start = nth_line_cb(cb_data, anchor);
	}
					   lines, anchor, begin, end,
		return term;
			eol++;
#include "git-compat-util.h"
 * Parse one item in the -L option
		if (*bol == '\n')
	int reg_error;
	line = nth_line(data, begin);

	/* Allow "-L <something>,+20" to mean starting at <something>
	if (*arg == ',')
{
 *
		    void *cb_data, long lines, long anchor,
		return term;
			*ret = num;
		return spec;
		const char *bol = nth_line_cb(cb_data, *end);
			return bol;
	if (*begin >= lines)
	if (1 <= begin && (spec[0] == '+' || spec[0] == '-')) {
				break;

		die("-L parameter '%s' starting at line %ld: no match",
					    0, 0, NULL, NULL,
}
		anchor = 1;
static const char *find_funcname_matching_regexp(xdemitconf_t *xecfg, const char *start,
			if (!ret)
		/* is it a funcname line? */
		char errbuf[1024];
}
		*ret = begin;
 *
	}
	int reg_error;
				*ret = begin + num > 0 ? begin + num : 1;
		    pattern, anchor + 1);
		arg = parse_loc(arg + 1, nth_line_cb, cb_data, lines, *begin + 1, end);
	regmatch_t match[1];

	if (term != spec) {
	void *cb_data, long lines, long anchor, long *begin, long *end,
	*begin = *end = 0;

#include "strbuf.h"
	}

		anchor = 1;
		arg = parse_range_funcname(arg, nth_line_cb, cb_data,
	while (*end < lines) {
		return parse_range_funcname(arg, NULL, NULL,
	 * <something>.

	 */
	}
	const char *start;
			begin = -begin;
	}

		return term+1;
	long num;
		if (*eol == '\n')
			return -1;
	begin--; /* input is in human terms */
		return 1;
	if (*term != '/')
	*end = *begin+1;
	/* in the scan-only case we are not interested in the regex */
{
	return term;

			bol--;
		while (*eol && *eol != '\n')
static const char *parse_range_funcname(
	p = find_funcname_matching_regexp(xecfg, (char*) start, &regexp);
		if (match_funcname(xecfg, bol, eol))
const char *skip_range_arg(const char *arg, struct index_state *istate)
	if (*arg == '^') {
{
static const char *parse_loc(const char *spec, nth_line_fn_t nth_line,
	while (*term && *term != ':') {
			eol++;
		const char *nline;

	if (*arg == ':' || (*arg == '^' && *(arg + 1) == ':')) {

	if (xecfg) {
		}
		char buf[1];
		if (*term == '\\' && *(term+1))
	const char *arg, nth_line_fn_t nth_line_cb,
		return NULL;
		regfree(&regexp);
					xecfg->find_func_priv) >= 0;
	/* try [spec+1 .. term-1] as regexp */
			nline = nth_line(data, begin);
		(*begin)++;
		const char *cp = line + match[0].rm_so;

	if (anchor < 1)

		}
	if (*arg == ',')
		eol = start+match[0].rm_eo;
		else {
	if (!(reg_error = regcomp(&regexp, spec + 1, REG_NEWLINE)) &&
		regerror(reg_error, &regexp, errbuf, 1024);
	free(pattern);
			begin = 1;
		}
			break;
	arg = parse_loc(arg, nth_line_cb, cb_data, lines, -anchor, begin);
		else if (reg_error) {
}
	if (drv && drv->funcname.pattern) {
	assert(*arg == ':');

				die("-L invalid empty range");
			line = nline;


	xdemitconf_t *xecfg = NULL;
	return 0;
		SWAP(*end, *begin);
 * When parsing "-L A,B", parse_loc() is called once for A and once for B.
	char *term;
		(*end)++;
 * following the line computed for 'A'.
		xdiff_set_find_func(xecfg, pe->pattern, pe->cflags);
		    const char *path, struct index_state *istate)
	anchor--; /* input is in human terms */
	reg_error = regcomp(&regexp, pattern, REG_NEWLINE);
	const char *line;
		return 0;
			if (0 < num)
	if (!begin) /* skip_range_arg case */
		    spec + 1, begin + 1, errbuf);
	}
			term++;
	int reg_error;
				*ret = begin + num - 2;
	arg = parse_loc(arg, NULL, NULL, 0, -1, NULL);
					   path, istate);
	return arg;
		term++;
				*ret = begin;
				return term;
		const char *bol, *eol;
		return -1;

	for (term = (char *) spec + 1; *term && *term != '/'; term++) {
	}
		if (*term == '\\')
int parse_range_arg(const char *arg, nth_line_fn_t nth_line_cb,
	regfree(&regexp);
			spec++;
#include "line-range.h"

			if (spec[0] == '-')
		start = eol;
	regex_t regexp;
	free(xecfg);
		char errbuf[1024];
	regmatch_t match[1];
	const char *p;

		num = strtol(spec + 1, &term, 10);
		if (!arg || *arg)


	}
			if (num == 0)
	if (term == arg+1)
 * When parsing B, 'begin' must be the positive line number immediately
			die("-L parameter: regexec() failed: %s", errbuf);
#include "userdiff.h"

	while (p > nth_line_cb(cb_data, *begin))
	}
	}
static int match_funcname(xdemitconf_t *xecfg, const char *bol, const char *eol)
		const char *eol = nth_line_cb(cb_data, *end+1);
	if (reg_error) {
 */
		die("-L parameter '%s' matches at EOF", pattern);
		}
		return spec;
	if (!p)
		if (ret) {

			else
		return 0;
		if (match_funcname(xecfg, (char*) bol, (char*) eol))
	(*begin)++;
		/* determine extent of line matched */
		arg++;
 * based. Beginning of file is represented by -1.
 * ignore this value.
}
			regerror(reg_error, regexp, errbuf, 1024);
			return NULL;
	const char *path, struct index_state *istate)
		while (bol > start && *bol != '\n')

			term++;
		return xecfg->find_func(bol, eol - bol, buf, 1,
 *
	struct userdiff_driver *drv;
	if (spec[0] != '/')
			char errbuf[1024];

	if (begin < 0) {
		xecfg = xcalloc(1, sizeof(*xecfg));

			if (num <= 0)
	}
	return 0;
}
	/* it could be a regexp of form /.../ */
				die("-L invalid line number: %ld", num);
	}
	}
						 regex_t *regexp)
		arg = parse_loc(arg+1, NULL, NULL, 0, 0, NULL);
	if (!ret)
	/* compensate for 1-based numbering */
/*

			else if (!num)
 * When parsing A, 'begin' must be a negative number, the absolute value of
		if (term != spec + 1) {
					    NULL, istate);
	while (1) {
		const struct userdiff_funcname *pe = &drv->funcname;


	term = arg+1;
	}
	if (bol == eol)
	char *pattern;
	pattern = xstrndup(arg+1, term-(arg+1));

		if (reg_error == REG_NOMATCH)
	regex_t regexp;
		bol = start+match[0].rm_so;
		}
			if (line <= cp && cp < nline)
		return term;
				num = 0 - num;
		if (spec[0] != '^')
	    !(reg_error = regexec(&regexp, line, 1, match, 0))) {
 *


	if (*begin && *end && *end < *begin) {

	else {
	if (*arg == ':' || (*arg == '^' && *(arg + 1) == ':'))
		die("-L parameter '%s' starting at line %ld: %s",
 * 'begin' is applicable only to relative range anchors. Absolute anchors
	drv = userdiff_find_by_path(istate, path);
		anchor = lines + 1;
 * which is the line at which relative start-of-range anchors should be
		*term++ = '/';
	const char *term;
			bol++;
{
	num = strtol(spec, &term, 10);
		reg_error = regexec(regexp, start, 1, match, 0);
{
			return term;
		    long *begin, long *end,
		regerror(reg_error, &regexp, errbuf, 1024);

	*begin = 0;
#include "xdiff-interface.h"
}
