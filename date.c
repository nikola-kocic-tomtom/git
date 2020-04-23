			r->tm_year = year - 1900;

	{ "EAST", +10, 0, },	/* Eastern Australian Standard */
		return -1;
{
			unsigned int minutes = num % 100;
		 * is the norm there, so giving precedence to
		return;
				/* Leave just weekday if it was a few days ago */
		if (isdigit(end[1])) {
	{ "days", 24*60*60 },
{
		    is_date(num3, num, num2, refuse_future, now, tm))

		if (end - (date + 1) != 5)

		tm->tm_sec) < 0;
	 *  (b) keep the maximum length "similar", and in check
			}
			weekday_names[tm->tm_wday], tm->tm_mday,
static time_t tm_to_time_t(const struct tm *tm)
	if (diff < 1825) {
				sign, tz / 100, tz % 100);
	char *end;
	if (*end == c && isdigit(end[1]))
		return n;
	date_time(tm, now, 0);
		strbuf_addftime(&timebuf, mode->strftime_fmt, tm, tz,
			*touched = 1;

		return;
{
	if (skip_prefix(format, "relative", end))
		int n;
{

}
	int hour, n = *num;


	const char *x;
	for (i = 0; i < ARRAY_SIZE(timezone_names); i++) {
		n = tm->tm_mon - *num;
	if (match_string(date, "PM") == 2) {

};
	/* historical alias */
}
	{ "FWT",   +1, 0, },	/* French Winter */


		if (num < 25 && num2 >= 0 && num2 < 60 && num3 >= 0 && num3 <= 60) {
{
}
	return (year * 365 + (year + 1) / 4 + mdays[month] + day) * 24*60*60UL +

};
			match = match_tz(date, offset);
		} else {
	{ "WADT",  +7, 1, },	/* West Australian Daylight */
	{ "EADT", +10, 1, },	/* Eastern Australian Daylight */
}
 * The "tz" thing is passed in as this strange "decimal parse of tz"
	}
	 * Make sure that we fit into time_t, as well.
	if (n == 4) {

static void date_now(struct tm *tm, struct tm *now, int *num)
	offset /= 60; /* in minutes */
	return timebuf.buf;
/*
}
	case '-':
			now = time(NULL);
	if (date[-1] == '-')
{
	{ "NZT",  +12, 0, },	/* New Zealand */
 */
	if (skip_prefix(format, "short", end))
		strbuf_addf(timebuf,
	if (diff < 90) {

}
		if (year != -1)
{
	{ NULL }
	{ "MESZ",  +1, 1, },	/* Middle European Summer */
			int len = strlen(number_name[i]);
	}
	}
		strbuf_addf(&timebuf, "%"PRItime, time);
}
	int length;
	if (mode->type == DATE_RELATIVE) {
		*error_ret = 0;
	strbuf_addf(timebuf,
		}
}
static void date_midnight(struct tm *tm, struct tm *now, int *num)
	const char *p;
}
*/
		if (match >= 3) {
		if (*date == '-')
	if (tm->tm_year < 0) {
	if (tm->tm_mday < 0)
	if (num >= 100000000 && nodate(tm)) {
		return 2;
}
		    is_date(num3, num, num2, refuse_future, now, tm))

			date = approxidate_digit(date-1, &tm, &number, time_sec);
		 */
		return -1;
	 */
		while (n < 0) {
		return DATE_SHORT;
 * Parse a string like "0 +0000" as ancient timestamp near epoch, but

	pending_number(tm, num);
	int errors = 0;
			continue;
	time_sec = tv->tv_sec;
	mode->type = parse_date_type(format, &p);
	"July", "August", "September", "October", "November", "December"
	if (now.tv_sec < time) {
	/* Time? Date? */
	if (!hide.wday)
	"zero", "one", "two", "three", "four",

	if (skip_prefix(format, "unix", end))
	tl = typelen;
		*timestamp = approxidate_careful(date, &errors);

int parse_date(const char *date, struct strbuf *result)
	{ "MEST",  +1, 1, },	/* Middle European Summer */
		int match = match_string(date, weekday_names[i]);
static const struct {

	}
		return;
		offset = -offset;
		tz = local_tzoffset(time);
{
	tm.tm_hour = -1;
 */
	/*
		return 0; /* error; just use +0000 */
		timestamp = &dummy_timestamp;
		temp_time = mktime(&tm);
	{ "WAST",  +7, 0, },	/* West Australian Standard */
	else if (mode->type == DATE_ISO8601_STRICT) {
			diff = tm->tm_wday - i;

		return;
	{ "Z",      0, 0, },    /* Zulu, alias for UTC */
	tm.tm_min = -1;
	if (!parse_date_basic(date, &timestamp, &offset))
		hour = n;
	pending_number(tm, num);
	return approxidate_str(date, (const struct timeval *) &tv, &errors);
	hide.tz = local || tz == human_tz;
		*num = 0;
{
 * local timezone?



		 * mm/dd/yy[yy] form only when separator is not '.'

/*
			if (match_string(date, number_name[i]) == len) {
	{ "WET",    0, 0, },	/* Western European */
			r->tm_year = now_tm->tm_year;
}
		tm->tm_mon = r->tm_mon;
	}
			r->tm_year = year;
	timestamp_t timestamp;
	sys = t;
	int offset;
{
	get_time(&tv);
	get_time(&now);

	hide.year = tm->tm_year == human_tm->tm_year;
	if (!offset)

{
static int match_string(const char *date, const char *str)
			*touched = 1;
		return;

			*touched = 1;
}
	int month = tm->tm_mon;
{
				return end;
			return end;
	int i = 0;
/*
	}
static const char *number_name[] = {
		strbuf_addf(buf, " %d", tm->tm_year + 1900);
 * Relative time update (eg "2 days ago").  If we haven't set the time
}
		if (!now)
/*
		tm->tm_min = 0;
	{ "YDT",   -9, 1, },	/* Yukon Daylight */

	}
			/* BAD CRAP */
	for (i = 0; i < 12; i++) {
	{ "never", date_never },
	date_time(tm, now, 12);
	tm->tm_hour = (hour % 12);
	if (n > 2)
	{ "EDT",   -5, 1, },	/* Eastern Daylight */
	 * Hide weekday and time if showing year.
	/* Turn it into minutes */
	time += minutes * 60;
	} hide = { 0 };

	 *
		/* European dd.mm.yy[yy] or funny US dd/mm/yy[yy] */

		return 2;
void datestamp(struct strbuf *out)
	/* If we overflowed our timestamp data type, that's bad... */
	{ "now", date_now },
		return DATE_ISO8601;
{
	mode.local = 0;
		}
		/* Be it commit time or author time, it does not make
			tm->tm_hour, tm->tm_min, tm->tm_sec, tz);
			*num = 1;
	if (diff < 70) {
	{ "IDLE", +12, 0, },	/* International Date Line East */
	struct tm human_tm = { 0 };
		offset = t_local - t;
		 */
	/*
	if (offset < 0) {
		tm->tm_mday = num;
			tm->tm_year = num - 1900;
	*num = 0;
		offset = &dummy_offset;
	timestamp_t num;
			r->tm_year = year + 100;
			return end;
			 Q_("%"PRItime" hour ago", "%"PRItime" hours ago", diff), diff);
	{ "yesterday", date_yesterday },
 */
		return -1;

	if (minutes > 0) {
 */
	/* Give years and months for 5 years or so */
		ofs = -ofs;
	int errors = 0;
	static const int mdays[] = {
	return gmtime_r(&t, tm);

			break;
	int i;
	for (i = 0; i < 12; i++) {
	num = parse_timestamp(date, &end, 10);
	 */
	}
	 *  (a) only show details when recent enough to matter
	if (month < 2 || (year + 2) % 4)
	 */
				*touched = 1;

 * thing, which means that tz -0100 is passed in as the integer -100,
		strbuf_addf(&timebuf, "%04d-%02d-%02dT%02d:%02d:%02d%c%02d:%02d",
	}
	if (skip_prefix(format, "rfc2822", end) ||
/*
	int number = 0;
		strbuf_addf(buf, " %+05d", tz);
		 * sense to specify timestamp way into the future.  Make

{
	if (!hide.tz)
	if (tm->tm_hour < hour)
	if (!parse_date_basic(date, &timestamp, &offset)) {
	struct {
			/* Only use the tz name offset if we don't have anything better */
	if (!hide.date)

		}
	{ "PM", date_pm },
		if ((specified != -1) && (now + 10*24*3600 < specified))
{
static int skip_alpha(const char *date)
		return;
		else if (tm->tm_year < 0) {

	if (diff < 365) {
		}
}
	if (x) {
		tm->tm_mday &
	tm->tm_hour = hour;
	else if (!strcmp(date, "all") || !strcmp(date, "now"))
			 (diff + 15) / 30);
static inline int nodate(struct tm *tm)
			tm->tm_year = num;
static int match_alpha(const char *date, struct tm *tm, int *offset)
static struct tm *time_to_tm(timestamp_t time, int tz, struct tm *tm)
{
}
	if (!touched)

			 Q_("%"PRItime" second ago", "%"PRItime" seconds ago", diff), diff);
	tm->tm_sec = 0;
		strbuf_rtrim(buf);
		if (!hide.seconds)
}
}
		tz = 0;
	}
	else
			strbuf_addf(&sb, Q_("%"PRItime" year", "%"PRItime" years", years), years);
	return offset * eastwest;
	} while (isalpha(date[i]));
}
	if (num > 0 && num < 32 && tm->tm_mday < 0) {
	return end - date;
	if (mode->type == DATE_STRFTIME) {

	const struct special *s;
}

			*offset = ((time_t)*timestamp - temp_time) / 60;
				tm->tm_year = 100 + number;
	die("unknown date format %s", format);
 *
		}
	switch (c) {
static int local_tzoffset(timestamp_t time)
			refuse_future = &now_tm;
	return t != sys || (t < 1) != (sys < 1);
static void date_time(struct tm *tm, struct tm *now, int hour)
{
}
			*num = 0;
	update_tm(tm, now, 0);
	switch (*end) {
			 Q_("%"PRItime" month ago", "%"PRItime" months ago", (diff + 15) / 30),

			break;
		tm->tm_mon = n;
		/* hhmm */
{
 */



		die("Timestamp too large for this system: %"PRItime, time);


		}
	 */
		tm->tm_hour * 60*60 + tm->tm_min * 60 + tm->tm_sec;
		return -1;
	struct tm tm, now;
	}
		} else
			tm->tm_hour = num;
static void date_am(struct tm *tm, struct tm *now, int *num)
	for (;;) {
void show_date_relative(timestamp_t time, struct strbuf *timebuf)
		*offp = offset;
	if (month < 0 || month > 11) /* array bounds */
		/* Funny European mm.dd.yy */
	return local_time_tzoffset((time_t)time, &tm);

	*num = 0;
	 * more than 8 digits. This is because we don't want to rule out
	if (month > 0 && month < 13 && day > 0 && day < 32) {

		now->tv_usec = 0;
		num3 = strtol(end+1, &end, 10);
{
		*num = 0;
		int match = 0;
	if (diff < 36) {
	timestamp_t diff;
	{ "CST",   -6, 0, },	/* Central Standard */
			if (diff <= 0)
	/* Four-digit year or a timezone? */
 * even though it means "sixty minutes off"
	tm.tm_year = -1;
	switch (*end) {
		return DATE_NORMAL;

	}
				return match;
		BUG("cannot create anonymous strftime date_mode struct");
			if (match)
				date:1,
		day--;
	/*
		*error_ret = 1;
			continue;
		offset = t - t_local;
		update_tm(tm, now, 0); /* fill in date fields if needed */
		strbuf_addf(timebuf,
	}
			return match;
		}
	if (skip_prefix(format, "auto:", &p)) {
	{ "CET",   +1, 0, },	/* Central European */
   (i.e. English) day/month names, and it doesn't work correctly with %z. */
		i++;
static void get_time(struct timeval *now)
	return 0;

	 * offset larger than 12 hours (e.g. Pacific/Kiritimati is at
	*num = 0;
		hide.wday = hide.time = !hide.year;

		/*
	minutes = (minutes / 100)*60 + (minutes % 100);
		sign = '-';
	}
static int match_digit(const char *date, struct tm *tm, int *offset, int *tm_gmt)
	if (skip_prefix(p, "-local", &p))
	{ "CAT",  -10, 0, },	/* Central Alaska */
{
			*tm_gmt = 1;
	*timestamp = tm_to_time_t(&tm);
				tm->tm_mday,
				tz:1;
		return timestamp;
		strbuf_reset(&timebuf);
 * GIT - The information manager from hell
		if (c != '.' &&
		tm->tm_mon = now->tm_mon;
	{ "AM", date_am },
		strbuf_addf(&timebuf, "%04d-%02d-%02d", tm->tm_year + 1900,
	const char *end = date;
		if (match >= 3) {
			off += timezone_names[i].dst;
	return &mode;
			} else if (tm->tm_mday == human_tm->tm_mday) {
		return end;
			struct strbuf sb = STRBUF_INIT;
	};
			tm->tm_year--;
	}
	{ "MST",   -7, 0, },	/* Mountain Standard */
	    skip_prefix(format, "rfc", end))
	if (!hide.year)
			month_names[tm->tm_mon], tm->tm_year + 1900,

 */
	if (min < 60 && hour < 24) {
	}
 * we see a new one? Let's assume it's a month day,

	if (skip_prefix(format, "format", end))
 * in other ways too.
int date_overflows(timestamp_t t)
	case '.':


				break;
		*touched = 1;
	t_local = tm_to_time_t(tm);
	time_t t_local;
} special[] = {
			break;

				 Q_("%s, %"PRItime" month ago", "%s, %"PRItime" months ago", months),
		strbuf_addf(buf, "%02d:%02d", tm->tm_hour, tm->tm_min);
		mode->strftime_fmt = xstrdup(p);

	 * numbers like 20070606 as a YYYYMMDD date.
{
			*num = 0;
		/* Our eastern European friends say dd.mm.yy[yy]
 * We've seen a digit. Time? Year? Date?
	 * git-completion.bash when you add new formats.
	int offset;
				hide.date = 1;
}
				tm->tm_year + 1900,
	timestamp_t number = parse_timestamp(date, &end, 10);
	int touched = 0;
			      char *end, struct tm *tm, time_t now)
		if (match_string(date, s->name) == len) {
};
}
{
	}
	int minutes;
			    time, tz);
		}
	update_tm(tm, now, 24*60*60);
		}
	if (skip_prefix(format, "human", end))
	if (mode->type == DATE_SHORT)
	 */
}
	int offset;
{
	}
		 * really means to expire everything she has done in
	 * functions that expect time_t, which is often "signed long".
	{ "EET",   +2, 0, },	/* Eastern Europe, USSR Zone 1 */
	int number = *num;
		int match = match_string(date, weekday_names[i]);
	if (!error_ret)
	}

		strbuf_addf(buf, "%.3s ", weekday_names[tm->tm_wday]);
{
};
	 * Please update $__git_log_date_formats in

	}
			n += 12;
		n++;
	tm->tm_min = 0;
/*
	 * Days or months must be one or two digits.
		strbuf_addf(timebuf,
static void date_never(struct tm *tm, struct tm *now, int *num)
			if (!now_tm)
	}
		unsigned int	year:1,
		strbuf_addf(timebuf,
	}
	int tm_gmt;

		return DATE_STRFTIME;
		/* gmtime_r() in match_digit() may have clobbered it */
	else if (mode->type == DATE_ISO8601)
			/* yyyy-dd-mm? */
		else
	if (n == 2 && tm->tm_year < 0) {
	{ "EST",   -5, 0, },	/* Eastern Standard */
		return -1;
		 (diff + 183) / 365);
		 */
	offset /= 60;
		}
	/* BAD CRAP */
}
		tm->tm_year = now->tm_year;

	hour = tm->tm_hour;
	int ofs;
	} else if (*end == ':') {
	}
		r->tm_mday = day;
	    !match_object_header_date(date + 1, timestamp, offset))
		strbuf_addf(&timebuf, "%.3s, %d %.3s %d %02d:%02d:%02d %+05d",
				n++;

	}

static int match_object_header_date(const char *date, timestamp_t *timestamp, int *offset)
		strbuf_reset(&timebuf);
	if (tm->tm_mon < 0)
		mode->local = 1;
		time_t specified;

		struct tm *r = (now_tm ? &check : tm);
		return end;

static time_t update_tm(struct tm *tm, struct tm *now, time_t sec)
			match = match_alpha(date, &tm, offset);
{
	static struct date_mode mode;
				 /* TRANSLATORS: "%s" is "<n> years" */
		now->tv_sec = atoi(x);
		return n;
			if (tm->tm_mday > human_tm->tm_mday) {
 */
	tm.tm_mday = -1;
{
	else
	} else
	{ "MEWT",  +1, 0, },	/* Middle European Winter */
			tm->tm_year = r->tm_year;
* Parse month, weekday, or timezone name
		die("Timestamp too large for this system: %"PRItime, time);
		if (match_string(date, "last") == 4) {
	if ((uintmax_t)t >= TIME_MAX)
		if (isalpha(c))
		timestamp_t years = totalmonths / 12;
	tm.tm_isdst = -1;

				tm->tm_hour, tm->tm_min, tm->tm_sec,
		if (!c || c == '\n')
	}

		}

		}
		time_t temp_time;
	*offset = -1;
	timestamp_t timestamp;
		 * to be kept.
		if (!isalnum(*date))
	if (*timestamp == -1)
	{ "CCT",   +8, 0, },	/* China Coast, USSR Zone 7 */
		return 0;
	if (!hide.time) {
	}
 */
				/* Future date: think timezones */
		if (match_string(date, tl->type) >= len-1) {

} timezone_names[] = {
			tm->tm_mon = i;
		}
	return i;
		if ((time_t)*timestamp > temp_time) {
		if (num3 < 0)
			 Q_("%"PRItime" week ago", "%"PRItime" weeks ago", (diff + 3) / 7),

 *
		return DATE_RFC2822;
		}
		if (gmtime_r(&time, tm)) {
		show_date_normal(&timebuf, time, tm, tz, &human_tm, human_tz, mode->local);

	/*
	char *end;
	struct tm tmbuf = { 0 };

	{ "CDT",   -6, 1, },	/* Central Daylight */

						       tm, now);
	} while (isdigit(date[n]));
 * only when it appears not as part of any other string.
{
	if (n) {
				return 1;
	hour = tm->tm_hour;
	localtime_r(&time_sec, &tm);
	/* Say months for the past 12 months or so */
	char *end;
	 * None of the special formats? Try to guess what
		tm->tm_hour &
}
	num2 = strtol(end+1, &end, 10);
			tm->tm_mday = number;
	else
{
			*touched = 1;
				tm->tm_mday,
	{ "seconds", 1 },
		hour = n;
	{ "EEST",  +2, 1, },	/* Eastern European Daylight */
			break;
	{ "ADT",   -3, 1, },	/* Atlantic Daylight */
	}
		tm.tm_isdst = -1;

	time_t t = gm_time_t(time, tz);

			/* This is bogus, but we like summer */
	struct tm *tm;
	} else if (*p)
		if (num <= 1400 && *offset == -1) {
	if (skip_prefix(format, "default", end))
	struct tm tm = { 0 };
	now = tm;
			int diff, n = *num -1;
	if (skip_prefix(format, "raw", end))
	/*
			tm->tm_year = num + 100;
		tm->tm_mon &
	if (skip_prefix(format, "iso8601-strict", end) ||
		min = 99; /* random crap */
		*num = number;
static time_t gm_time_t(timestamp_t time, int tz)

		if (year == -1) {
			/* yyyy-mm-dd? */
			continue;
		else if (year < 38)
			return match;
			touched = 1;
		}

		int len = strlen(tl->type);
	int offset;
		unsigned char c = *date;
/* Gr. strptime is crap for this; it doesn't have a way to require RFC2822
			return end;

		return -1;
	if (*end != ' ' || stamp == TIME_MAX || (end[1] != '+' && end[1] != '-'))
		} else if (num > 1900 && num < 2100)
	ofs = (ofs / 100) * 60 + (ofs % 100);

		return -1;
		update_tm(tm, now, 24*60*60);
	return localtime_r(&t, tm);
	if (date_overflows(time))
	 * Ignore lots of numerals. We took care of 4-digit years above.
				tm->tm_year + 1900,
		return DATE_UNIX;
 * We just do a binary 'and' to see if the sign bit
	return end;
		return timebuf.buf;
static const struct special {
	time_t time_sec;
			match = match_digit(date, &tm, offset, &tm_gmt);
	}
	if (t_local == -1)
	}
		strbuf_addf(&timebuf, "%"PRItime" %+05d", time, tz);
}
			 (diff + 3) / 7);
		struct tm check = *tm;
	}
	struct timeval now;
	{ "PST",   -8, 0, },	/* Pacific Standard */
	timestamp_t dummy_timestamp;
	}
	{ "PDT",   -8, 1, },	/* Pacific Daylight */
	 */

{
	{ "AST",   -3, 0, },	/* Atlantic Standard */

const char *show_date(timestamp_t time, int tz, const struct date_mode *mode)
	{ "GMT",    0, 0, },	/* Greenwich Mean */
		return DATE_RAW;
			s->fn(tm, now, num);
	*offset = ofs;
	} else if (mode->type == DATE_RFC2822)
	}
		else if (year >= 1970 && year < 2100)
	tm.tm_year = -1;
static const char *approxidate_alpha(const char *date, struct tm *tm, struct tm *now, int *num, int *touched)
	/*
		if (match >= 3 || match == strlen(timezone_names[i].name)) {
		if (num > 70) {
	return n;
		return;
	{ "BST",    0, 1, },	/* British Summer */
		specified = tm_to_time_t(r);
	time_t n = 0;

}
	int dst;
	else
	return end - date;
	 * minutes are divisible by 15 or something too. (Offset of
	int year = tm->tm_year - 70;
	if (n) {
	if (!tm) {
		else if (year > 70 && year < 100)
		error_ret = &dummy;
			return n;
			tm->tm_sec = num3;
	strbuf_addf(buf, "%"PRItime" %c%02d%02d", date, sign, offset / 60, offset % 60);
	 */
static void date_tea(struct tm *tm, struct tm *now, int *num)
	{ "HST",  -10, 0, },	/* Hawaii Standard */

static void date_yesterday(struct tm *tm, struct tm *now, int *num)
		tz = abs(tz);
	}
		int offset = hour * 60 + min;
			return 1;
		return DATE_RELATIVE;
			offset = -offset;
 * yet, we need to set it from current time.
{
			else if (number < 38)
{
	}
		tm->tm_hour = (tm->tm_hour % 12) + 12;
		date += match;
		if (isdigit(end[1])) {
	/* do not use mktime(), which uses local timezone, here */
static struct tm *time_to_tm_local(timestamp_t time, struct tm *tm)
	return 0;
			break;
	for (i = 0; *date; date++, str++, i++) {
	int hour = strtoul(date + 1, &end, 10);
				!mode->local);
	if (diff < 14) {
{
		tm->tm_min &
		}
	}
{
		return;
	minutes = tz < 0 ? -tz : tz;
	if (mode->type == DATE_RAW) {
	while (tl->type) {
{
				   const struct timeval *tv,
	while (isalpha(*++end))
	 * year numbers in the 1-12 range. So 05 is always "mday 5",
		update_tm(tm, now, 0); /* fill in date fields if needed */
	{ "UTC",    0, 0, },	/* Universal (Coordinated) */
	int dummy = 0;


	int n = end - (date + 1);
			strbuf_addf(timebuf,
	if (hide.wday) {

	/* "auto:foo" is "if tty/pager, then foo, otherwise normal" */
		}
	}
}
		*timestamp = TIME_MAX;
		*timestamp -= *offset * 60;
	timestamp_t timestamp;
static void date_pm(struct tm *tm, struct tm *now, int *num)
			tm->tm_mon = i;
		r->tm_mon = month - 1;
	}

 * and return the local tz.
	pending_number(tm, num);
	time_t sys;
	case '/':
/*
	    skip_prefix(format, "iso-strict", end))
		if (num < 10 && tm->tm_mday >= 0) {
	    skip_prefix(format, "iso", end))
	{ "weeks", 7*24*60*60 },
	if (!*num) {
	{ "NT",   -11, 0, },	/* Nome */
{
	const struct typelen *tl;
	time_t t = time;
	{ "JST",   +9, 0, },	/* Japan Standard, USSR Zone 8 */
		strbuf_addf(timebuf,
{
int parse_expiry_date(const char *date, timestamp_t *timestamp)
			return 0;
}
		}
				tm->tm_hour, tm->tm_min, tm->tm_sec,
	}
		 * to the current timestamp.  This is because the user

			 Q_("%"PRItime" day ago", "%"PRItime" days ago", diff), diff);
				break;
		die("unknown date format %s", format);
	"January", "February", "March", "April", "May", "June",

		timestamp_t totalmonths = (diff * 12 * 2 + 365) / (365 * 2);
		if (gmtime_r(&now, &now_tm))
	mode.type = type;
		}
 */
			update_tm(tm, now, diff * 24 * 60 * 60);
	{ "tea", date_tea },
		if (!now_tm)
	if (type == DATE_STRFTIME)
	{ "minutes", 60 },
		*timestamp = 0;
	if (parse_date_basic(date, &timestamp, &offset))
	num3 = -1;
		}

}
	const char *name;
	for (i = 0; i < 7; i++) {
			diff += 7*n;
	return (time_t)time;

		unsigned char c = *date;
	 * the number meant. We use the number of digits
	diff = (diff + 30) / 60;
		}

		return timestamp;
	if (*date == '@' &&
	{ "YST",   -9, 0, },	/* Yukon Standard */

	 * Hide timezone if showing date.
	get_time(&tv);
			match = 1;

	date_string(now, offset, out);
		/* Stop at end of string or newline */

		hide.tz |= !hide.date;
	if (t_local < t) {

}
				time:1,
	}
			return n;
void parse_date_format(const char *format, struct date_mode *mode)
}
			tm->tm_wday = i;
			tm->tm_mon = number-1;

	if (*date < '0' || '9' < *date)
		tm->tm_sec = 0;
	timestamp_t stamp;
	}
	return skip_alpha(date);
	 * Don't accept any random crap. Even though some places have
			return 0;
		/* Fill in the data for "current time" in human_tz and human_tm */
timestamp_t approxidate_relative(const char *date)

	{ "NZDT", +12, 1, },	/* New Zealand Daylight */
 * In my world, it's always summer, and things are probably a bit off
		if (isalpha(c))

 */
	{ "NZST", +12, 0, },	/* New Zealand Standard */
 * Check these. And note how it doesn't do the summer-time conversion.
};
			tm->tm_min = num2;
 * Fill in the localtime 'struct tm' for the supplied time,
	localtime_r(&t, tm);
static int match_tz(const char *date, int *offp)
	date_time(tm, now, 17);
		hide.seconds = 1;
		time_t time = num;

			if (*offset == -1)
	case ':':
		if (!skip_prefix(p, ":", &p))

	time_t now;
	ofs = strtol(date, &end, 10);
	strbuf_reset(&timebuf);
	 * Check for special formats: num[-.:/]num[same]num
{

		return 0; /* success */
	 *
			return end - date;
		if (tm->tm_mon == human_tm->tm_mon) {
	{ "IDLW", -12, 0, },	/* International Date Line West */
	 * UTC+14), there is something wrong if hour part is much
			return end;
	struct tm tm;

	if (num > 0 && num < 13 && tm->tm_mon < 0)

static int local_time_tzoffset(time_t t, struct tm *tm)
	int sign = '+';
	tm.tm_mon = -1;
		tm->tm_mon = num-1;
static void pending_number(struct tm *tm, int *num)
	if (skip_prefix(format, "iso8601", end) ||
	if (date[0] != '0' || end - date <= 2)
		 * of the past, and there is nothing from the future

		format = "default-local";
	int n;
		strbuf_reset(&timebuf);
}
			if (is_date(num, num3, num2, NULL, now, tm))
timestamp_t approxidate_careful(const char *date, int *error_ret)
		eastwest = 1;
	if (year < 0 || year > 129) /* algo only works for 1970-2099 */
	tm.tm_mon = -1;
	}
	}
		eastwest = -1;
	if (!timestamp)
	{ "MDT",   -7, 1, },	/* Mountain Daylight */
		return n;
		tm->tm_mday = r->tm_mday;
 * Copyright (C) Linus Torvalds, 2005
	if (match_string(date, "months") >= 5) {
	x = getenv("GIT_TEST_DATE_NOW");

	}
				tm->tm_year = number;
				tm->tm_year = number - 1900;

	/* Turn it into hours */
		timestamp_t months = totalmonths % 12;
static void show_date_normal(struct strbuf *buf, timestamp_t time, struct tm *tm, int tz, struct tm *human_tm, int human_tz, int local)
static int match_multi_number(timestamp_t num, char c, const char *date,
		if (c == '.' &&
static int is_date(int year, int month, int day, struct tm *now_tm, time_t now, struct tm *tm)
	n = 0;
	case ':':
		 Q_("%"PRItime" year ago", "%"PRItime" years ago", (diff + 183) / 365),
		return timebuf.buf;
	return 0;
		if (is_date(num3, num2, num, refuse_future, now, tm))

static void date_string(timestamp_t date, int offset, struct strbuf *buf)
	} else if (n != 2) {
			if (is_date(num, num2, num3, NULL, now, tm))
		if (tm->tm_mon > now->tm_mon)
{

			num3 = 0;
			return match;

	for (i = 0; i < 7; i++) {
	if (*offset == -1) {
		tm->tm_year -= *num;
	int offset;
				seconds:1,
	return approxidate_str(date, &tv, error_ret);
	} else {
	if (mode->type == DATE_UNIX) {
	} /* otherwise we parsed "hh" */
			pending_number(&tm, &number);
		tm->tm_min = 0;
	case '-':
	else if (mode->type == DATE_STRFTIME)
	struct timeval tv;


		tm->tm_mday = now->tm_mday;
static void date_noon(struct tm *tm, struct tm *now, int *num)
	const char *type;
	mode->local = 0;
	*num = 0;
			strbuf_addf(buf, ":%02d", tm->tm_sec);
static const char *weekday_names[] = {
	int i;
	 */

	long num2, num3;
		int match = match_string(date, timezone_names[i].name);
				return date + match;




	tm_gmt = 0;
	}
static enum date_mode_type parse_date_type(const char *format, const char **end)
	localtime_r(&n, tm);
			*offset = -(int)((temp_time - (time_t)*timestamp) / 60);
}

	 * Always hide seconds for human-readable.

	/* Say weeks for the past 10 weeks or so */
	if (mode->local)


	struct tm *refuse_future;
		tm = time_to_tm_local(time, &tmbuf);

			break;
	date = end + 2;
		gettimeofday(now, NULL);
	int min = 0;
	if (n == 4) {
		else if (tm->tm_mon < 0 && number < 13)
	{ "CEST",  +1, 1, },	/* Central European Summer */
	if (match_string(date, "years") >= 4) {
	}
				     time_t now)


	pending_number(&tm, &number);
	if ((*end != '\0' && (*end != '\n')) || end != date + 4)
}
	diff = now.tv_sec - time;
{
	struct tm tm;
	for (s = special; s->name; s++) {
	int hour, n = *num;
	int i = 0;
	 * to make a more educated guess..
	return errors;
		if (toupper(*date) == toupper(*str))
	if (human_tm->tm_year) {
			die("date format missing colon separator: %s", format);
	return (timestamp_t)update_tm(&tm, &now, 0);
	if (diff < 90) {
}
	{ "MET",   +1, 0, },	/* Middle European */
		;
	tm->tm_hour = (hour % 12) + 12;
	{ "WAT",   -1, 0, },	/* West Africa */
static const char *approxidate_digit(const char *date, struct tm *tm, int *num,


	int dummy_offset;
				*offset = 60*off;
			strbuf_release(&sb);
		min = hour % 100;
static timestamp_t approxidate_str(const char *date,
	if (hide.year) {
}
	/* Two-digit year? */
			date = approxidate_alpha(date-1, &tm, &now, &number, &touched);
	 * larger than that. We might also want to check that the
	 * ...but we also are going to feed the result to system
		int match = match_string(date, month_names[i]);
	if (tm->tm_hour < 0 || tm->tm_min < 0 || tm->tm_sec < 0)

				tm->tm_mon + 1, tm->tm_mday);
	if (mode->local)
			 Q_("%"PRItime" minute ago", "%"PRItime" minutes ago", diff), diff);

static const char *month_names[] = {
{
		die("Timestamp before Unix epoch: %"PRItime" %04d", time, tz);
		 * sure it is not later than ten days from now...
	{ NULL }
	{ "FST",   +1, 1, },	/* French Summer */
	/* Show "today" times as just relative times */
	void (*fn)(struct tm *, struct tm *, int *);
	return end;
static const struct typelen {
		if (tm->tm_mday < 0 && number < 32)

	/* Otherwise, just years. Centuries is probably overkill. */
		if (isdigit(c)) {
		else if (isdigit(c))
/*

				hide.date = hide.wday = 1;
	return 0; /* success */
	tm.tm_mday = -1;
	/*
		tm->tm_sec = 0;
{
	struct timeval tv;
} typelen[] = {
			tm->tm_year--;
	/* Do we want AM/PM depending on locale? */
	if (!tm_gmt)
		if (unsigned_add_overflows(time, minutes * 60))
			min = 99; /* random crap */
}
			*offset = hours*60 + minutes;
		date++;
	if (date_overflows(time))
		human_tz = local_time_tzoffset(now.tv_sec, &human_tm);
	}
 */
		strbuf_addf(buf, "%.3s %d ", month_names[tm->tm_mon], tm->tm_mday);

		return 1;
			unsigned int hours = num / 100;
 * This is like mktime, but without normalization of tm_wday and tm_yday.
			if (number > 1969 && number < 2100)
		/* hh:mm? */
	memset(&tm, 0, sizeof(tm));
		*touched = 1;
				wday:1,
		return 0;
	 */
	{ "hours", 60*60 },

 * Have we filled in any part of the time/date yet?
	{ "midnight", date_midnight },
}
	return n;
		if (months) {
	if (!strcmp(date, "never") || !strcmp(date, "false"))
			int match = match_multi_number(num, *end, date, end, tm, 0);

		return -1;
		struct timeval now;
		if (num >= 70) {
		char sign = (tz >= 0) ? '+' : '-';
			} else if (tm->tm_mday + 5 > human_tm->tm_mday) {
{
	do {
	}
		return 1;

{
	const char *name;
		for (i = 1; i < 11; i++) {
		else
		}
struct date_mode *date_mode_from_type(enum date_mode_type type)

				tm->tm_mon + 1,
		if (!match) {
	"Sundays", "Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays"
		return DATE_HUMAN;
				tm->tm_mon + 1,
};
			break;
		strbuf_addstr(timebuf, _("in the future"));
		return 0;
			die("Timestamp+tz too large: %"PRItime" +%04d",

		if (isatty(1) || pager_in_use())
		return DATE_ISO8601_STRICT;
	time(&now);

	    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
		hour = hour / 100;
	{ "noon", date_noon },

	offset = tm_to_time_t(localtime_r(&now, &tm)) - now;
	*num = 0;
			update_tm(tm, now, tl->length * *num);
		tm = time_to_tm(time, tz, &tmbuf);
	stamp = parse_timestamp(date, &end, 10);
			strbuf_addf(timebuf,
	diff = (diff + 12) / 24;
	minutes = tz < 0 ? -minutes : minutes;
	case '-':
			int off = timezone_names[i].offset;
}
	 * unless we already have a mday..
		if (!c)
		refuse_future = NULL;

	date_string(timestamp, offset, result);


}
	if (match_string(date, "AM") == 2) {

	tm.tm_sec = -1;
		strbuf_addf(&timebuf, "%04d-%02d-%02d %02d:%02d:%02d %+05d",
	diff = (diff + 30) / 60;
			if (match)
	case '/':
		show_date_relative(time, buf);
	time_t n;
	localtime_r(&n, tm);
 * Do we have a pending number at the end, or when
			format = "default";
		return timebuf.buf;
		*num = 0;
	int offset, eastwest;
		get_time(&now);
#include "cache.h"
	n = mktime(tm) - sec;
		int len = strlen(s->name);
	if (!strcmp(format, "local"))
			int match = match_multi_number(number, *end, date, end,
	 * Seconds since 1970? We trigger on that for any numbers with

/*
	int day = tm->tm_mday;
		tm->tm_hour = (tm->tm_hour % 12) + 0;

				   int *error_ret)
	/* We deal with number of days from here on */
	 * The logic here is two-fold:
			}
	{ "HDT",  -10, 1, },	/* Hawaii Daylight */
		}
	 * NOTE! We will give precedence to day-of-month over month or
/*
				 sb.buf, months);

		 * We take over "now" here, which usually translates
		if (match >= 3) {
/*
	for (;;) {
	}
	char *end;
			/* We screw up for number = 00 ? */
	offset = (offset % 60) + ((offset / 60) * 100);
			*touched = 1;
		 * the past, and by definition reflogs are the record
			else if (number > 69 && number < 100)
	{ "GST",  +10, 0, },	/* Guam Standard, USSR Zone 9 */
{
	do {




}
	if (mode->type == DATE_HUMAN) {
	return (tm->tm_year &
}
			format = p;

	if (number) {
int parse_date_basic(const char *date, timestamp_t *timestamp, int *offset)
				tz);

		return end;
				*num = i;


	*timestamp = stamp;
	static struct strbuf timebuf = STRBUF_INIT;
	}
 * is set in all the values.
	struct tm now_tm;


	/* Accept zero-padding only for small numbers ("Dec 02", never "Dec 0002") */
	int human_tz = -1;
	case '.':
		show_date_relative(time, &timebuf);
		tm = time_to_tm(0, 0, &tmbuf);
	 * Kathmandu, Nepal is UTC+5:45)
 * as in "Dec 6, 1992"
}
	}
/*
		if (*date == *str)
	 * IOW, 01 Apr 05 parses as "April 1st, 2005".
	/*
		int match = match_string(date, month_names[i]);
	} else if (time < -minutes * 60)

				 Q_("%"PRItime" year ago", "%"PRItime" years ago", years), years);
 * What value of "tz" was in effect back then at "time" in the
	"five", "six", "seven", "eight", "nine", "ten",
	return i;
		strbuf_addf(timebuf,
		return;
		tl++;
	case ':':
	/*
		else if ((c == '-' || c == '+') && isdigit(date[1]))

	case '/':

		min = strtoul(end + 1, &end, 10);
	case '.':
		if (match >= 3) {

