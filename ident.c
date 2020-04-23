 *
	 * the string, because will always hit the split->mail_end closing
	int a_len = a_end - a_begin;
		if (!value)
 */
static int canonical_name(const char *host, struct strbuf *out)
}
		}
static void copy_email(const struct passwd *pw, struct strbuf *email,
				name = git_author_name.buf;
		if (strict && ident_use_config_only
		name = getenv("GIT_AUTHOR_NAME");
	if (!strcmp(var, "committer.name")) {
				die(_("unable to auto-detect name (got '%s')"), name);
#else
		ident_config_given |= IDENT_MAIL_GIVEN;
	 */
	}
	/* success! */
	case WANT_COMMITTER_IDENT:
		strbuf_addstr(&git_committer_email, value);
		pw = &fallback;
			break;
}
			name = ident_default_name();
	struct hostent *he = gethostbyname(host);
			}
	 * never have a ">" in it.

		if (email && email[0]) {
		ident_config_given |= IDENT_NAME_GIVEN;

		}
	 * (name + '@' + hostname [+ '.' + domainname])
		committer_ident_explicitly_given |= IDENT_MAIL_GIVEN;
	while (len > 0) {
	char *src;
	}
		goto person_only;
		if (whose_ident == WANT_AUTHOR_IDENT && git_author_email.len)
{
	 * Copy the rest to the buffer, but avoid the special
		static struct passwd fallback;
	if (!mailname)
const char *fmt_name(enum want_ident whose_ident)
   "  git config --global user.name \"Your Name\"\n"
		if (!value)
	int min = a_len < b_len ? a_len : b_len;
				   &git_default_email, &default_email_is_bogus);
	}
		strbuf_addstr(&git_author_email, value);
}
}
	}

		c == ':' ||
	int b_len = b_end - b_begin;
		if (!crud(c))
	FILE *mailname;
	strbuf_release(&mailnamebuf);
		strbuf_trim(&git_default_name);
	 * Look from the end-of-line to find the trailing ">" of the mail
static int default_name_is_bogus;
			copy_email(xgetpwuid_self(&default_email_is_bogus),

			strbuf_addstr(name, w->pw_name + 1);
			 getenv("GIT_COMMITTER_EMAIL"),
	return fmt_ident(getenv("GIT_COMMITTER_NAME"),
	return 0;
}
#endif
		return;

	split->tz_begin = NULL;
	split->date_begin = cp;
/*
			name = pw->pw_name;
			status = 0;
		strbuf_addstr(&ident, " <");
		} else
		return 0;
	return 0;
static void set_env_if(const char *key, const char *value, int *given, int bit)

					fputs(_(env_hint), stderr);
	 * with commas.  Also & stands for capitalized form of the login name.

			strbuf_addch(name, toupper(*w->pw_name));

	return ident_is_sufficient(author_ident_explicitly_given);
		split->name_end = split->name_begin;
		ident_config_given |= IDENT_MAIL_GIVEN;
	}
	char *name = NULL;
			if (strict && default_name_is_bogus) {
		    && !(ident_config_given & IDENT_MAIL_GIVEN)) {
	errno = 0;
	if (!span)
static int ident_is_sufficient(int user_ident_explicitly_given)
	if (getenv("GIT_COMMITTER_NAME"))
static struct strbuf git_author_name = STRBUF_INIT;
	}
		if (!value)
			using_default = 1;
			if (parse_date(date_str, &ident) < 0)
		}
int git_ident_config(const char *var, const char *value, void *data)

	len = strlen(src);
#ifndef NO_GECOS_IN_PWENT
	if (getenv("GIT_AUTHOR_EMAIL"))
		}
		strbuf_addstr(&git_default_email, value);
	if (!strcmp(var, "user.email")) {
 * characters ('\n', '<' and '>') and remove crud at the end
static void add_domainname(struct strbuf *out, int *is_bogus)
			    && !(ident_config_given & IDENT_NAME_GIVEN)) {
	case WANT_BLANK_IDENT:
	for (i = 0; i < len; i++) {
void prepare_fallback_ident(const char *name, const char *email)
	size_t span;
	return ident.buf;
			break;
	/* Remove crud from the end.. */
		else {
	 */
	return git_default_name.buf;
	if (!split->name_end) {
	if (!strcmp(var, "author.name")) {

const char *ident_default_name(void)

}
		}
		if (!value)
		   &committer_ident_explicitly_given, IDENT_NAME_GIVEN);
{
	else if (canonical_name(buf, out) < 0) {
		return 0;
	const char *cp;
			die(_("name consists only of disallowed characters: %s"), name);
	 * in the email address.  Note that we are assuming the timestamp will

}
		strbuf_trim(&git_default_email);
static const char *ident_default_date(void)
			warning_errno("cannot read /etc/mailname");
	static struct strbuf ident = STRBUF_INIT;
		const char *email = getenv("EMAIL");
			strbuf_addstr(&git_default_email, email);
		} else if ((email = query_user_email()) && email[0]) {
		;
			if (strict) {
			 WANT_COMMITTER_IDENT,
}
			break;
			email = git_author_email.buf;
	strbuf_addstr(email, pw->pw_name);
{
}
 * ident.c
	}
person_only:
	if (!split->mail_end)
		if (strict && default_email_is_bogus) {
	 *
static void copy_gecos(const struct passwd *w, struct strbuf *name)
{
{
static int ident_config_given;
	}

static void strbuf_addstr_without_crud(struct strbuf *sb, const char *src)

	}
		c == '>' ||
static struct strbuf git_default_name = STRBUF_INIT;
			continue;
static int default_email_is_bogus;
}
	/*

			 flag);
		ident_config_given |= IDENT_NAME_GIVEN;
	if (want_name)
			split->mail_begin = cp + 1;
	hints.ai_flags = AI_CANONNAME;
		committer_ident_explicitly_given |= IDENT_MAIL_GIVEN;
			author_ident_explicitly_given |= IDENT_MAIL_GIVEN;
	 * characters '\n' '<' and '>' that act as delimiters on
		return; /* nothing to do */
const char *ident_default_email(void)

		strbuf_addstr(out, he->h_name);
			die(_("unable to auto-detect email address (got '%s')"), email);
	/*
 * create git identifier lines of the form "name <email> date"

		if (!value)
	if (line + len <= cp || (*cp != '+' && *cp != '-'))
			return config_error_nonbool(var);
int author_ident_sufficiently_given(void)
		email = getenv("GIT_AUTHOR_EMAIL");
	return set_ident(var, value);
		       int *is_bogus)
	return 0;
#include "config.h"
			/* Sorry, Mr. McDonald... */
#else
		   &author_ident_explicitly_given, IDENT_MAIL_GIVEN);
	}
N_("\n"
const char *git_author_info(int flag)

			fputs(_(env_hint), stderr);

 */
		strbuf_addstr(out, "(none)");
	if (getenv("GIT_COMMITTER_EMAIL"))
		return;	/* read from "/etc/mailname" (Debian) */
	char buf[HOST_NAME_MAX + 1];
	}
		c == '.' ||
		strbuf_reset(&git_author_email);
		if (date_str && date_str[0]) {
	switch (whose_ident) {
#endif
int split_ident_line(struct ident_split *split, const char *line, int len)

			 getenv("GIT_AUTHOR_DATE"),
	if (!add_mailname_host(email))
		return status;
		goto person_only;
	return ident_is_sufficient(committer_ident_explicitly_given);
	for (cp = line + len - 1; *cp != '>'; cp--)
	struct strbuf mailnamebuf = STRBUF_INIT;
				name = git_committer_name.buf;
	if (getenv("GIT_AUTHOR_NAME"))
	}

 */
}
	struct passwd *pw;
		email = getenv("GIT_COMMITTER_EMAIL");
		c == '\'';
	}
		else
			}
static int ident_use_config_only;
		ident_use_config_only = git_config_bool(var, value);
	}

   "\n"
	return 0;

	char *email = NULL;
int committer_ident_sufficiently_given(void)
			return config_error_nonbool(var);
		strbuf_addstr(out, buf);
	return git_default_email.buf;

		return cmp;
	 * bracket.
				if (using_default)

		if (!value)
	if (strchr(buf, '.'))
		ident_config_given |= IDENT_NAME_GIVEN;
	if (line + len <= cp)
	return fmt_ident(name, email, whose_ident, NULL,
			email = git_committer_email.buf;
		warning_errno("cannot get host name");
	sb->buf[sb->len] = '\0';

}
			split->name_end = cp + 1;
		if (*cp == '<') {
static int has_non_crud(const char *str)
			return config_error_nonbool(var);
		c = *src++;
const char *fmt_ident(const char *name, const char *email,
 * Copyright (C) 2005 Linus Torvalds
	struct addrinfo hints, *ai;
{
		return -1;
	split->tz_begin = cp;
	int want_date = !(flag & IDENT_NO_DATE);
}

{
		datestamp(&git_default_date);

#endif /* NO_IPV6 */
	}
			fputs(_(env_hint), stderr);
}
	/*
		       b->name_begin, b->name_end);

		strbuf_reset(&git_committer_name);
		}
	}
{
		strbuf_addf(out, "%s.(none)", buf);
		strbuf_addstr(&git_default_name, value);
#define IDENT_ALL_GIVEN (IDENT_NAME_GIVEN|IDENT_MAIL_GIVEN)
	set_env_if("GIT_COMMITTER_EMAIL", email,
{
}
static struct passwd *xgetpwuid_self(int *is_bogus)
		if (!name) {
		if (!crud(*str))
{
	for (cp = cp + 1; cp < line + len && isspace(*cp); cp++)
	return (user_ident_explicitly_given & IDENT_MAIL_GIVEN);
		;
   "\n"
		c == '\\' ||
#define IDENT_NAME_GIVEN 01
	if (!span)
		committer_ident_explicitly_given |= IDENT_MAIL_GIVEN;
	if (want_name) {
	strbuf_grow(sb, len);
	return 0;
	strbuf_reset(&git_default_date);
	return status;
	 * an identification line. We can only remove crud, never add it,
		strbuf_reset(&git_default_email);
			free((char *)email);
	if (!pw) {
	for (; *str; str++) {
			IDENT_STRICT | IDENT_NO_DATE);
			die(_("no email was given and auto-detection is disabled"));
static struct strbuf git_committer_name = STRBUF_INIT;
	for (cp = line; *cp && cp < line + len; cp++)
{
	fclose(mailname);

}
		if (ch != '&')
#define IDENT_MAIL_GIVEN 02
{
	/* Traditionally GECOS field had office phone numbers etc, separated
}
 * (e.g. reading from a reflog entry).
	while ((c = *src) != 0) {
   "to set your account\'s default identity.\n"
	if (xgethostname(buf, sizeof(buf))) {
		author_ident_explicitly_given |= IDENT_MAIL_GIVEN;

{
		return 0;
#else
	pw = getpwuid(getuid());
	return git_default_date.buf;
			if (whose_ident == WANT_AUTHOR_IDENT && git_author_name.len)
		break;
	 * Note that we will always find some ">" before going off the front of
		committer_ident_explicitly_given |= IDENT_NAME_GIVEN;
	if (!strcmp(var, "author.email")) {

		sb->buf[sb->len++] = c;

		if (is_bogus)
	if (!split->mail_begin)
			if (strict && ident_use_config_only
 * can still be NULL if the input line only has the name/email part
		fallback.pw_gecos = "Unknown";
{
}

		else if (whose_ident == WANT_COMMITTER_IDENT && git_committer_email.len)

		committer_ident_explicitly_given |= IDENT_NAME_GIVEN;
		switch (c) {
	 */
		author_ident_explicitly_given |= IDENT_MAIL_GIVEN;
		strbuf_addch(&ident, ' ');
static int committer_ident_explicitly_given;
static int author_ident_explicitly_given;


	}
	if (he && strchr(he->h_name, '.')) {
		goto person_only;
/*
#ifdef NO_GECOS_IN_PWENT
   "  git config --global user.email \"you@example.com\"\n"
			return 1;
		fallback.pw_name = "unknown";
#include "cache.h"
	int strict = (flag & IDENT_STRICT);
		status = 0;
	span = strspn(cp + 1, "0123456789");


	}

#ifndef WINDOWS
	}
	 * Make up a fake email address
{
}
	for (cp = split->date_end; cp < line + len && isspace(*cp); cp++)
	}
	if (!strcmp(var, "user.name")) {
int ident_cmp(const struct ident_split *a,
static struct strbuf git_committer_email = STRBUF_INIT;
		if (!name) {
	for (cp = split->mail_begin; cp < line + len; cp++)

	      const struct ident_split *b)
			return config_error_nonbool(var);
		author_ident_explicitly_given |= IDENT_NAME_GIVEN;
			strbuf_addch(&ident, '>');
		*is_bogus = 1;
			strbuf_addstr(&git_default_email, email);
static struct strbuf git_default_email = STRBUF_INIT;

	 * This can help in cases of broken idents with an extra ">" somewhere
	mailname = fopen_or_warn("/etc/mailname", "r");
		}
				die(_("empty ident name (for <%s>) not allowed"), email);
	strbuf_addstr_without_crud(&ident, email);
				die(_("no name was given and auto-detection is disabled"));
	if (!strcmp(var, "user.useconfigonly")) {
			split->mail_end = cp;

		break;
				fputs(_(env_hint), stderr);
		strbuf_addstr_without_crud(&ident, name);
		   const char *b_begin, const char *b_end)
	for (src = get_gecos(w); *src && *src != ','; src++) {
static int set_ident(const char *var, const char *value)
	if (!getaddrinfo(host, NULL, &hints, &ai)) {
	/* Remove crud from the beginning.. */
	for (cp = split->mail_begin - 2; line <= cp; cp--)
			strbuf_addstr(&ident, ident_default_date());
		copy_gecos(xgetpwuid_self(&default_name_is_bogus), &git_default_name);
#define get_gecos(struct_passwd) ((struct_passwd)->pw_gecos)
		if (ferror(mailname))
static struct strbuf git_author_email = STRBUF_INIT;
		}
		strbuf_addstr(&git_committer_name, value);
	return fmt_ident(getenv("GIT_AUTHOR_NAME"),
{
		int using_default = 0;
	split->name_begin = line;
	if ((*given & bit) || getenv(key))
	return  c <= 32  ||
		return 0;

		/* no human readable name */
		goto person_only;
	if (cmp)
   "*** Please tell me who you are.\n"
#ifndef NO_IPV6
	strbuf_reset(&ident);
   "Omit --global to set the identity only in this repository.\n"
		return 0;

	 * so 'len' is our maximum.
		if (!*name) {
			return config_error_nonbool(var);
		case '\n': case '<': case '>':
	int want_name = !(flag & IDENT_NO_NAME);
	if (strbuf_getline(&mailnamebuf, mailname) == EOF) {
		if (strict && !has_non_crud(name))
		src++;
		      b->mail_begin, b->mail_end);
		strbuf_reset(&git_default_name);
{
			}
}
	if (cmp)

static const char *env_hint =
			strbuf_addch(name, ch);

	split->date_end = split->date_begin + span;
	if (!(ident_config_given & IDENT_MAIL_GIVEN) && !git_default_email.len) {
static int crud(unsigned char c)
		fclose(mailname);
	split->tz_end = NULL;
		strbuf_release(&mailnamebuf);
	}
	if (!email) {
{

				die(_("invalid date format: %s"), date_str);
		if (!crud(c))

			committer_ident_explicitly_given |= IDENT_MAIL_GIVEN;
		freeaddrinfo(ai);
		return -1;
			 WANT_AUTHOR_IDENT,
	memset (&hints, '\0', sizeof (hints));
		return 0;

			struct passwd *pw;
}
}
#define get_gecos(ignored) "&"

		   &author_ident_explicitly_given, IDENT_NAME_GIVEN);
		return cmp;
{

	int cmp;
		return 0;
	size_t i, len;
		break;
	int status = -1;
static int add_mailname_host(struct strbuf *buf)
	cmp = memcmp(a_begin, b_begin, min);
{

	return pw;

	set_env_if("GIT_COMMITTER_NAME", name,
		}
	set_env_if("GIT_AUTHOR_EMAIL", email,
		name = getenv("GIT_COMMITTER_NAME");
		c = src[len-1];

	if (want_date) {

#endif
{
	}
	if (!strcmp(var, "committer.email")) {
		strbuf_addstr(&git_author_name, value);

		if (!isspace(*cp)) {

{
 * Copy over a string to the destination, but avoid special
		ident_config_given |= IDENT_MAIL_GIVEN;
		return status;
 *
		   &committer_ident_explicitly_given, IDENT_MAIL_GIVEN);

void reset_ident_date(void)

			break;
}

/*
	strbuf_addbuf(buf, &mailnamebuf);
	}
		committer_ident_explicitly_given |= IDENT_NAME_GIVEN;
static struct strbuf git_default_date = STRBUF_INIT;
		      enum want_ident whose_ident, const char *date_str, int flag)
			 getenv("GIT_AUTHOR_EMAIL"),
		strbuf_reset(&git_author_name);
}
   "\n"

	}
		if (*cp == '>') {
	set_env_if("GIT_AUTHOR_NAME", name,
			return config_error_nonbool(var);
   "Run\n"
			strbuf_addstr(out, ai->ai_canonname);
	*given |= bit;
 * to allow the caller to parse it.
	}
			break;
	strbuf_addch(email, '@');
	return a_len - b_len;
		author_ident_explicitly_given |= IDENT_NAME_GIVEN;
	unsigned char c;
	if (want_name) {
					git_committer_name.len)

	case WANT_AUTHOR_IDENT:
	add_domainname(email, is_bogus);
		if (ai && ai->ai_canonname && strchr(ai->ai_canonname, '.')) {
		author_ident_explicitly_given |= IDENT_NAME_GIVEN;
			 flag);
		}
 * Reverse of fmt_ident(); given an ident line, split the fields
			pw = xgetpwuid_self(NULL);

}
		--len;
{
 * Signal a success by returning 0, but date/tz fields of the result
		c == ',' ||


		c == '<' ||
	split->date_end = NULL;
{
		c == '"' ||
			 getenv("GIT_COMMITTER_DATE"),
		*is_bogus = 1;
static int buf_cmp(const char *a_begin, const char *a_end,
		email = ident_default_email();
	 * address, even though we should already know it as split->mail_end.

	span = strspn(cp, "0123456789");
   "\n");
		author_ident_explicitly_given |= IDENT_MAIL_GIVEN;
		strbuf_reset(&git_committer_email);
	}
			else if (whose_ident == WANT_COMMITTER_IDENT &&
	if (!git_default_date.len)
	if (!email) {
	}
	memset(split, 0, sizeof(*split));
	int status = -1;
		int ch = *src;
const char *git_committer_info(int flag)
{
	return (user_ident_explicitly_given == IDENT_ALL_GIVEN);
				fputs(_(env_hint), stderr);
	setenv(key, value, 0);
	return buf_cmp(a->name_begin, a->name_end,
}
	split->tz_end = split->tz_begin + 1 + span;
}
{
	 */
		c == ';' ||
	int cmp;
			*is_bogus = 1;
	if (!(ident_config_given & IDENT_NAME_GIVEN) && !git_default_name.len) {

	cmp = buf_cmp(a->mail_begin, a->mail_end,
{
		;
		}
	split->date_begin = NULL;
		}
