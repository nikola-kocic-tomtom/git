out:
			name = xstrfmt("%s/%s", *sub, dent->d_name);
		} else {
		} else if ( arg[1] == 'o' && arg[2] ) {
	}
			buf.buf[buf.len-2] == '\r') {
		if (stat(arg, &argstat) == -1) {
	return 1;
			nb = strtol(b, (char **)&b, 10);
		if ((dir = opendir(name)) == NULL) {
		}
			error_errno("cannot open mail %s", file);
			if (na != nb)
	int ret = -1;
static int populate_maildir_list(struct string_list *list, const char *path)
				usage(git_mailsplit_usage);
	int i;

			/* strtol advanced our pointers */
		if (S_ISDIR(argstat.st_mode))
	}
	int nr = 0, nr_prec = 4, num = 0;
	free(name);
 * file.
		if (f != stdin) {
{
	    !isdigit(colon[-1]) ||
			break; /* done with one message */
		struct stat argstat;
		if (ret < 0) {
static int split_mbox(const char *file, const char *dir, int allow_bare,
			b++;
		} else if ( arg[1] == 'h' ) {
		fclose(f);
				break;
			else {
				error("cannot split patches from stdin");
		}

		}
#include "builtin.h"
			}
{
		if ( arg[1] == 'd' ) {
			na = strtol(a, (char **)&a, 10);

	    !isdigit(colon[-2]) ||
		char *name;
				return 1;
	while (*a && *b) {
			strbuf_remove(&buf, 0, 1);
		const char *arg = *argp;


"git mailsplit [-d<prec>] [-f<n>] [-b] [--keep-cr] -o<directory> [(<mbox>|<Maildir>)...]";

	return ret;
		} else if ( arg[1] == 'b' && !arg[2] ) {
		}
	FILE *f = !strcmp(file, "-") ? stdin : fopen(file, "r");
		if (mboxrd && is_gtfrom(&buf))
		if (fwrite(buf.buf, 1, buf.len, output) != buf.len)
			num += (ret - nr);
		error_errno("cannot open mbox %s", file);
		}

		fclose(f);

}
		/* Backwards compatibility: if no -o specified, accept
			keep_cr = 1;

	FILE *output;
 *


	if (strtol(colon+3, NULL, 10) <= 90)
	}
	line += 5;
			usage(git_mailsplit_usage);
	}
	return (unsigned char)*a - (unsigned char)*b;
		int ret = 0;
		/* New usage: if no more argument, parse stdin */
			mboxrd = 1;
	int is_bare = !is_from_line(buf.buf, buf.len);
			nr = strtol(arg+2, NULL, 10);
	ret = skip;
			goto out;
		closedir(dir);
			if (f == stdin)
				/* empty stdin is OK */
	return ret;
}
	char *subs[] = { "cur", "new", NULL };
		if (strbuf_getwholeline(&buf, mbox, '\n')) {

			error("cannot read mbox %s", file);
	if (!f) {
		}
	} while (isspace(peek));
	}

	    !isdigit(colon[ 1]) ||
	}
			nr = ret;
			return 1;
		goto out;
		split_one(f, name, 1);
	while (*argp) {

	static const char *stdin_only[] = { "-", NULL };
	}
static int is_from_line(const char *line, int len)
	const char **argp;
			break;
			error("cannot split patches from %s", arg);
 * Totally braindamaged mbox splitter program.

			continue;
			free(name);

out:
			error_errno("cannot stat %s", arg);
			}
			argp = stdin_only;
	printf("%d\n", num);
		}
}
		free(name);
static struct strbuf buf = STRBUF_INIT;

			if (feof(mbox)) {
}
static int maildir_filename_cmp(const char *a, const char *b)
#include "string-list.h"
/*

	/* Ok, close enough */
	char *file = NULL;
		else
		name = xstrfmt("%s/%s", path, *sub);
		}
	if (buf->len < min)
	for (;;) {
		file_done = 1;
 * the Unix "From " line.  Write it into the specified
	    !isdigit(colon[ 2]))
	struct dirent *dent;
	if (f != stdin)
 */
	if (!isdigit(colon[-4]) ||

	return ngt && starts_with(buf->buf + ngt, "From ");
static int is_gtfrom(const struct strbuf *buf)

}
		return 0;
			stdin_only[0] = argp[0];
		   <mbox> <dir> or just <dir> */
{
		if (*--colon == ':')
		}
		if (arg[0] == '-' && arg[1] == 0) {
			die_errno("cannot write output");
	if (populate_maildir_list(&list, maildir) < 0)
{
		peek = fgetc(f);
				fclose(f);
		} else if (!strcmp(arg, "--keep-cr")) {
	}
		if (isdigit(*a) && isdigit(*b)) {
	/* Copy it out, while searching for a line that begins with

			a++;
			goto out;

			ret = split_mbox(arg, dir, allow_bare, nr_prec, nr);
	struct string_list list = STRING_LIST_INIT_DUP;
	 * "From " and having something that looks like a date format.
 * It just splits a mbox into a list of files: "0001" "0002" ..
			break;
	int status = 0;

		file = xstrfmt("%s/%s", maildir, list.items[i].string);
			if (*a != *b)
		}

		name = xstrfmt("%s/%0*d", dir, nr_prec, ++skip);
			error_errno("cannot opendir %s", name);
	int allow_bare = 0;
		if (strbuf_getwholeline(&buf, f, '\n')) {
		}
		char *name = xstrfmt("%s/%0*d", dir, nr_prec, ++skip);
 * already in buf[] -- normally that should begin with
			argp = stdin_only;
		switch (argc - (argp-argv)) {
		die_errno("cannot open output file '%s'", name);

		return 0;
		/* do flags here */
		      int nr_prec, int skip)
	for (sub = subs; *sub; ++sub) {
	if (f)
{

			goto out;
	if (is_bare && !allow_bare) {
	if (fd < 0)
			if (ret < 0) {

}
static int split_maildir(const char *maildir, const char *dir,
	const char *colon;
	if (strbuf_getwholeline(&buf, f, '\n')) {
			nr_prec = strtol(arg+2, NULL, 10);
				return na - nb;
			if (nr_prec < 3 || 10 <= nr_prec)
		while ((dent = readdir(dir)) != NULL) {
	for (i = 0; i < list.nr; i++) {

	const char *dir = NULL;
static int mboxrd;
	int nr_prec, int skip)
			break;
{
	fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0666);
	size_t ngt;
	list.cmp = maildir_filename_cmp;
			goto out;
 * so you can process them further from there.
	output = xfdopen(fd, "w");
 */
out:
			usage(git_mailsplit_usage);
		}
	ungetc(peek, f);
		return 0;
			die("unknown option: %s", arg);
			ret = split_mbox(arg, dir, allow_bare, nr_prec, nr);

	char *name = NULL;
		free(name);
		f = NULL;
{

	}
/* Called with the first line (potentially partial)
		fprintf(stderr, "corrupt mailbox\n");
	ret = skip;
			die_errno("cannot read mbox");
#include "cache.h"
			if (dent->d_name[0] == '.')
				ret = skip;

	}
			}
	int ret = -1;
#include "strbuf.h"
				status = 1;
			allow_bare = 1;
			dir = argp[0];
		f = fopen(file, "r");

			return 0;
		}
		if (!is_bare && is_from_line(buf.buf, buf.len))
	/* year */
		} else if ( arg[1] == '-' && !arg[2] ) {
			error_errno("cannot read mail %s", file);
		if (!keep_cr && buf.len > 1 && buf.buf[buf.len-1] == '\n' &&
static const char git_mailsplit_usage[] =
		nr = ret;

			string_list_insert(list, name);
		default:
	FILE *f = NULL;
		exit(1);
	int fd;

			continue;
	while (!file_done) {
	if ( !dir ) {
		goto out;
			return 1;
int cmd_mailsplit(int argc, const char **argv, const char *prefix)
		const char *arg = *argp++;

	}
	char **sub;


				continue;
			if (errno == ENOENT)
			strbuf_addch(&buf, '\n');

	}
	string_list_clear(&list, 1);
}

	return ret;
		if (peek == EOF) {
	for (;;) {


	return 0;
		free(name);
		file_done = split_one(f, name, allow_bare);

		if (arg[0] != '-')
		} else if ( arg[1] == 'f' ) {
	} else {
	DIR *dir;
				return (unsigned char)*a - (unsigned char)*b;
		return 0;

	return status;
			argp = stdin_only;
	size_t min = strlen(">From ");

static int keep_cr;
			long int na, nb;
			ret = split_maildir(arg, dir, nr_prec, nr);
{
		}
	colon = line + len - 2;
		if (!f) {
	ret = 0;

	int file_done = 0;
		free(file);
		case 1:
				error(_("empty mbox: '%s'"), file);
			break;


		if (colon < line)
static int split_one(FILE *mbox, const char *name, int allow_bare)
			dir = arg+2;
			goto out;
				continue;
	ngt = strspn(buf->buf, ">");


}
	if (len < 20 || memcmp("From ", line, 5))
			break;
			dir = argp[1];
			strbuf_setlen(&buf, buf.len-2);
	free(file);
	for (argp = argv+1; *argp; argp++) {
		case 2:
			argp++;	/* -- marks end of options */
		num += (ret - nr);
		/* empty stdin is OK */
		}
	int peek;
	do {
		else {

		} else if (!strcmp(arg, "--mboxrd")) {
	 */
		fclose(f);
		if ( !*argp )
	int ret = -1;



	fclose(output);
