 * available bytes, otherwise).
	DWORD read = 0;

}


static int enable_non_canonical(void)
		string_list_clear(&stty_restore, 0);
				p[1] = '[';
}
		return NULL;
		}
			"platform; reading line instead");
	if (warning_displayed || enable_non_canonical() < 0) {
	}
#endif
		 * We are most likely looking at an Escape sequence. Let's try
		return -1;
 * our `poll()` emulation calls `PeekNamedPipe()`, which seems to require
		for (i = 0; i < stty_restore.nr; i++)
		return -1;
{
	if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &read, NULL))
	strbuf_addstr(buf, res);
}
			return;
		int i;


				break;
#else
	if (!input_fh)
			if (!p)

		char *p, *eol;
		 * half a second when we know that the sequence is complete.
		if (run_command(&cp) == 0)
	if (!SetConsoleMode(hconin, cmode & ~bits)) {
			string_list_append(&stty_restore, "-ignbrk");

				hashmap_add(&sequences, &e->entry);
static struct termios old_term;
		 * Start by replacing the Escape byte with ^[ */

static struct string_list stty_restore = STRING_LIST_INIT_DUP;
	return !!hashmap_get_from_hash(&sequences, strhash(sequence), sequence);
			p++;
		for (eol = p = buf.buf; *p; p = eol + 1) {

	const char *res;
		warning_displayed = 1;

#include "hashmap.h"

{
{
	tcsetattr(term_fd, TCSAFLUSH, &old_term);
}
 * To avoid depending on ncurses or other platform-specific libraries, we rely
	int ch;

	strbuf_addch(buf, ch);
	return disable_bits(ICANON | ECHO);
		restore_term();
		argv_array_push(&cp.args, "stty");
	}

	FILE *input_fh, *output_fh;

#include "compat/terminal.h"
	restore_term();
	input_fh = fopen(INPUT_PATH, "r" FORCE_TEXT);
		hashmap_init(&sequences, (hashmap_cmp_fn)sequence_entry_cmp,
			return 0;
	fclose(input_fh);
	}
			argv_array_push(&cp.args, "-echo");
			      const struct escape_sequence_entry *e2,

		fclose(input_fh);
	close(term_fd);
	if (!echo && disable_echo()) {
#elif defined(GIT_WINDOWS_NATIVE)
}
 * input has more characters, as the default of Git for Windows is to start the
 * The `is_known_escape_sequence()` function returns 1 if the passed string

}

	SetConsoleMode(hconin, cmode);
	if (!read) {
			     NULL, 0);
		strbuf_splice(buf, buf->len - 1, 1, "^[", 2);



error:
		struct child_process cp = CHILD_PROCESS_INIT;
	int r;
static int disable_echo(void)
static void restore_term(void);
{
{
#define INPUT_PATH "CONIN$"
		}


 * Override `getchar()`, as the default implementation does not use
#include "git-compat-util.h"
		use_stty = 0;


	return ch;
	if (ch == '\033' /* ESC */) {

		 * within that time.
	char sequence[FLEX_ARRAY];
 * corresponds to an Escape sequence that the terminal capabilities contains.

		return;
				break;
#include "string-list.h"
			strbuf_setlen(&buf, 0);
		 * Query the terminal capabilities once about all the Escape
 * go our merry ways from here.

	return disable_bits(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
				FLEX_ALLOC_MEM(e, sequence, p, comma - p);
};
	fflush(output_fh);
 * `ReadFile()` to be called first to work properly (it only reports 0
				return 0;
int read_key_without_echo(struct strbuf *buf)

			string_list_append(&stty_restore, "^c");

int read_key_without_echo(struct strbuf *buf)


		return NULL;
#endif
}
static int enable_non_canonical(void)
	return strcmp(e1->sequence, keydata ? keydata : e2->sequence);
 */
#define FORCE_TEXT
}

static HANDLE hconin = INVALID_HANDLE_VALUE;
}
		initialized = 1;
		/* `stty` could not be executed; access the Console directly */
			ch = getchar();
	}
	sigchain_push_common(restore_term_on_signal);
		struct strbuf buf = STRBUF_INIT;
		 * to read more bytes, waiting at most half a second, assuming
	return 0;
		argv_array_push(&cp.args, "stty");
		/*
		if (bits & ENABLE_ECHO_INPUT) {

		CloseHandle(hconin);
 * So let's just override `getchar()` with a version backed by `ReadFile()` and
	term_fd = -1;
			if (ch == EOF)

	fputs(prompt, output_fh);

		 *

	return getpass(prompt);
}
static int mingw_getchar(void)
 * on the presence of the `infocmp` executable to do the job for us (failing

}
		 * sequences it knows about, so that we can avoid waiting for
	if (term_fd < 0)
 * Bash in a MinTTY, which uses a named pipe to emulate a pty, in which case


	}
			warning_displayed = 1;
#define FORCE_TEXT "t"
char *git_terminal_prompt(const char *prompt, int echo)
	return 0;
			argv_array_push(&cp.args, "-icanon");
	}
	fclose(output_fh);

		struct child_process cp = CHILD_PROCESS_INIT;
			if (!*eol)
	if (use_stty) {
	return disable_bits(ECHO);
#define getchar mingw_getchar

#include "run-command.h"

		warning("reading single keystrokes not supported on this "
}

	static int warning_displayed;
{
				struct escape_sequence_entry *e;
		error("Unexpected 0 read");

static int disable_bits(tcflag_t bits)
static void restore_term(void)
		 */
		fflush(output_fh);
	}

static DWORD cmode;
static void restore_term(void)
		return;
			if (poll(&pfd, 1, 500) < 1)
#endif
static int disable_echo(void)


	GetConsoleMode(hconin, &cmode);
	if (!initialized) {
	term_fd = -1;

				"this platform; reading line instead");
		if (bits & ENABLE_PROCESSED_INPUT) {
	if (!warning_displayed) {
		hconin = INVALID_HANDLE_VALUE;

		}
	output_fh = fopen(OUTPUT_PATH, "w" FORCE_TEXT);
		return NULL;
{
	}

		return EOF;
char *git_terminal_prompt(const char *prompt, int echo)
	static int initialized;

		argv_array_pushl(&cp.args, "infocmp", "-L", "-1", NULL);
	    FILE_SHARE_READ, NULL, OPEN_EXISTING,
	ch = getchar();
		}

		while (!is_known_escape_sequence(buf->buf)) {
 *
}

}
		return strbuf_getline(buf, stdin);
	if (r == EOF)
	return disable_bits(ENABLE_ECHO_INPUT);
	strbuf_reset(buf);
		/*
			struct pollfd pfd = { .fd = 0, .events = POLLIN };
static int is_known_escape_sequence(const char *sequence)
		struct child_process cp = CHILD_PROCESS_INIT;
#include "strbuf.h"
{
		return EOF;
	hconin = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE,


	if (hconin == INVALID_HANDLE_VALUE)
		if (stty_restore.nr == 0)
			strbuf_addch(buf, ch);

			argv_array_push(&cp.args, stty_restore.items[i].string);
	sigchain_push_common(restore_term_on_signal);
static int disable_bits(DWORD bits)
{
		if (bits & ENABLE_LINE_INPUT) {
				char *comma = memchr(p, ',', eol - p);
	struct hashmap_entry entry;
		putc('\n', output_fh);
			      const struct escape_sequence_entry *e1,
 *
#define OUTPUT_PATH "/dev/tty"
			p = strchr(p, '=');
 *
	unsigned char ch;
{

	}
 * silently if the program is not available or refused to run).
}
	if (tcgetattr(term_fd, &t) < 0)
		return 0;
#include "sigchain.h"

	old_term = t;
		return EOF;
#ifdef HAVE_DEV_TTY

		fclose(input_fh);
	struct termios t;

 * `ReadFile()`.
	if (use_stty) {
		fclose(output_fh);
/*
						   strhash(e->sequence));
	raise(sig);
	return buf.buf;
{
static int sequence_entry_cmp(const void *hashmap_cmp_fn_data,
	if (ch == EOF) {
			warning("reading single keystrokes not supported on "
				hashmap_entry_init(&e->entry,
{
		goto error;


	static int warning_displayed;
	static struct strbuf buf = STRBUF_INIT;
			string_list_append(&stty_restore, "icanon");

 */
		run_command(&cp);
		 * that the sequence is complete if we did not receive any byte
	t.c_lflag &= ~bits;
			argv_array_push(&cp.args, "intr");
static int use_stty = 1;

		return;
		if (pipe_command(&cp, NULL, 0, &buf, 0, NULL, 0))
#define INPUT_PATH "/dev/tty"
			if (starts_with(p, "\\E")) {

#ifndef FORCE_TEXT
static void restore_term_on_signal(int sig)
/*
			argv_array_push(&cp.args, "ignbrk");
	r = strbuf_getline_lf(&buf, input_fh);
	if (!output_fh) {
	if (!tcsetattr(term_fd, TCSAFLUSH, &t))
			eol = strchrnul(p, '\n');
	strbuf_reset(buf);
 * This poses a problem when we want to see whether the standard

{

	return 0;
	CloseHandle(hconin);

	}
#if defined(HAVE_DEV_TTY) || defined(GIT_WINDOWS_NATIVE)
	static struct hashmap sequences;
#define OUTPUT_PATH "CONOUT$"
	if (!echo) {
	sigchain_pop(sig);

	close(term_fd);
		}
			string_list_append(&stty_restore, "echo");
	term_fd = open("/dev/tty", O_RDWR);


	res = getpass("");

		if (!warning_displayed) {
static int term_fd = -1;
				break;
	if (hconin == INVALID_HANDLE_VALUE)
			string_list_append(&stty_restore, "intr");
	hconin = INVALID_HANDLE_VALUE;

	if (!res)
			argv_array_push(&cp.args, "");
		return EOF;

	restore_term();
				p[0] = '^';
{
struct escape_sequence_entry {
{
{
	}
		}
	return -1;
	    FILE_ATTRIBUTE_NORMAL, NULL);
	}
			      const void *keydata)
	restore_term();
}
			}
		return NULL;
