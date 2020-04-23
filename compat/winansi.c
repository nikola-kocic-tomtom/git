
			case 42: /* Green */
 to implement any codes that are not used by git.
				0, KEY_READ, &hkey)) {
			!wcsstr(name, L"-pty"))
	WriteConsoleW(console, wbuf, wlen, &dummy, NULL);
	return hresult;
static int is_console(int fd)
		console = duplicate;
			case 6:  /* fast blink */
	/* initialize attributes */
			continue;

						write_console(buffer + start,
			case 47: /* White */

	FillConsoleOutputCharacterA(console, ' ',
	/*
		hconsole1 = swap_osfhnd(1, duplicate_handle(hwrite));
				memmove(buffer, buffer + end, bytes - end);
		 * attached to stdout/stderr, i.e. we will not need to output
				attr &= ~FOREGROUND_ALL;
{
	/* only called from console_thread, so a static buffer will do */
	case 'K':
	 * (because it has been associated with it).
	POBJECT_NAME_INFORMATION nameinfo = (POBJECT_NAME_INFORMATION) buffer;
			case 4:  /* underline */
		die("Could not initialize winansi pipe name");
				break;
	while (1) {
static void detect_msys_tty(int fd)
		bytes += end;

	 */
	dup2(new_fd, fd);

	case 'm':
	/* remember if non-ascii characters are printed */
			case 7:  /* negative */
	/* get pipe name */
					set_attr(c, params, parampos + 1);
				attr |= FOREGROUND_RED;
	WCHAR FaceName[LF_FACESIZE];
	DECLARE_PROC_ADDR(kernel32.dll, BOOL, GetCurrentConsoleFontEx,
enum {


	if (hwrite == INVALID_HANDLE_VALUE)
		/*
#endif
		if (attr & FOREGROUND_RED)
		break;
	default:
	DWORD dummy; /* Needed for Windows 7 (or Vista) regression */
			/* exit if pipe has been closed or disconnected */
			case 22: /* normal */
{
#include <winternl.h>
		sbi.dwSize.X - sbi.dwCursorPosition.X, sbi.dwCursorPosition,
		return;
	/* check if either stdout or stderr is a console output screen buffer */
			case 31: /* Red */
	return duplicate;
	if (GetFileType(h) != FILE_TYPE_PIPE)
	if (atexit(winansi_exit))

	/* don't bother if output was ascii only */
	 *
	COORD dwFontSize;
	assert((fd == 1) || (fd == 2));
				break;
		WriteConsoleW(console, msg, wcslen(msg), &dummy, NULL);
			case 8:  /* conceal */
			case 44: /* Blue */
	UINT FontWeight;
				attr |= BACKGROUND_GREEN;
/*

				write_console(buffer + start, end - start);

{
#ifdef __MINGW32__


	 *
	 * call SetStdHandle(), so we don't need to worry about that.
		/* scan the bytes and handle ANSI control codes */

		die_errno("atexit(winansi_exit) failed");

				break;
				attr |= BACKGROUND_RED | BACKGROUND_BLUE;

	 * Note that we need to update the cached console handle to the
		break;
				attr |= BACKGROUND_GREEN | BACKGROUND_BLUE;
	WCHAR NameBuffer[FLEX_ARRAY];
		}
	 * Use stock dup2() to re-bind fd to the new handle.  Note that
	} else if (!GetConsoleScreenBufferInfo(hcon, &sbi))
		hconsole2 = swap_osfhnd(2, duplicate_handle(hwrite));
		if (!ReadFile(hread, buffer + end, BUFFER_SIZE - end, &bytes,
				attr |= FOREGROUND_INTENSITY;
				attr |= COMMON_LVB_UNDERSCORE; */

			case 24: /* no underline */
			case 36: /* Cyan */

			case 38: /* Unknown */
			switch (params[i]) {
		return 0;
	/* schedule cleanup routine */
	FlushFileBuffers(hwrite);
	 * duplicated one because the dup2() call will implicitly close
		if (attr & BACKGROUND_BLUE)
		return;
		return;
	SetConsoleTextAttribute(console, attributes);
	DWORD mode;
	return ret == (HANDLE)-2 ? INVALID_HANDLE_VALUE : ret;
	}
		return;
	HANDLE ret;
				break;
					params[parampos] *= 10;
	 */
	int ret = dup2(oldfd, newfd);
				/* We don't have blink, but we do have
{
	_flushall();

				break;
				break;
		CONSOLE_FONT_INFOEX cfi;
		/* This could probably use a bitmask
}
			/* move remaining bytes to the front */
#undef dup2
				break;

 */
				attr |= (plain_attr & BACKGROUND_ALL);
typedef struct _OBJECT_NAME_INFORMATION
	 * Note that dup2() when given target := {0,1,2} will also
	 * It is because of this implicit close() that we created the
void winansi_init(void)
	if (hthread == INVALID_HANDLE_VALUE)
	}
				} else {
		/* check if stdin / stdout / stderr are MSYS2 pty pipes */
					state = ESCAPE;
					/*
				break;
	/* signal console thread to exit */

	GetConsoleScreenBufferInfo(console, &sbi);
	}

	wchar_t name[32];
	/* redirect stdout / stderr to the pipe */
	con2 = is_console(2);

		sbi.wAttributes = 0;
			/* print remaining complete UTF-8 sequences */
				break;

					parampos = 0;
		attr = plain_attr = sbi.wAttributes;
	/* Also compute console bit for fd 0 even though we don't need the result here. */
				attr &= ~FOREGROUND_INTENSITY;
					GetLastError() == ERROR_BROKEN_PIPE)
	errno = err_win_to_posix(GetLastError());
				break;
	/* check if its a device (i.e. console, printer, serial port) */
				attr &= ~FOREGROUND_ALL;
		if (attr & FOREGROUND_BLUE)
				else if (end - 1 > start &&

#define BUFFER_SIZE 4096
				break;
	name[nameinfo->Name.Length / sizeof(*name)] = 0;

				break;
	/* flush all streams */
				attr &= ~FOREGROUND_ALL;
		wchar_t *err = L"[invalid]";
#include <wingdi.h>
	if (negative) {
					BACKGROUND_GREEN |
	 * originally associated handle.  It will open a new fd=1 and
		detect_msys_tty(0);
		if (GetCurrentConsoleFontEx(console, 0, &cfi))
static HANDLE console;
	fd_is_interactive[fd] |= FD_MSYS;
	switch (func) {
{
				attr &= ~BACKGROUND_ALL;
				}

				attr &= ~BACKGROUND_INTENSITY;
		die_lasterr("CreateNamedPipe failed");
			case 30: /* Black */

		 * use black as foreground color.
static HANDLE duplicate_handle(HANDLE hnd)
				attr &= ~BACKGROUND_ALL;
		while (end < bytes) {
	TEXT = 0, ESCAPE = 033, BRACKET = '['
			c = buffer[end++];
	return 1;



				   background intensity */
	close(new_fd);
				/* Unsupported code */

		console = hcon;
#define FD_SWAPPED 0x2
			L"doesn\'t support Unicode. If you experience strange "
		 */
				negative = 1;
	 * the original one.
	if (wlen != len)
	if (wlen < 0) {
	if (!non_ascii_used)
	return 0;
	WaitForSingleObject(hthread, INFINITE);
			L"characters in the output, consider switching to a "
			HANDLE, BOOL, PCONSOLE_FONT_INFOEX);
		set_console_attr();
				negative = 0;
	die_errno(fmt, params);
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
	if (hcon == INVALID_HANDLE_VALUE)
			case 25: /* no blink */
	if (!con1 && !con2) {
	if (hread == INVALID_HANDLE_VALUE)
	warn_if_raster_font();
	} else {


				break;
#endif
	is_console(0);
HANDLE winansi_get_osfhandle(int fd)
				break;
		erase_in_line();
static void erase_in_line(void)
						buffer[end - 3] >= 0xf0)
 * do).
	UINT FontFamily;
				break;
	 * copy of the original.


	}
				/* Unsupported */
				break;

	if (!ret && newfd >= 0 && newfd <= 2)
			case 21: /* double underline */
						state = TEXT;
			case 33: /* Yellow */
}
					end -= 3;
				break;
		return 0;


	}
				}
#if defined(_MSC_VER)
	if (!fd) {
	WORD attributes = attr;
	 */
	if (GetFileType(hcon) != FILE_TYPE_CHAR)
	if ((!wcsstr(name, L"msys-") && !wcsstr(name, L"cygwin-")) ||
	HANDLE hresult, hproc = GetCurrentProcess();
	va_end(params);
				/* Wikipedia says this flag does nothing */
					 * bounds
#undef NOGDI
				if (c >= '0' && c <= '9') {

#if !defined(__MINGW64_VERSION_MAJOR) || __MINGW64_VERSION_MAJOR < 5
}
					 * next parameter, bail out if out of
				break;
		attributes &= ~BACKGROUND_ALL;
	 * because the original will get closed when we dup2().
		if (attr & BACKGROUND_GREEN)
static void winansi_exit(void)
					end--;
}
		HKEY hkey;
	 * There are obviously circumstances under which _get_osfhandle()
{
}
			case ESCAPE:
				attr |= FOREGROUND_GREEN;
	 * Check if this could be a MSYS2 pty pipe ('msys-XXXX-ptyN-XX')
	HANDLE hcon;
	 */
	DWORD bytes;
int winansi_dup2(int oldfd, int newfd)
				/* Furthermore, mingw doesn't define this flag

	/*
	DWORD nFont;
				break;
		}
		if (attr & BACKGROUND_RED)
 This file is git-specific. Therefore, this file does not attempt

				attr &= ~BACKGROUND_ALL;
			case 45: /* Magenta */
				break;
}
				attr |= FOREGROUND_GREEN | FOREGROUND_BLUE;
	ret = (HANDLE)_get_osfhandle(fd);
			}
					 */
		 * This code path is only reached if there is no console
				if (c == ESCAPE) {
#undef isatty
#define FD_MSYS    0x4
static void die_lasterr(const char *fmt, ...)
{


					/*
		return;
static DWORD WINAPI console_thread(LPVOID unused)
	CloseHandle(hread);
		if (ERROR_SUCCESS == RegOpenKeyExA(HKEY_CURRENT_USER, "Console",
	CloseHandle(hwrite);
#endif
			RegQueryValueExA(hkey, "FontFamily", NULL, NULL,
}
				break;

}
				/* attr &= ~COMMON_LVB_UNDERSCORE; */
			if (GetLastError() == ERROR_PIPE_NOT_CONNECTED ||
			case 48: /* Unknown */
		return fd_is_interactive[fd] != 0;
			case 34: /* Blue */
		setvbuf(stderr, NULL, _IONBF, BUFSIZ);
{
	 * call DuplicateHandle() on the handle associated with new_fd.
				attr &= ~FOREGROUND_ALL;
	/* cleanup handles... */
	if (swprintf(name, ARRAY_SIZE(name) - 1, L"\\\\.\\pipe\\winansi%lu",
				negative = 0;
	hthread = CreateThread(NULL, 0, console_thread, NULL, 0, NULL);
	/* wait for console thread to copy remaining data */
};
	if (fd == 2 && (fd_is_interactive[2] & FD_SWAPPED))
		detect_msys_tty(2);

		non_ascii_used = 1;
static HANDLE swap_osfhnd(int fd, HANDLE new_handle)
				attr &= ~BACKGROUND_ALL;
	if (console == handle)
}

	if (con2)
				attr |= FOREGROUND_RED | FOREGROUND_GREEN;

		negative = 0;


	 * or a cygwin pty pipe ('cygwin-XXXX-ptyN-XX')
/*
}
	/* check if its a handle to a console output screen buffer */
			0 : fd_is_interactive[oldfd];
				break;
					if (parampos >= MAX_PARAMS)
	PWSTR name;
	hcon = (HANDLE) _get_osfhandle(fd);
					FOREGROUND_BLUE;
			case 27: /* positive */
	int new_fd = _open_osfhandle((intptr_t)new_handle, O_BINARY);
			attributes |= FOREGROUND_BLUE;
				break;
			(long) (intptr_t) hnd);

					start = end;
	va_list params;

			/* check for incomplete UTF-8 sequences and fix end */
				/* parse [0-9;]* into array of parameters */
					 * end of escape sequence, change
 ANSI codes used by git: m, K
		} else {
		PIPE_TYPE_BYTE | PIPE_WAIT, 1, BUFFER_SIZE, 0, 0, NULL);
				attr |= (plain_attr & FOREGROUND_ALL);
static HANDLE hconsole1, hconsole2;
				break;
				/* Unsupported */
#include <ntstatus.h>
	 * clearly an invalid handle value that we can just work around this
				break;
		   instead of a series of ifs */

					/* print text seen so far */


		     GetCurrentProcessId()) < 0)
		 * any text to any console, therefore we might just as well
	return ret;
	/* Create a temp fd associated with the already open "new_handle". */
#define FOREGROUND_ALL (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
		return;
				if (buffer[end -1] >= 0xc0)
static void set_attr(char func, const int *params, int paramlen)
		die_lasterr("DuplicateHandle(%li) failed",
	if (!(fontFamily & TMPF_TRUETYPE)) {
			case 2:  /* faint */
				attr |= BACKGROUND_RED |
			attributes |= BACKGROUND_BLUE;
		}
			return 0;
	/*
{
			/* ignore other errors */
			case 37: /* White */
				attr &= ~BACKGROUND_ALL;
	name = nameinfo->Name.Buffer;
				attr = plain_attr;
 * startup (and ignore any pipe redirection we internally
	if (fd == 2)
		fd_is_interactive[fd] |= FD_CONSOLE;
			}
							end - 1 - start);
				attr &= ~BACKGROUND_ALL;
					parampos++;

				attr &= ~FOREGROUND_ALL;
		&dummy);
		if (!GetConsoleMode(hcon, &mode))
				/* continue if "\033[", otherwise bail out */
#define ObjectNameInformation 1
int winansi_isatty(int fd)

{
	/*
{
					FOREGROUND_GREEN |
	if (!NT_SUCCESS(NtQueryObject(h, ObjectNameInformation,
		setvbuf(stderr, NULL, _IONBF, BUFSIZ);
typedef struct _CONSOLE_FONT_INFOEX {
	if (fd == 1 && (fd_is_interactive[1] & FD_SWAPPED))
			case 46: /* Cyan */
				} else if (c == ';') {

				else if (end - 2 > start &&
#else
	int params[MAX_PARAMS];
				attr |= BACKGROUND_RED | BACKGROUND_GREEN;
		WriteConsoleW(console, err, wcslen(err), &dummy, NULL);
					params[parampos] += c - '0';
	HANDLE duplicate = duplicate_handle(handle);
		initialized = 1;
	static wchar_t wbuf[2 * BUFFER_SIZE + 1];
				attr |= BACKGROUND_RED;
				break;


					 */
}
}
}
static void warn_if_raster_font(void)
	int wlen = xutftowcsn(wbuf, (char*) str, ARRAY_SIZE(wbuf), len);


				break;

static HANDLE hthread, hread, hwrite;
	static int initialized = 0;
			case 41: /* Red */

			if (end < bytes)
#define FD_CONSOLE 0x1
	 * Create a copy of the original handle associated with fd
#include "win32/lazyload.h"
				attr |= FOREGROUND_BLUE;
			case 49: /* reset */
			case 35: /* Magenta */
		cfi.cbSize = sizeof(cfi);
				attr &= ~FOREGROUND_ALL;
{
				attr |= BACKGROUND_INTENSITY;
#include "../git-compat-util.h"
				NULL)) {
			case 40: /* Black */
				attr |= FOREGROUND_RED | FOREGROUND_BLUE;

			DWORD size = sizeof(fontFamily);

#define BACKGROUND_ALL (BACKGROUND_RED | BACKGROUND_GREEN | BACKGROUND_BLUE)
#ifdef DETECT_MSYS_TTY
	/* check if fd is a pipe */
			attributes |= FOREGROUND_RED;

				break;
	con1 = is_console(1);
	HANDLE h = (HANDLE) _get_osfhandle(fd);
 * call isatty(1 or 2) to see if the instance is interactive
	CloseHandle(hthread);
				attr &= ~BACKGROUND_ALL;
				break;
		/* print remaining text unless parsing an escape sequence */

		const wchar_t *msg = L"\nWarning: Your console font probably "


			fontFamily = cfi.FontFamily;
	CONSOLE_SCREEN_BUFFER_INFO sbi;
	/* start console spool thread on the pipe's read end */
 * Copyright 2008 Peter Harris <git@peter.is-a-geek.org>
}
#define MAX_PARAMS 16
#include "win32.h"
	DisconnectNamedPipe(hwrite);
		for (i = 0; i < paramlen; i++) {
			attributes |= FOREGROUND_GREEN;
			RegCloseKey(hkey);
static int non_ascii_used = 0;
	 * and return the correct value for invalid handles.
		/* pre-Vista: check default console font in registry */
		return 0;

					/* then start parsing escape sequence */
 * We lie and give results for what the descriptor WAS at
/*
		return hconsole1;
		die_lasterr("CreateThread(console_thread) failed");
			attributes |= BACKGROUND_RED;


		attributes &= ~FOREGROUND_ALL;
#ifdef DETECT_MSYS_TTY
*/
				attr &= ~FOREGROUND_ALL;
 */
	va_start(params, fmt);
	/* get OS handle of the file descriptor */
	}
			case BRACKET:
		start = end = 0;
		}

	int start, end = 0, c, parampos = 0, state = TEXT;
			/* all data has been consumed, mark buffer empty */
		die_lasterr("CreateFile for named pipe failed");
			case 39: /* reset */
	DWORD dummy;
	 * returns (HANDLE)-2. This is not documented anywhere, but that is so
			end = 0;
				attr &= ~BACKGROUND_ALL;
				break;
	UNICODE_STRING Name;
			case 0: /* reset */

				break;
static WORD attr;
				break;
	ULONG cbSize;
				state = (c == BRACKET) ? BRACKET : TEXT;
{

	 */

	if (INIT_PROC_ADDR(GetCurrentConsoleFontEx)) {
	/* GetCurrentConsoleFontEx is available since Vista */
	if (fd >= 0 && fd <= 2)
static int fd_is_interactive[3] = { 0, 0, 0 };
	}
	if (!console)
	/* Close the temp fd.  This explicitly closes "new_handle"
					start = end - 1;
		if (state == TEXT && end > start) {
			switch (state) {
	/* check if the console font supports unicode */
		fd_is_interactive[newfd] = oldfd < 0 || oldfd > 2 ?
		if (attr & FOREGROUND_GREEN)
					if (end - 1 > start)

	fd_is_interactive[fd] |= FD_SWAPPED;
 * Wrapper for isatty().  Most calls in the main git code
}
					memset(params, 0, sizeof(params));
 * and should: be colored, show progress, paginate output.
	if (!initialized) {
				break;
static int negative;
static void set_console_attr(void)
			L"TrueType font such as Consolas!\n";
	if (fd == 2)
	DWORD fontFamily = 0;
static void write_console(unsigned char *str, size_t len)
			DUPLICATE_SAME_ACCESS))
			attributes |= BACKGROUND_GREEN;
 * to the console. Allows spawn / exec to pass the console to the next process.
{
}
} CONSOLE_FONT_INFOEX, *PCONSOLE_FONT_INFOEX;
#endif
			case 5:  /* slow blink */


	}

		/* read next chunk of bytes from the pipe */
#endif
			case 3:  /* italic */
	/* create a named pipe to communicate with the console thread */

				break;
	BYTE buffer[1024];
			case TEXT:
{
			if (end > start)
#include <winreg.h>
	/* write directly to console */
/*
	unsigned char buffer[BUFFER_SIZE];
				attr &= ~FOREGROUND_ALL;
	ULONG result;
	if (con1)

	if (!DuplicateHandle(hproc, hnd, hproc, &hresult, 0, TRUE,
				break;
			case 43: /* Yellow */
	hwrite = CreateNamedPipeW(name, PIPE_ACCESS_OUTBOUND,
		DWORD dummy;
	CONSOLE_SCREEN_BUFFER_INFO sbi;
 * Returns the real console handle if stdout / stderr is a pipe redirecting
					BACKGROUND_BLUE;
			}
			case 1: /* bold */
			case 28: /* reveal */
	if (fd >= 0 && fd <= 2)
	return isatty(fd);
	/* convert utf-8 to utf-16 */
 */
		return;
			default:
		detect_msys_tty(1);
	int i;
	HANDLE handle = (HANDLE)_get_osfhandle(fd);
						buffer[end - 2] >= 0xe0)
		return hconsole2;
static WORD plain_attr;
				attr |= FOREGROUND_RED |
	 * this will implicitly close(1) and close both fd=1 and the
					(LPVOID) &fontFamily, &size);
					state = TEXT;
			buffer, sizeof(buffer) - 2, &result)))
				break;
		}
	int con1, con2;
				attr |= BACKGROUND_BLUE;

			end = bytes - end;
					 * console attributes
{
			case 32: /* Green */

		/* Unsupported code */
	hread = CreateFileW(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
			if (buffer[end - 1] >= 0x80) {
{
					end -= 2;

		break;
