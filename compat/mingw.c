	/* initialize critical section for waitpid pinfo_t list */
	return ret;
	}
			FILE_ATTRIBUTE_NORMAL, NULL);
segment_start:
		 * specific errors, which are values beginning at 38 or so.
				}

				} else
		errno = EINVAL;
		/* ignore errors here; open() will report them */
			return 0;
#define GETENV_MAX_RETAIN 64
		wlen = xutftowcs(p, deltaenv[i], wdeltaenv + delta_size - p);
			if (!iprog) {
	if (timer_thread) {
		 * Convert all dir separators to forward slashes,

		return NULL;
	else if (!is_valid_win32_path(filename, 1)) {
				pid = mingw_spawnve_fd(iprog, argv, deltaenv, dir, 1,

			size_t s = wcslen(p) + 1;
pid_t mingw_spawnvpe(const char *cmd, const char **argv, char **deltaenv,
}
	return -1;
			if (waitpid(pid, &status, 0) < 0)
{
				(utf[upos + 2] & 0xc0) == 0x80) {
	return p+1;
		free(argv2);
	if (!ret && restrict_handle_inheritance && stdhandles_count) {
	LPPROC_THREAD_ATTRIBUTE_LIST attr_list = NULL;
			exit(128 + SIGINT);
	ts->tv_sec = (time_t)(hnsec / 10000000);
#define HCAST(type, handle) ((type)(intptr_t)handle)

		CloseHandle(h[0]);
		 * Since the child is a console process, Windows

	maybe_redirect_std_handle(L"GIT_REDIRECT_STDERR", STD_ERROR_HANDLE, 2,
	       ask_yes_no_if_possible("Rename from '%s' to '%s' failed. "

	    (attrs & FILE_ATTRIBUTE_READONLY)) {
				goto repeat;
		if (*p == '\\' || *p == '"')
		CloseHandle(h[1]);
		return -1;
	/* Find the keys */

	/* did not find an answer we understand */
	}
		(*len)--;
			wbuf += 2;
			return 0;

{
	case FILE_TYPE_PIPE:
					tmp = NULL; /* use $USERPROFILE */
	 * Create a UTF-8 version of w_argv. Also create a "save" copy

	}
	errno = EINVAL;
				}
		 * ERROR_INVALID_PARAMETER instead of expected error
					     c == 'N') &&
	/* simulate TERM to enable auto-color (see color.c) */
	case ERROR_INVALID_ACCESS: error = EACCES; break;
		open_fn = _wopen;
	const char *basename;
	}
		errno = create ? EINVAL : ENOENT;
		ALLOC_GROW(array, nr + 1, alloc);
	int ret, tries = 0;
	}
		else if (!wcsnicmp(wbuf, L"\\DosDevices\\", 12))
#include <conio.h>
	NameUserPrincipal = 8
		if (h) {
	case ERROR_BAD_UNIT: error = ENODEV; break;

	return ret;
	wchar_t *wenv = GetEnvironmentStringsW(), *wdeltaenv, *result, *p;
		dup2(new_fd, fd);
	SIZE_T size;
	close(fd);
		 * If we have to retry again, we do sleep a bit.
		} else {
		if (pid >= 0) {

		return error("unable to make a socket file descriptor: %s",
		free(w_key);
}
	long long hnsec;
		if (err == ERROR_INVALID_PARAMETER)
		return;
			return NULL;
{

					if (follow) {
				"Please type 'y' or 'n'\n");
static const char *quote_arg_msvc(const char *arg)
	} else

		return 0;
	const char *p = path;
		static char *sh;

	fputs("fatal: not enough memory for initialization", stderr);
static int has_valid_directory_prefix(wchar_t *wfilename)
	if (!ret && errno == EINVAL)
						       fhin, fhout, fherr);

		array[nr++] = p;

static void stop_timer_thread(void)
{
		if (ret >= 0)
{
	if (!file && GetLastError() == ERROR_INVALID_NAME)
	/*
			if (isatty(STDERR_FILENO))
{
static char *lookup_prog(const char *dir, int dirlen, const char *cmd,



			prog = lookup_prog(path, dirlen, cmd, isexe, exe_only);
{
	}

char *mingw_getcwd(char *pointer, int len)
	 * is not useful for this purpose. But we cannot close it, either,
/* Used to match and chomp off path components */
	return rc;
	s = WSASocket(domain, type, protocol, NULL, 0, 0);
	if (!h) {
	pid_t pid;
	 */
	}
	if (xutftowcs(wotype, otype, ARRAY_SIZE(wotype)) < 0)
			else

	static char user_name[100];
					break;
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);


	argv[i] = save[i] = NULL;
{
	return i1->tv_sec == i2->tv_sec && i1->tv_usec == i2->tv_usec;
			handle = GetStdHandle(std_id);
		}
}
		return -1;
static void ensure_socket_initialization(void)
static inline long long filetime_to_hnsec(const FILETIME *ft)
			/* invalid utf-8 byte, non-printable unicode: convert to hex */
	if (initialized)
				status = 255;
		     const char *dir,
				      "\tSUPPRESS_HANDLE_INHERITANCE_WARNING=1"
			break;
	ensure_socket_initialization();
}
	case ERROR_SHARING_VIOLATION: error = EACCES; break;
		     * On Windows 7 and earlier, handles on pipes and character
		return 0;
	return ret;
	STARTUPINFOEXW si;
static void maybe_redirect_std_handles(void)
{
	HANDLE fh = (HANDLE)_get_osfhandle(fd);
#undef bind
		return errno = EINVAL,
		return NULL;
		rc = 0;
		errno = ENOENT;
	} else
				(utf[upos] & 0xc0) == 0x80 &&
int mingw_listen(int sockfd, int backlog)
			SetStdHandle(std_id, handle);


	if (gle == ERROR_ACCESS_DENIED &&
	    !is_timeval_eq(&in->it_interval, &in->it_value))
		 * try $HOMEDRIVE$HOMEPATH - the home share may be a network
		error("could not unhide %s", filename);
		 * to help shell commands called from the Git
	case FILE_TYPE_DISK:
		i++;
	case SIGABRT:

		pid = -1;
{
		}
		 * instead of CREATE_NO_WINDOW to make ssh
	return TRUE;
		strbuf_addch(&buf, '"');

	if (utflen)

		}
	ts->tv_nsec = (hnsec % 10000000) * 100;
			/* 4-byte utf-8: convert to \ud8xx \udcxx surrogate pair */
	case ERROR_BAD_COMMAND: error = EIO; break;

	while (!prog) {
{
	}
				!(c == 0xf4 && utf[upos] >= 0x90) && /* > \u10ffff */
	int namelen;
}
	if (filename && !strcmp(filename, "/dev/null"))
 * state.
			/* contains reserved name */
		timer_thread = (HANDLE) _beginthreadex(NULL, 0, ticktack, NULL, 0, NULL);
			strbuf_release(&buf);
	}
						i += 4; /* CONOUT$ */
	} else if (xutftowcs_path(wfilename, filename) < 0)


		case '/': case '\\':

	}
	if (!wide)
struct pinfo_t {
	return pointer;
	}
				return 0;
{


	case ERROR_BAD_DEVICE: error = ENODEV; break;
				  GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL);
	case ERROR_LOCK_VIOLATION:
	if (!is_timeval_eq(&in->it_interval, &zero) &&

		break;
not_a_reserved_name:
		return -1;
{
			int count = 0;
			c -= 0x10000;
		/* There is no console associated with this process.
	int n, fd;

	case ERROR_ACCOUNT_RESTRICTION: error = EACCES; break;

{
			got_full_line = 1;
{


			"Should I try again?", pathname))
				wcs[wpos++] = hex[c & 0x0f];
	struct strbuf args;
		p += s;
{

static inline int needs_hiding(const char *path)
	return 0;
};
	 * will remove claimed items from the argv that we pass down.
			strbuf_release(&buf);

/*
	case ERROR_HANDLE_DISK_FULL: error = ENOSPC; break;
	 */
	case ERROR_DISK_CHANGE: error = EIO; break;
			/* fallthru */
}
		     * back to creating the process without trying to limit the
{
#undef gethostbyname
	case ERROR_META_EXPANSION_TOO_LONG: error = E2BIG; break;
}
			case ERROR_FILE_NOT_FOUND:
	if (xwcstoutf(pointer, wpointer, len) < 0)
unsigned int sleep (unsigned int seconds)
		s = wcslen(p) + 1;
{
		} else {

	    (attrs & FILE_ATTRIBUTE_READONLY)) {
		wcmd[0] = L'\0';
{
	wchar_t wfilename[MAX_PATH], wotype[4];
	/* Determine whether or not we are associated to a console */
		 * Therefore, we choose to leave the biased error code
			return -1;
	open_fn_t open_fn;
	long long hnsec = filetime_to_hnsec(ft);
	case ERROR_NONE_MAPPED: error = EINVAL; break;
	goto segment_start;
					goto not_a_reserved_name;
		free(converted);

{
	int n = wcslen(wfilename);
				git_config_bool(var, value);
				/* This implies parent directory exists. */
	return s;
}
	handle = CreateFileW(wfilename, FILE_APPEND_DATA,
	InitializeCriticalSection(&pinfo_cs);
			if (attrsold == INVALID_FILE_ATTRIBUTES ||
};
			continue;
	return 0;
}

}
	/* set up default file mode and file modes for stdin/out/err */

		return NULL;
	}
{
		}
		die("invalid strftime format: '%s'", format);

			int i;
				fputs("Alarm clock\n", stderr);
	buf->st_uid = 0;
		const char *sep = strchrnul(path, ';');
	DWORD avail, type = GetFileType(fh) & ~FILE_TYPE_REMOTE;
			 * whether it actually is one: trailing spaces, a file
static BOOL WINAPI ctrl_ignore(DWORD type)
 * That is, does it have a "//./pipe/" prefix?
static int is_local_named_pipe_path(const char *filename)
	case ERROR_READ_FAULT: error = EIO; break;

		       "Should I try again?", pold, pnew))
		tries++;
static inline int match_last_path_component(const char *path, size_t *len,
	atexit((void(*)(void)) WSACleanup);
		return 0;
char *mingw_query_user_email(void)
			strbuf_insert(&args, 0, "strace ", 7);
			return -1;
			c = ((c & 0x07) << 18);
			*d++ = '\\';
			wcs[wpos++] = c;
		 * complete its operation, we give up our time slice now.
	free(w_key);
/* Windows only */
	if (filename && !strcmp(filename, "/dev/null"))
	FreeEnvironmentStringsW(wenv);
	unsigned mode;

	if (timer_thread)
 * needs the real getpagesize function, we need to find another solution.
		CloseHandle(cons);
	_setmode(_fileno(stdout), _O_BINARY);
				return 0;
	 * It is based on MoveFile(), which cannot overwrite existing files.
		if (!timer_thread )
		else if (*arg == '\\') {
		warning("could not mark '%s' as hidden.", filename);
			strbuf_addstr(&buf, tmp);

	size_t alloc = 0, nr = 0, i;
	} else
			strbuf_addstr(&buf, "\nThis is a bug; please report it "
	if (!cmd)
				wpos + 1 < wcslen &&


	if (!path)
	si.StartupInfo.hStdError = winansi_get_osfhandle(fherr);
		int exec_id;
	} else if (!ret)
 * is documented in [1] as opening a writable file handle in append mode.
}
	if (xutftowcs_path(wpath, path) < 0)
				errno = ENOENT;
	/* insert \ where necessary */
				if ((findbuf.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
		(!basename[4] || is_dir_sep(basename[4]));
			FindClose(handle);
	 * because it is not possible to turn a process ID into a process
		argv2[0] = (char *)cmd;	/* full path to the script file */
	case ERROR_CALL_NOT_IMPLEMENTED: error = ENOSYS; break;
 * We implement wmain() and compile with -municode, which would
	case ERROR_INVALID_PRIMARY_GROUP: error = EINVAL; break;
		xutftowcs_path(wnewpath, newpath) < 0)
	case SIGALRM:
		/*
	case ERROR_SHARING_BUFFER_EXCEEDED: error = ENFILE; break;
			wbuf += 4;
		memset(buf, 0, sizeof(*buf));
	NameDisplay = 3,
		filename[2] == '.'  &&
}
}
#undef write
	case ERROR_DEV_NOT_EXIST: error = ENODEV; break;
}
	case ERROR_WRITE_FAULT: error = EIO; break;
		 */
/* The timer works like this:
/* Normalizes NT paths as returned by some low-level APIs. */
		return *basename == '.';
		filetime_to_timespec(&(fdata.ftLastAccessTime), &(buf->st_atim));
			answer[answer_len-1] = '\0';
			free(p);
		} else if (c >= 0xa0) {
{
#undef fgetc

	if (fd < 0)
		if (xwcstoutf(converted, wbuffer, len) >= 0)
		si.lpAttributeList = attr_list;
	return listen(s, backlog);
	errno = ERANGE;
			else if (!_wrmdir(wpnew))
	}
		return NULL;
	 * error. Rather than playing finicky and fragile games, let's just try

		if (wpos >= wcslen) {
				if (((c = path[++i]) != 'u' && c != 'U') ||

{
			errno = ENOTEMPTY;
	if (timer_event)
{
	filedes[0] = _open_osfhandle(HCAST(int, h[0]), O_NOINHERIT);
						char buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];

				break;
	wcscpy(wbuf, wpath);
			return NULL;
		rc = -1;
	if (handle == INVALID_HANDLE_VALUE) {
 */
	*d++ = '\0';
{
				} else if (c == 'n' || c == 'N') { /* CON */
}
int mingw_rmdir(const char *pathname)
	EnterCriticalSection(&pinfo_cs);

				*ppinfo = info->next;


		 * Go figure!
			NULL, create, FILE_ATTRIBUTE_NORMAL, NULL);
	if (localtime_s(result, timep) == 0)
	unsigned flags = CREATE_UNICODE_ENVIRONMENT;
			case 'l': case 'L': /* LPT<N> */
		const char *, const struct tm *);
	return (pid_t)pi.dwProcessId;
	DWORD create_flag = fd ? OPEN_ALWAYS : OPEN_EXISTING;
		if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
{

}

	path = mingw_getenv("PATH");
 * Multiple entries in deltaenv for the same key are explicitly allowed.
	if (tolower(answer[0]) == 'n' && !answer[1])

		 * match *exactly*. As there is no mode or flag we can set that
		return raise(sig);
					if (!(findbuf.dwFileAttributes & FILE_ATTRIBUTE_READONLY))
				if (c == 'm' || c == 'M') { /* COM1 ... COM9 */
		COPY_ARRAY(result, wenv, size);
{
}

			periods++;
		ALLOC_GROW(array, nr + 1, alloc);
		CloseHandle(h);
		stop_timer_thread();

	utflen = WideCharToMultiByte(CP_UTF8, 0, wcs, -1, utf, utflen, NULL, NULL);
	if (!strncasecmp(answer, "yes", sizeof(answer)))
			if (c && c != '.' && c != ':' && c != '/' && c != '\\')
				CloseHandle(handle);
		restrict_handle_inheritance = core_restrict_inherited_handles;
	/* chomp off repeated dir separators */

	/* a pointer to the original strftime in case we can't find the UCRT version */
		else if (rc != WAIT_OBJECT_0)
	case ERROR_CANNOT_MAKE: error = EACCES; break;
{
}
		/*
	if (xutftowcs_path(wpold, pold) < 0 || xutftowcs_path(wpnew, pnew) < 0)
	if (!*p) force_quotes = 1;
				break;
	return pid;
	/* reserve space for \0 */
		return p;
	{
		restrict_handle_inheritance = GetVersion() >> 16 >= 7601;

		if (answer_len >= 2 && answer[answer_len-2] == '\r') {
		return signal(sig, handler);
	case SIGSEGV:

	case ERROR_FILE_NOT_FOUND: error = ENOENT; break;
			strbuf_add(&buf, p2, p - p2);

					goto not_a_reserved_name;
}
	if (prog) {
			return converted;
		} else if (c >= 0xc2 && c < 0xe0 && upos < utflen &&
			force_quotes = 1;
static wchar_t *normalize_ntpath(wchar_t *wbuf)
	}
	size = strlen(namevalue) * 2 + 1;
		return 0;

			case 'n': case 'N': /* NUL */
#if defined(_MSC_VER)
			warning("could not mark '%s' as hidden.", filename);

		errno = WSAGetLastError();
		goto revert_attrs;
	buf->st_gid = 0;
}
{
		    !strcasecmp("yes", strace_env) ||
	if (!ret && needs_hiding(path))
	return p;
			ppinfo = &info->next;
			c = path[i];
	case ERROR_INVALID_TARGET_HANDLE: error = EIO; break;
}
		if (interpr) {
{
	filetime_to_timespec(&(fdata.ftLastWriteTime), &(buf->st_mtim));
		size_t answer_len = strlen(answer);
		/*
	BOOL ret;
/* We keep the do_lstat code in a separate function to avoid recursion.
	else
}
	ret = GetLongPathNameW(cwd, wpointer, ARRAY_SIZE(wpointer));
			}
	for (delta_size = 0, i = 0; deltaenv[i]; i++)
			if (*arg == '"' || !*arg) {


				p++;
{
/* Compare only keys */
		atexit_done = 1;
		}
			strbuf_addf(&buf, "strace -o %s ", quoted);
	wchar_t wtemplate[MAX_PATH];
	else
			int count = 0;
		 * executable (by not mistaking the dir separators
	return memcpy(malloc_startup(len), buffer, len);
	if (wbuf[0] == '\\') {
}
		/*
	if (p == arg)
	       ask_yes_no_if_possible("Unlink of file '%s' failed. "
	if (xutftowcs_path(wpath, path) < 0)
			if (info->pid == pid) {
		strbuf_add(&buf, p2, p - p2);
	HANDLE proc;
	assert(hide_dotfiles == HIDE_DOTFILES_DOTGITONLY);
		/* check if fd is a pipe */
	free(save);
					path += i;
	}
				if (is_directory(buf.buf))
	while (ret == -1 && errno == EACCES && is_file_in_use_error(GetLastError()) &&
			case 'p': case 'P': /* PRN */
		if (one_shot)
		errno = err_win_to_posix(GetLastError());
	while (WaitForSingleObject(timer_event, timer_interval) == WAIT_TIMEOUT) {
		ret = GetFinalPathNameByHandleW(hnd, wpointer, ARRAY_SIZE(wpointer), 0);
		return arg;
	argv_array_pushl(&cp.args, "mintty", "gdb", NULL);
{
		return -1;
			return -1;
	 * invalidating the buffer after GETENV_MAX_RETAIN getenv() calls.
int mingw_core_config(const char *var, const char *value, void *cb)
	strace_env = getenv("GIT_STRACE_COMMANDS");
		    !strcasecmp("true", strace_env))
	}
			switch (*path) {
	if (xutftowcs_path(woldpath, oldpath) < 0 ||
		free(prog);
				break;
			c |= (utf[upos++] & 0x3f);
}
	p->pw_name = user_name;
		 * location, thus also check if the path exists (i.e. is not
	int pid = 0;
	if (!value)
 * mingw startup code, see init.c in mingw runtime).

	    si.StartupInfo.hStdError != si.StartupInfo.hStdInput &&
				!(c == 0xf0 && utf[upos] < 0x90) && /* over-long encoding */
	filedes[1] = _open_osfhandle(HCAST(int, h[1]), O_NOINHERIT);
	case ERROR_BUFFER_OVERFLOW: error = ENAMETOOLONG; break;
 */
	/* concatenate argv, quoting args as we go */

static int do_lstat(int follow, const char *file_name, struct stat *buf)
		if (handle != INVALID_HANDLE_VALUE)
		return NULL;
			hide_dotfiles = git_config_bool(var, value);
	va_list args;

	if (attr_list)
	}
		return -1;
	for (i = 0; i < argc; i++)
{
	case ERROR_BAD_PATHNAME: error = ENOENT; break;
 * merged with the given list of settings.
			}
		if ((answer = read_yes_no_answer()) >= 0)
	case ERROR_WAIT_NO_CHILDREN: error = ECHILD; break;
		modified = original | FILE_ATTRIBUTE_HIDDEN;
		strbuf_release(&buf);
#undef signal
	int i, maxlen, exit_status;
		return;
		return result;
	 * calls report EINVAL. It is impossible to notice whether this
		 * CREATE_ALWAYS flag of CreateFile()).
	}
		}
	while (*len > 0 && is_dir_sep(path[*len - 1]))

		SetFileAttributesW(wfilename, attrs & ~FILE_ATTRIBUTE_READONLY);
	return wpos;
	case ERROR_SUCCESS: BUG("err_win_to_posix() called without an error!");
		return -1;

		len++;
				c = path[++i];
			if (c > '\0' && c < '\x20')
	if (xutftowcs_path(wfilename, filename) < 0)

	if (strpbrk(cmd, "/\\"))
	switch (sig) {
	if (stdhandles_count)
			case 'c': case 'C':
		 * The same is true for CREATE_NO_WINDOW.

	d = q = xmalloc(st_add3(len, n, 3));
		if (isspace(*p) || *p == '*' || *p == '?' || *p == '{' || *p == '\'')
	case ERROR_ALREADY_EXISTS: error = EEXIST; break;
FILE *mingw_fopen (const char *filename, const char *otype)
	/* GetEnvironmentVariableW() only sets the last error upon failure */
		int dirlen = sep - path;
				attributes == FILE_ATTRIBUTE_DEVICE)
			const char *argv0 = argv[0];
	return NULL;
		}
static enum hide_dotfiles_type hide_dotfiles = HIDE_DOTFILES_DOTGITONLY;
						buf->st_size = readlink(file_name, buffer, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);
		break;
	size_t p_len, q_len;

	/*
}
				(utf[upos] & 0xc0) == 0x80) {
		timer_fn = handler;
			sh = path_lookup("sh", 0);
			errno = err_win_to_posix(GetLastError());
	DWORD attrs;

{
			errno = EINVAL;
	static char *values[GETENV_MAX_RETAIN];
	 * handle inheritance. This is still better than failing to create
	ssize_t result = write(fd, buf, len);


		SetStdHandle(std_id, handle);
}
		int pid, status;
				;
		/* Skip any duplicate keys; last one wins */
	case ERROR_IO_DEVICE: error = EIO; break;
	case ERROR_PRIVILEGE_NOT_HELD: error = EACCES; break;
		errno = ENOENT;
				strbuf_addf(&buf, "handle #%d: %p (type %lx, "
	timer_interval = in->it_value.tv_sec * 1000 + in->it_value.tv_usec / 1000;
		return 1;
		ALLOC_ARRAY(argv2, argc + 1);
		return NULL;
	int tries = 0;
						 ((c = path[i + 3]) == 't' ||
		/* There is already a console. If we specified
	}
	 * Keep the handle in a list for waitpid.

	return 0;
{
		int got_full_line = 0, c;
	ALLOC_ARRAY(wdeltaenv, delta_size);
	p = xmalloc(sizeof(*p));

	if (!strcmp(cmd, "sh")) {
	return pid;
static const wchar_t *wcschrnul(const wchar_t *s, wchar_t c)
	if (n >= 4 && !strcasecmp(cmd+n-4, ".exe"))
	case ERROR_ACCOUNT_DISABLED: error = EACCES; break;
		HANDLE h = (HANDLE) _get_osfhandle(fd);
		return arg;
		errno = err_win_to_posix(GetLastError());
		pinfo = info;
	wchar_t wcmd[MAX_PATH], wdir[MAX_PATH], *wargs, *wenvblk = NULL;
	timer_fn = in->sa_handler;
static sig_handler_t timer_fn = SIG_DFL, sigint_fn = SIG_DFL;

}
	 */
	       ret = _wunlink(wpathname);
					c = path[++i];
			     stdhandles_count ? TRUE : FALSE,
#ifdef _DEBUG
		p += size;
	if (p_len < q_len)
	 * to append to the file.
				errno = EISDIR;

		/* ignore errors again */

		p = path_lookup(cmd, 0);
char *mingw_getenv(const char *name)
	initialized = 1;

					       fhin, fhout, fherr);
struct tm *gmtime_r(const time_t *timep, struct tm *result)
int mingw_execv(const char *cmd, char *const *argv)
		int ws = isspace(*p);
	case ERROR_SHARING_VIOLATION:
	return -1;
		result = SetEnvironmentVariableW(wide, equal + 1);
			/* invalid utf-8 byte, printable unicode char: convert 1:1 */
			const char *quoted = quote_arg(strace_env);
		DWORD attrs = GetFileAttributesW(wfilename);
				      stdhandles,
	/* count chars to quote */
	 * expecting to have to free it, so we keep a round-robin array,
				    ((c = path[++i]) != 'n' && c != 'N'))

#endif
	if (GetFileAttributesExW(wfilename, GetFileExInfoStandard, &fdata)) {
	if (MoveFileExW(wpold, wpnew, MOVEFILE_REPLACE_EXISTING))

	while (!wcscmp(findbuf.cFileName, L".") ||
	return q;
/*
	const char *strace_env;
	}

			CloseHandle(h);
	}
}
	buf->st_nlink = 1;
static int start_timer_thread(void)

		if (status)

		 * In order to give the other process a higher chance to
					continue;
			      GetLastError());
		if (dirlen)
	int len = 0, n = 0;
	}
}
{
			hide_dotfiles = HIDE_DOTFILES_DOTGITONLY;

	 */
	return 0;
		die("Out of memory, (tried to allocate %u wchar_t's)", size);
	}
			break;
	wchar_t wfilename[MAX_PATH];
		while (*ppinfo) {
	FILETIME mft, aft;
		return -1;
	}
	case ERROR_IO_INCOMPLETE: error = EINTR; break;
		return 0;
		return 0;
	while (n > 0) {
		if (!strcmp("1", strace_env) ||

		return 0;

	tv->tv_sec = hnsec / 10000000;
			return ret;

	 * necessary (and may lead to races) for a file created with
				      "at\nhttps://github.com/git-for-windows/"
				error("cannot start timer thread");
	return do_stat_internal(1, file_name, buf);
static char *path_lookup(const char *cmd, int exe_only)
	if (hide && !access(filename, F_OK) && set_hidden_flag(wfilename, 0)) {
			char *iprog = path_lookup(interpr, 1);
		buf->st_ino = 0;
	else {
			if (path[i] == ' ') {
	return getaddrinfo(node, service, hints, res);
	case ERROR_INVALID_ADDRESS: error = EFAULT; break;

/* We provide our own lstat/fstat functions, since the provided


		if (!wcsncmp(wbuf, L"\\??\\", 4) ||
		if (!*sep)
		return errno = ENOSYS, -1;
	/* We cannot use basename(), as it would remove trailing slashes */
	case ERROR_PASSWORD_EXPIRED: error = EACCES; break;
		tries++;
			struct strbuf buf = STRBUF_INIT;
			CloseHandle(h);
	wchar_t *p = *(wchar_t **)a, *q = *(wchar_t **)b;
	default:
	return connect(s, sa, sz);
		/* use $USERPROFILE if the home share is not available */

#include "win32.h"
			 * matter, the name is still reserved if any of those
	if ((opt = strchr(p+1, ' ')))
	while (namelen && file_name[namelen-1] == '/')
		errno = err_win_to_posix(GetLastError());
				free((char *)quoted);
			if (wpos < wcslen)
				if (((c = path[++i]) != 'r' && c != 'R') ||
	value = calloc(len_value, sizeof(char));
 * If follow is true then act like stat() and report on the link
 * (which do not have an extension)
		return NULL;
	static int done;
	if (!wcscmp(buf, L"off")) {
	/* check if git_command is a shell script */
				if ((c = path[++i]) != 'o' && c != 'O')
int link(const char *oldpath, const char *newpath)
}
	if ((sockfd = _open_osfhandle(s, O_RDWR|O_BINARY)) < 0) {
	if (tries < ARRAY_SIZE(delay) && gle == ERROR_ACCESS_DENIED) {
		if (c < 0x80) {
	 */
 */
	BY_HANDLE_FILE_INFORMATION fdata;
	return bind(s, sa, sz);
	initialized = 1;
	*p = L'\0';
		if (hnd == INVALID_HANDLE_VALUE)
		p += wlen + 1;
static int timer_interval;
		     */
				      "\n");
#include "../run-command.h"
	}
		mingw_execv(prog, argv);
 * this case, we strip the trailing slashes and stat again.
	return NULL;
		while (argv[argc]) argc++;
	/* only these flags are supported */

	wchar_t woldpath[MAX_PATH], wnewpath[MAX_PATH];

		int argc = 0;
ssize_t mingw_write(int fd, const void *buf, size_t len)
		static int ret = -1;
	SOCKET s2 = accept(s1, sa, sz);
	if ((oflags & O_CREAT) && needs_hiding(filename)) {
		COPY_ARRAY(&argv2[1], &argv[1], argc);
 * complete. Note that Git stat()s are redirected to mingw_lstat()
	if (attrs != INVALID_FILE_ATTRIBUTES &&
	wcslen--;
		return;
		if (quoted != cmd)

		return error("unable to make a socket file descriptor: %s",

}
	 * FILE_SHARE_WRITE is required to permit child processes
	wchar_t *w_key;
		} else if (timer_fn != SIG_IGN)
static void maybe_redirect_std_handle(const wchar_t *key, DWORD std_id, int fd,
 * too, since Windows doesn't really handle symlinks that well.
		if (rc == WAIT_TIMEOUT)
		if (xutftowcs_path(wcmd, p) < 0) {
		rc = -1;
	if (!ret || ret >= ARRAY_SIZE(wpointer))
			     flags, wenvblk, dir ? wdir : NULL,
		 * "Invalid signal or error" (which in DEBUG builds causes the
		return -1;
#include "../cache.h"

	do_unset_environment_variables();
	int ch;

static inline int is_timeval_eq(const struct timeval *i1, const struct timeval *i2)
		 * so, let's turn the error to ERROR_PATH_NOT_FOUND instead.
struct hostent *mingw_gethostbyname(const char *host)
int err_win_to_posix(DWORD winerr)
	free(wenvblk);
		     * to catch each and every corner case (and running the
	}
	if (is_timeval_eq(&in->it_value, &zero) &&
	if (out != NULL)
 * argv into UTF8 and pass them directly to main().
				      NULL, NULL)) {
{
	if (!ret)
static int read_yes_no_answer(void)
	case ERROR_TOO_MANY_MODULES: error = EMFILE; break;
		strbuf_addstr(&args, quoted);
	return start_timer_thread();
	static int initialized = 0;

			DWORD fl = 0;

		info->next = pinfo;
		}
		(((off_t)fdata.nFileSizeHigh)<<32);
		time_t_to_filetime(times->modtime, &mft);
	 */
	case ERROR_INVALID_NAME: error = EINVAL; break;
		int new_fd = _open_osfhandle((intptr_t)handle, O_BINARY);
 * normally ignore main(), but we call the latter from the former
	return -1;
		case '<': case '>': case '"': case '|': case '?': case '*':
				/* COM1 ... COM9, CON, CONIN$, CONOUT$ */

		if (ret && buf.len) {
	    (attrs = GetFileAttributesW(wpnew)) != INVALID_FILE_ATTRIBUTES) {
	 * that we want to present in log and error messages. The handle
		}
		pid = mingw_spawnv(cmd, (const char **)argv, 0);
}
		flags |= DETACHED_PROCESS;

	DWORD stdhandles_count = 0;

}

		}
			c |= ((utf[upos++] & 0x3f) << 12);
		if (*args.buf)
	if (xutftowcs_path(wpathname, pathname) < 0)

	maybe_redirect_std_handles();
			int new_fd = _open_osfhandle((intptr_t)handle, O_BINARY);
					goto not_a_reserved_name;
		options &= ~WNOHANG;
		return;
		errno = err_win_to_posix(GetLastError());
	case ERROR_BAD_DRIVER_LEVEL: error = ENXIO; break;
	} else {
				free(info);
{
	/*
	free(buffer);
	if (original == modified || SetFileAttributesW(path, modified))
	return strbuf_detach(&buf, 0);
		int c = utf[upos++] & 0xff;
{
 *
		errno = err_win_to_posix(GetLastError());
	return -1;
}
	}
	return -1;
	HIDE_DOTFILES_TRUE,
		if (!has_valid_directory_prefix(wfilename)) {
	ALLOC_ARRAY(argv, argc + 1);
 * the thread to terminate by setting the timer_event to the signalled
{
		CloseHandle(h);
 * This trick does not appear to work for named pipes.  Instead it creates
		return -1;
			exit(status);
#ifndef _MSC_VER
	return value;
 * The unit of FILETIME is 100-nanoseconds since January 1, 1601, UTC.

 *
	case ERROR_INVALID_LOGON_HOURS: error = EACCES; break;

	SetLastError(ERROR_SUCCESS);
	}
enum hide_dotfiles_type {
int is_valid_win32_path(const char *path, int allow_literal_nul)
				     TRUE, flags, wenvblk, dir ? wdir : NULL,
	if (s == INVALID_SOCKET) {
	if (!result)
		time_t_to_filetime(times->actime, &aft);
	case ERROR_BUSY_DRIVE: error = EBUSY; break;
	if (!do_lstat(follow, file_name, buf))
int setitimer(int type, struct itimerval *in, struct itimerval *out)
	errno = EACCES;
	int fd;
	if (!deltaenv || !*deltaenv) {
		die_startup();
	PROCESS_INFORMATION pi;
	p->pw_gecos = get_extended_user_info(NameDisplay);

	size_t ret;
int xutftowcsn(wchar_t *wcs, const char *utfs, size_t wcslen, int utflen)
		 * WSAGetLastError() values are regular BSD error codes
		modified = original & ~FILE_ATTRIBUTE_HIDDEN;
			strbuf_addch(&buf, '"');
				    !isdigit(path[++i]))
	xsnprintf(buf->release, sizeof(buf->release),
			wcs[wpos++] = c;
		return NULL;
    return gethostname(name, namelen);
	return _wchdir(wdirname);
/*

		 * since we'll be redirecting std streams, we do
	static wchar_t wbuffer[1024];
}
		stdhandles[stdhandles_count++] = si.StartupInfo.hStdError;
			case ERROR_PATH_NOT_FOUND:
		filetime_to_timespec(&(fdata.ftLastWriteTime), &(buf->st_mtim));
		     * specified in the thread handle list. Rather than trying
	for (basename = path; *path; path++)
	} else
static int is_msys2_sh(const char *cmd)
		sigint_fn = handler;
	return template;
	case ERROR_BUSY: error = EBUSY; break;

		 * out with an ERROR_ACCESS_DENIED if CREATE_ALWAYS was
		HANDLE hnd = CreateFileW(cwd, 0,
#endif
				break;
		if (!wcsnicmp(wbuf, L"UNC\\", 4)) {
	 * Try native rename() first to get errno right.
		pid = mingw_spawnv(prog, argv2, 1);
}
	if (ends_with(cmd, "\\sh.exe")) {

		path = sep + 1;
			!wcscmp(findbuf.cFileName, L".."))
		errno = EINVAL;
			while (*arg == '\\') {
	int ret = fflush(stream);
	xutftowcs(wide, namevalue, size);
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
			if (!c)
	xutftowcs(wargs, args.buf, 2 * args.len + 1);
{

		die("unable to initialize winsock subsystem, error %d",
	if (errno != EEXIST)
		if (wbuf[i] == '\\')
	static unsigned initialized;
	static size_t (*fallback)(char *, size_t, const char *, const struct tm *) = strftime;
 * Values of the form "KEY" in deltaenv delete inherited values.
	int len_key, len_value;
	 * handle after the process terminated.

		 * would correspond to FILE_ATTRIBUTE_HIDDEN, let's just try
				*d++ = '\\';
{
}
	static int value_counter;
		      const char *format, const struct tm *tm)
{
	char *q, *d;

	}
	errno = 0;
	case ERROR_OUTOFMEMORY: error = ENOMEM; break;

	}
{
	return 0;
revert_attrs:

int mingw_setsockopt(int sockfd, int lvl, int optname, void *optval, int optlen)
		wfilename[n] = c;
	SetEnvironmentVariableW(key, NULL);
						(findbuf.dwReserved0 == IO_REPARSE_TAG_SYMLINK)) {
}
	void *result = malloc(size);
	}
		}
{
#endif
	return gethostbyname(host);
				    (allow_literal_nul &&
		if (!tmp && (tmp = getenv("USERPROFILE")))
		return -1;
	one_shot = is_timeval_eq(&in->it_interval, &zero);
			}
		close(fd);
{


#ifdef _DEBUG

		 * complete its operation, we give up our time slice now.
		die("Out of memory, (tried to allocate %u wchar_t's)", len_key);

	return -1;
	case ERROR_DIRECTORY: error = EINVAL; break;
	/* on Windows it is TMP and TEMP */
 * lstat/fstat functions are so slow. These stat functions are
		return 0;
		enum EXTENDED_NAME_FORMAT, LPCWSTR, PULONG);
		char *quoted = (char *)quote_arg(*argv);
	case ERROR_NO_MORE_SEARCH_HANDLES: error = EIO; break;
	}
				FindClose(handle);
	long long winTime = t * 10000000LL + 116444736000000000LL;
	unsigned v = (unsigned)GetVersion();
	hnsec = filetime_to_hnsec(&ft);

	     GetLastError() == ERROR_INSUFFICIENT_BUFFER) &&
		 * Internally, _wopen() uses the CreateFile() API which errors
		return NULL;
static int ask_yes_no_if_possible(const char *format, ...)
					else if ((c == 'o' || c == 'O') &&
			return -1;
			}
		if (!ret)
			timer_fn(SIGALRM);
		case ' ':
				     !path[i + 1] && p == path))
	errno = EINVAL;

static void setup_windows_environment(void)
	case ERROR_DISK_FULL: error = ENOSPC; break;
	if (!GetUserNameW(buf, &len)) {
			return 0;
	wchar_t wpathname[MAX_PATH];
		return errno = EINVAL,
		wchar_t c = wfilename[--n];

	/*
						buf->st_mode = S_IFLNK;

		if (tmp) {
	return result;
		errno = EINVAL;
		else {

	case ERROR_NOACCESS: error = EFAULT; break;
	return _waccess(wfilename, mode & ~X_OK);
		 */
	if (xutftowcs_path(wdirname, dirname) < 0)
	sleep(1);
		if (err != ERROR_NO_SYSTEM_RESOURCES &&
		    !(err == ERROR_INVALID_PARAMETER &&
	return fd;
		if (!ret || ret >= ARRAY_SIZE(wpointer))
		buf->st_nlink = 1;
	static int restrict_handle_inheritance = -1;
		    /*
			}

}

	if ((oflags & ~O_CREAT) != (O_WRONLY | O_APPEND))
	/* invoke the real main() using our utf8 version of argv. */
	if ((oflags & O_APPEND) && !is_local_named_pipe_path(filename))
			return err == ERROR_NO_MORE_FILES;
	const char **argv;

			got_full_line = 1;

	va_start(args, format);
#include "../git-compat-util.h"
	}
	wchar_t wpath[MAX_PATH];
	}
	return shutdown(s, how);
int _CRT_glob = 0;
		if (!ws && *p != '\\' && *p != '"' && *p != '{' && *p != '\'' &&
		/* replace remaining '...UNC\' with '\\' */
	*d++ = '"';

		char *quoted = (char *)quote_arg(cmd);
	case ERROR_GEN_FAILURE: error = EIO; break;

	       ask_yes_no_if_possible("Deletion of directory '%s' failed. "
	if (restrict_handle_inheritance < 0)
		return 0;
	/* convert backslashes to slashes */

		exec_id = trace2_exec(cmd, (const char **)argv);
		 * In order to give the other process a higher chance to
	case ERROR_INVALID_FLAGS: error = EINVAL; break;
int mingw_putenv(const char *namevalue)
		return NULL;
#endif
	default:
			sigint_fn(SIGINT);
		if (type == FILE_TYPE_CHAR) {
 * Disable MSVCRT command line wildcard expansion (__getmainargs called from
	case ERROR_OPEN_FILES: error = EBUSY; break;
	case ERROR_PATH_BUSY: error = EBUSY; break;
	 * FILE_APPEND_DATA.
int mingw_rename(const char *pold, const char *pnew)
	case ERROR_MAPPED_ALIGNMENT: error = EINVAL; break;
		Sleep(delay[tries]);
	typedef int (*open_fn_t)(wchar_t const *wfilename, int oflags, ...);
	if (pid > 0 && sig == SIGTERM) {
		} else if (c >= 0xf0 && c < 0xf5 && upos + 2 < utflen &&
		} else {
	int hide = needs_hiding(filename);
	mode = va_arg(args, int);
		 * Some network storage solutions (e.g. Isilon) might return
		if (!p)
		attributes = GetFileAttributesW(wfilename);

{

	if (!is_valid_win32_path(filename, !create)) {
			/* 2-byte utf-8 */
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
	skip_dos_drive_prefix((char **)&path);
	cp.clean_on_exit = 1;
			break;
		return -1;
		CloseHandle(hnd);
		else if (*p == '\\') {
	else if (xutftowcs_path(wcmd, cmd) < 0)

	/* convert into a file descriptor */
	errno = err_win_to_posix(GetLastError());
	}
#undef fopen
		/* fallthru */
	len = ARRAY_SIZE(buf);
	case ERROR_NO_PROC_SLOTS: error = EAGAIN; break;
		goto repeat;
	wchar_t wpath[MAX_PATH];
	DECLARE_PROC_ADDR(ucrtbase.dll, size_t, strftime, char *, size_t,
			switch (GetLastError()) {
					    GetFileType(h),
}
			 * So far, this looks like a reserved name. Let's see

	}
CRITICAL_SECTION pinfo_cs;
/* See https://msdn.microsoft.com/en-us/library/windows/desktop/ms724435.aspx */
		}
	case SIGTERM:
		if (!is_dir_empty(wpathname)) {
	while ((ret = _wunlink(wpathname)) == -1 && tries < ARRAY_SIZE(delay)) {
		}
			warning("failed to restrict file handles (%ld)\n\n%s",
		/*

		errno = create ? EINVAL : ENOENT;
	len_value = GetEnvironmentVariableW(w_key, w_value, ARRAY_SIZE(w_value));
	return NULL;
		p->pw_gecos = "unknown";
		if (fd < 0 && errno == EACCES)
		 * We assume that some other process had the source or
			do {
			    (i != periods || periods > 2))
	WSADATA wsa;
	case ERROR_INVALID_WORKSTATION: error = EACCES; break;
}
	case ERROR_FILENAME_EXCED_RANGE: error = ENAMETOOLONG; break;

	 * The process ID is the human-readable identifier of the process
		LeaveCriticalSection(&pinfo_cs);
	return (is_dir_sep(filename[0]) &&
		close(new_fd);
	case ERROR_SHARING_BUFFER_EXCEEDED:
			error("sigaction: param 3 != NULL not implemented");
		utflen = INT_MAX;
	case ERROR_LOCK_VIOLATION: error = EACCES; break;
	if (hide_dotfiles == HIDE_DOTFILES_TRUE)
		CloseHandle(timer_event);
	if (!isatty(_fileno(stream)))
			wbuf += 12;
	HANDLE handle;
		else
		if (!FindNextFileW(handle, &findbuf)) {
			/* ignore trailing slashes */
{
	return 0;

		return NULL;
		if (value && !strcasecmp(value, "dotgitonly"))
		case '\0':
	int upos = 0, wpos = 0;
		 * would normally create a console window. But

}
 * [1] https://docs.microsoft.com/en-us/windows/desktop/fileio/file-access-rights-constants
			c |= ((utf[upos++] & 0x3f) << 6);
		return get_file_info_by_handle(fh, buf);
	switch (errcode) {
	 * on Windows Vista and 2008.
	/* calculate HOME if not set */
		return xstrdup(path);
				      stdhandles_count * sizeof(HANDLE),
 * exe_only means that we only want to detect .exe files, but not scripts
	case ERROR_ACCESS_DENIED: error = EACCES; break;
				continue;
		errno = EINVAL;
static int mingw_open_append(wchar_t const *wfilename, int oflags, ...)
}
}
	strbuf_addch(&buf, '"');
	q_len = wcschrnul(q, L'=') - q;
	static struct passwd *p;
	/* fix absolute path prefixes */
{
	if (utflen < 0)
{
	case ERROR_ENVVAR_NOT_FOUND: error = EINVAL; break;
			}
			WIN32_FIND_DATAW findbuf;
	if (!len_value && GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
	}
					c = path[i + 1];


		struct pinfo_t *info = xmalloc(sizeof(struct pinfo_t));
		ret = fallback(s, max, format, tm);
{
	case SIGILL:

	case ERROR_PIPE_BUSY: error = EBUSY; break;
 */
			strbuf_addch(&args, ' ');
	sig_handler_t old;
		buf->st_nlink = 1;
		closesocket(s);
		argv[i] = save[i] = wcstoutfdup_startup(buffer, wargv[i], maxlen);

		return NULL;
	case ERROR_INVALID_EXE_SIGNATURE: error = ENOEXEC; break;
			DWORD err = GetLastError();
	if (gle == ERROR_ACCESS_DENIED &&

	if (errno != ENOENT)
		if (ch != EOF || GetLastError() != ERROR_OPERATION_ABORTED)
	char *filename = mktemp(template);
	if (!p->pw_gecos)
	} else if (xutftowcs_path(wfilename, filename) < 0)
		ppinfo = &pinfo;
					    GetHandleInformation(h, &fl),
	for (;;) {
	if (!isatty(_fileno(stdin)) || !isatty(_fileno(stderr)))
		return NULL;
	/*
				count++;
	buffer = malloc_startup(maxlen);
	}
		if (attrs & FILE_ATTRIBUTE_DIRECTORY) {

	}
	return mingw_spawnve_fd(cmd, argv, NULL, NULL, prepend_cmd, 0, 1, 2);
	/* TODO: translate more errors */
			errno = err_win_to_posix(GetLastError());

		 * default answer which is no */
			if (preceding_space_or_period &&
						i += 3; /* CONIN$ */
		exec_id = trace2_exec(prog, argv2);
sig_handler_t mingw_signal(int sig, sig_handler_t handler)
		if (is_dir_sep(*path)) {
		if (!(tmp = getenv("TMP")))
			return NULL;
{
	int force_quotes = 0;
		*d++ = *arg++;
}
	FILE *file;
			errno = EPIPE;
	switch (sig) {
		}
			SetFileAttributesW(wpnew, attrs);
	HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
 * Values of the form "KEY=VALUE" in deltaenv override inherited values.
			errno = ERANGE;

		 * destination file open at the wrong moment and retry.
	n = strlen(cmd);

			error("setitimer: it_interval must be zero or eq it_value");
}
		     * chance of *still* forgetting a few), let's just fall
	wchar_t wfilename[MAX_PATH];
		preceding_space_or_period = 0;
	 * On Windows 2008 R2, it seems that specifying certain types of handles
static int one_shot;
	case ERROR_BAD_PIPE: error = EPIPE; break;
	/*


	return setsockopt(s, lvl, optname, (const char*)optval, optlen);
char *mingw_mktemp(char *template)
/*

	ft->dwHighDateTime = winTime >> 32;
		return ret;
				continue;
		if (!p)
		return NULL;
	DWORD ret = GetEnvironmentVariableW(key, buf, max);
		return NULL;
}
}
#ifdef USE_MSVC_CRTDBG
	win32_skip_dos_drive_prefix((char **)&path);
}
	/* this creates non-inheritable handles */
	}
		       i++;
	if (!namevalue || !*namevalue)
static HANDLE timer_event;
	fd = open(cmd, O_RDONLY);
{
	if (filename && !strcmp(filename, "/dev/null"))
{
			/* cannot end in ` ` or `.`, except for `.` and `..` */
		p = comma + 1;
 *

					setenv("HOME", buf.buf, 1);
	 * operation, it can happen that write() is called by a later
	if (si.StartupInfo.hStdInput != INVALID_HANDLE_VALUE)
	return get_extended_user_info(NameUserPrincipal);
	if (!_wmktemp(wtemplate))


	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
	}
	case ERROR_OPERATION_ABORTED: error = EINTR; break;
		return -1;
	case ERROR_DIR_NOT_EMPTY: error = ENOTEMPTY; break;
		return 0;
			default:

	case SIGFPE:
		return -1;
		closesocket(s2);
	else if (xutftowcs_path(wfilename, filename) < 0)
		if (value && !strcasecmp(value, "auto"))
			return error("strace not found!");
	case ERROR_NOT_ENOUGH_MEMORY:
		/* Skip "to delete" entry */
			}
	HANDLE cons;
					}
	if (xutftowcs(wotype, otype, ARRAY_SIZE(wotype)) < 0)
	}
	 */
		*equal = L'\0';
#undef strftime

	timer_thread = NULL;
	return 0;
		 * If we have to retry again, we do sleep a bit.
	static const struct timeval zero;
		free(unset_environment_variables);
	if (n < 4)	/* at least '#!/x' and not error */
}
	const char *retry_hook[] = { NULL, NULL, NULL };
	if (!atexit_done) {
}

			 */
	/* initialize Unicode console */
#include "../strbuf.h"
		 "%u.%u", v & 0xff, (v >> 8) & 0xff);
	}

	/* Windows to Unix Epoch conversion */
	for (;;) {
}

	wchar_t w_value[32768];
static HANDLE timer_thread;
 * Does the pathname map to the local named pipe filesystem?

static unsigned __stdcall ticktack(void *dummy)
	if (done || !p)
		     * devices are inherited automatically, and cannot be
	_setmode(_fileno(stdin), _O_BINARY);
	case ERROR_DEVICE_IN_USE: error = EBUSY; break;
				while (count-- > 0)
	if (!strcmp(var, "core.restrictinheritedhandles")) {

			static const char *hex = "0123456789abcdef";
	if (filedes[0] < 0) {
	return si.dwAllocationGranularity;
		 * already know will fail.
		errno = err_win_to_posix(err);
{
		buf->st_size = fdata.nFileSizeLow |
{
		wcscpy(wfilename, L"nul");
			path[strlen(path)-4] = '\0';

			 * follow immediately after the actual name.
/*
{
	 * to remember all the string pointers because parse_options()
	 * No O_APPEND here, because the CRT uses it only to reset the
		EnterCriticalSection(&pinfo_cs);
{


	return result ? 0 : -1;
	case ERROR_CURRENT_DIRECTORY: error = EACCES; break;
	if (filedes[1] < 0) {
	case ERROR_INVALID_PARAMETER: error = EINVAL; break;
	HIDE_DOTFILES_FALSE = 0,
static inline int is_file_in_use_error(DWORD errcode)
		free(prog);
	}
				*d++ = *arg++;
	return old;
static int core_restrict_inherited_handles = -1;
#endif
{
/*
	if (start_command(&cp) < 0)
		maxlen = max(maxlen, wcslen(wargv[i]));
		return;
				len++;
			for (i = 0; i < stdhandles_count; i++) {
		int exec_id;
			FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
int mingw_socket(int domain, int type, int protocol)


	case ERROR_NOT_READY: error = EAGAIN; break;
		unsetenv(p);
			answer[answer_len-2] = '\0';
		return -1;
		return 0;
#include "dir.h"
	GetSystemTimeAsFileTime(&ft);
		old = timer_fn;

#ifdef _MSC_VER
	if (handle == INVALID_HANDLE_VALUE)
{
		break;
 * only waits to receive the signal to terminate. The main thread tells
}
		return -1;
			error("waiting for timer thread failed: %lu",
	}
		is_dir_sep(filename[3]) &&

		/*
	char *prog;
int mingw_chmod(const char *filename, int mode)

		break;
		return NULL;
	free(wdeltaenv);
	/* strip options */
 */
	}
	filetime_to_timespec(&(fdata.ftLastAccessTime), &(buf->st_atim));
#undef fflush
 */
	if (restrict_handle_inheritance < 0)
		}
static const int delay[] = { 0, 1, 10, 20, 40 };
}
		 * We assume that some other process had the source or
	snprintf(path, sizeof(path), "%.*s\\%s.exe", dirlen, dir, cmd);
	case ERROR_TOO_MANY_OPEN_FILES: error = EMFILE; break;
	if (tolower(answer[0]) == 'y' && !answer[1])
		if (!got_full_line)
						goto not_a_reserved_name;
				      "git/issues/new\n\n"
static void do_unset_environment_variables(void)
			if (*path)
static char *wcstoutfdup_startup(char *buffer, const wchar_t *wcs, size_t len)
				     &si.StartupInfo, &pi);
		    !getenv("SUPPRESS_HANDLE_INHERITANCE_WARNING")) {
	if (!utf || !wcs || wcslen < 1) {
{

	/* fix Windows specific environment settings */
		filetime_to_timespec(&(fdata.ftCreationTime), &(buf->st_ctim));
	DWORD len;
	if (*len < component_len + 1 ||

			WSAGetLastError());
			wcs[wpos++] = c;
static inline void time_t_to_filetime(time_t t, FILETIME *ft)
		 * ERROR_PATH_NOT_FOUND, which results in an unknown error. If
			case 'a': case 'A': /* AUX */
		buf->st_dev = buf->st_rdev = 0; /* not used by Git */
		handle = GetStdHandle(STD_OUTPUT_HANDLE);
	 * fflush invocation triggered such a case, therefore, we have to
	case ERROR_BUFFER_OVERFLOW:
	buf[n] = '\0';
static void *malloc_startup(size_t size)
			size += s;
	if ((sockfd2 = _open_osfhandle(s2, O_RDWR|O_BINARY)) < 0) {
		/* we could not read, return the
		return NULL;
}
	if (filename == NULL)
}

				      "the environment variable\n\n"
	case ERROR_MORE_DATA: error = EPIPE; break;
	case ERROR_BAD_LENGTH: error = EINVAL; break;
 * zero word.
		pid = 1;	/* indicate that we tried but failed */
	long long winTime = ((long long)ft->dwHighDateTime << 32) + ft->dwLowDateTime;
	struct pinfo_t *next;
	wchar_t buf[100];
	if (!*p)
				goto not_a_reserved_name;
		setenv("TERM", "cygwin", 1);


		errno = ECHILD;
	cons = CreateFileW(L"CONOUT$", GENERIC_WRITE,
#undef shutdown
	HANDLE handle;
		return -1;
	len_value = len_value * 3 + 1;
	for (i = 0, p = wdeltaenv; deltaenv[i]; i++) {
		aft = mft;

		COPY_ARRAY(p, array[i], size);
	for (p = arg; *p; p++) {
};
	DECLARE_PROC_ADDR(secur32.dll, BOOL, GetUserNameExW,
	wchar_t wfilename[MAX_PATH];
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);

		HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
			      int prepend_cmd, int fhin, int fhout, int fherr)
	} else if (pid > 0 && sig == 0) {
{
		char *p;
			else {
	setup_windows_environment();
	values[value_counter++] = value;
		return !run_command_v_opt(retry_hook, 0);
	}
	    (attr_list = (LPPROC_THREAD_ATTRIBUTE_LIST)
	case ERROR_SEEK: error = EIO; break;
		 */
	if ((retry_hook[0] = mingw_getenv("GIT_ASK_YESNO"))) {

	const unsigned char *utf = (const unsigned char*) utfs;
	}
			if (MoveFileExW(wpold, wpnew, MOVEFILE_REPLACE_EXISTING))
				strbuf_addstr(&buf, tmp);
	if (fd < 0 && (oflags & O_ACCMODE) != O_RDONLY && errno == EACCES) {
					goto not_a_reserved_name;
{
	else if (!is_valid_win32_path(filename, 1)) {
{
	FILETIME ft;

	*p = '\0';

	case ERROR_INVALID_DRIVE: error = ENODEV; break;
	int i;
				if (!*arg)
		DWORD attributes;
		wcscpy(wfilename, L"nul");
			return errno = ENOMEM,
{
	/* (over-)assess size needed for wchar version of deltaenv */
	}
		return result;
			/* ASCII */
 * https://docs.microsoft.com/en-us/cpp/cpp/parsing-cpp-command-line-arguments
	case SIGABRT_COMPAT:
	fd = open_fn(wfilename, oflags, mode);
	wenvblk = make_environment_block(deltaenv);
		return NULL;
{
	if (!getenv("TERM"))
		buf->st_gid = 0;
	if (!CreatePipe(&h[0], &h[1], NULL, 8192)) {
		return 0;
	_wchmod(wpathname, 0666);
			p += s;
					} else {
int mingw_gethostname(char *name, int namelen)
		buf->st_mode = file_attr_to_st_mode(fdata.dwFileAttributes);
		 * complete its operation, we give up our time slice now.
			return answer;
#endif

	int len = strlen(cmd);
			error("sigaction only implemented for SIGALRM");
		int answer;
	wide = calloc(size, sizeof(wchar_t));
int mingw_accept(int sockfd1, struct sockaddr *sa, socklen_t *sz)
		if (fd >= 0 && set_hidden_flag(wfilename, 1))
{
	char *buffer, **save;
	for (p = wenv; p && *p; ) {
	return -1;

	if (INIT_PROC_ADDR(strftime))

	case ERROR_PATH_NOT_FOUND: error = ENOENT; break;
				preceding_space_or_period = 1;
		 * We assume that some other process had the source or
	int sockfd;
	}
		trace2_exec_result(exec_id, -1);
	}
 * The thread, ticktack(), is a trivial routine that most of the time

	default:
	case ERROR_INSUFFICIENT_BUFFER: error = ENOMEM; break;
	 * If there is a deltaenv, let's accumulate all keys into `array`,
/**

	case ERROR_WRITE_PROTECT: error = EROFS; break;
	xsnprintf(buf->version, sizeof(buf->version),
		char **argv2;
					    "handle info (%d) %lx\n", i, h,
		 */
	 * sort them using the stable git_stable_qsort() and then copy,
	memcpy(alt_name, file_name, namelen);
			status = 255;
	case FILE_TYPE_CHAR:
		error("could not unhide %s", filename);
	char answer[1024];
		 */

 * See "Parsing C++ Command-Line Arguments" at Microsoft's Docs:
}
	return winTime - 116444736000000000LL;
struct passwd *getpwuid(int uid)
	}
	while (*arg) {
				(utf[upos] & 0xc0) == 0x80 &&

		/* flush the buffer in case we did not get the full line */
int mingw_raise(int sig)
	char alt_name[PATH_MAX];
{
					*d++ = '\\';
	case ERROR_SHARING_VIOLATION:
		errno = ENOENT;
		return -1;

		result = SetEnvironmentVariableW(wide, NULL);
			strbuf_insert(&args, 0, buf.buf, buf.len);
				    ((c = path[++i]) != 't' && c != 'T') ||
		if ((attrs & FILE_ATTRIBUTE_READONLY) &&
{
/*
	CloseHandle(pi.hThread);
		errno = ENOENT;
	if (prog) {
int uname(struct utsname *buf)
	/* if file_name ended in a '/', Windows returned ENOENT;
		return 0;

			argv[0] = prog;
	/*
			gle = GetLastError();
		return -1;
{

	if (si.StartupInfo.hStdError != INVALID_HANDLE_VALUE &&
		int err = errno;
		if (!comma)
	}


 * to avoid data loss.
static int is_dir_empty(const wchar_t *wpath)
	case ERROR_PIPE_CONNECTED: error = EPIPE; break;
	while (*s && *s != c)
	if (!result)
			FILE_SHARE_WRITE | FILE_SHARE_READ,
int mingw_access(const char *filename, int mode)
	for (i = 0; i < argc; i++)

	if (file && hide && set_hidden_flag(wfilename, 1))
}
		return 0;
}
 */

				match_last_path_component(p, &len, "bin") &&
			c |= (utf[upos++] & 0x3f);
				      DWORD desired_access, DWORD flags)
	case ERROR_NOT_ENOUGH_MEMORY: error = ENOMEM; break;
	return !strncasecmp(".git", basename, 4) &&
		return 1;
 *
	if (!INIT_PROC_ADDR(GetUserNameExW))
	maxlen = 3 * maxlen + 1;
			wcs[wpos++] = c;
		 */
FILE *mingw_freopen (const char *filename, const char *otype, FILE *stream)
		int rc = WaitForSingleObject(timer_thread, 10000);
	buf->st_dev = buf->st_rdev = 0; /* not used by Git */
{

				!(c == 0xe0 && utf[upos] < 0xa0) && /* over-long encoding */
static int try_shell_exec(const char *cmd, char *const *argv)
		p_len++;
	if ((!exe_only || isexe) && _waccess(wpath, F_OK) == 0) {
	if (fgets(answer, sizeof(answer), stdin)) {

{
		if (utflen == INT_MAX && c == 0)

#undef accept
static int get_file_info_by_handle(HANDLE hnd, struct stat *buf)
						 ((c = path[i + 2]) == 'u' ||


	    is_timeval_eq(&in->it_interval, &zero))
	if (!name || !*name)
static const char *parse_interpreter(const char *cmd)
	}
	return sockfd2;
	/* allocate buffer (wchar_t encodes to max 3 UTF-8 bytes) */
		filename[9]);

				  GENERIC_READ, FILE_ATTRIBUTE_NORMAL);
	int preceding_space_or_period = 0, i = 0, periods = 0;
			pid = mingw_spawnve_fd(prog, argv, deltaenv, dir, 0,
	case ERROR_PIPE_NOT_CONNECTED: error = EPIPE; break;
		 */
		return -1;
			if (handle != INVALID_HANDLE_VALUE)
		}


 * We return a contiguous block of UNICODE strings with a final trailing
		ret = CreateProcessW(*wcmd ? wcmd : NULL, wargs, NULL, NULL,
	done = 1;
				buf->st_size = avail;
		FreeEnvironmentStringsW(wenv);
		    !wcsncmp(wbuf, L"\\\\?\\", 4))
	if (buf[0] != '#' || buf[1] != '!')
		 * disconnected)
}
	char *prog = path_lookup(cmd, 0);

	while (upos < utflen) {
	maybe_redirect_std_handle(L"GIT_REDIRECT_STDIN", STD_INPUT_HANDLE, 0,
		return 0;
}

int mingw_fstat(int fd, struct stat *buf)
		else if (*p == '"')
		 * for escape characters).
	wchar_t **array = NULL;
	 * We return `value` which is an allocated value and the caller is NOT
{

	if (hide && !access(filename, F_OK) && set_hidden_flag(wfilename, 0)) {
		char *converted = xmalloc((len *= 3));
}
	DWORD original = GetFileAttributesW(path), modified;
	if (!(p = strrchr(buf+2, '/')) && !(p = strrchr(buf+2, '\\')))
	if (cons == INVALID_HANDLE_VALUE) {
		return raise(sig);
		ALLOC_ARRAY(result, size);
				  GENERIC_WRITE, FILE_FLAG_NO_BUFFERING);
	argv_array_pushf(&cp.args, "--pid=%d", getpid());
				if (((c = path[++i]) != 'p' && c != 'P') ||
	p->pw_dir = NULL;
		 * destination file open at the wrong moment and retry.
		/* initialize stat fields */
	if (!namelen || namelen >= PATH_MAX)
	if (!is_valid_win32_path(path, 0)) {
	if (!wcs || !utf || utflen < 1) {
{
 * But ticktack() interrupts the wait state after the timer's interval
	*len -= component_len + 1;
	case ERROR_SEEK_ON_DEVICE: error = ESPIPE; break;
	return 0;
		return -1;
		Sleep(delay[tries]);
	}
		die("Out of memory, (tried to allocate %u bytes)", len_value);
	char *tmp = getenv("TMPDIR");
	wchar_t wpold[MAX_PATH], wpnew[MAX_PATH];
static struct pinfo_t *pinfo = NULL;
	memset(&pi, 0, sizeof(pi));
	if (!_wrename(wpold, wpnew))
	 * (such as FILE_TYPE_CHAR or FILE_TYPE_PIPE) will always produce an
			core_restrict_inherited_handles =
	    FALSE, pid);
		errno = EPIPE;

	BOOL result;
		return -1;
	case ERROR_DRIVE_LOCKED: error = EBUSY; break;
			ret = match_last_path_component(p, &len, "sh.exe") &&
		}
			free(quoted);

	if (prepend_cmd) {
			i = periods = preceding_space_or_period = 0;

	SOCKET s1 = (SOCKET)_get_osfhandle(sockfd1);
	case SIGINT:
{
{
		--namelen;
	if (pid > 0 && options & WNOHANG) {
	if (si.StartupInfo.hStdOutput != INVALID_HANDLE_VALUE &&
		return -1;
	va_start(args, oflags);
 *
		if (waitpid(pid, &status, 0) < 0)
	return 0;
		if (!sh)

			tmp = getenv("TEMP");
	wchar_t wdirname[MAX_PATH];
				return 1;
			GetExitCodeProcess(h, (LPDWORD)status);
	char *p = unset_environment_variables;
			setenv("TMPDIR", tmp, 1);
	wchar_t buf[MAX_PATH];
	return do_stat_internal(0, file_name, buf);
	wpath[wcslen(wpath)-4] = '\0';

			*wbuf = '\\';
		return NULL;
	 */

{
	switch (GetLastError()) {
		SetEvent(timer_event);	/* tell thread to terminate */
	static char buf[100];
		if (fdata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
	 * to detect this situation and simply try again without restricting any
		return 1;
	return 1;
		stdhandles[stdhandles_count++] = si.StartupInfo.hStdOutput;

	return -1;

			if (PeekNamedPipe(fh, NULL, 0, NULL, &avail, NULL))
	switch(winerr) {
	return -1;
		 * In order to give the other process a higher chance to
	SetConsoleCtrlHandler(ctrl_ignore, FALSE);
		if (*arg == '"')
		}
			CloseHandle(handle);
		close(filedes[0]);
			c |= ((utf[upos++] & 0x3f) << 6);
	prog = path_lookup(interpr, 1);
			trace2_exec_result(exec_id, status);
	const char *p = arg;
	case ERROR_ALREADY_ASSIGNED: error = EBUSY; break;
			OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
int mingw_kill(pid_t pid, int sig)
					    ((c = path[i + 2]) == 'n' ||

	while (1) {
int mingw_open (const char *filename, int oflags, ...)
	wcs[wpos] = 0;
	 * Since git code does not check for errors after each stdio write
			dup2(new_fd, fd);
	if (!protect_ntfs)

					; /* skip all spaces */
			break;

	if (!try_shell_exec(cmd, argv)) {

#undef gethostname
{
		errno = err_win_to_posix(GetLastError());


			preceding_space_or_period = 1;
	if (si.lpAttributeList)
	case ERROR_CANTREAD: error = EIO; break;


	}
	ALLOC_ARRAY(wargs, st_add(st_mult(2, args.len), 1));
			DWORD attrsold = GetFileAttributesW(wpold);
		HeapFree(GetProcessHeap(), 0, attr_list);
	ALLOC_ARRAY(result, size + delta_size);
	case ERROR_OPEN_FAILED: error = EIO; break;
		 * If we have to retry again, we do sleep a bit.
 * tailored for Git's usage (read: fast), and are not meant to be
				      PROC_THREAD_ATTRIBUTE_HANDLE_LIST,

	if (timer_event) {
			error("setitimer param 3 != NULL not implemented");
		}
static int set_hidden_flag(const wchar_t *path, int set)
			free(p);
		size = wcslen(array[i]) + 1;
		return -1;
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);


	case ERROR_ACCESS_DENIED:
 * When a path ends with a slash, the stat will fail with ENOENT. In
	char path[MAX_PATH];
	case SIGINT:
	else if (!buf.len)
		}
	xwcstoutf(value, w_value, len_value);
			return xstrdup(path);
	if (attrs != INVALID_FILE_ATTRIBUTES &&
	return fd;
	    si.StartupInfo.hStdError != si.StartupInfo.hStdOutput)
	else
	if (xutftowcs_path(wfilename, filename) < 0)
		return -1;
		return NULL;

			errno = EISDIR;
#ifdef _MSC_VER
}
		return NULL;
	if (xutftowcs_path(wtemplate, template) < 0)
		return NULL;
		 * However, strerror() does not know about networking

	case ERROR_CANTWRITE: error = EIO; break;
	wchar_t wbuf[MAX_PATH + 2];
	case ERROR_LOCKED: error = EBUSY; break;
	default:
	case ERROR_NO_SUCH_PRIVILEGE: error = EACCES; break;
	for (p = result, i = 0; i < nr; i++) {
	for (; *argv; argv++) {
	case ERROR_EXE_MARKED_INVALID: error = ENOEXEC; break;
		free(p);
	ensure_socket_initialization();
	case ERROR_INVALID_HANDLE: error = EBADF; break;
	/* read-only files cannot be removed */
		CloseHandle(h[1]);
	timer_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	}
			core_restrict_inherited_handles = -1;

			}
		} else if (answer_len >= 1 && answer[answer_len-1] == '\n') {
	}
	p_len = wcschrnul(p, L'=') - p;

		HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
#undef listen

		 */
	if (WSAStartup(MAKEWORD(2,2), &wsa))
	/* convert into a file descriptor */
		restrict_handle_inheritance = 0;
		s++;
	wchar_t *wide, *equal;
			}
		 * again *without* the O_CREAT flag (that corresponds to the
		}
	if (sig != SIGALRM)

	/*
	buf->st_mode = file_attr_to_st_mode(fdata.dwFileAttributes);
			trace2_exec_result(exec_id, -1);
	 * call to write() reports EPIPE on Windows. Subsequent write()
	if (!getenv("HOME")) {



		free(save[i]);
}
}
		CloseHandle(timer_thread);
	tv->tv_usec = (hnsec % 10000000) / 10;
	if (!GetFileInformationByHandle(hnd, &fdata)) {
				match_last_path_component(p, &len, "usr");
 */
}
	wchar_t wpathname[MAX_PATH];
				else
			c = ((c & 0x1f) << 6);
static char *unset_environment_variables;
		die_errno("Could not start gdb");
int pipe(int filedes[2])
		case '.':
	if (!SetFileTime((HANDLE)_get_osfhandle(fh), NULL, &aft, &mft)) {
		handle = GetStdHandle(std_id);
	trace2_initialize_clock();

	case ERROR_INVALID_DATA: error = EINVAL; break;
	}
	default:

			return 0;
		break;

	case ERROR_STACK_OVERFLOW: error = ENOMEM; break;
	}
		if (attributes == FILE_ATTRIBUTE_DIRECTORY ||
}
			wbuf[i] = '/';
	attrs = GetFileAttributesW(wfilename);
		return NULL;
	const char *(*quote_arg)(const char *arg) =
		return -1;
		}

			i++;

	return ch;
			/* do *not* close the new_fd: that would close stdout */
}


{
		for (p = wenv; p && *p; ) {
				    ((c = path[++i]) != 'l' && c != 'L') ||

		quote_arg_msys2 : quote_arg_msvc;
	case ERROR_BAD_EXE_FORMAT: error = ENOEXEC; break;
	return _wcsnicmp(p, q, p_len);
		 * destination file open at the wrong moment and retry.
		info->pid = pi.dwProcessId;
	len_key = strlen(name) + 1;
{
#endif

}
		DeleteProcThreadAttributeList(si.lpAttributeList);
				/* illegal character */
		 * in errno so that _if_ someone looks up the code somewhere,
			argv[0] = argv0;

			exit(128 + SIGALRM);
static NORETURN void die_startup(void)
						buf->st_mode |= S_IWRITE;
	return 0;
			size_t len = strlen(p);
			}
	si.StartupInfo.hStdInput = winansi_get_osfhandle(fhin);
	buf->st_size = fdata.nFileSizeLow |
	if (xwcstoutf(user_name, buf, sizeof(user_name)) < 0) {
	unset_environment_variables = xstrdup("PERL5LIB");
			int status;
	case ERROR_UNRECOGNIZED_MEDIA: error = ENXIO; break;
	}
#endif
		value_counter = 0;
	}
			strerror(errno));
		}

}
		int create = otype && strchr(otype, 'w');
		if ((tmp = getenv("HOMEDRIVE"))) {
						 path[i + 4] == '$')
		    SetFileAttributesW(wpnew, attrs & ~FILE_ATTRIBUTE_READONLY)) {
	if (*argv && !strcmp(cmd, *argv))
	ret = _wmkdir(wpath);
		return errno = EINVAL,
	if (options == 0) {
	/* don't even try a .exe */
	convert_slashes(pointer);
	 * skipping duplicate keys
	WIN32_FILE_ATTRIBUTE_DATA fdata;
		return 0;
	return 0;
		unset_environment_variables = xstrdup(value);

			continue;
		info->proc = pi.hProcess;
			     flags, NULL);
	size_t component_len = strlen(component);
}
#undef connect
		warning("could not mark '%s' as hidden.", filename);
	}
	extern char *_pgmptr;
		old = sigint_fn;
}
	int sockfd2;
		} else if (c >= 0xe0 && c < 0xf0 && upos + 1 < utflen &&
		if (WAIT_OBJECT_0 != WaitForSingleObject(h, 0)) {
	const char *path;
	 * file pointer to EOF before each write(); but that is not
int sigaction(int sig, struct sigaction *in, struct sigaction *out)
	wchar_t wfilename[MAX_PATH];
						  c == 'T') &&
	}
			HANDLE handle = FindFirstFileW(wfilename, &findbuf);
/*
		}
			fd = open_fn(wfilename, oflags & ~O_CREAT, mode);

			if ((tmp = getenv("HOMEPATH"))) {
int mingw_utime (const char *file_name, const struct utimbuf *times)
}
	while (ret == -1 && is_file_in_use_error(GetLastError()) &&

		buf->st_uid = 0;
			if (*p == '"' || !*p)
		}
		errno = ret ? ENAMETOOLONG : err_win_to_posix(GetLastError());
	/* We cannot use xcalloc() here because that uses getenv() itself */
		if (!is_file_in_use_error(GetLastError()))
	SetConsoleCtrlHandler(ctrl_ignore, TRUE);
	SYSTEM_INFO si;
 */

}
pid_t waitpid(pid_t pid, int *status, int options)
	FindClose(handle);
	DWORD attrs, gle;
	}
	DWORD max = ARRAY_SIZE(buf);
		char *comma = strchr(p, ',');
	}
		is_dir_sep(filename[1]) &&
				while (path[++i] == ' ')

int mingw_fgetc(FILE *stream)
		retry_hook[1] = question;
	 * processes.
	if (initialized)

size_t mingw_strftime(char *s, size_t max,
	if (!strcmp(var, "core.hidedotfiles")) {
	if (xutftowcs_path(wfilename, file_name) < 0)

			(((off_t)fdata.nFileSizeHigh)<<32);

	int size;
	int error = ENOSYS;
	if (xwcstoutf(template, wtemplate, strlen(template) + 1) < 0)
}
		else
		flags &= ~EXTENDED_STARTUPINFO_PRESENT;
		size += s;
 * UTF-8 versions of getenv(), putenv() and unsetenv().
	equal = wcschr(wide, L'=');
		free(prog);
#undef raise
			continue;
						  c == 'U') &&
	static struct child_process cp = CHILD_PROCESS_INIT;
			error("cannot allocate resources for timer");
		}
}
}
	if (ret && errno == EINVAL)
	}
	va_list args;
			} while (is_dir_sep(*path));
	if (std_id == STD_ERROR_HANDLE && !wcscmp(buf, L"2>&1")) {
		struct pinfo_t **ppinfo;
			error("timer thread did not terminate timely");
			}
		return 0;
	if (!isexe && _waccess(wpath, F_OK) == 0)

 * Build an environment block combining the inherited environment

	GetSystemInfo(&si);
	if (file && hide && set_hidden_flag(wfilename, 1))
	}
		errno = ENAMETOOLONG;
	if (!interpr)
		DWORD err = GetLastError();
	exit_status = main(argc, argv);
	char *value;
		errno = EINVAL;
		return fgetc(stream);

{
		GetSystemTimeAsFileTime(&mft);
		goto repeat;
		if (pid < 0) {
int mingw_lstat(const char *file_name, struct stat *buf)
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);
	ensure_socket_initialization();
				    ((c = path[++i]) != 'x' && c != 'X')) {
		 * DETACHED_PROCESS here, too, Windows would
 * If cmd contains a slash or backslash, no lookup is performed.
		*opt = '\0';
		strbuf_addstr(&args, quoted);
				basename = path;
	if (!ret && GetLastError() == ERROR_ACCESS_DENIED) {
				n += count*2 + 1;
	if (restrict_handle_inheritance && stdhandles_count &&
	xutftowcs(w_key, name, len_key);
}
	HIDE_DOTFILES_DOTGITONLY
	return do_lstat(follow, alt_name, buf);
		return 0;
	va_end(args);
			break;
			break;

}
			 * extension, or an NTFS Alternate Data Stream do not
			free(quoted);

 * Note that this doesn't return the actual pagesize, but
		int create = otype && strchr(otype, 'w');
		return -1;
	case ERROR_INVALID_FUNCTION: error = ENOSYS; break;
		 */
int xwcstoutf(char *utf, const wchar_t *wcs, size_t utflen)
	ret = CreateProcessW(*wcmd ? wcmd : NULL, wargs, NULL, NULL,
 * Determines the absolute path of cmd using the split path in path.
					goto not_a_reserved_name;
		SetFileAttributesW(wfilename, attrs);
}

{
	/* determine size of argv and environ conversion buffer */

		return NULL;
			struct strbuf buf = STRBUF_INIT;

	while (*p) {
			/*
 */
		p++;

	/* If the length differs, include the shorter key's NUL */
		/* strip NT namespace prefixes */
		ret = strftime(s, max, format, tm);
		 * not need the console.
{
}
		CloseHandle(handle);
		return -1;
		break;

	fd = _open_osfhandle((intptr_t)handle, O_BINARY);
		stdhandles[stdhandles_count++] = si.StartupInfo.hStdInput;
}
	return result;
	git_stable_qsort(array, nr, sizeof(*array), wenvcmp);
	struct strbuf buf = STRBUF_INIT;
	wchar_t cwd[MAX_PATH], wpointer[MAX_PATH];
	if (result < 0 && errno == EINVAL && buf) {
	free(values[value_counter]);
			setenv("HOME", tmp, 1);
	free(wide);
		 * then it is at least the number that are usually listed.

	case ERROR_INVALID_BLOCK: error = EFAULT; break;
		 */
		errno = create ? EINVAL : ENOENT;
 * just use the regular _wopen() for them.  (And since client handle gets
	maxlen = wcslen(wargv[0]);
		while (i + 1 < nr && !wenvcmp(array + i, array + i + 1))
			c = ((c & 0x0f) << 12);

}
	if (!w_key)
	case ERROR_CANTOPEN: error = EIO; break;
 * Returns the 100-nanoseconds ("hekto nanoseconds") since the epoch.
		return NULL;
}
	if (!CreateHardLinkW(wnewpath, woldpath, NULL)) {
int mingw_bind(int sockfd, struct sockaddr *sa, size_t sz)
int mingw_stat(const char *file_name, struct stat *buf)

	}
{
		if (xwcstoutf(pointer, normalize_ntpath(wpointer), len) < 0)
		atexit(stop_timer_thread);
	timer_event = NULL;
	 * to work properly only on Windows 7 and later, so let's disable it
		wfilename[n] = L'\0';
		if (WaitForSingleObject(h, INFINITE) != WAIT_OBJECT_0) {
		}
repeat:

		return -1;
		return -1;
		struct strbuf buf = STRBUF_INIT;
}
 */
	else
{
					    const char *component)
				(utf[upos + 1] & 0xc0) == 0x80 &&
 * a named pipe client handle that cannot be written to.  Callers should
			err = ERROR_PATH_NOT_FOUND;
		}
		if (!is_file_in_use_error(GetLastError()))
		if (!(GetFileAttributesW(wpath) & FILE_ATTRIBUTE_DIRECTORY)) {
	if (xutftowcs_path(wfilename, file_name) < 0)
		errno = EBADF;
{
	 */
			*comma = '\0';
	}
		if (!wcschr(array[i], L'='))
	strbuf_init(&args, 0);
		return errno = ENOMEM,
	p = buf + strcspn(buf, "\r\n");
#include "../config.h"

			return 1;
	return 0;
		}
	}
		      GetVersion() >> 16 < 9200) &&
		wcscpy(wfilename, L"nul");
int mingw_shutdown(int sockfd, int how)
 * Verifies that safe_create_leading_directories() would succeed.
				break;
	}
		DWORD err = GetLastError();
enum EXTENDED_NAME_FORMAT {
	wchar_t wfilename[MAX_PATH];
	while ((ret = _wrmdir(wpathname)) == -1 && tries < ARRAY_SIZE(delay)) {
		 * Abort/Retry/Ignore dialog). We by-pass the CRT for things we
	winansi_init();
			c |= (utf[upos++] & 0x3f);
	int fd, create = (oflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
		else

	    (InitializeProcThreadAttributeList(NULL, 1, 0, &size) ||
	wchar_t wfilename[MAX_PATH], wotype[4];

	SOCKET s;
			    !(attrsold & FILE_ATTRIBUTE_DIRECTORY))
	FILE *file;
	if (!ret || ret >= ARRAY_SIZE(cwd)) {
	return wbuf;
	/*
int wmain(int argc, const wchar_t **wargv)
 * length to call the signal handler.

{
}



	} else {
}
		}
			continue;
	    si.StartupInfo.hStdOutput != si.StartupInfo.hStdInput)
{
				(utf[upos + 1] & 0xc0) == 0x80) {

 * so that we can handle non-ASCII command-line parameters
 *
	CloseHandle(h);
 * target. Otherwise report on the link itself.
	/* Make sure to override previous errors, if any */
		if (!is_dir_sep(c))

	case ERROR_NO_DATA: error = EPIPE; break;
		return GetLastError() == ERROR_NO_MORE_FILES;
	n = read(fd, buf, sizeof(buf)-1);
	va_end(args);
		const
			struct pinfo_t *info = *ppinfo;
	si.StartupInfo.hStdOutput = winansi_get_osfhandle(fhout);
	}
	/* X_OK is not supported by the MSVCRT version */
	case ERROR_BAD_USERNAME: error = EINVAL; break;
 * bound to a unique server handle, it isn't really an issue.)

	return open(filename, O_RDWR | O_CREAT, 0600);

	char *p, *opt;

int mkstemp(char *template)
	char question[4096];
		return xstrdup(cmd);
			close(fd);
	w_key = calloc(len_key, sizeof(wchar_t));

{
			/* illegal character */
		return 0;
#undef setsockopt
}
		}
	if (hide_dotfiles == HIDE_DOTFILES_FALSE)
#include <crtdbg.h>
	/* make sure this does not leak into child processes */

	DWORD len;
{
struct tm *localtime_r(const time_t *timep, struct tm *result)
	size_t wlen, s, delta_size, size;
	_fmode = _O_BINARY;
static int do_stat_internal(int follow, const char *file_name, struct stat *buf)
	case ERROR_FILE_INVALID: error = ENODEV; break;
			while (*p == '\\') {

 *
 */
			continue;
				path++;
				if (((c = path[++i]) != 'u' && c != 'U') ||
			strerror(err));
		is_msys2_sh(cmd ? cmd : *argv) ?
	if (set)
}
	}
	 * catch all EINVAL errors whole-sale.
	else {
#include "quote.h"
	_setmode(_fileno(stderr), _O_BINARY);
	case ERROR_INVALID_SIGNAL_NUMBER: error = EINVAL; break;
		if (handle == INVALID_HANDLE_VALUE) {

}
	case ERROR_LOGON_FAILURE: error = EACCES; break;
		/* remove the newline */
				pid = -1;
	handle = CreateFileW(buf, desired_access, 0, NULL, create_flag,
		char *p = path_lookup("strace.exe", 1);
void open_in_gdb(void)
	if (!ret || ret >= max)
		return set_hidden_flag(wpath, 1);
	return prog;
	size = 1; /* for extra NUL at the end */
		if (sigint_fn == SIG_DFL)
	WIN32_FIND_DATAW findbuf;
	if (strace_env) {
	}
		/*
	case ERROR_ARITHMETIC_OVERFLOW: error = ERANGE; break;
	 */

				count++;

		return 1;
int mingw_chdir(const char *dirname)
			while ((c = getchar()) != EOF && c != '\n')
	if (handle != INVALID_HANDLE_VALUE) {
{

		}
	free(argv);
}
	return ret;
	case SIGALRM:
	if (xutftowcs_path(wpathname, pathname) < 0)
	if ((fh = _wopen(wfilename, O_RDWR | O_BINARY)) < 0) {
		return 0;
		delta_size += strlen(deltaenv[i]) * 2 + 1;
	if (dir && xutftowcs_path(wdir, dir) < 0)

	if (tmp) {
				/* don't escape the surrounding end quote */
	char *prog = NULL;
	 * case of a pipe whose readable end was closed, only the first

			i++;
		tries++;
			}
	ALLOC_ARRAY(save, argc + 1);
		/*
	 * write() is used behind the scenes of stdio output functions.
	return _wchmod(wfilename, mode);
	if (!force_quotes && n == 0)
		 */
					    path[i + 3] == '$')
		      const struct addrinfo *hints, struct addrinfo **res)
		p2 = p;
	file = _wfopen(wfilename, wotype);
	return 0;
			setenv("SUPPRESS_HANDLE_INHERITANCE_WARNING", "1", 1);
		/*
	/* If there is no deltaenv to apply, simply return a copy. */
	/* must have write permission */
{
			return 0;
		 * biased by WSABASEERR.
	else if (p_len > q_len)
{
	if (!prog) {
	/* assuming NT variants only.. */
	return result;
			break;
	LeaveCriticalSection(&pinfo_cs);
	case ERROR_INVALID_OWNER: error = EINVAL; break;


	case SIGBREAK:
	}

		  "%u", (v >> 16) & 0x7fff);
		si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
}
			CloseHandle(h);


		else {
	pid_t pid;
	case ERROR_UNRECOGNIZED_VOLUME: error = ENODEV; break;
					if ((c == 'i' || c == 'I') &&
		if (timer_fn == SIG_DFL) {

				err, buf.buf);
	/* convert the deltaenv, appending to array */
		mingw_raise(SIGALRM);
	 * The following code to restrict which handles are inherited seems
		return -1;
	if (times) {
			ret = 0;
	if (!*path)
					    fl);

	switch (type) {
		char c = *(path++);


	case ERROR_NOT_SAME_DEVICE: error = EXDEV; break;
static pid_t mingw_spawnve_fd(const char *cmd, const char **argv, char **deltaenv,
int gettimeofday(struct timeval *tv, void *tz)
	*d++ = '"';
			wcs[wpos++] = 0xd800 | (c >> 10);
		initialized = 1;
		convert_slashes(tmp);
	    fspathncmp(path + *len - component_len, component, component_len))
	       ret = _wrmdir(wpathname);
	int hide = needs_hiding(filename);

	}
/*
	const char *interpr = parse_interpreter(cmd);
		if (GetFileType(h) == FILE_TYPE_PIPE)
	}
		if (quoted != *argv)
		return 0;
			/* revert file attributes on failure */
	alt_name[namelen] = 0;

			/* 3-byte utf-8 */

		 * disassociate the child from the console.
	DWORD create = (oflags & O_CREAT) ? OPEN_ALWAYS : OPEN_EXISTING;
	free(wargs);
			CloseHandle(h);

		else
	vsnprintf(question, sizeof(question), format, args);
{

		if (p != p2)
	if (!equal)

	si.StartupInfo.cb = sizeof(si);
	case ERROR_SWAPERROR: error = ENOENT; break;
 */
			errno = ENOTDIR;
		return NULL;
	}
		p_len = q_len + 1;
		if (errno != EACCES)
		if (comma)
		return -1;

				return 0;
int mingw_execvp(const char *cmd, char *const *argv)
		/* Ctrl+C was pressed, simulate SIGINT and retry */
			break;
	Sleep(seconds*1000);
{
		 * recognize that it has no console.
 * To be more compatible with the core git code, we convert
	case ERROR_PIPE_LISTENING: error = EPIPE; break;
	len = xwcstoutf(buffer, wcs, len) + 1;
}
			strbuf_addch(&buf, '\\');
	filetime_to_timespec(&(fdata.ftCreationTime), &(buf->st_ctim));
	return 1;
}
int mingw_fflush(FILE *stream)
	char *prog = path_lookup(cmd, 0);
				break;
		return 0;
	HANDLE h[2];
		switch (c) {

 */
				break;
	 */
		errno = ENOMEM;
			wcs[wpos++] = 0xdc00 | (c & 0x3ff);
			buf->st_mode = _S_IFIFO;
}
		mingw_raise(SIGINT);

	if (!strcmp(var, "core.unsetenvvars")) {
int mingw_mkdir(const char *path, int mode)
			"Should I try again?", pathname))
	return exit_status;
		flags |= EXTENDED_STARTUPINFO_PRESENT;

}
				HANDLE h = stdhandles[i];
	case ERROR_PATH_NOT_FOUND:
static wchar_t *make_environment_block(char **deltaenv)
	case ERROR_FILE_EXISTS: error = EEXIST; break;
		 * as being supported on the platform. Anything else causes an
	/* The list of handles cannot contain duplicates */
	case ERROR_BROKEN_PIPE: error = EPIPE; break;

	if (gmtime_s(result, timep) == 0)
	case ERROR_INVALID_PASSWORD: error = EPERM; break;
}
	for (i = 0; wbuf[i]; i++)
		fprintf(stderr, "%s (y/n) ", question);
 * the allocation granularity. If future Windows specific git code
 * Calling CreateFile() using FILE_APPEND_DATA and without FILE_WRITE_DATA
	len = ARRAY_SIZE(wbuffer);
	if (GetUserNameExW(type, wbuffer, &len)) {
int mingw_getpagesize(void)
			n++;
	close(fh);
{
		return pointer;
	return file;
				CloseHandle(info->proc);
		    *p != '?' && *p != '*' && *p != '~')
	maybe_redirect_std_handle(L"GIT_REDIRECT_STDOUT", STD_OUTPUT_HANDLE, 1,
			break;

	}
int mingw_connect(int sockfd, struct sockaddr *sa, size_t sz)
		exit(status);
static int wenvcmp(const void *a, const void *b)

	 * stdio function even if an earlier write() call failed. In the
		fprintf(stderr, "Sorry, I did not understand your answer. "
/*

			tmp = getenv("TMPDIR");
		}
 */
	if (out != NULL)
	if (timer_event)
		 * specified and an already existing file's attributes do not
		else if (sigint_fn != SIG_IGN)
#include "win32/lazyload.h"
	file = _wfreopen(wfilename, wotype, stream);
	strbuf_release(&args);
	case ERROR_BAD_FORMAT: error = ENOEXEC; break;

		if (!buf.len)
	case ERROR_NEGATIVE_SEEK: error = ESPIPE; break;
 * kernel unlike the O_APPEND flag which is racily maintained by the CRT.
/*
		ch = fgetc(stream);
#include <wchar.h>
{
		if (attributes == INVALID_FILE_ATTRIBUTES)
static inline void filetime_to_timespec(const FILETIME *ft, struct timespec *ts)
int mingw_unlink(const char *pathname)
		array[nr++] = p;
		errno = EACCES;
		return 0;
					if (c < '1' || c > '9')
{
	buf->st_ino = 0;
	    !is_dir_sep(path[*len - component_len - 1]) ||
	handle = FindFirstFileW(wbuf, &findbuf);

		trace2_exec_result(exec_id, status);
	return ret;
		Sleep(delay[tries]);
				free(iprog);
{
	HANDLE stdhandles[3];
	if (!tmp) {
		return pid;
	}
	int isexe = len >= 4 && !strcasecmp(cmd+len-4, ".exe");
		open_fn = mingw_open_append;
	return NULL;
		return result;
			return 0;
	if (!strncasecmp(answer, "no", sizeof(answer)))
	/*
				      "To suppress this warning, please set "
	int fh, rc;
	}
	    InitializeProcThreadAttributeList(attr_list, 1, 0, &size) &&

	const char *p2 = arg, *p;


		if (TerminateProcess(h, -1)) {
		default:
#if !defined(_MSC_VER)
		return -1;
	/* We cannot use xcalloc() here because that uses getenv() itself */
	while (1) {
}
{

	xsnprintf(buf->sysname, sizeof(buf->sysname), "Windows");

			wcs[wpos] = 0;
}
	if (namelen && file_name[namelen-1] != '/')
	memset(&si, 0, sizeof(si));
	ft->dwLowDateTime = winTime;
		 * The <signal.h> header in the MS C Runtime defines 8 signals
	gle = GetLastError();
	 * try again without trailing slashes
		return -1;
		 * It is necessary to use DETACHED_PROCESS

		return !fspathcmp(cmd, sh);
 * appropriately.
	}
 * (It is believed that) this is atomic since it is maintained by the

			     &si.StartupInfo, &pi);
	if (fd < 0)
	static int atexit_done;
	for (i = 1; i < argc; i++)
{
	return error;

		case ':': /* DOS drive prefix was already skipped */
		return errno = EINVAL,
#undef rename
	    UpdateProcThreadAttribute(attr_list, 0,
	return file;
		!strncasecmp(filename+4, "pipe", 4) &&
#else
	DWORD ret = GetCurrentDirectoryW(ARRAY_SIZE(cwd), cwd);
	int ret;
static const char *quote_arg_msys2(const char *arg)
		const char *interpr = parse_interpreter(prog);
	SOCKET s = (SOCKET)_get_osfhandle(sockfd);


		return -1;
}
	return sockfd;
			 int isexe, int exe_only)
	wcscat(wbuf, L"\\*");
	case ERROR_CRC: error = EIO; break;
{
	case ERROR_ACCESS_DENIED:
			buf->st_mode = _S_IFCHR;
	free(array);
		initialized = 1;
		return utflen - 1;
			wcs[wpos++] = hex[c >> 4];
				return 1;
	int ret, tries = 0;
#undef getaddrinfo
			if (quoted != strace_env)
 * Internally, they use the CRT's stock UNICODE routines
					buf->st_mode |= S_IREAD;
	}
		     int fhin, int fhout, int fherr)

			      const char *dir,
int mingw_getaddrinfo(const char *node, const char *service,
}
}
	HANDLE handle;
static pid_t mingw_spawnv(const char *cmd, const char **argv, int prepend_cmd)

	}
			(HeapAlloc(GetProcessHeap(), 0, size))) &&
	if (value_counter >= ARRAY_SIZE(values))
		is_dir_sep(filename[8]) &&
	exit(128);
		     * handle inheritance.
    ensure_socket_initialization();
static char *get_extended_user_info(enum EXTENDED_NAME_FORMAT type)
	memset(buf, 0, sizeof(*buf));
		return NULL;
			if (handle != INVALID_HANDLE_VALUE) {
	namelen = strlen(file_name);
