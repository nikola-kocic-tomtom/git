		? TRUE
#endif
			strerror(err));
int cmd__windows_named_pipe(int argc, const char **argv)

	if (argc < 2)

	int err;

	HANDLE h;
		: (GetLastError() == ERROR_PIPE_CONNECTED);
	return 0;
	if (!connected) {
#include "git-compat-util.h"

	const char *filename;
print_usage:
{
		write(1, buf, nbr);
	strbuf_addf(&pathname, "//./pipe/%s", filename);
			strerror(err));
	DisconnectNamedPipe(h);
		buf[nbr] = 0;
		PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
		DWORD nbr;
	struct strbuf pathname = STRBUF_INIT;
	while (1) {
	}
		BOOL success = ReadFile(h, buf, TEST_BUFSIZE, &nbr, NULL);
		CloseHandle(h);
	if (strpbrk(filename, "/\\"))
	fprintf(stderr, "usage: %s %s\n", argv[0], usage_string);
	return 1;
	}

#include "strbuf.h"
	 * Create a single instance of the server side of the named pipe.
		if (!success || nbr == 0)
	h = CreateNamedPipeA(

		return err;
	char buf[TEST_BUFSIZE + 1];
		return err;
	 */

		TEST_BUFSIZE, TEST_BUFSIZE, 0, NULL);
	filename = argv[1];
#define TEST_BUFSIZE (4096)
	if (h == INVALID_HANDLE_VALUE) {
		goto print_usage;
static const char *usage_string = "<pipe-filename>";

	}
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		fprintf(stderr, "CreateNamedPipe failed: %s\n",
		pathname.buf,
#include "test-tool.h"
#ifdef GIT_WINDOWS_NATIVE
	 * This will allow exactly one client instance to connect to it.

	CloseHandle(h);
}
		err = err_win_to_posix(GetLastError());
		PIPE_UNLIMITED_INSTANCES,

	BOOL connected;
			break;
	/*
		fprintf(stderr, "ConnectNamedPipe failed: %s\n",
	connected = ConnectNamedPipe(h, NULL)
		err = err_win_to_posix(GetLastError());
		goto print_usage;
