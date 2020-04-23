	 * moved the cwd of the whole process, which could confuse calling
int unix_stream_connect(const char *path)
	unix_sockaddr_cleanup(&ctx);
			errno = ENAMETOOLONG;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		}
{

}
	return -1;
	return 0;
		if (size > sizeof(sa->sun_path)) {
		return;
		goto fail;
#include "unix-socket.h"
	struct sockaddr_un sa;

{
fail:
		if (strbuf_getcwd(&cwd))
static int unix_sockaddr_init(struct sockaddr_un *sa, const char *path,
	saved_errno = errno;
	errno = saved_errno;
			return -1;
		die("unable to restore original working directory");
	if (chdir(ctx->orig_dir) < 0)
	 */
}

static void unix_sockaddr_cleanup(struct unix_sockaddr_context *ctx)
	close(fd);
	memset(sa, 0, sizeof(*sa));

	sa->sun_family = AF_UNIX;
	int fd, saved_errno;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	return r;
	if (listen(fd, 5) < 0)

	struct unix_sockaddr_context ctx;
	 * If we fail, we can't just return an error, since we have
	unix_sockaddr_cleanup(&ctx);

	free(path);
		const char *slash = find_last_dir_sep(path);
	if (fd < 0)
#include "cache.h"
	unix_sockaddr_cleanup(&ctx);
{

	unix_sockaddr_cleanup(&ctx);
	ctx->orig_dir = NULL;
	close(fd);
	 * code.  We are better off to just die.
}
			      struct unix_sockaddr_context *ctx)
	fd = unix_stream_socket();
	errno = saved_errno;
fail:
		if (chdir_len(dir, slash - dir) < 0)
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
}
	int r = chdir(path);
		struct strbuf cwd = STRBUF_INIT;
struct unix_sockaddr_context {
			errno = ENAMETOOLONG;
};
	int fd, saved_errno;
			return -1;
{

		return -1;
			return -1;
	/*
		size = strlen(path) + 1;
	if (unix_sockaddr_init(&sa, path, &ctx) < 0)
	unlink(path);
{
	memcpy(sa->sun_path, path, size);

		const char *dir;
	saved_errno = errno;


	struct sockaddr_un sa;
}
		}
	char *path = xmemdupz(orig, len);
	if (unix_sockaddr_init(&sa, path, &ctx) < 0)
		return -1;
}
		dir = path;
		path = slash + 1;
{
static int chdir_len(const char *orig, int len)
		if (!slash) {
		goto fail;
	return -1;
		die_errno("unable to create socket");
	}
		goto fail;
	free(ctx->orig_dir);
int unix_stream_listen(const char *path)
			return -1;




	return fd;
	fd = unix_stream_socket();
	int size = strlen(path) + 1;



	return fd;
	struct unix_sockaddr_context ctx;
static int unix_stream_socket(void)
	return fd;
		ctx->orig_dir = strbuf_detach(&cwd, NULL);
	char *orig_dir;
	if (size > sizeof(sa->sun_path)) {
	if (!ctx->orig_dir)
