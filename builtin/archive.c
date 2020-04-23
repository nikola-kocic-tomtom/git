}
	transport_connect(transport, "git-upload-archive", exec, fd);

	struct option local_opts[] = {
		die(_("git archive: expected ACK/NAK, got a flush packet"));
			   PACKET_READ_CHOMP_NEWLINE |

	};
	 * Inject a fake --format field at the beginning of the
	if (packet_reader_read(&reader) != PACKET_READ_FLUSH)

		die(_("git archive: expected a flush"));
			       const char *name_hint)
			     PARSE_OPT_NO_INTERNAL_HELP	)
		create_output_file(output);
		OPT_STRING(0, "remote", &remote, N_("repo"),
 * Copyright (c) 2006 Franck Bui-Huu
			packet_write_fmt(fd[1], "argument --format=%s\n", format);
#include "builtin.h"
	setvbuf(stderr, NULL, _IOLBF, BUFSIZ);
			   PACKET_READ_DIE_ON_ERR_PACKET);
	}
		OPT_STRING(0, "exec", &exec, N_("command"),
/*
#include "pkt-line.h"
			N_("path to the remote git-upload-archive command")),
#include "parse-options.h"
{
	if (packet_reader_read(&reader) != PACKET_READ_NORMAL)
		die(_("git archive: Remote with no URL"));
	 * it.
	if (name_hint) {
			die_errno(_("could not redirect output"));
			     PARSE_OPT_KEEP_ARGV0 | 	\
		OPT_FILENAME('o', "output", &output,
			       const char *remote, const char *exec,
		else
 * Copyright (c) 2006 Rene Scharfe

}
		return run_remote_archiver(argc, argv, remote, exec, output);
int cmd_archive(int argc, const char **argv, const char *prefix)
{
#define PARSE_OPT_KEEP_ALL ( PARSE_OPT_KEEP_DASHDASH | 	\

			     N_("write the archive to this file")),
	if (strcmp(reader.line, "ACK")) {
	/* Now, start reading from fd[0] and spit it out to stdout */
	 * filename. This way explicit --format options can override
	if (output_fd < 0)

}
	if (remote)
		packet_write_fmt(fd[1], "argument %s\n", argv[i]);
	 */
		if (starts_with(reader.line, "NACK "))
	/*
	const char *remote = NULL;

			     PARSE_OPT_KEEP_UNKNOWN |	\

 */
	 * arguments, with the format inferred from our output
	transport = transport_get(_remote, _remote->url[0]);
	struct transport *transport;
		OPT_END()
#include "cache.h"
	if (output_fd != 1) {

		const char *format = archive_format_from_filename(name_hint);
	struct packet_reader reader;
		die_errno(_("could not create archive file '%s'"), output_file);
		if (dup2(output_fd, 1) < 0)
		die(_("git archive: protocol error"));
	init_archivers();

	const char *output = NULL;


	argc = parse_options(argc, argv, prefix, local_opts, NULL,
static void create_output_file(const char *output_file)
#include "transport.h"
			close(output_fd);
static int run_remote_archiver(int argc, const char **argv,
#include "sideband.h"


	return !!rv;
	return write_archive(argc, argv, prefix, the_repository, output, 0);

	rv |= transport_disconnect(transport);
	struct remote *_remote;
{
	for (i = 1; i < argc; i++)
	int fd[2], i, rv;
			     PARSE_OPT_KEEP_ALL);
	int output_fd = open(output_file, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	rv = recv_sideband("archive", fd[0], 1);
	if (!_remote->url[0])
#include "archive.h"
			die(_("git archive: NACK %s"), reader.line + 5);
	}

	if (output)
	}
	_remote = remote_get(remote);
	packet_reader_init(&reader, fd[0], NULL, 0,
	packet_flush(fd[1]);

			N_("retrieve the archive from remote repository <repo>")),
	const char *exec = "git-upload-archive";
		if (format)
