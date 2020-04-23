{
#include "cache.h"
{
	}
			pack_line(argv[i]);
}

	if (argc) { /* read from argv */
}

			printf("0001\n");
			break;
			band = reader.line[0] & 0xff;
		packet_write_fmt(1, "%s", line);

				die("unexpected side band %d", band);
		pack(argc - 2, argv + 2);
		case PACKET_READ_NORMAL:
		packet_flush(1);
		}
static void unpack(void)
			break;
		packet_delim(1);
			fd = band;
static void unpack_sideband(void)
		case PACKET_READ_NORMAL:
}
			   PACKET_READ_CHOMP_NEWLINE);
		switch (reader.status) {
		die("too few arguments");
			printf("0000\n");
	}
		die("invalid argument '%s'", argv[1]);

	packet_reader_init(&reader, 0, NULL, 0,
}
		case PACKET_READ_FLUSH:
			printf("%s\n", reader.line);
	}
		unpack();
	else
		unpack_sideband();

		case PACKET_READ_EOF:
		int band;
	if (!strcmp(line, "0000") || !strcmp(line, "0000\n"))

		case PACKET_READ_FLUSH:
		case PACKET_READ_DELIM:
static void pack_line(const char *line)
		switch (reader.status) {
		case PACKET_READ_EOF:
			break;
	while (packet_reader_read(&reader) != PACKET_READ_EOF) {

		}

			if (band < 1 || band > 2)
		while (fgets(line, sizeof(line), stdin)) {
			break;
#include "test-tool.h"
		int fd;
			   PACKET_READ_CHOMP_NEWLINE);
	else if (!strcmp(line, "0001") || !strcmp(line, "0001\n"))
			break;
#include "pkt-line.h"
	} else { /* read from stdin */
int cmd__pkt_line(int argc, const char **argv)
	else
			write_or_die(fd, reader.line + 1, reader.pktlen - 1);
		char line[LARGE_PACKET_MAX];

	else if (!strcmp(argv[1], "unpack-sideband"))
{
	packet_reader_init(&reader, 0, NULL, 0,
			break;
}
		int i;
	struct packet_reader reader;
{
	return 0;
		for (i = 0; i < argc; i++)

	if (argc < 2)
	else if (!strcmp(argv[1], "unpack"))
	struct packet_reader reader;
{
	while (packet_reader_read(&reader) != PACKET_READ_EOF) {
			   PACKET_READ_GENTLE_ON_EOF |
static void pack(int argc, const char **argv)
			pack_line(line);
			   PACKET_READ_GENTLE_ON_EOF |

			return;
			break;
		case PACKET_READ_DELIM:
	if (!strcmp(argv[1], "pack"))
		}
