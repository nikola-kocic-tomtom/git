		    (!*out || *out == '=')) {

}
		/* serve by default supports v2 */
	 */
			break;
	 * This field should be NULL for capabilities which are not commands.
	}
	PROCESS_REQUEST_KEYS,

	struct packet_reader reader;
		case PACKET_READ_DELIM:
	 * Optionally a value can be specified by adding it to 'value'.
			 * if command specific arguments were provided after a
	if (skip_prefix(key, "command=", &out)) {
	reader.options &= ~PACKET_READ_GENTLE_ON_EOF;
		if (skip_prefix(keys->argv[i], capability, &out) &&
	int i;
			return c;
			BUG("Should have already died when seeing EOF");

		const char *out;
		strbuf_reset(&value);
		strbuf_reset(&capability);
		 * immediately after advertising capabilities


	 * a single request/response exchange


	packet_flush(1);
	argv_array_clear(&keys);
		return 1;
		struct protocol_capability *cmd = get_capability(out);
			state = PROCESS_REQUEST_DONE;
	struct strbuf capability = STRBUF_INIT;
}
		*command = cmd;
			    out, (*command)->name);
			break;
		       struct packet_reader *request);
	}
	command->command(the_repository, &keys, &reader);
		 * If only the list of capabilities was requested exit
};
{
			 */
				strbuf_addbuf(&capability, &value);

			if (value.len) {

		if (options->advertise_capabilities)
	}
			    is_valid_capability(reader.line))

		const char *out;
			/* Consume the peeked line */
			    struct strbuf *value)
	if (packet_reader_peek(&reader) == PACKET_READ_EOF)
				die("unknown capability '%s'", reader.line);
			}

	 * use to read the command specific part of the request.  Every command
		for (;;)
	/*
};
#include "pkt-line.h"
		switch (packet_reader_peek(&reader)) {
			 * If no command and no keys were given then the client
	int i;

		       struct argv_array *keys,
		if (!cmd || !cmd->advertise(the_repository, NULL) || !cmd->command)
{
	 * specify this capability.
	for (i = 0; i < ARRAY_SIZE(capabilities); i++) {
static int is_valid_capability(const char *key)
			return 1;
	for (i = 0; i < ARRAY_SIZE(capabilities); i++) {




}
	 * The function will be provided the capabilities requested via 'keys'
		}
	if (!key)
		return NULL;


		}
}
	}
		if (*command)
	struct protocol_capability *command = NULL;

			packet_write(1, capability.buf, capability.len);
		}
	struct argv_array keys = ARGV_ARRAY_INIT;

{
#include "argv-array.h"
				argv_array_push(&keys, reader.line);
			   PACKET_READ_GENTLE_ON_EOF |
	enum request_state state = PROCESS_REQUEST_KEYS;
{
			/* Consume the peeked line */
		   const char **value)
	if (value)
			 * so that the command can read the flush packet and
#include "version.h"
	{ "server-option", always_advertise, NULL },
	 * MUST read until a flush packet is seen before sending a response.

			 * The flush packet isn't consume here like it is in
		die("no command requested");
	PROCESS_REQUEST_DONE,
	int (*command)(struct repository *r,
}
	 * If stateless-rpc was requested then exit after
			if (is_command(reader.line, &command) ||
			 * the other parts of this switch statement.  This is
	strbuf_release(&capability);
			 * see the end of the request in the same way it would
	 * If a value is added to 'value', the server will advertise this
		/*

	if (options->advertise_capabilities || !options->stateless_rpc) {
	 * as well as a struct packet_reader 'request' which the command should
static struct protocol_capability *get_capability(const char *key)
#include "ls-refs.h"
			state = PROCESS_REQUEST_DONE;

			/* collect request; a sequence of keys and values */
}
				strbuf_addch(&capability, '=');
	if (options->stateless_rpc) {
	for (i = 0; i < keys->argc; i++) {
	int (*advertise)(struct repository *r, struct strbuf *value);
	const char *name;
#include "upload-pack.h"
			strbuf_addch(&capability, '\n');
	 */
			packet_reader_read(&reader);
enum request_state {

			/*
	if (!command)

{
		case PACKET_READ_NORMAL:
static int is_command(const char *key, struct protocol_capability **command)
{
	 * The name of the capability.  The server uses this name when
			   PACKET_READ_CHOMP_NEWLINE |
			 */
static int agent_advertise(struct repository *r,

			die("command '%s' requested after already requesting command '%s'",
			die("invalid command '%s'", out);
	}
	 * Function called when a client requests the capability as a command.
#include "cache.h"
		process_request();
				*value = out;
	return 1;

		case PACKET_READ_FLUSH:
		advertise_capabilities();
	{ "fetch", upload_pack_advertise, upload_pack_v2 },
	packet_reader_init(&reader, 0, NULL, 0,


	 *
}
}
		if (skip_prefix(key, c->name, &out) && (!*out || *out == '='))
	while (state != PROCESS_REQUEST_DONE) {
	return 0;
			if (!keys.argc)
	 */
			break;
		case PACKET_READ_EOF:
	{ "ls-refs", always_advertise, ls_refs },
			return;
			packet_reader_read(&reader);
	/*
			strbuf_addstr(&capability, c->name);

	 */
	} else {
static void advertise_capabilities(void)
			if (value) {


		struct protocol_capability *c = &capabilities[i];
	/*

	}
			   PACKET_READ_DIE_ON_ERR_PACKET);
#include "serve.h"
struct protocol_capability {
static int always_advertise(struct repository *r,
	int i;
	return NULL;
	return 1;
	struct strbuf value = STRBUF_INIT;
	{ "agent", agent_advertise, NULL },
			if (process_request())
{
			 * wanted to terminate the connection.
					out++;

				if (*out == '=')
void serve(struct serve_options *options)
#include "config.h"
	strbuf_release(&value);
		strbuf_addstr(value, git_user_agent_sanitized());
	 * capability as "<name>=<value>" instead of "<name>".
	return 0;
		if (c->advertise(the_repository, &value)) {
	return c && c->advertise(the_repository, NULL);

		 */
		return 1;
	const struct protocol_capability *c = get_capability(key);
			}

	/*
			   struct strbuf *value)

		packet_write_fmt(1, "version 2\n");
	return 0;
}
			 * delim packet.
				break;
	const char *out;

	 */

	 * request.  If so we can terminate the connection.
/* Main serve loop for protocol version 2 */
static int process_request(void)
			/*
{
#include "repository.h"
	 * Function queried to see if a capability should be advertised.
	 * advertising this capability, and the client uses this name to
	/*
	 * Check to see if the client closed their end before sending another
};
int has_capability(const struct argv_array *keys, const char *capability,
		struct protocol_capability *c = &capabilities[i];

	}
			else
static struct protocol_capability capabilities[] = {
{
				return 1;
