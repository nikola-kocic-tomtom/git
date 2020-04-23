	 */
		for_each_string_list_item(item, &list) {
	 * multiple 'version' keys can be sent by the client, indicating that
#include "config.h"
		return protocol_v1;
		const struct string_list_item *item;
		enum protocol_version env = parse_protocol_version(git_test_v);
			const char *value;
			enum protocol_version v;
		return env;


			die("server is speaking an unknown protocol");
{

	 * Determine which protocol version the client has requested.  Since
	const char *value;
{
		string_list_clear(&list, 0);
		if (version == protocol_unknown_version)
		return version;
		struct string_list list = STRING_LIST_INIT_DUP;
	if (git_protocol) {
		if (version == protocol_unknown_version)
			die("unknown value for config 'protocol.version': %s",
			die("unknown value for %s: %s", git_test_k, git_test_v);
				if (v > version)
			if (skip_prefix(item->string, "version=", &value)) {
	git_test_v = getenv(git_test_k);
			}
	 * the client is okay to speak any of them, select the greatest version
		return protocol_v2;
			    value);

	}


	else if (!strcmp(value, "1"))


	return version;
				v = parse_protocol_version(value);

		version = parse_protocol_version(server_response);
enum protocol_version determine_protocol_version_server(void)
		string_list_split(&list, git_protocol, ':', -1);
	if (skip_prefix(server_response, "version ", &server_response)) {

	enum protocol_version version = protocol_v0;
	if (!strcmp(value, "0"))
enum protocol_version determine_protocol_version_client(const char *server_response)

		if (version == protocol_v0)
	}
		}
#include "cache.h"
		enum protocol_version version = parse_protocol_version(value);
	const char *git_test_v;
	return version;


enum protocol_version get_protocol_version_config(void)
}
	else if (!strcmp(value, "2"))
#include "protocol.h"
	 * the most recent protocol version will be the most state-of-the-art.
	const char *git_protocol = getenv(GIT_PROTOCOL_ENVIRONMENT);
}
{
	return protocol_v2;
	if (git_test_v && *git_test_v) {

{
}
	/*
		return protocol_unknown_version;
	}

					version = v;
	}
	 * that the client has requested.  This is due to the assumption that


		return protocol_v0;
	if (!git_config_get_string_const("protocol.version", &value)) {
	const char *git_test_k = "GIT_TEST_PROTOCOL_VERSION";
static enum protocol_version parse_protocol_version(const char *value)

	enum protocol_version version = protocol_v0;
		if (env == protocol_unknown_version)
			die("protocol error: server explicitly said version 0");
}
	else
