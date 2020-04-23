
void argv_array_pushl(struct argv_array *array, ...)
	va_list ap;

}

const char *empty_argv[] = { NULL };
			free((char *)array->argv[i]);

		argv_array_push(array, *argv);
	ALLOC_GROW(array->argv, array->argc + 2, array->alloc);
}

}
		int i;

	argv_array_push_nodup(array, strbuf_detach(&v, NULL));

	}
			break;
}

	array->alloc = 0;
	array->argv[array->argc - 1] = NULL;
	else {
		for (i = 0; i < array->argc; i++)
void argv_array_pop(struct argv_array *array)
		to_split = p;
	va_start(ap, array);
const char *argv_array_pushf(struct argv_array *array, const char *fmt, ...)

	va_end(ap);

	const char *arg;
}
{

	}
{

	free((char *)array->argv[array->argc - 1]);
}
	return array->argv[array->argc - 1];
}
	va_end(ap);
	array->argv = empty_argv;
	}
		argv_array_push_nodup(array, xstrndup(to_split, p - to_split));
void argv_array_pushv(struct argv_array *array, const char **argv)
}
{


		const char *p = to_split;
		const char **ret = array->argv;
}
		free(array->argv);
const char **argv_array_detach(struct argv_array *array)
const char *argv_array_push(struct argv_array *array, const char *value)
	strbuf_vaddf(&v, fmt, ap);
		return xcalloc(1, sizeof(const char *));
		to_split++;
	if (array->argv == empty_argv)
{
{
	va_start(ap, fmt);
	while (isspace(*to_split))
	if (array->argv == empty_argv)

		if (!*p)
static void argv_array_push_nodup(struct argv_array *array, const char *value)
{
	argv_array_init(array);
		return;
	argv_array_push_nodup(array, xstrdup(value));
{
		argv_array_push(array, arg);
			p++;
#include "strbuf.h"
		argv_array_init(array);
		return ret;
	array->argc = 0;
{
		array->argv = NULL;
	array->argc--;
	va_list ap;

		while (*p && !isspace(*p))
#include "argv-array.h"
	for (; *argv; argv++)
void argv_array_init(struct argv_array *array)
#include "cache.h"
{
	struct strbuf v = STRBUF_INIT;
{
	array->argv[array->argc] = NULL;
void argv_array_split(struct argv_array *array, const char *to_split)
	if (!array->argc)
	if (array->argv != empty_argv) {
	while ((arg = va_arg(ap, const char *)))
	return array->argv[array->argc - 1];
void argv_array_clear(struct argv_array *array)
	for (;;) {
	array->argv[array->argc++] = value;
}

			p++;
		while (isspace(*p))

