	}
int run_column_filter(int colopts, const struct column_options *opts)
}
		return 0;
		{ "never",  COL_DISABLED, COL_ENABLE_MASK },

	column_process.in = -1;

	if (data->cols == 0)
{

		int len = strcspn(value, sep);
		if (total_width > data->opts.width) {
	int i, len, newline;
			continue;
		   const struct column_options *opts)
	layout(&data, &initial_width);
	 */
		return 0;
		if (*width < data->len[i])
				break;
			}
		return -2;
	fflush(stdout);
	unsigned int colopts;
		if (stdout_is_tty < 0)
	else
#define ENABLE_SET 2
		if (arg_len != name_len ||
	int group_set = 0;
		data->cols = DIV_ROUND_UP(data->list->nr, data->rows);
		newline = i + data->rows >= data->list->nr;
		len += initial_width - data->len[data->width[x]];
{
	if (!list->nr)

			break;


			    data->len[data->width[x]] < data->len[i])

	struct column_options nopts;

#include "cache.h"
{
		case COL_LAYOUT_MASK:
	return 0;
		for (x = 0; x < data->cols; x++) {
		printf("%s%s%s", indent, list->items[i].string, nl);
	/*
		}
			  const struct column_options *opts)
	data->rows = DIV_ROUND_UP(data->list->nr, data->cols);

		if (!opts[i].mask) {

/* Display COL_COLUMN or COL_ROW */
	data->cols = (data->opts.width - strlen(data->opts.indent)) / *width;
		}
	}
{
static void compute_column_width(struct column_data *data)
#define XY2LINEAR(d, x, y) (COL_LAYOUT((d)->colopts) == COL_COLUMN ? \
	};
	int i;

				arg_len -= 2;
			data->cols = cols;
			stdout_is_tty = isatty(1);
			REALLOC_ARRAY(data->width, data->cols);
				data->width[x] = i;
 * Shrink all columns by shortening them one row each time (and adding

 * for new columns. The process ends when the whole thing no longer
{
	fflush(stdout);

	if ((*colopts & COL_ENABLE_MASK) == COL_AUTO) {
 * fits in data->total_width.
	column_process.git_cmd = 1;
	       x == 0 ? data->opts.indent : "",
	assert((colopts & COL_ENABLE_MASK) != COL_AUTO);
	len = data->len[i];

	}
		 * space.
			else
			break;
	data.list = list;
{
#define LAYOUT_SET 1
{
static void display_plain(const struct string_list *list,
	if (opts && opts->indent)
	struct column_options opts;
			break;
		value += strspn(value, sep);
 * moved to the next column, column is shrunk so we have more space
		data->rows--;
	free(data.width);
 * more columns along the way). Hopefully the longest cell will be
		return config_error_nonbool(var);
	REALLOC_ARRAY(data->width, data->cols);



	int i;
		 */
	       newline ? data->opts.nl : empty_cell + len);

			*colopts = (*colopts & ~opts[i].mask) | opts[i].value;
		cols = data->cols;
			total_width += data->opts.padding;
	if (fd_out != -1)

	printf("%s%s%s",
};
{
#include "parse-options.h"
	if (arg)


		data.len[i] = item_length(list->items[i].string);


{
				arg_str += 2;
 * Calculate cell width, rows and cols for a table of equal cells, given
	}
		 * is narrower, increase len a bit so we fill less
	if (command && !strcmp(it, command))
int git_column_config(const char *var, const char *value,
		compute_column_width(data);

		{ "always", COL_ENABLED,  COL_ENABLE_MASK },
		return -1;
}
			  unsigned int colopts,
{
}
	if (fd_out == -1)
	finish_command(&column_process);
	nopts.indent = opts && opts->indent ? opts->indent : "";
	return 0;

		break;
#include "run-command.h"
			i = XY2LINEAR(data, x, y);
		{ "plain",  COL_PLAIN,    COL_LAYOUT_MASK },
{
{

#include "string-list.h"
	int *len;		/* cell length */
		const char *arg_str = arg;
		break;


		data->cols = 1;
	switch (COL_LAYOUT(colopts)) {
	close(1);

				*colopts &= ~opts[i].value;
}
struct colopt {


		rows = data->rows;
	/* --column == always unless "arg" states otherwise */
	memset(&nopts, 0, sizeof(nopts));
}
		argv_array_pushf(argv, "--indent=%s", opts->indent);
	argv_array_push(argv, "column");
	const char *name;
		if (len) {

	if ((group_set & LAYOUT_SET) && !(group_set & ENABLE_SET))
	unsigned int *colopts = opt->value;
	 * If none of "always", "never", and "auto" is specified, then setting
/* Print a cell to stdout with all necessary leading/traling space */
		{ "dense",  COL_DENSE,    0 },
		if (data->cols != cols)
 */
		}
static int display_cell(struct column_data *data, int initial_width,
	data.opts = *opts;
	dup2(column_process.in, 1);
	unsigned int value;

	}

		    strncmp(arg_str, opts[i].name, name_len))

struct column_data {
	close(1);
		else {
			if (set)
			if (arg_len > 2 && !strncmp(arg_str, "no", 2)) {

	unsigned int mask;
		case COL_ENABLE_MASK:
	struct argv_array *argv;
	if (!skip_prefix(var, "column.", &it))
	char *empty_cell;
		*colopts = (*colopts & ~COL_ENABLE_MASK) | COL_ENABLED;

			*colopts |= COL_ENABLED;
	*colopts |= COL_ENABLED;
	struct colopt opts[] = {
		return parse_config(colopts, arg);
	const char *it;
	}
		return;
	struct column_data data;

	}
		name_len = strlen(opts[i].name);
	free(data.len);
	nopts.nl = opts && opts->nl ? opts->nl : "\n";
		display_plain(list, nopts.indent, nopts.nl);
		{ "auto",   COL_AUTO,     COL_ENABLE_MASK },
	argv_array_pushf(argv, "--raw-mode=%d", colopts);
	return 0;
		display_table(list, colopts, &nopts);

	nopts.padding = opts ? opts->padding : 1;
			total_width += data->len[data->width[x]];
	*width += data->opts.padding;
	return 0;
int finalize_colopts(unsigned int *colopts, int stdout_is_tty)
	*width = 0;
#include "config.h"
	const char *sep = " ,";
	 * you set column.ui = auto and pass --column=row, then "auto"

	if (unset)		/* --no-column == never */
	memset(empty_cell, ' ', initial_width);
	return 0;

static void shrink_columns(struct column_data *data)
			value += len;
	compute_column_width(data);
	int i;
				*colopts |= opts[i].value;

 */
	return 0;
	i = XY2LINEAR(data, x, y);
	if (!strcmp(it, "ui"))
	       data->list->items[i].string,
		display_plain(list, "", "\n");
}
		switch (opts[i].mask) {
			const char *empty_cell, int x, int y)
	memset(&data, 0, sizeof(data));
	while (*value) {
		return error("invalid column.%s mode %s", key, value);
		return -1;
	if (start_command(&column_process))
		return 0;
	 * layout implies "always".
	if (i >= data->list->nr)
			*group_set |= ENABLE_SET;
	for (i = 0; i < list->nr; i++)
			*group_set |= LAYOUT_SET;
		}
		return -1;
		int x, total_width, cols, rows;
	free(empty_cell);
		 * empty_cell has initial_width chars, if real column
	if (!column_active(colopts)) {

/* Display without layout when not enabled */
	int x, y, i, initial_width;

		BUG("invalid layout mode %d", COL_LAYOUT(colopts));
		int set = 1, arg_len = len, name_len;
static int item_length(const char *s)
	child_process_init(&column_process);
static void display_table(const struct string_list *list,
	empty_cell = xmallocz(initial_width);
{
	default:
	if (opts && opts->padding)
			data->rows = rows;
{
	close(column_process.in);
	ALLOC_ARRAY(data.len, list->nr);
	nopts.width = opts && opts->width ? opts->width : term_columns() - 1;
/* return length of 's' in letters, ANSI escapes stripped */
		*colopts &= ~COL_ENABLE_MASK;
	 * Current value in COL_ENABLE_MASK is disregarded. This means if
			 const char *key, unsigned int *colopts)
	if (opts && opts->width)
	int rows, cols;
static int parse_option(const char *arg, int len, unsigned int *colopts,
				set = 0;
			int *group_set)
	*colopts &= ~COL_ENABLE_MASK;
	data.colopts = colopts;



};

		      const char *command, unsigned int *colopts)
}
		/*
	argv = &column_process.args;
}
	const struct string_list *list;
	for (x = 0; x < data->cols; x++) {
		len -= data->opts.padding;
		{ "row",    COL_ROW,      COL_LAYOUT_MASK },
	if (colopts & COL_DENSE)
			    (x) * (d)->rows + (y) : \

}

	while (data->rows > 1) {
	}
	if (parse_config(colopts, value))
int parseopt_column_callback(const struct option *opt,
	*colopts |= COL_PARSEOPT;
#include "column.h"
		argv_array_pushf(argv, "--padding=%d", opts->padding);
{
	return utf8_strnwidth(s, -1, 1);

		data->width[x] = XY2LINEAR(data, x, 0);
	for (i = 0; i < list->nr; i++)
		}
	int *width;	      /* index to the longest row in column */
void print_columns(const struct string_list *list, unsigned int colopts,
	close(fd_out);
 * table width and how many spaces between cells.
		return column_config(var, value, "ui", colopts);
/*
		newline = x == data->cols - 1 || i == data->list->nr - 1;
	if (COL_LAYOUT(data->colopts) == COL_COLUMN)
}

	return 0;
			if (parse_option(value, len, colopts, &group_set))



		for (x = 0; x < data.cols; x++)
		for (y = 0; y < data->rows; y++) {
}
#include "utf8.h"
int stop_column_filter(void)
}
		if (opts[i].mask)
	column_process.out = dup(1);
		return column_config(var, value, it, colopts);
	 *
			    (y) * (d)->cols + (x))
		shrink_columns(&data);
	fd_out = -1;


	int i, x, y;
	case COL_ROW:
	fd_out = dup(1);
	if (data->width && data->len[data->width[x]] < initial_width) {

{
}
static void layout(struct column_data *data, int *width)
	if (!value)
			if (i < data->list->nr &&
		{ "column", COL_COLUMN,   COL_LAYOUT_MASK },
	for (i = 0; i < data->list->nr; i++)
		total_width = strlen(data->opts.indent);
}

		argv_array_pushf(argv, "--width=%d", opts->width);
			     const char *arg, int unset)
	case COL_PLAIN:
/*
}
	for (i = 0; i < ARRAY_SIZE(opts); i++) {
static int fd_out = -1;
	}
		}
				return -1;
	return 0;
		if (stdout_is_tty || pager_in_use())
static struct child_process column_process = CHILD_PROCESS_INIT;
			*width = data->len[i];
	dup2(fd_out, 1);
static int parse_config(unsigned int *colopts, const char *value)
			  const char *indent, const char *nl)

	for (y = 0; y < data.rows; y++) {
			if (display_cell(&data, initial_width, empty_cell, x, y))
static int column_config(const char *var, const char *value,

		return;
	 * will become "always".
}
	return error("unsupported option '%s'", arg);
		}
	case COL_COLUMN:
