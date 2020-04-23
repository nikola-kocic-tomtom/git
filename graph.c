 * graph_show_commit() or graph_show_oneline()) before calling
	 * number of parents:
	return NULL;
{
			return i;
 */
		graph_line_write_column(line, col, '-');
}
	struct column *columns;

	 *
	 *
	 * Output the row
	 * Output an ellipsis to indicate that a portion
			graph->commit_index = i;
	strbuf_addch(line->buf, c);
enum graph_state {
	 */
#include "cache.h"
			int idx = graph->merge_layout;
{
	/*


					 struct graph_line *line)
{

	 * when state is GRAPH_PRE_COMMIT
				 * Set the mappings for all but the
	else
			}
				}
	graph->prev_commit_index = 0;
		shown_commit_line = 1;
				for (j = (target * 2) + 3; j < (i - 2); j += 2)
			 * There is a branch line to our left

}
			 */
	 * We'll automatically grow columns later if we need more room.
	 */
				 */
	/*
	 * will look correct on the next row.)

static void graph_draw_octopus_merge(struct git_graph *graph, struct graph_line *line)
			 * printed as "\" on the previous line.  Continue
/*
		if (!graph_is_commit_finished(graph)) {

				horizontal_edge_target = target;
				assert(par_column >= 0);
	/*
		}
	p = sb->buf;
		 *		| |/		| *
static int graph_needs_pre_commit_line(struct git_graph *graph)

		const char *comma = strchrnul(start, ',');
	struct commit *commit;
		} else {
static struct strbuf *diff_output_prefix_callback(struct diff_options *opt, void *data)
	 * If none of the incoming columns refer to this commit,
	graph_show_line_prefix(default_diffopt);
		break;

			graph_line_addch(&line, ' ');
		j = graph->mapping[(graph->commit_index + i + 2) * 2];
	 * This way we start at 0 for the first commit.
	graph->expansion_row = 0;

	 * are already in the correct positions, we are done.
			 * line as '\' on this line, instead of '|'.  This
		strbuf_setlen(&msgbuf, 0);
	 * 		| | \
}
	struct column *col;
			 * The current commit always takes up at least 2
		if (col_commit == first_parent->item)
	}
		graph->edges_added = graph->num_parents + graph->merge_layout  - 2;
	 * following a post-merge line.
	graph->edges_added = 0;
	}
	int num_new_columns;
			for (j = 0; j < graph->num_parents; j++) {
	 */
	/*
			graph_show_line_prefix(&graph->revs->diffopt);
		return;
	for (i = 0; i < graph->num_new_columns; i++) {
	}
				graph_line_addch(line, ' ');
	 * are mapped onto display columns, for example this is a valid merge:
static unsigned short graph_get_current_column_color(const struct git_graph *graph)
	 */
	}

	graph_line_addstr(line, "...");
	 * We need 2 extra rows for every parent over 2.

		if (col_commit == graph->commit) {
		graph_output_padding_line(graph, &line);
/*
	/* setup an output prefix callback if necessary */
}
			 * coming into this commit may have been '\',
			 * already, and it is our target.  We
			col_commit = graph->commit;
	 */
	graph_padding_line(graph, &msgbuf);
	/* The rev-info used for the current traversal */
		graph->merge_layout = (dist > 0) ? 0 : 1;
#include "argv-array.h"
 * This is similar to graph_next_line().  However, it is guaranteed to
		return 0;
		if (i == graph->num_columns) {

	unsigned short default_column_color;
			 * new_columns and use those to format the
			graph->revs->diffopt.file);
static inline void graph_line_addstr(struct graph_line *line, const char *s)
						graph_line_addch(line, ' ');
		graph_next_line(graph, &msgbuf);
	 * if our caller has a bug, and invokes graph_next_line()
	 * Update graph->state
	return next_interesting_parent(graph, parents);
			 * We always need to increment graph->width by at
			free(string);
	 *
	GRAPH_COLLAPSING
			seen_this = 1;
	 * To find the right color for each dash, we need to consult the
			graph_insert_into_new_columns(graph, col_commit, -1);
static int graph_find_new_column_by_commit(struct git_graph *graph,
	if (graph_is_commit_finished(graph)) {

	       sizeof(char),
			if (seen_this)
	}
		}
	return (graph->state == GRAPH_PADDING);
				graph_line_write_column(line, &graph->new_columns[par_column], c);
				/*
		/*
	 *
	 * commit.
 * If a NULL graph is supplied, the strbuf is printed as-is.


		graph_line_write_column(line, col, (i == dashed_parents - 1) ? '.' : '-');
			graph->revs->diffopt.file);
			 * combine with this line, since we share
 * and 0 otherwise.
		 * the merge line based on whether the parent appears in a
	 * mapping array, starting from the column 2 places to the right of the
	 */
	 * 2-way and octopus merges, this is usually one less than the
	 *
	/*

	 * children that we have already processed.)
	/*
		graph_output_collapsing_line(graph, &line);

					graph->mapping[i] = -1;
		return parents;
	if (!want_color(graph->revs->diffopt.use_color))
 * If the strbuf is empty, no output will be printed.
	 */
}
			 *
static void graph_output_commit_char(struct git_graph *graph, struct graph_line *line)

			putc('\n', graph->revs->diffopt.file);
			int len = (graph->num_parents - 2) * 2;
 */

			 * makes the output look nicer.
	 * The number of columns added to the graph by the current commit. For
	REALLOC_ARRAY(graph->columns, graph->column_capacity);
	} else if (graph->edges_added > 0 && i == graph->mapping[graph->width - 2]) {
 * graph_show_strbuf().
	}
	/*

	return &msgbuf;
	/*

		} else {
static void parse_graph_colors_config(struct argv_array *colors, const char *string)
}
	 * in some cases that means we don't need any expansion rows at all:
				par_column = graph_find_new_column_by_commit(graph, parents->item);
	 * The commit_index for the previously displayed commit.
			/*

		} else {

	}
		} else {
		int target = graph->old_mapping[i];
	 */
	end = string + strlen(string);
						custom_colors.argc - 1);
	graph->num_parents = 0;
	 * logcial column, so commit_index gives us the right visual offset for
	struct column *parent_col = NULL;
	 */
			 * merges, so this is the first line of output
	/*
		} else {
	 * been shown are always interesting, even if they have the
	if (i < 0) {

	/*
void graph_show_commit(struct git_graph *graph)
	 *
	 * Otherwise, we need to collapse some branch lines together.
	/*
		if (newline_terminated)

	/*
	if (graph->state != GRAPH_PADDING)
	while (start < end) {
		return 0;
	 */
			      struct strbuf const *sb)
	}
			 * There is a branch line to our left,
		}
	 */
static void graph_pad_horizontally(struct git_graph *graph, struct graph_line *line)
		if (!shown_commit_line) {

	/*
	 * The width of the graph output for this commit.
		else if (target * 2 == i)
			if (seen_this)
	 */
		graph_padding_line(graph, &msgbuf);
	 *	| |_|_|/
						column_colors_ansi_max);
		if (i == graph->num_columns) {
			else
	/*
			if (used_horizontal && i < horizontal_edge)
static void graph_update_state(struct git_graph *graph, enum graph_state s)
	case GRAPH_COLLAPSING:
		 * cross, only one is moving directions.
				if (parent_col)

{
			 * Mark this branch as the horizontal edge to
	 * column, and we don't need as many expansion rows to route around it;
	strbuf_release(&msgbuf);

			int par_column;
			 i != horizontal_edge - 1) {
			parse_graph_colors_config(&custom_colors, string);
	 */
	 * since the current commit may not be in any of the existing
		return -1;
				} else {

			 * horizontally.

	REALLOC_ARRAY(graph->old_mapping, graph->column_capacity * 2);
	graph->expansion_row++;
	 * the integer indicates the target position for this branch line.
			len = next_p - p;
		graph_line_addcolor(line, c->color);
static inline void graph_line_addch(struct graph_line *line, int c)

}
{
	 * columns, new_columns, and mapping.
	strbuf_release(&msgbuf);
	start = string;
	int i, seen_this, is_commit_in_columns;

				      struct graph_line *line)
	 * before the commit, to expand the branch lines around it and make
		 *		| *
}

		} else if (graph->prev_state == GRAPH_COLLAPSING &&
	 * A copy of the contents of the mapping array from the last commit,
	int seen_this = 0;
			return graph->columns[i].color;
		graph_line_write_column(line, &graph->new_columns[i], '|');
	column_colors = colors;
		if (col->commit == graph->commit && graph->num_parents > 2) {
	/*
}

	struct commit_list *parents = graph->commit->parents;
			 *
	if (c->color < column_colors_max)
	graph->column_capacity = 30;
	 */
	 *
 * Draw the horizontal dashes of an octopus merge.

	for (;;) {
			is_commit_in_columns = 0;
	return graph->num_parents >= 3 &&
	 */
	struct graph_line line = { .buf = sb, .width = 0 };
	 */
	/*
}
 * Since the first line will not include the graph output, the caller is
	int horizontal_edge_target = -1;
		graph->mapping_size--;
	 */
	 * field tells us how many columns the first parent occupies.

	if (!graph->commit)
	 *
	 * The current output state.
	 * commit line.

			assert(graph->mapping[i] == -1);
	max_new_columns = graph->num_columns + graph->num_parents;
{


	 */
		return column_colors_max;
	 * The number of interesting parents that this commit has.
			 * lines after graph->prev_commit_index were

	if (!graph)
	return -1;
	 */

	assert(opt);
}
			graph->mapping[i - 2] = target;

			      FILE *file,
	/*
	 * The number of entries in the mapping array
	 * An array that tracks the current state of each
	line->width += n;

				horizontal_edge_target = target;

	for (i = 0; i < graph->num_new_columns; i++) {



	 * If the merge is skewed to the left, then its parents occupy one less
	seen_this = 0;
	 * be graph->num_columns + graph->num_parents columns for the next
			 */
			 */
		if (git_config_get_string("log.graphcolors", &string)) {
	} else {
	 * Normally, we need two expansion rows for each dashed parent line from
		if (target < 0)
			/*

		size_t len;
		return;
		return;
	for (i = 0; i < graph->num_columns; i++) {
	if (graph_needs_pre_commit_line(graph))
 */
	graph->num_parents = 0;
			break;
static void graph_output_commit_line(struct git_graph *graph, struct graph_line *line)
	 * Clear out graph->mapping
	line->width += strlen(s);
	 * previous commit.
	graph->state = s;
	 * The numbers denote which parent of the merge each visual column
	for (list = orig->next; list; list = list->next) {
	/*
	/*
				 */
	       graph->commit_index < (graph->num_columns - 1) &&
	COPY_ARRAY(graph->old_mapping, graph->mapping, graph->mapping_size);
{
	int max_new_columns;
		} else {
static void graph_increment_column_color(struct git_graph *graph)

{
		/*
			return 1;
	 * Output the row containing this commit
	if (graph)
	 * All rows for this commit are padded to this width, so that

	struct graph_line line = { .buf = sb, .width = 0 };


	int i;
};

	for (i = 0; i < graph->mapping_size; i++) {
		return NULL;
			 * least 2, even if it has no interesting parents.
	case GRAPH_SKIP:
 *
	if (line->width < graph->width)
		}
	 * which we use to improve the display of columns that are tracking
			if (graph->merge_layout != 0 || i != graph->commit_index - 1) {
	 */
		/*

	/*
	fwrite(msgbuf.buf, sizeof(char), msgbuf.len, graph->revs->diffopt.file);
				/*
	 */
}
{
	 */
			   opt->line_prefix_length);
		 * column to the left of the merge

		if (target < 0)
	if (opt->line_prefix)
struct graph_line {
void graph_update(struct git_graph *graph, struct commit *commit)

	 * with multiple parents, to make room for it.  It should only be
	 */
	}
			next_p++;
	 */
	if (graph->state != GRAPH_COMMIT) {
		 */
	if (!diffopt || !diffopt->line_prefix)


		 */
	graph->num_columns = graph->num_new_columns;
		if (target < 0)
	 */

	 * graph->columns.  If so, graph->new_columns should only contain a
	int width;

	 * case.
	int prev_commit_index;
	 * columns.  (This happens when the current commit doesn't have any
		}
	 * The maximum number of columns that can be stored in the columns
		if (next_p) {

			 * cross over it.

}
	/*
		} else {
		graph->state = GRAPH_PRE_COMMIT;
	fwrite(diffopt->line_prefix,
	 * (If it is 1 greater than the target, '/' will be printed, so it
{
		return;
	 *
	strbuf_addstr(line->buf, column_get_color_code(color));
		graph_line_addchars(line, ' ', graph->width - line->width);

	 * Output the post-merge row
{
	 * this will be equal to num_columns.

	 *		edges_added: 1		edges_added: 3
		 */
		} else if (seen_this) {
static struct commit_list *next_interesting_parent(struct git_graph *graph,
			argv_array_push(colors, color);
	enum graph_state state;
{
	 * columns.  (This happens when the current commit doesn't have any
 *
			 * line of output was.

	return;
	 * The maximum capacity of this array is always
	 * sizeof(int) * 2 * column_capacity.
	case GRAPH_COMMIT:
		assert(target * 2 <= i);
		 * column first, each branch's target location should
	     parent = next_interesting_parent(graph, parent))
	strbuf_addstr(line->buf, s);
	 * graph_update_columns() will update graph->commit_index for this
		graph->column_capacity *= 2;
	if (!graph_is_commit_finished(graph)) {

		 *
	}

			 * There is no GRAPH_PRE_COMMIT stage for such
	}
	/*
		}
static int graph_is_interesting(struct git_graph *graph, struct commit *commit)
			 * We don't have to add anything to the
	 * Call graph_update_columns() to update
	 * 		| | | *-.		| | *---.

	graph->prev_state = graph->state;
	 * Update graph->prev_state since we have output a padding line
		graph->state = GRAPH_COMMIT;
	graph->num_columns = 0;
		/*
	GRAPH_SKIP,
	/*
	int i, j;
	int i, seen_this;
	enum graph_state prev_state;
			 * but it isn't our target.  We need to
	/*
		struct column *col = &graph->columns[i];

	if (!graph)
{
	 */
	 * If the previous commit didn't get to the GRAPH_PADDING state,
	 *
	 * 		| |\
	 */
	return get_commit_action(graph->revs, commit) == commit_show;
				break;
	 * UNINTERESTING or TREESAME flags set.


	 */
{
	 */
	 */
		 * We never have to move branches to the right.  This makes
	 * aligned for the entire commit.
	 */
	 * This is primarily used to determine how the first merge line
}
			}
	       diffopt->line_prefix_length,
	 */
static void graph_show_strbuf(struct git_graph *graph,
			}
	 * Which layout variant to use to display merge commits. If the
	 *
			 * to print them as "\" on this line.  Otherwise,
			if (graph->prev_state == GRAPH_POST_MERGE &&
	for (i = 0; i < graph->mapping_size; i++) {
}
	/*

 * - Limit the number of columns, similar to the way gitk does.

	for (i = 0; i <= graph->num_columns; i++) {
		break;
	int newline_terminated;
	 *	|/| | |
	 * and display the graph info before each line but the first.
	int expansion_row;
		 * always be either its current location or to the left of

	graph->commit = commit;
		graph_output_pre_commit_line(graph, &line);
	/*
			len = (sb->buf + sb->len) - p;
	while (!shown_commit_line && !graph_is_commit_finished(graph)) {
	SWAP(graph->columns, graph->new_columns);
	 * The next expansion row to print
	strbuf_release(&msgbuf);
		return;
			continue;
			col_commit = graph->commit;
}
	 * The new mapping may be 1 smaller than the old mapping


	return column_colors[color];

		 * numbers so that the two edges immediately join, i.e.:
struct git_graph *graph_init(struct rev_info *opt)
}
	 * Copy the current mapping array into old_mapping
		graph->width += 2;
{
	 * The mapping is up to date if each entry is at its target,
	 * lines for a particular commit have the same width.
}
}

	struct git_graph *graph = xmalloc(sizeof(struct git_graph));
		return 0;
	       graph->mapping[graph->mapping_size - 1] < 0)
	 */
					graph_increment_column_color(graph);
	 * Store the old commit_index in prev_commit_index.
	 */
{
			col_commit = graph->columns[i].commit;
			col_commit = col->commit;
	 * The index of the column that refers to this commit.
	 * an octopus merge:

			   struct strbuf const *sb)
	 * Otherwise, use get_commit_action() to see if this commit is
	/*
	 * The number of columns added by the previous commit, which is used to
	 * Shrink mapping_size to be the minimum necessary
	 * Show the commit message
	 * 		|/|\ \
	int edges_added;
static const char *column_get_color_code(unsigned short color)
				graph_line_write_column(line, col, '|');
	 */
#include "graph.h"
	 */
			graph_show_line_prefix(&graph->revs->diffopt);

	struct git_graph *graph = data;
		graph_update_state(graph, GRAPH_POST_MERGE);
	 */
				 * color.
	int i;
		else if (target == horizontal_edge_target &&
	 */
	switch (graph->state) {
	seen_this = 0;
		 * the graph much more legible, since whenever branches
	/*

	 * avoid allocating a fresh array when we compute the next mapping.
	 * 		| | |			| |    \
				/*
	 * character in the output line during state GRAPH_COLLAPSING.
static void graph_padding_line(struct git_graph *graph, struct strbuf *sb);
	/*
	 * Start the column color at the maximum value, since we'll
	 */
				    !is_commit_in_columns) {
	     parent;
struct git_graph {
int graph_show_remainder(struct git_graph *graph)
	 * Note that we don't call graph_update_state() here, since
{
			if (seen_this)
	graph->prev_state = GRAPH_PADDING;
					if (graph->edges_added > 0 || j < graph->num_parents - 1)
			 * output or mapping, since the
	{
 * Output a padding line in the graph.
	/*
			putc('\n', file);
{
	 * This count excludes parents that won't be printed in the graph
	/*

		break;
	 * If there are less than 3 parents, we can immediately print the
					graph->mapping[j] = target;
{
		if (i == graph->num_columns) {

	 * This is used to determine how the first line of a merge
 *   If we reach more than a specified number of columns, omit
			struct commit_list *parents = first_parent;
	 */
}
				graph_line_write_column(line, col, '\\');
 * Update the graph's default column color.
		} else if (seen_this && (graph->expansion_row > 0)) {
};
		if (commit->object.flags & CHILD_SHOWN)
		fwrite(msgbuf.buf, sizeof(char), msgbuf.len,
	 *
			if (horizontal_edge == -1) {
			else
	 * edge will collapse to.
 * graph_show_strbuf can be called even with a NULL graph.
{
		graph_line_write_column(&line, col, '|');
	column_colors_max = colors_max;
	 *		| | |			| |  \
				graph_insert_into_new_columns(graph, parent->item, i);
};
	 * We'll re-use the old columns array as storage to compute the new
	 *		| | * \			| * |

		}
static void graph_output_collapsing_line(struct git_graph *graph, struct graph_line *line)
		diffopt->output_prefix = diff_output_prefix_callback;
static const struct diff_options *default_diffopt;
	 * a line to indicate that portion of the graph is missing.


	 */

			if (horizontal_edge == -1) {
}
	 * the merge commit.
	} while (graph->column_capacity < num_columns);
			seen_this = 1;
	 *
	if (!parents)
	 */
{
	/*
}
	graph->prev_edges_added = 0;
void graph_show_commit_msg(struct git_graph *graph,
	 * The parents of a merge commit can be arbitrarily reordered as they
	/*
		graph_output_commit_line(graph, &line);
				break;
		 *		* |		* |
			graph_line_write_column(line, &graph->new_columns[target], '|');
			if (graph->num_parents == 0)
	 *	| | *---.
	 * columns list for the commit after this one.
	 * 		| *-. \
				graph_line_write_column(line, col, '|');

	 * Allocate a reasonably large default number of columns

	if (!graph_needs_pre_commit_line(graph))
		 */
	int num_parents;
	       diffopt->file);
		graph->new_columns[i].commit = commit;
		 *
	struct strbuf *buf;
	 * 		|/| | | | |		| | | | | *
	 *
			 * This is the first line of the pre-commit output.
			   FILE *file,
{
	 */
			 * spaces.
			graph->mapping[i] = target;

 * If the strbuf ends with a newline, the output will end after this
	 */
			 */
	 *		num_parents: 2		num_parents: 4
	 *		| * |			| *---. \
	 *
	default_diffopt = diffopt;
			 * the same parent commit.
{
	GRAPH_PADDING,
static void graph_output_post_merge_line(struct git_graph *graph, struct graph_line *line)
			 * edges.

	 * Clear out the mapping array
	return graph;
		 * If some columns have been added by a merge, but this commit
		graph->mapping[i] = -1;
			return list;
	argv_array_push(colors, GIT_COLOR_RESET);
	 * Now update new_columns and mapping with the information for the
			if (graph->edges_added == 0)
			 */
			graph->merge_layout = -1;
	 * integer if the character contains a branch line.  The value of
		graph_output_post_merge_line(graph, &line);

		break;
				int j;
	GRAPH_COMMIT,
	 *		| * |			| *-. \
	 */
		graph_next_line(graph, sb);
	 * and new_columns arrays.  This is also half the number of entries

}
	 */
		int dist, shift;
	}
	 * we don't want to update graph->prev_state.  No line for
	if (graph_is_interesting(graph, parents->item))
	 *
	 *
			graph_line_write_column(line, col, '|');
				graph_line_write_column(line, col, '|');
						   struct commit_list *orig)
static int graph_num_expansion_rows(struct git_graph *graph)
 * next, it will simply output a line of vertical padding, extending the
	/*
	 * contain information about where each current branch line is
	graph_pad_horizontally(graph, &line);
	/*
	 * 		| |\ \ \
}
	 * supposed to end up after the collapsing is performed.
				parents = next_interesting_parent(graph, parents);
}
	 * and new_columns now contains the state for our commit.
	/*
				    char col_char)
	 * Otherwise, the value is 1 and the layout on the right is used. This
		} else {
	 * parent is interesting.  None of the others are.
	 * If there are 3 or more parents, we may need to print extra rows

 */
	strbuf_reset(&msgbuf);
 * responsible for printing this line's graph (perhaps via
			graph_line_write_column(line, col, '\\');
}
	newline_terminated = (sb->len && sb->buf[sb->len - 1] == '\n');
	int seen_this = 0;
 * prefixed with the graph output.
	graph_show_line_prefix(default_diffopt);
	int commit_index;
	graph_next_line(graph, &msgbuf);

static struct commit_list *first_interesting_parent(struct git_graph *graph)
 */
		graph_show_remainder(graph);
			/* graph_set_column_colors takes a max-index, not a count */
				}
			 * branch should always be empty.
	}
static void graph_output_padding_line(struct git_graph *graph,
}
			warning(_("ignore invalid color '%.*s' in log.graphColors"),
	 * all the diff output to align with the graph lines.
	int shown_commit_line = 0;
				for (j = (target * 2)+3; j < (i - 2); j += 2)
 * TODO:

{
		}

	 * it never finished its output.  Goto GRAPH_SKIP, to print out
	 * The new column state after we output the current commit.
	graph->commit_index = 0;
	 *		|/| |			|/|\ \ \
 * never print the current commit line.  Instead, if the commit line is
	 * We could conceivable be called with a NULL commit
	 *		| * \			| * |
	return graph_num_dashed_parents(graph) * 2;

	 *
			 * Since the current commit is a merge find
				 * column, and therefore target*2+3 is the
				if (i != (target * 2)+3)


 *   sections of some columns.
		start = comma + 1;
	 * The number of columns (also called "branch lines" in some places)
	graph_line_addch(line, col_char);
	opt->diffopt.output_prefix = diff_output_prefix_callback;
	 * When showing a diff of a merge against each of its parents, we

			continue;


		mapping_idx = graph->width - 2;
	else
			 */
	 * commit.
		char *string;
		break;
			 * select this one.
	 * graph->columns contains the state for the previous commit,
					graph->mapping[j] = target;
	 * interesting
		graph->mapping_size--;
		if (!color_parse_mem(start, comma - start, color))
{
				used_horizontal = 1;
void graph_show_oneline(struct git_graph *graph)
	graph->expansion_row = 0;
	 * The number of columns in the new_columns array
	is_commit_in_columns = 1;
	 * The commit currently being processed
	 * desired positions.)


	for (parent = first_interesting_parent(graph);

 * Returns 1 if the commit will be printed in the graph output,
	int i;
		}
#include "config.h"
	 * line would otherwise be used.
	SWAP(graph->mapping, graph->old_mapping);
	case GRAPH_POST_MERGE:
		} else if (graph->mapping[i - 1] == target) {
		struct commit *col_commit;
}
			 * the columns for the parent commits in
	unsigned short color;
	if (graph->revs->first_parent_only)
		if (col_commit == graph->commit) {
	 * output, as determined by graph_is_interesting().
	 * If the first parent is interesting, return it
	 */
	int i = graph_find_new_column_by_commit(graph, commit);
			/*
	       graph->expansion_row < graph_num_expansion_rows(graph);
	/*

	line->width++;
	 * If the commit is not already in the new_columns array, then add it
	 * 		| * \
	/*
}
		graph_update_state(graph, GRAPH_PADDING);
	if (graph_is_mapping_correct(graph))
 *
	 * Iterate up to and including graph->num_columns,
	else if (graph_needs_pre_commit_line(graph))
	int mapping_idx;
		struct commit *col_commit;
		 * so we can start the remainder of the graph output on a
		} else {
		fwrite(p, sizeof(char), len, file);
	 */
	if (graph_is_mapping_correct(graph))
			 * for this commit.  Check to see what the previous
			graph->mapping[i - 1] = target;
	 *		| |\ \			| |\ \ \ \
{
	 * corresponds to; we can't assume that the parents will initially
				int j;
			/*
	 */
			seen_this = 1;
	}
			argv_array_clear(&custom_colors);
		 * its current location.
	 *	| | |/ / /
	int dashed_parents = graph_num_dashed_parents(graph);

	graph->prev_commit_index = graph->commit_index;
#include "color.h"
		graph_show_padding(graph);
}
}
		}
		if (next_p && *next_p != '\0')
			 * If there isn't already an edge moving horizontally
		column_colors_max;
#include "revision.h"
	struct strbuf msgbuf = STRBUF_INIT;
	 * This way, fields printed to the right of the graph will remain
	/*
	if (c->color < column_colors_max)
	 *
	 */
{
	 * For boundary commits, print 'o'
	 *
}
		struct column *col = &graph->columns[i];
	/*
	/*
	/*
	 */
				horizontal_edge = i - 1;

					graph_line_addch(line, ' ');
	while (p) {
		} else {
{
			seen_this = 1;
				 */
		if (target == (i / 2))
				(int)(comma - start), start);
	/*
	 */
				 * If this is a merge, or the start of a new
		} else {
	 * and record it as being in the final column.

				graph_line_write_column(line, col, '\\');
	 */
			 * If it was GRAPH_POST_MERGE, the branch line
	 * Update graph->state
			graph_line_write_column(line, col, '\\');
	 * First, make sure we have enough room.  At most, there will

				graph->width += 2;
	if (graph->num_parents > 1)
	int i, j;
	int mapping_size;
	 * commit after this one.
	/*
			parent_col = col;

			 * care of it.
	/*
		graph_update_state(graph, GRAPH_COMMIT);
	 */
		graph->state = GRAPH_SKIP;
	if (!column_colors) {
			 * existing branch line has already taken
	 *	3 1 0 2
	/*
 * Print a strbuf.  If the graph is non-NULL, all lines but the first will be
	 *

			   graph->old_mapping[2 * i + 1] == i &&
		int target = graph->mapping[i];
		return NULL;
	else
	 * Update graph->state.

	GRAPH_POST_MERGE,
	 *	| | |\ \ \
		if (col_commit == graph->commit) {
	 * always increment it for the first commit we output.
	graph->num_new_columns = 0;
			}

{
	 * immediately after graph_init(), without first calling
	}
	/*
	int i;

	 * Output the row containing this commit
	strbuf_addchars(line->buf, c, n);
		graph_update_state(graph, GRAPH_COLLAPSING);
	}
	}
	int i;

	 * Some of the parents of this commit may already be in
	graph_ensure_capacity(graph, max_new_columns);
			graph_line_write_column(line, col, '/');

}
		} else if (seen_this && (graph->edges_added > 1)) {
		 */
	int horizontal_edge = -1;
			 * The space just to the left of this
void graph_show_padding(struct git_graph *graph)
	seen_this = 0;
			    graph->prev_edges_added > 0 &&
	 * called.  In this case, simply output a single padding line.
		graph->new_columns[i].color = graph_find_commit_color(graph, commit);
};
	/*
	fwrite(msgbuf.buf, sizeof(char), msgbuf.len, graph->revs->diffopt.file);
			graph_line_write_column(line, col, '|');
	 * Add additional spaces to the end of the strbuf, so that all
	 * graph->expansion_row tracks the current expansion row we are on.
	assert(graph->num_parents >= 3);


				 * actual screen column of the first horizontal
					      const struct commit *commit)
	int merge_layout;
				 * won't continue into the next line.
 * branch lines downwards, but leaving them otherwise unchanged.
	 *		| | | |         	| | | | | |
	 * 		| |\
	 * 		| |  \
		assert(graph->revs->boundary);
			/*

	 * This function formats a row that increases the space around a commit
		graph_line_addch(line, ' ');
	return graph->num_parents + graph->merge_layout - 3;

	struct strbuf msgbuf = STRBUF_INIT;
	else
static void graph_update_columns(struct git_graph *graph)
	 * merge commit, and use that to find out which logical column each
			if (graph->num_parents > 2)
	/*
{
			col_commit = graph->commit;
		} else if (seen_this && (graph->expansion_row == 0)) {
				break;
	/*
		graph_line_addcolor(line, column_colors_max);
			graph_line_addchars(&line, ' ', len);

}
			 * commit, or a left-skewed 3-way merge.
	graph->edges_added = 0;
	return shown_commit_line;


{
		 *		|\ \	=>	|\|
	if (graph->mapping[graph->mapping_size - 1] < 0)
		graph->num_parents++;
			      FILE *file,
	 * since the current commit may not be in any of the existing
	graph_update_columns(graph);
		/*
/*
static void graph_ensure_capacity(struct git_graph *graph, int num_columns)
	graph->commit = NULL;
	int num_columns;
	 * If revs->boundary is set, commits whose children have
	 * Note that this is not the same as the actual number of parents.
{
	if (diffopt && !diffopt->output_prefix)
	 * Iterate up to and including graph->num_columns,
	if (!graph)
			/*
				if (idx == 2) {
		if (graph_is_interesting(graph, list->item))
static inline void graph_line_addchars(struct graph_line *line, int c, size_t n)
	/*
	struct commit_list *list;
{
	 * 		| *
	 * display in the order given by new_columns.
			if (graph->edges_added > 0)

		p = next_p;
						line, parent_col, '_');
	 * single entry for each such commit.  graph->mapping should
	 * Swap the mapping and old_mapping arrays
			     parent;
	for (i = 0; i < graph->num_columns; i++) {
}
	opt->diffopt.output_prefix_data = graph;
	 *
	/*
	/*

		mapping_idx = graph->width + (graph->merge_layout - 1) * shift;
	graph->prev_state = GRAPH_PADDING;
		if (graph->columns[i].commit == commit)
	 *
			graph_line_write_column(line, col, '|');
	       graph->expansion_row < graph_num_expansion_rows(graph));
	 */


			for (parent = first_interesting_parent(graph);
			putc('\n', file);
}
		return;
	struct commit *commit;
	 */
	/*
	struct rev_info *revs;

	REALLOC_ARRAY(graph->new_columns, graph->column_capacity);
			else

	graph->num_new_columns = 0;
	graph->mapping_size = 2 * max_new_columns;
	graph_line_addstr(line, get_revision_mark(graph->revs, graph->commit));
	 * The color to (optionally) print this column in.  This is an
			char c;
	 */
	 */
	/*
static void graph_output_pre_commit_line(struct git_graph *graph,
	 * Return the next interesting commit after orig

				 * line.
		shift = (dist > 1) ? 2 * dist - 3 : 1;

	}
	for (i = 0; i <= graph->num_columns; i++) {
	 * 		| |_|/|\ \		| | |\ \ \
		graph->width += 2 * graph->merge_layout;
					graph_line_write_column(
}
	 * from right to left through a commit line.  We also use this to
			   graph->mapping[2 * i] < i) {
			graph_output_commit_char(graph, line);
		char color[COLOR_MAXLEN];
	}
}
	short used_horizontal = 0;
			 * print the branch lines as "|".
		graph_line_addch(line, 'o');
	 */
			graph_line_addch(line, ' ');
	 */
	 * or is 1 greater than its target.
		graph_output_skip_line(graph, &line);

		else
	 * The output state for the previous line of output.
 * handle directly. It is assumed that this is the same file handle as the
			 *
	const char *end, *start;
	/*
{
	graph_show_line_prefix(default_diffopt);
		shown_commit_line = 1;

	}
		 * If this is the first parent of a merge, choose a layout for
		graph_line_addch(line, ' ');
/*
			 */
{
	GRAPH_PRE_COMMIT,
{

	/*


{
		if (graph->new_columns[i].commit == commit)
{
	 * the next interesting parent
	 * (We should only see boundary commits when revs->boundary is set.)
	strbuf_release(&msgbuf);
	int *mapping;
	graph->merge_layout = 0;
	struct commit_list *first_parent = first_interesting_parent(graph);
	return graph_get_current_column_color(graph);
	for (i = 0; i < graph->mapping_size; i++) {
	if (!graph)
	 * This number determines how edges to the right of the merge are
	 * index into column_colors.
	 * Output out a line based on the new mapping info
		mapping_idx = graph->width;
	 */

	/*
		dist = idx - i;
			graph_show_oneline(graph);
static void graph_show_strbuf(struct git_graph *graph,
			}
	if (graph->column_capacity >= num_columns)
{
	 * called when there are 3 or more parents.
	/*
	graph_show_line_prefix(default_diffopt);
		break;
	 * of the graph is missing.
	graph->mapping_size = 0;
	}
	int i;
	/*
/*
	 * displayed in commit and post-merge lines; if no columns have been
	 * and move to state GRAPH_COMMIT if necessary
		int target = graph->mapping[i];
void graph_set_column_colors(const char **colors, unsigned short colors_max)
static unsigned short graph_find_commit_color(const struct git_graph *graph,
			if (graph->prev_state == GRAPH_POST_MERGE &&

		}
	}
	 * graph output should appear, based on the last line of the
			graph_line_addch(line, ' ');
	 */

	 * Print the strbuf line by line,
		graph_update_state(graph, GRAPH_PADDING);
}

	/*

	else if (graph_is_mapping_correct(graph))
		} else {
	 */
		graph_update_state(graph, GRAPH_COLLAPSING);
		 * If sb doesn't have a terminating newline, print one now,
{
	struct strbuf msgbuf = STRBUF_INIT;
			    graph->prev_commit_index < i)

	 */
static void graph_show_line_prefix(const struct diff_options *diffopt)

		if (target * 2 == i) {
	graph->default_column_color = column_colors_max - 1;
	for (i = 0; i < dashed_parents; i++) {
	assert(0 <= graph->expansion_row &&
 * newline.  A new graph line will not be printed after the final newline.
	}
		graph->edges_added = -1;
	}
	 *		edges_added: 0		edges_added: 2
			/*
	 *		num_parents: 2		num_parents: 4
{
static int graph_num_dashed_parents(struct git_graph *graph)
}
	 * It should be in the range [0, num_expansion_rows - 1]
	struct strbuf msgbuf = STRBUF_INIT;
	 * Otherwise, call next_interesting_parent() to get
	 */
				 * first segment to -1 so that they
			assert(graph->mapping[i - 2] < 0);
	 */

static const char **column_colors;
	 * are called once for each parent without graph_update having been
struct column {

			    graph->prev_commit_index < i)
{
	ALLOC_ARRAY(graph->mapping, 2 * graph->column_capacity);

	 * (I.e., this array maps the current column positions to their
			 * ended in the GRAPH_POST_MERGE state, all branch
	int prev_edges_added;
		}
				 * childless column, increment the current
	 * get_revision_mark() handles all other cases without assert()
			 * If the previous commit was a merge commit and
	 * graph->state was ever printed.
			 * prevent any other edges from moving
}
	ALLOC_ARRAY(graph->old_mapping, 2 * graph->column_capacity);
			/* not configured -- use default */
{
	if (graph->commit->object.flags & BOUNDARY) {
	 *
	while (graph->mapping_size > 1 &&
				graph->mapping[i] = -1;
	 * The parent commit of this column.
	 * Swap graph->columns with graph->new_columns
	 * For left-skewed merges, the first parent fuses with its neighbor and
 * Note that unlike some other graph display functions, you must pass the file
	 */
	 * children that we have already processed.)

	size_t width;
					  struct commit *commit,
}

			graph_line_write_column(line, col, '|');
		} else if (seen_this && (graph->edges_added == 1)) {

	 * Only valid when state is GRAPH_COLLAPSING.
			 * and not '|' or '/'.  If so, output the branch
	/*
	graph->state = GRAPH_PADDING;
	graph->default_column_color = (graph->default_column_color + 1) %
	 * room for it.  We need to do this only if there is a branch row
	for (i = 0; i < graph->mapping_size; i++)
	for (i = 0; i < graph->num_columns; i++) {
	/*
	 * (or more) to the right of this commit.
			putc('\n', graph->revs->diffopt.file);
			graph_set_column_colors(column_colors_ansi,
		graph_update_state(graph, GRAPH_PRE_COMMIT);
	 */
			 * Nothing is to the left.
				c = merge_chars[idx];
	do {
	/*
	 * commit's first parent is known to be in a column to the left of the
		shown_commit_line = graph_next_line(graph, &msgbuf);
	char *p;
	return 1;
	struct commit_list *parent;
	 *		| | |			| | | | |
		char *next_p = strchr(p, '\n');
	 * Set the new commit
			 * Move to the left by one
}
	 */
	if (graph_is_commit_finished(graph))
	static struct strbuf msgbuf = STRBUF_INIT;
			graph_set_column_colors(custom_colors.argv,
	int i;
/*
			col_commit = graph->columns[i].commit;
	 * The diff output prefix callback, with this we can make
	/*
	REALLOC_ARRAY(graph->mapping, graph->column_capacity * 2);
	struct commit_list *parent;
}
}
	 * should appear, based on the last line of the previous commit.
		graph->mapping[i] = -1;
			 */
	 * This tells us what kind of line graph_next_line() should output.
	case GRAPH_PADDING:
	if (graph->revs && graph->revs->boundary) {
	case GRAPH_PRE_COMMIT:
	}
static int graph_is_mapping_correct(struct git_graph *graph)
static unsigned short column_colors_max;
		graph_line_addch(line, ' ');
	graph->revs = opt;
	 * Increment graph->expansion_row,
	 * graph_update().  Return without outputting anything in this
	 * Populate graph->new_columns and graph->mapping
			graph_line_addchars(line, ' ', graph->expansion_row);

	graph_pad_horizontally(graph, &line);
	 */
		col = &graph->new_columns[j];
	if (graph->num_parents > 1 && idx > -1 && graph->merge_layout == -1) {
static void graph_insert_into_new_columns(struct git_graph *graph,
	/*
			      struct strbuf const *sb);
			/*
	for (i = 0; i <= graph->num_columns; i++) {
	graph_show_strbuf(graph, file, sb);
	return graph->width;
		strbuf_add(&msgbuf, opt->line_prefix,
		 * If sb ends with a newline, our output should too.
			     parent = next_interesting_parent(graph, parent)) {
		if (col->commit == graph->commit) {
					  int idx)

	/*
	 */

	 * messages printed after the graph output are aligned.
}
	 *	| |/| | /
	if (!graph)
		graph_update_state(graph, GRAPH_PADDING);
		shown = 1;
		struct commit *col_commit;

			 * This column is already in the
	 * The column state before we output the current commit.

	struct column *new_columns;
	return graph->default_column_color;
				horizontal_edge = i;
	/*
	 * If there is more output needed for this commit, show it now
			graph_line_write_column(line, &graph->new_columns[target], '_');
/* Internal API */
#include "commit.h"

	 * Output a padding row, that leaves all branch lines unchanged
{
	 *

	 * so one less column is added:
	ALLOC_ARRAY(graph->columns, graph->column_capacity);
}


	 */
	 * added then a vertical line should be used where a right-tracking
		 * was found in the last existing column, then adjust the
		if (!newline_terminated)
	int *old_mapping;
			assert(graph->mapping[i - 1] > target);
		return;

 * file specified by the graph diff options. This is necessary so that
		}
			graph_line_write_column(line, &graph->new_columns[target], '/');
	 *
		 * Since update_columns() always inserts the leftmost
	 * The current default column color being used.  This is
	 * If graph->mapping indicates that all of the branch lines
void graph_setup_line_prefix(struct diff_options *diffopt)
int graph_width(struct git_graph *graph)
		 * new line.
			 */
			 */
{
int graph_next_line(struct git_graph *graph, struct strbuf *sb)
	/*
	 * Count how many interesting parents this commit has
			 * This is either a right-skewed 2-way merge

				graph_line_write_column(line, col, '\\');
	int column_capacity;

	 *		| |\ \			|/| |
	return shown;
	/*
	ALLOC_ARRAY(graph->new_columns, graph->column_capacity);
	graph->width = 0;
				 * The variable target is the index of the graph
static void graph_output_skip_line(struct git_graph *graph, struct graph_line *line)
	 * 		0)			1)
				if (graph->num_parents > 1 ||
		}
			/*
	 *
	/*
		fwrite(msgbuf.buf, sizeof(char), msgbuf.len,
			/*

	 * Commits are rendered once all edges have collapsed to their correct
static void graph_line_write_column(struct graph_line *line, const struct column *c,
		} else {
int graph_is_commit_finished(struct git_graph const *graph)
			static struct argv_array custom_colors = ARGV_ARRAY_INIT;
					idx++;
		struct column *col = &graph->columns[i];
	graph->mapping[mapping_idx] = i;
	 * stored as an index into the array column_colors.
		} else if (graph->mapping[i - 1] < 0) {

{
static inline void graph_line_addcolor(struct graph_line *line, unsigned short color)
	 * If this commit has no parents, ignore it
		struct column *col = &graph->columns[i];
	 *
	 * Each entry is -1 if this character is empty, or a non-negative

				graph_draw_octopus_merge(graph, line);
static void graph_padding_line(struct git_graph *graph, struct strbuf *sb)
	 * 		| *
{
	for (i = 0; i < graph->mapping_size; i++)
		i = graph->num_new_columns++;
		strbuf_setlen(&msgbuf, 0);
			continue;
	 * that can be stored in the mapping and old_mapping arrays.
	graph->prev_edges_added = graph->edges_added;
					   struct commit *commit)
	}
			 * correct place

		graph_update_state(graph, GRAPH_COMMIT);

				else
 */
	 * merge, then this value is 0 and we use the layout on the left.
		return;

	int shown = 0;
	 * smooth edges appearing to the right of a commit in a commit line

	 * If revs->first_parent_only is set, only the first
	}
	int shown_commit_line = 0;
	/*
const char merge_chars[] = {'/', '|', '\\'};
