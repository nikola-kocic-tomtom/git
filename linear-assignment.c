		int i1 = free_row[free_count], low = 0, up = 0, last, k;
				if (u2 > c) {
						min = c;
					j = col[k];
					if (c < min) {

			i0 = column2row[j1];
	free(v);
						d[j] = c;

	free(col);

				int j1 = col[low++];
					}
	}
			column2row[j1] = i;

			int min = COST(!j1, i) - v[!j1];
			if (j < 0)
		do {

		int j1 = row2column[i];
			column2row[j] = i;
				row2column[i1] = -2 - row2column[i1];
				}
				if (column2row[col[k]] == -1)
			row2column[i] = -2 - j1;
		int min, c, u1;
		free_count = 0;
				else
			if (j2 < 0) {
			}
			if (COST(j, i1) > COST(j, i))
			i = pred[j];
 * Based on: Jonker, R., & Volgenant, A. (1987). <i>A shortest augmenting path
			}
						j2 = j;
			if (u1 < u2)
					c = COST(j, i) - v[j] - u1;
	free(d);
		j = -1;
 * 38(4), 325-340.
				j2 = j1;
 * The parameter `cost` is the cost matrix: the cost to assign column j to row
						u2 = u1;

					}
	for (j = column_count - 1; j >= 0; j--) {
	if (free_count ==
		for (k = 0; k < last; k++) {
		return;
			SWAP(j, row2column[i]);
	/* column reduction */
					goto update;

 * i is `cost[j + column_count * i].
							if (column2row[j] == -1)
		else if (j1 < -1)
						j2 = j1;
			}
				int c = COST(j, i) - v[j];
			column2row[j] = -1;
		v[j] = COST(j, i1);
								goto update;
	if (column_count < 2) {
		if (j1 == -1)
			i = free_row[k++];
			last = low;
			if (i0 >= 0) {
	memset(column2row, -1, sizeof(int) * column_count);
		return;
				v[j1] -= u2 - u1;
		free(v);
			for (k = up; k < column_count; k++) {
				i1 = i;
			if (row2column[i1] >= 0)
				if (j != j1 && min > COST(j, i) - v[j])
			int j1 = 0, j2, i0;
			u1 = COST(j1, i) - v[j1];
						}

	}
			v[j1] += d[j1] - min;
/*
	}
				}
	for (free_count = 0; free_count < saved_free_count; free_count++) {
			j2 = -1;
void compute_assignment(int column_count, int row_count, int *cost,
	/* augmentation */
			u2 = INT_MAX;
#include "cache.h"
				j = col[k];
		memset(row2column, 0, sizeof(int) * row_count);


	free(free_row);
				}
							col[k] = col[up];
		}
			v[j1] -= min;
			do {
			else if (i0 >= 0) {
	int *v, *d;
	ALLOC_ARRAY(pred, column_count);
							col[up++] = j;
			row2column[i1] = j;
			d[j] = COST(j, i1) - v[j];
					}
				if (c <= min) {
			int u1, u2;
#define COST(column, row) cost[(column) + column_count * (row)]
 */
	int i, j, phase;
		} while (low == up);
			int *column2row, int *row2column)
		} while (i1 != i);
update:
		int i1 = 0;
		else {
			for (k = low; k < up; k++)
					} else {
	ALLOC_ARRAY(col, column_count);
		}
	/* augmenting row reduction */
					if (c < d[j]) {
	for (phase = 0; phase < 2; phase++) {

		/* updating of the column pieces */
		}
	ALLOC_ARRAY(v, column_count);
			}

		for (i = 1; i < row_count; i++)
		} else {
	}
			/* row i1 unassigned */
			col[j] = j;
 * algorithm for dense and sparse linear assignment problems</i>. Computing,
	    (column_count < row_count ? row_count - column_count : 0)) {
					free_row[free_count++] = i0;
			pred[j] = i1;
				BUG("negative j: %d", j);
		while (k < saved_free_count) {
					min = COST(j, i) - v[j];
		memset(column2row, 0, sizeof(int) * column_count);
	ALLOC_ARRAY(free_row, row_count);
				u1 = COST(j1, i) - v[j1] - min;

			int j1 = col[k];
 */
				u2 = u1;
						u2 = c;
#include "linear-assignment.h"
					free_row[--k] = i0;
			row2column[i] = j1;
				i = column2row[j1];
	memset(row2column, -1, sizeof(int) * row_count);



			} while (low != up);
	ALLOC_ARRAY(d, column_count);
		saved_free_count = free_count;
		int k = 0;
			for (j = 1; j < column_count; j++) {
			/* scan a row */

				c = d[j];
}
		do {
						pred[j] = i;

	}
				i0 = column2row[j1];

	saved_free_count = free_count;
		if (row2column[i1] == -1) {
	}
				if (u1 < u2)
				j1 = j2;
					col[up++] = j;
		free(free_row);
		}
		/* augmentation */
			}

			for (j = 1; j < column_count; j++)
						up = low;
		for (j = 0; j < column_count; j++) {
/*
	int *free_row, free_count = 0, saved_free_count, *pred, *col;
	free(pred);
	/* reduction transfer */

			min = d[col[up++]];
					col[k] = col[up];
			column2row[j] = i1;
						j1 = j;
				for (k = up; k < column_count; k++) {
			free_row[free_count++] = i;
					if (u1 < c) {
	for (i = 0; i < row_count; i++) {
		}
{
						u1 = c;
						if (c == min) {
