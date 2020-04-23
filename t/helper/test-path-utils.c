			argv++;

			names[i][--len] = (char)(' ' + (my_random() % ('\x7f' - ' ')));
			puts(absolute_path(argv[2]));
		else if (!strcmp(to, data[i].alternative))
	{ "usr/lib///",      "lib"  },
		else
	for (protect_ntfs = 0; protect_ntfs < 2; protect_ntfs++)
			if (count < 0)
	}
};

		for (i = 4; i < argc; i++)
		argv[1] ? argv[1] : "(there was none)");
struct test_data {
		return !!res;
		 * that use forward slashes.

	{ NULL,              "."    },
		struct string_list list = STRING_LIST_INIT_NODUP;
	{ "////",            "/", "//" },
	double cumul2;
	intptr_t x = (intptr_t)((struct string_list_item *)a)->util;

		puts(argv[2]);
		return test_function(basename_data, posix_basename, argv[1]);
		struct string_list ceiling_dirs = STRING_LIST_INIT_DUP;
			continue;
	{ "C:usr/lib",       "lib"  },
					verify_path(names[j], file_mode);
{
				data[i].alternative);
	double x = value;
		for (protect_hfs = 0; protect_hfs < 2; protect_hfs++)
		char *prefix = strip_path_suffix(argv[2], argv[3]);

	ALLOC_ARRAY(names, nr);
		failed = 1;
		int res = 0, i;

					"'%s' is%s a valid path\n",
	if (argc == 4 && !strcmp(argv[1], "longest_ancestor_length")) {

				break;
{
			puts(strlen(rel) > 0 ? rel : "(empty)");
		}
		int fd = open(argv[2], O_RDONLY), offset = atoi(argv[3]);
	nr = argc > 1 ? strtoul(argv[1], NULL, 0) : 1000000;
	}
				printf("protect_ntfs = %d, protect_hfs = %d: %lfms\n", protect_ntfs, protect_hfs, (end-begin) / (double)1e6);
			ssize_t count = read(fd, buffer, sizeof(buffer));

	{ "C:///",           "/"    },
{
			buf = "++failed++";
		strbuf_release(&realpath);
	}
#include "utf8.h"
				cumul2 += (end - begin) * (end - begin);
#include "string-list.h"
	{ "//",              "/", "//" },
		if (fd < 0)
	{ "\\usr\\",         "\\"     },
		int nongit_ok;

static double my_sqrt(double value)
	{ NULL,              "."      },

		return 0;
	{ "C:/usr",          "C:/"    },
			argv++;

		/*
}
			else
#endif
	char **names;
	return failed;
		puts(buf);
				die_errno("could not read '%s'", argv[2]);
	{ "C:",              "."    },
 */
	{ "//",              "/", "//" },
			stride = 1;
	for (i = 0; i < nr; i++) {
 */
	}
		const char *prefix = argv[2];
	{ "/usr/lib",        "/usr"   },
		filter_string_list(&ceiling_dirs, 0,
	intptr_t y = (intptr_t)((struct string_list_item *)b)->util;
	{ "usr\\lib",        "usr"    },
		while (argc > 3) {
static int test_function(struct test_data *data, char *(*func)(char *input),
		for (i = offset; i < list.nr; i+= stride)
			to = func(NULL);
	{ "usr/lib",         "usr"    },
	return my_random_value;
	if (argc > 1 && !strcmp(argv[1], "is_valid_path")) {
{
				res = error_errno("Cannot stat '%s'", argv[i]);
		string_list_split(&ceiling_dirs, argv[3], PATH_SEP, -1);
	{ "..",              ".."   },
	{ "usr\\lib\\\\\\",  "usr"    },
static char *posix_dirname(char *path)
	{ "C:/usr/lib",      "lib"  },
	if (argc >= 4 && !strcmp(argv[1], "prefix_path")) {
	/* --- win32 type paths --- */
	const char *to;    /* output: ... to this.            */
		return 0;
	/* --- POSIX type paths --- */
		argv++;
		return 0;
		if (argc > 3)

	return 1;
			xsnprintf(buffer, sizeof(buffer), "%s", data[i].from);
			return x + delta;
			if (write(1, buffer, count) < 0)

	char *to;
	{ "\\usr",           "\\"     },
		for (i = 2; i < argc; i++)

#include "cache.h"

					argv[i], expect ? "" : "not ");
	if (argc > 1 && !strcmp(argv[1], "--with-symlink-mode")) {
		for (;;) {
	return basename(path);
		normalize_argv_string(&prefix, argv[3]);
static uint64_t my_random_value = 1234;
	{ "C:usr/lib///",    "lib"  },

				fprintf(stderr,
			}
		*var = NULL;
		struct stat st;
			else

		argc--;
	if (argc > 1 && !strcmp(argv[1], "protect_ntfs_hfs"))
	{ "\\usr\\\\",       "usr"  },
	{ "\\\\",            "\\\\"   },
#include "test-tool.h"
	if (*var && (**var == '<' || **var == '('))
/*
					    argv[i], expect ? " not" : "");
	{ "/usr",            "/"      },
	return 1;
				funcname, data[i].from, to, data[i].to,

 * A very simple, reproducible pseudo-random generator. Copied from
		return !!res;
			die("Path \"%s\" could not be normalized", argv[2]);
				res = error("'%s' is %s.gitmodules", argv[i],


		 * absolute POSIX paths into DOS paths (e.g.,
	{ "\\\\\\",          "\\", "/" },
	{ "/usr/",           "/"      },
	}
	if (argc >= 2 && !strcmp(argv[1], "absolute_path")) {
#if defined(__MINGW32__) || defined(_MSC_VER)
	{ "\\\\\\",          "\\"     },
	{ "\\usr\\lib",      "lib"  },
	{ "C:///",           "C:/"    },
}
		}
			printf("ntfs=%d/hfs=%d: %lf%% slower\n", protect_ntfs, protect_hfs, (m[protect_ntfs][protect_hfs] - m[0][0]) * 100 / m[0][0]);


				res = error("'%s' is%s a valid path",
	}
		char *buf = xmallocz(strlen(argv[2]));
	{ "usr/lib///",      "usr"    },

}
static int cmp_by_st_size(const void *a, const void *b)
			argc--;
		while (argc > 2) {
		 * Windows, bash mangles arguments that look like
static char *posix_basename(char *path)
	{ "C:usr/lib",       "C:usr"  },

	{ "/",               "/"    },
		struct strbuf sb = STRBUF_INIT;
	}
	{ "\\",              "\\", "/" },
		size_t len = min_len + (my_random() % (max_len + 1 - min_len));
	}
}
 * die with an explanation.
static void normalize_argv_string(const char **var, const char *input)
				expect = 0;
	}

	}

		return 0;
		}
/*
	{ "",                "."      },
		double delta = (value / x - x) / 2;
		 * "D:\Src\msysgit\foo;D:\Src\msysgit\foo\bar"),


{
	if (argc >= 2 && !strcmp(argv[1], "real_path")) {
		if (stride < 1)
static struct test_data dirname_data[] = {
			v[protect_ntfs][protect_hfs] = my_sqrt(cumul2 / (double)repetitions - m[protect_ntfs][protect_hfs] * m[protect_ntfs][protect_hfs]);
	{ "C:/",             "/"    },
	char *ceil = item->string;
		 * We have to normalize the arguments because under
			puts(realpath.buf);

			printf("mean: %lfms, stddev: %lfms\n", m[protect_ntfs][protect_hfs] / (double)1e6, v[protect_ntfs][protect_hfs] / (double)1e6);
		*var = input;
		return !!res;
	{ "C:a",             "a"    },
				cumul += end - begin;
 *
	const char *alternative; /* output: ... or this.      */
 * have const parameters.
		}
 */
	my_random_value = my_random_value * 1103515245 + 12345;
			else
	{ "///",             "/", "//" },
	{ "/usr//",          "usr"  },
		}
	{ "C:/",             "C:/"    },
	{ "/usr",            "usr"  },
	{ "/",               "/"      },
}
			if (!strcmp("--not", argv[i]))
		int res = 0;
	return is_hfs_dotgitmodules(path) || is_ntfs_dotgitmodules(path);
		normalize_argv_string(&in, argv[2]);

			else if (expect != is_dotgitmodules(argv[i]))
 * It uses Newton's method to approximate the solution of 0 = x^2 - value.
	{ NULL,              NULL     }
				funcname, data[i].from, to, data[i].to);
	uint64_t cumul;
		long offset, stride, i;
}
	{ "usr",             "usr"  },
	{ "\\usr\\lib",      "\\usr"  },
			die_errno("could not skip %d bytes", offset);
{
	{ "C:/usr",          "usr"  },
		int len;
	{ "/usr/lib",        "lib"  },
		}
	{ "///",             "/", "//" },

	for (i = 0; data[i].to; i++) {
		stride = strtol(argv[3], NULL, 10);

			if (!strcmp("--not", argv[i]))
			error("FAIL: %s(%s) => '%s' != '%s', '%s'\n",
	{ "/usr/",           "usr"  },

		printf("%s\n", prefix ? prefix : "(null)");
		for (protect_hfs = 0; protect_hfs < 2; protect_hfs++) {
		 * absolute POSIX paths or colon-separate lists of
};
			if (!count)
			for (i = 0; i < repetitions; i++) {
 */
					argv[i], expect ? "" : " not");

	if (argc == 3 && !strcmp(argv[1], "normalize_path_copy")) {
			cumul2 = 0;
	if (!is_absolute_path(ceil))
	{ "\\usr\\\\",       "\\"     },
				printf("%"PRIuMAX"\n", (uintmax_t)st.st_size);
		len = longest_ancestor_length(path, &ceiling_dirs);

	if (argc > 2) {
 * A fast approximation of the square root, without requiring math.h.
		if (lseek(fd, offset, SEEK_SET) < 0)
				fprintf(stderr, "ok: '%s' is %s.gitmodules\n",
	if (argc == 2 && !strcmp(argv[1], "dirname"))
	const char *from;  /* input:  transform from this ... */
#if defined(__MINGW32__) || defined(_MSC_VER)
		die("Path \"%s\" is not absolute", ceil);
	{ "C:",              "C:.", "." },
/*
	fprintf(stderr, "%s: unknown function name: %s\n", argv[0],
	{ "C:/usr//",        "C:/"    },
	{ "usr",             "."      },
	uint64_t begin, end;
		struct stat st;
static int protect_ntfs_hfs_benchmark(int argc, const char **argv)
	{ "\\usr\\",         "usr"  },
 * `test-genrandom.c`.

	{ "..",              "."      },
		 * whereas longest_ancestor_length() requires paths
		die("Bad value: %s\n", input);
static int is_dotgitmodules(const char *path)
	for (protect_ntfs = 0; protect_ntfs < 2; protect_ntfs++)

	for (;;) {
 * GIT_CEILING_DIRECTORIES.  If the path is unusable for some reason,
				die_errno("could not write to stdout");
	else if (!strcmp(input, "<empty>"))
	}
	if (!strcmp(input, "<null>"))
		int rv = normalize_path_copy(buf, argv[2]);
static struct test_data basename_data[] = {
	/* --- POSIX type paths --- */
		offset = strtol(argv[2], NULL, 10);
		strbuf_release(&sb);
	if (argc == 4 && !strcmp(argv[1], "strip_path_suffix")) {
	if (argc == 3 && !strcmp(argv[1], "print_path")) {
{
		if (delta < epsilon && delta > -epsilon)
		else
	{ "",                "."    },
		return 0;
int cmd__path_utils(int argc, const char **argv)
					(void *)(intptr_t)st.st_size;
	double m[3][2], v[3][2];
		return 0;
static uint64_t my_random(void)
		return 0;
			strbuf_realpath(&realpath, argv[2], 1);

	char buffer[1024];
	if (value == 0)
/*
		printf("%d\n", len);
		string_list_clear(&ceiling_dirs, 0);

		setup_git_directory_gently(&nongit_ok);
		return !!res;
	if (argc > 2 && !strcmp(argv[1], "is_dotgitmodules")) {
	}
{
		x += delta;
	if (argc == 2 && !strcmp(argv[1], "basename"))
		for (i = 2; i < argc; i++)
	return dirname(path);
	{ "\\usr",           "usr"  },
		char buffer[65536];
	if (argc == 4 && !strcmp(argv[1], "relative_path")) {

	return x > y ? -1 : (x < y ? +1 : 0);
	const char *funcname)
		return 0;
#endif
		int res = 0, expect = 1, i;
		names[i] = xmallocz(len);

					    expect ? "not " : "");

		return 0;
	{ "usr\\lib\\\\\\",  "lib"  },
			argv++;
		char *path = xstrdup(argv[2]);
		while (len > 0)
	{ ".",               "."    },
		const char *in, *prefix, *rel;
	{ "\\\\",            "\\", "/" },
}
	{ "/usr//",          "/"      },
		die("Path \"%s\" could not be normalized", ceil);
		if (rv)
	if (argc == 4 && !strcmp(argv[1], "skip-n-bytes")) {
	size_t i, j, nr, min_len = 3, max_len = 20;
	{ "C:usr/lib///",    "C:usr"  },

	}
			argc--;
{
}
	/* --- win32 type paths --- */
	{ "C:/usr//",        "usr"  },
	{ "\\\\\\\\",        "\\"     },
			continue;
		close(fd);
				   normalize_ceiling_entry, NULL);

		min_len = strtoul(argv[2], NULL, 0);
	if (argc > 2 && !strcmp(argv[1], "file-size")) {
		QSORT(list.items, list.nr, cmp_by_st_size);
				res = error_errno("Cannot stat '%s'", argv[i]);
				string_list_append(&list, argv[i])->util =
				for (j = 0; j < nr; j++)
	{ "usr/lib",         "lib"  },

static int normalize_ceiling_entry(struct string_list_item *item, void *unused)
};
	return 0;
			max_len = strtoul(argv[3], NULL, 0);
	{ "C:/usr/",         "C:/"    },
		int res = 0, expect = 1, i;
		int prefix_len = strlen(prefix);
			if (stat(argv[i], &st))
	}
		rel = relative_path(in, prefix, &sb);
		struct strbuf realpath = STRBUF_INIT;
			m[protect_ntfs][protect_hfs] = cumul / (double)repetitions;
		 * "/foo:/foo/bar" might be converted to
		for (i = 2; i < argc; i++)
		return test_function(dirname_data, posix_dirname, argv[1]);

			die_errno("could not open '%s'", argv[2]);
	if (!*ceil)
		if (!data[i].alternative)

		file_mode = 0120000;

 * Compatibility wrappers for OpenBSD, whose basename(3) and dirname(3)
 * A "string_list_each_func_t" function that normalizes an entry from
		die("Empty path is not supported");
			puts(prefix_path(prefix, prefix_len, argv[3]));
	{ "\\",              "\\"     },
		if (normalize_path_copy(path, path))
	else

	if (argc > 5 && !strcmp(argv[1], "slice-tests")) {
	const double epsilon = 1e-6;
}
				end = getnanotime();
			die("min_len > max_len");
	{ "C:/usr/lib",      "C:/usr" },
			else if (expect != is_valid_path(argv[i]))
{
	}
		if (!data[i].from)
			else
		free(path);
		if (!strcmp(to, data[i].to))
{
}
	{ "usr\\lib",        "lib"  },

			puts("(null)");
	if (normalize_path_copy(ceil, ceil) < 0)

			cumul = 0;
	{ ".",               "."      },

				expect = !expect;
	{ "C:/usr",          "usr"  },
	{ "C:/usr/",         "usr"  },
	}
	}
	}
				begin = getnanotime();

}
		if (min_len > max_len)
		while (argc > 2) {
	int failed = 0, i;
		return !!protect_ntfs_hfs_benchmark(argc - 1, argv + 1);
			argc--;
			printf("%s\n", list.items[i].string);
			if (stat(argv[i], &st))
			error("FAIL: %s(%s) => '%s' != '%s'\n",
		return 0;
	{ "C:a",             "C:."    },
	{ NULL,              NULL   }
		 */
		else {
			to = func(buffer);
	{ "////",            "/", "//" },

		if (!rel)
		*var = "";
	int repetitions = 15, file_mode = 0100644;
