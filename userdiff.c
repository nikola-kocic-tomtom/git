		struct userdiff_driver *drv = drivers + i;
	 /* -- */
		/*
}
		if (!strncmp(drv->name, k, len) && !drv->name[len])
		return git_config_string(&drv->word_regex, k, v);
	 /* Numbers */
	 /* Operators and atoms that represent them */
		drv->name = xmemdupz(name, namelen);
#include "attr.h"
	 /* C functions */
	return userdiff_find_by_namelen(name, len);
	 "|[-+*/<>%&^|=!.]=|--|\\+\\+|<<=?|>>=?|===|&&|\\|\\||::|->"),
IPATTERN("fortran",
	 "!^[ \t]*[A-Za-z_][A-Za-z_0-9]*:[[:space:]]*($|/[/*])\n"
	return 0;
	 "[a-zA-Z_][a-zA-Z0-9_]*"
IPATTERN("fountain", "^((\\.[^.]|(int|ext|est|int\\.?/ext|i/e)[. ]).*)$",
	 "!;\n"
}
	 "[^<>= \t]+"),
	 "![:;][[:space:]]*$\n"

	int i;
	 /* -- */
		"(\\([^)]*\\)[ \t]*)?" /* prototype */
	 "^(((class[ \t]+)?(procedure|function)|constructor|destructor|interface|"
	int len = strlen(name);
	 /* Objective-C class/protocol definitions */
	1,
	if (parse_config_key(k, "diff", &name, &namelen, &type) || !name)
	 "^(@(implementation|interface|protocol)[ \t].*)$",
PATTERNS("pascal",
	 "|[0-9][0-9_a-fA-Fiosuxz]*(\\.([0-9]*[eE][+-]?)?[0-9_fF]*)?"
	if (!path)
	if (ATTR_UNSET(check->items[0].value))
	 "!^[ \t]*(do|while|for|if|else|instanceof|new|return|switch|case|throw|catch|using)\n"
	 "|&&=|\\|\\|=|//=|\\*\\*="
		return parse_funcname(&drv->funcname, k, v, REG_EXTENDED);
	 "|[-+*/<>%&^|=!]=|--|\\+\\+|<<=?|>>=?|&&|\\|\\||::|->\\*?|\\.\\*"),
PATTERNS("php",
PATTERNS("tex", "^(\\\\((sub)*section|chapter|part)\\*{0,1}\\{.*)$",
	NULL,
		ALLOC_GROW(drivers, ndrivers+1, drivers_alloc);
	if (!strcmp(type, "binary"))
	 "^[ \t]*(([A-Za-z_][A-Za-z_0-9]*[ \t]+)+[A-Za-z_][A-Za-z_0-9]*[ \t]*\\([^;]*)$",
#include "userdiff.h"
	else
	 "|[-+*/<>%&^|=!]=|--|\\+\\+|<<=?|>>=?|&&|\\|\\||::|->"),

	return 0;
	 /* Structs and interfaces */
	 "|=~|!~"
{
#define IPATTERN(name, pattern, word_regex)			\
#include "cache.h"
	 "[a-zA-Z_][a-zA-Z0-9_]*"
	0,
	struct userdiff_driver *drv;
		driver->textconv_cache = c;
	 "^[ \t]*((END[ \t]+)?(PROGRAM|MODULE|BLOCK[ \t]+DATA"
	if (!strcmp(type, "xfuncname"))
		struct userdiff_driver *drv = builtin_drivers + i;
	 "^((::[[:space:]]*)?[A-Za-z_].*)$",
	if (!strcmp(type, "textconv"))
	  word_regex "|[^[:space:]]|[\xc0-\xff][\x80-\xbf]+" }
static int drivers_alloc;
{
{
	{ NULL, 0 }
IPATTERN("ada",
	 "^(BEGIN|END|INIT|CHECK|UNITCHECK|AUTOLOAD|DESTROY)[ \t]*"
		return NULL;
	 "|[-+0-9.eE]+i?|0[xX]?[0-9a-fA-F]+i?"
	 "^[\t ]*((((final|abstract)[\t ]+)?class|interface|trait).*)$",
	  * allow ISO 10646 characters U+00A0 and higher,
	  */
		const char *v, int cflags)
	 "^[ \t]*([-+][ \t]*\\([ \t]*[A-Za-z_][A-Za-z_0-9* \t]*\\)[ \t]*[A-Za-z_].*)$\n"
	 "^[\t ]*((pub(\\([^\\)]+\\))?[\t ]+)?((async|const|unsafe|extern([\t ]+\"[^\"]+\"))[\t ]+)?(struct|enum|union|mod|trait|fn|impl)[< \t]+[^;]*)$",
	*b = git_config_bool(k, v);
	 "^[ \t]*((/[ \t]*\\{|&?[a-zA-Z_]).*)",
	 /* -- */
	 /* Objective-C methods */

};
	 "|//=?|[-+*/<>%&^|=!]=|<<=?|>>=?|===|\\.{1,3}|::|[!=]~"),
	 "!=\n"
		strbuf_addf(&name, "textconv/%s", driver->name);
	 "[a-zA-Z_][a-zA-Z0-9_]*"
	const char *name, *type;
		return &driver_false;
	  word_regex "|[^[:space:]]|[\xc0-\xff][\x80-\xbf]+" }

	{ NULL, 0 }
static struct userdiff_driver *userdiff_find_by_namelen(const char *k, int len)
PATTERNS("python", "^[ \t]*((class|(async[ \t]+)?def)[ \t].*)$",
		return git_config_string(&drv->external, k, v);
		return -1;
	 "|=>|-[rwxoRWXOezsfdlpSugkbctTBMAC>]|~~|::"
	  * that is understood by both.
}
	 "[a-zA-Z][a-zA-Z0-9_]*"
	  * This regex comes from W3C CSS specs. Should theoretically also
	if (v && !strcasecmp(v, "auto"))

		return NULL;
}
	if (driver->textconv_want_cache && !driver->textconv_cache) {
IPATTERN("css",
		 * point it seems reasonable enough to give up.
		*b = git_config_bool(k, v);
	 "|[-+0-9.e]+[fFlL]?|0[xXbB]?[0-9a-fA-F]+[lL]?"
	if (ATTR_TRUE(check->items[0].value))
		"|([^'\" \t]+[ \t]+)*(SUBROUTINE|FUNCTION))[ \t]+[A-Z].*)$",
	 /* Not real operators, but should be grouped */
	static struct attr_check *check;
	return userdiff_find_by_name(check->items[0].value);


	 /* -- */
	"diff=true",
	  * but they are not handled in this regex.
	 /*
	 /* taking care not to interpret 3..5 as (3.)(.5) */
	 /* Properties */
		struct strbuf name = STRBUF_INIT;
PATTERNS("elixir",
	 "\n"
static int parse_tristate(int *b, const char *k, const char *v)
	if (!strcmp(type, "command"))
		*b = -1;
	 "[a-zA-Z_][a-zA-Z0-9_]*|[-+0-9.e]+|[=~<>]=|\\.[*/\\^']|\\|\\||&&"),
static struct userdiff_driver builtin_drivers[] = {
	}
		strbuf_release(&name);
};
	 "!^[ \t]*(do|for|if|else|return|switch|while)\n"
	 "^package .*\n"
	 "[a-zA-Z_][a-zA-Z0-9_]*"
	return NULL;
	 "^[ \t]*((procedure|function)[ \t]+.*)$\n"
	 /* Namespace */
					      struct userdiff_driver *driver)
		return parse_bool(&drv->textconv_want_cache, k, v);
PATTERNS("java",
	 "|--|\\+\\+|<<=?|>>>?=?|&&|\\|\\|"),
PATTERNS("bibtex", "(@[a-zA-Z]{1,}[ \t]*\\{{0,1}[ \t]*[^ \t\"@',\\#}{~%]*).*$",
	 /* -- */
		 */
	 "[a-zA-Z_][a-zA-Z0-9_]*"
struct userdiff_driver *userdiff_find_by_name(const char *name)
	 "!^[ \t]*MODULE[ \t]+PROCEDURE[ \t]\n"
	 "[a-zA-Z0-9,._+?#-]+"
		"(#.*)?$\n"
	 "|<>|<=|>=|:=|\\.\\."),
	 "\\\\[a-zA-Z@]+|\\\\.|[a-zA-Z0-9\x80-\xff]+"),
static struct userdiff_driver driver_false = {

	 "[={}\"]|[^={}\" \t]+"),
PATTERNS("golang",
	 "|[-+0-9.e]+[jJlL]?|0[xX]?[0-9a-fA-F]+[lL]?"
	 "!^[ \t]*(catch|do|for|if|instanceof|new|return|switch|throw|while)\n"
		return &driver_true;
	 "|[-+*/%.^&<>=!|]="
	f->cflags = cflags;
	 "|[-+0-9.e]+|0[xXbB]?[0-9a-fA-F]+"

	for (i = 0; i < ARRAY_SIZE(builtin_drivers); i++) {
	 "|=>|\\.\\.|\\*\\*|:=|/=|>=|<=|<<|>>|<>"),
		"(\\{[ \t]*)?" /* brace can come here or on the next line */
};
	return 0;
PATTERNS("matlab",
	 /* Property names and math operators */
	 "|:?(\\+\\+|--|\\.\\.|~~~|<>|\\^\\^\\^|<?\\|>|<<<?|>?>>|<<?~|~>?>|<~>|<=|>=|===?|!==?|=~|&&&?|\\|\\|\\|?|=>|<-|\\\\\\\\|->)"
	  * '##' can also be used to begin code sections, in addition to '%%'
PATTERNS("html", "^[ \t]*(<[Hh][1-6]([ \t].*)?>.*)$",
{
#define PATTERNS(name, pattern, word_regex)			\
	if (!check)
	 "|[-+*/<>%&^|=!]=|//=?|<<=?|>>=?|\\*\\*=?"),
			return drv;
PATTERNS("perl",
	 /* -- */
int userdiff_config(const char *k, const char *v)
	 "^(.*=[ \t]*(class|record).*)$",
	 /* -- */
		memset(drv, 0, sizeof(*drv));
static int ndrivers;
}
			return drv;
		 * to accept lines like "sub foo; # defined elsewhere".

	 "!^[ \t]*with[ \t].*$\n"
	drv = userdiff_find_by_namelen(name, namelen);
	 /* -- */
PATTERNS("ruby", "^[ \t]*((class|module|def)[ \t].*)$",
	 "|<<|<>|<=>|>>"),
		if (!strncmp(drv->name, k, len) && !drv->name[len])
	 "^[ \t]*(([A-Za-z_][A-Za-z_0-9]*[ \t]+)+[A-Za-z_][A-Za-z_0-9]*[ \t]*\\([^;]*)$\n"
	 "|[-+0-9.e]+[fFlL]?|0[xXbB]?[0-9a-fA-F]+[lLuU]*"
PATTERNS("csharp",
	 "^=head[0-9] .*",	/* POD */
	 /* Negate C statements that can look like functions */
	 /* -- */
	  * Octave pattern is mostly the same as matlab, except that '%%%' and
	 /*
	 /* -- */
	 "[a-zA-Z_][a-zA-Z0-9_]*"
	 /* Type definitions */
	 "^[ \t]*(((static|public|internal|private|protected|new|virtual|sealed|override|unsafe|async)[ \t]+)*[][<>@.~_[:alnum:]]+[ \t]+[<>@._[:alnum:]]+[ \t]*\\(.*\\))[ \t]*$\n"
	 "|[-+]?0[xob][0-9a-fA-F]+"
	 /* Jump targets or access declarations */
	 "^[ \t]*(((static|public|internal|private|protected|new|unsafe|sealed|abstract|partial)[ \t]+)*(class|enum|interface|struct)[ \t]+.*)$\n"
	 "[a-zA-Z_][a-zA-Z0-9_]*"
	 "(@|@@|\\$)?[a-zA-Z_][a-zA-Z0-9_]*"
	if (!drv) {
		drv->binary = -1;
	 /* -- */
PATTERNS("rust",
					      const char *path)
	  * Don't worry about format statements without leading digits since
	 "^[[:space:]]*((classdef|function)[[:space:]].*)$|^(%%%?|##)[[:space:]].*$",
	 "^sub [[:alnum:]_':]+[ \t]*"
	 "|0[xb]?[0-9a-fA-F_]*"
	git_check_attr(istate, path, check);

	if (!strcmp(type, "wordregex"))
	 /* Numbers with specific base */

struct userdiff_driver *userdiff_get_textconv(struct repository *r,
	return 0;
	 "^[ \t]*(namespace[ \t]+.*)$",
	for (i = 0; i < ndrivers; i++) {
	 "|[-+]?[0-9.]+([AaIiDdEeFfLlTtXx][Ss]?[-+]?[0-9.]*)?(_[a-zA-Z0-9][a-zA-Z0-9_]*)?"
	 "|:?%[A-Za-z0-9_.]\\{\\}?"),
	int namelen;
	}
	if (!driver->textconv)
	 "|[-+0-9.e]+|0[xXbB]?[0-9a-fA-F]+"
}
	 "|[0-9a-fA-F_]+(\\.[0-9a-fA-F_]+)?([eE][-+]?[0-9_]+)?"

static struct userdiff_driver *drivers;
	 "|[-+]?[0-9][0-9#_.aAbBcCdDeEfF]*([eE][+-]?[0-9_]+)?"
	 "|[-+*/<>%&^|=!]=|--|\\+\\+|<<=?|>>=?|&&|\\|\\||::|->"),
	 "|//|\\*\\*|::|[/<>=]="),
	 "-?[_a-zA-Z][-_a-zA-Z0-9]*" /* identifiers */
		drv = &drivers[ndrivers++];

	 /* lines beginning with a word optionally preceded by '&' or the root */
	 "|[-+*/%&^|!~]|>>|<<|&&|\\|\\|"),
	return driver;
	 "|[-+]?[0-9][0-9_.]*([eE][-+]?[0-9_]+)?"
	 "|[-+*/<>%&^|=!:]=|--|\\+\\+|<<=?|>>=?|&\\^=?|&&|\\|\\||<-|\\.{3}"),
	 "|\\.([Ee][Qq]|[Nn][Ee]|[Gg][TtEe]|[Ll][TtEe]|[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][Ee]|[Aa][Nn][Dd]|[Oo][Rr]|[Nn]?[Ee][Qq][Vv]|[Nn][Oo][Tt])\\."
		return git_config_string(&drv->textconv, k, v);

#undef PATTERNS
	if (git_config_string(&f->pattern, k, v) < 0)
	 "|&&|\\|\\||//|\\+\\+|--|\\*\\*|\\.\\.\\.?"
		"implementation|initialization|finalization)[ \t]*.*)$"

	 "[a-zA-Z_][a-zA-Z0-9_]*"
static int parse_funcname(struct userdiff_funcname *f, const char *k,
		"(\\{[ \t]*)?" /* brace can come here or on the next line */
static int parse_bool(int *b, const char *k, const char *v)
	if (!strcmp(type, "cachetextconv"))
	 /* numbers and format statements like 2E14.4, or ES12.6, 9X.
	{ name, NULL, -1, { pattern, REG_EXTENDED },		\
	if (!strcmp(type, "funcname"))
PATTERNS("cpp",
	 "^[ \t]*((package|protected|task)[ \t]+.*)$",
		struct notes_cache *c = xmalloc(sizeof(*c));

	 /* Methods and constructors */
	 "[^ \t-]+"),
struct userdiff_driver *userdiff_find_by_path(struct index_state *istate,
	"!diff",
	{ name, NULL, -1, { pattern, REG_EXTENDED | REG_ICASE }, \
	 /* Keywords */
	 /* -- */
	 /* Atoms, names, and module attributes */
	 /* -- */
	 "[a-zA-Z_][a-zA-Z0-9_]*"
		return NULL;


	 "^[ \t]*((def(macro|module|impl|protocol|p)?|test)[ \t].*)$",
	 /* -- */
		"(#.*)?$\n" /* comment */
		return parse_tristate(&drv->binary, k, v);
	 "!^([C*]|[ \t]*!)\n"
	 "^[ \t]*(((static|public|internal|private|protected|new|virtual|sealed|override|unsafe)[ \t]+)*[][<>@.~_[:alnum:]]+[ \t]+[@._[:alnum:]]+)[ \t]*$\n"
{
		 * so just slurp up whatever we see, taking care not
	 "|[-+*\\/<>%&^|=!:]=|<<=?|>>=?|&&|\\|\\||->|=>|\\.{2}=|\\.{3}|::"),
#include "config.h"
		check = attr_check_initl("diff", NULL);
	 "!^(.*[ \t])?(is[ \t]+new|renames|is[ \t]+separate)([ \t].*)?$\n"
	 "^[ \t]*(func[ \t]*.*(\\{[ \t]*)?)\n"
	 "[@:]?[a-zA-Z0-9@_?!]+"
	}
	 "[[:alpha:]_'][[:alnum:]_']*"
	 /* -- */
		return 0;
	 /* -- */

}
	 "^[_a-z0-9].*$",
	  */
	NULL,
		 *
	}
}

	 "|[-+0-9.e]+[fFlL]?|0[xXbB]?[0-9a-fA-F]+[lL]?"
	 "|[-+*/<>%&^|=!]="
{ "default", NULL, -1, { NULL, 0 } },
	if (ATTR_FALSE(check->items[0].value))
	 /* Functions */
		"(:[^;#]*)?"
		return parse_funcname(&drv->funcname, k, v, 0);
	 "|[-+0-9.e]+[fFlL]?|0[xXbB]?[0-9a-fA-F]+[lL]?"
{
#undef IPATTERN
PATTERNS("objc",
	 "|[-+0-9.e]+|0[xXbB]?[0-9a-fA-F]+|\\?(\\\\C-)?(\\\\M-)?."
{
		 * Attributes.  A regex can't count nested parentheses,
	 /* functions/methods, variables, and compounds at top level */
	 /* -- */
	 "|-?[0-9]+|\\#[0-9a-fA-F]+" /* numbers */
{
),
static struct userdiff_driver driver_true = {
	 "[a-zA-Z][a-zA-Z0-9_]*"
	  * they would have been matched above as a variable anyway. */
	 "^[\t ]*(((public|protected|private|static)[\t ]+)*function.*)$\n"
		 * An attribute could contain a semicolon, but at that
	 "^[ \t]*(type[ \t].*(struct|interface)[ \t]*(\\{[ \t]*)?)",
PATTERNS("dts",
		notes_cache_init(r, c, name.buf, driver->textconv);
