}


	free(buf);
	LPWSTR                 TargetName;
	else if (!strcmp(argv[1], "store"))
static void read_credential(void)
			write_item("password",
}
 */


	load_cred_funcs();
		 die("Out of memory");

			protocol = utf8_to_utf16_dup(v);
{
 * Match an (optional) expected string and a delimiter in the target string,
	cred.CredentialBlob = (LPVOID)password;
	CredDeleteW = (CredDeleteWT)GetProcAddress(advapi, "CredDeleteW");
	/* load DLLs */
				creds[i]->CredentialBlobSize / sizeof(WCHAR));
	if (!protocol || !(host || path))


/* common helpers */
	if (!advapi)

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
	    FALSE);

}
	/* prepare 'target', the unique key for the credential */
}
}
			wusername = utf8_to_utf16_dup(v);
		die("WideCharToMultiByte failed!");
/*
	return ret;
		while (len && strchr("\r\n", buf[len - 1]))
} CREDENTIAL_ATTRIBUTEW, *PCREDENTIAL_ATTRIBUTEW;
		if (!strcmp(buf, "protocol"))


		match_part_last(&target, wusername, L"@") &&
		else if (!strcmp(buf, "path"))
static CredDeleteWT CredDeleteW;
		if (match_cred(creds[i]))
	wcsncat(target, protocol, ARRAY_SIZE(target));
				(LPCWSTR)creds[i]->CredentialBlob,
typedef VOID (WINAPI *CredFreeT)(PVOID);
	/* otherwise, ignore unknown action */
	va_end(params);
	const char *usage =
		return;
	if (!wusername || !password)
	if (host)
	LPWSTR                 TargetAlias;
	exit(1);
	else if (!strcmp(argv[1], "erase"))
 * A git credential helper that interface with Windows' Credential Manager
				LOAD_LIBRARY_SEARCH_SYSTEM32);
		char *v;
	fwrite(buf, 1, len, stdout);
		store_credential();
}
 */

	if (!argv[1])
{
	int i;
		*ptarget = delim_pos ? delim_pos + wcslen(delim) : start + len;
		return 0;
{
 * consuming the matched text by updating the target pointer.


	/* find start of delimiter (or end-of-string if delim is empty) */
}
{
	cred.CredentialBlobSize = (wcslen(password)) * sizeof(WCHAR);
	cred.UserName = wusername;
	cred.Attributes = NULL;
	DWORD  Flags;
	else



			break;
static void die(const char *err, ...)
	LPWSTR                 Comment;
#define CRED_PERSIST_LOCAL_MACHINE 2
	DWORD                  CredentialBlobSize;
	/*
	CredEnumerateW = (CredEnumerateWT)GetProcAddress(advapi,
	}
		return 0;
	if (delim_pos || want)
	void *ret = malloc(size);
/* MinGW doesn't have wincred.h, so we need to define stuff */

		if (!*buf)
	MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, wlen);
 *
		else if (!strcmp(buf, "username")) {
		wcsncat(target, host, ARRAY_SIZE(target));
	wcscpy(target, L"git:");
	vsnprintf(msg, sizeof(msg), err, params);
{
typedef BOOL (WINAPI *CredEnumerateWT)(LPCWSTR, DWORD, DWORD *,
{
				creds[i]->UserName ? wcslen(creds[i]->UserName) : 0);
	LPCWSTR target = cred->TargetName;
	cred.AttributeCount = 0;
		v = strchr(buf, '=');
	CredFree(creds);
		die(usage);
{
int main(int argc, char *argv[])
	if (delim_pos)
/*
	WCHAR *wstr = xmalloc(sizeof(WCHAR) * wlen);
static void write_item(const char *what, LPCWSTR wbuf, int wlen)
{
	for (i = 0; i < num_creds; ++i)
		match_part(&target, host, L"/") &&
	CREDENTIALW **creds;


	 * match text up to delimiter, or end of string (e.g. the '/' after
	char buf[1024];
	FILETIME               LastWritten;
			buf[--len] = 0;

{
	if (!CredWriteW || !CredEnumerateW || !CredFree || !CredDeleteW)
	DWORD  ValueSize;
static int match_cred(const CREDENTIALW *cred)
}

{
			password = utf8_to_utf16_dup(v);
	_setmode(_fileno(stdin), _O_BINARY);


		wcsncat(target, wusername, ARRAY_SIZE(target));

	int len = WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, NULL, 0, NULL,
{
	if (!ret)
	putchar('\n');
		wcsncat(target, path, ARRAY_SIZE(target));
	cred.TargetName = target;
#include <windows.h>
		return;

	DWORD                  AttributeCount;
	DWORD                  Type;
		die("failed to load advapi32.dll");
	buf = xmalloc(len);
#include <fcntl.h>
	if (path) {
		}
		match_part(&target, protocol, L"://") &&
	if (!CredWriteW(&cred, 0))
	LPBYTE                 CredentialBlob;
	return !want || (!wcsncmp(want, start, len) && !want[len]);
	return match_part_with_last(ptarget, want, delim, 0);
		return;
	printf("%s=", what);
	int wlen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);

}
static HMODULE advapi;
static int match_part(LPCWSTR *ptarget, LPCWSTR want, LPCWSTR delim)

static CredEnumerateWT CredEnumerateW;
static void load_cred_funcs(void)
	return res;

	if (!WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, buf, len, NULL, FALSE))


	    "usage: git credential-wincred <get|store|erase>\n";
		match_part(&target, path, L"");
	va_start(params, err);

static CredWriteWT CredWriteW;
		return;
static int match_part_with_last(LPCWSTR *ptarget, LPCWSTR want, LPCWSTR delim, int last)
#include <io.h>
	/* git use binary pipes to avoid CRLF-issues */
static void erase_credential(void)
	read_credential();
		else if (!strcmp(buf, "host"))
static WCHAR *utf8_to_utf16_dup(const char *str)
}
	CredFree(creds);
		if (!v)
	}
	if (!wbuf || !wlen) {
		ret = malloc(1);
	int i;
}
	DWORD num_creds;
static void *xmalloc(size_t size)
		delim_pos = last ? wcsstr_last(start, delim) : wcsstr(start, delim);
	_setmode(_fileno(stdout), _O_BINARY);
		else
	/* update ptarget if we either found a delimiter or need a match */
	cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

		} else if (!strcmp(buf, "password"))
{


	 */
static void store_credential(void)
		wcsncat(target, L"/", ARRAY_SIZE(target));
	if (wusername) {
	CREDENTIALW **creds;
	return 0;
			write_item("username", creds[i]->UserName,
	for (i = 0; i < num_creds; ++i) {
		if (match_cred(creds[i])) {
static LPCWSTR wcsstr_last(LPCWSTR str, LPCWSTR find)
		die("failed to load functions");

	while (fgets(buf, sizeof(buf), stdin)) {
			die("unrecognized input");
	cred.Comment = L"saved by git-credential-wincred";
	if (wusername && wcscmp(wusername, cred->UserName ? cred->UserName : L""))
{
	else
} CREDENTIALW, *PCREDENTIALW;
	advapi = LoadLibraryExA("advapi32.dll", NULL,
	PCREDENTIAL_ATTRIBUTEW Attributes;
		len = wcslen(start);
	cred.TargetAlias = NULL;

	cred.Flags = 0;
	LPWSTR Keyword;
{
			die("bad input: %s", buf);
static void get_credential(void)
	    "CredEnumerateW");


	CredFree = (CredFreeT)GetProcAddress(advapi, "CredFree");

		erase_credential();
	LPBYTE Value;
	va_list params;

typedef struct _CREDENTIALW {
typedef struct _CREDENTIAL_ATTRIBUTEW {
	return match_part_with_last(ptarget, want, delim, 1);
		*v++ = '\0';


			CredDeleteW(creds[i]->TargetName, creds[i]->Type, 0);
#define CRED_TYPE_GENERIC 1
	char msg[4096];
#define CRED_MAX_ATTRIBUTES 64
{

	if (!ret && !size)
	DWORD                  Persist;
	 * host is optional if not followed by a path)
	if (!CredEnumerateW(L"git:*", 0, &num_creds, &creds))
}
	LPCWSTR delim_pos, start = *ptarget;
	return wstr;

	}
		delim_pos = start + wcslen(start);

typedef BOOL (WINAPI *CredWriteWT)(PCREDENTIALW, DWORD);
	/* get function pointers */
}
		/* strip trailing CR / LF */
	for (pos = wcsstr(str, find); pos; pos = wcsstr(pos + 1, find))
			host = utf8_to_utf16_dup(v);
    PCREDENTIALW **);

		get_credential();
	fprintf(stderr, "%s\n", msg);
	DWORD                  Flags;
			path = utf8_to_utf16_dup(v);
#include <stdio.h>

		printf("%s=\n", what);
}
	cred.Type = CRED_TYPE_GENERIC;
typedef BOOL (WINAPI *CredDeleteWT)(LPCWSTR, DWORD, DWORD);
		die("CredWrite failed");
	wcsncat(target, L"://", ARRAY_SIZE(target));

	CredWriteW = (CredWriteWT)GetProcAddress(advapi, "CredWriteW");
	}
	if (*delim)
		res = pos;
	return match_part(&target, L"git", L":") &&
static WCHAR *wusername, *password, *protocol, *host, *path, target[1024];
	DWORD num_creds;
static int match_part_last(LPCWSTR *ptarget, LPCWSTR want, LPCWSTR delim)
	char *buf;

	}


	if (!CredEnumerateW(L"git:*", 0, &num_creds, &creds))
}
		len = delim_pos - start;

	/* search for the first credential that matches username */
	LPWSTR                 UserName;
	CREDENTIALW cred;
		wcsncat(target, L"@", ARRAY_SIZE(target));


static CredFreeT CredFree;
		int len = strlen(buf);
	if (!strcmp(argv[1], "get"))
	int len;
			break;
	LPCWSTR res = NULL, pos;
