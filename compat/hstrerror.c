#include <string.h>
	case HOST_NOT_FOUND:
}
#include <netdb.h>
	case NO_DATA:
	return buffer;
	}

const char *githstrerror(int err)
{
	static char buffer[48];
#include <stdio.h>
		return "Valid name, no data record of requested type";
		return "Non-authoritative \"host not found\", or SERVERFAIL";
	case TRY_AGAIN:
	snprintf(buffer, sizeof(buffer), "Name resolution error %d", err);
	{
		return "Authoritative answer: host not found";
	switch (err)
		return "Non recoverable errors, FORMERR, REFUSED, NOTIMP";
	case NO_RECOVERY:
