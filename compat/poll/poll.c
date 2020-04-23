  rc = 0;
      WSASetLastError (0);
#ifdef WIN32_NATIVE
      errno = EINVAL;
	  *p_sought &= POLLIN | POLLRDNORM;
   any later version.
	}
typedef struct _FILE_PIPE_LOCAL_INFORMATION {
      ptv->tv_usec = (timeout % 1000) * 1000;
  ULONG NamedPipeType;
	      FD_SET ((SOCKET) h, &xfds);
	      DispatchMessage (&msg);
	  if (FD_ISSET ((SOCKET) h, &xfds))
#endif

  static HANDLE hEvent;
    }
	happened |= (POLLIN | POLLRDNORM) & sought;

      r = recv (fd, data, sizeof (data), MSG_PEEK);
    return rc;
    }
      return -1;
  if (FD_ISSET (fd, rfds))
/* Convert select(2) returned fd_sets into poll(2) revents values.  */
#endif

  if (!pfd && nfd)
					&rfds, &wfds, &efds);
      goto restart;
	int happened = compute_revents (pfd[i].fd, pfd[i].events,
     WSAEnumNetworkEvents instead distinguishes the two correctly.  */
      char data[64];
  int rc = 0;
      happened = 0;
#include <limits.h>

    {
	  maxfd = pfd[i].fd;
	  WSAEventSelect ((SOCKET) h, NULL, 0);
    happened |= (POLLIN | POLLRDNORM) & sought;

  FilePipeLocalInformation = 24
  /* Under Wine, it seems that getsockopt returns 0 for pipes too.
# if defined __MACH__ && defined __APPLE__

  BOOL bRet;
	{
} FILE_PIPE_LOCAL_INFORMATION, *PFILE_PIPE_LOCAL_INFORMATION;
	    return POLLHUP;
      ptv->tv_sec = 0;
	continue;
#include <sys/types.h>
   Copyright 2001-2003, 2006-2011 Free Software Foundation, Inc.

# include <stdio.h>
	      requested |= FD_WRITE | FD_CONNECT;
      WSASetLastError (0);
	      && !(ev.lNetworkEvents & (FD_READ | FD_ACCEPT)))
#include "git-compat-util.h"
    }
      else
   This program is distributed in the hope that it will be useful,
   Contributed by Paolo Bonzini.

   the Free Software Foundation; either version 2, or (at your option)

	    rc++;


      else
  nfds_t i;
    {
#  endif /* OPEN_MAX -- else, no check is needed */
      if (r > 0 || error == WSAENOTCONN)
#ifndef INFTIM
  /* Classify socket handles and create fd sets. */
static int
	  bRet = PeekConsoleInput (h, irbuffer, nbuffer, &avail);

  ULONG CurrentInstances;
      int socket_errno;
  int i, ret, happened;
	    pfd[i].revents = happened;

    happened |= (POLLPRI | POLLRDBAND) & sought;

	    }
  nhandles = 1;
      bRet = GetNumberOfConsoleInputEvents (h, &nbuffer);
      ptv = &tv;
# else /* !_SC_OPEN_MAX */
	}
typedef DWORD (WINAPI *PNtQueryInformationFile)
      int sought = pfd[i].events;
	  happened = win32_compute_revents_socket ((SOCKET) h, pfd[i].events,
      else
#if (__GNUC__ == 4 && 3 <= __GNUC_MINOR__) || 4 < __GNUC__
	    return POLLHUP;
      r = recv (h, data, sizeof (data), MSG_PEEK);
typedef enum _FILE_INFORMATION_CLASS {
  ULONG ReadDataAvailable;
    }
    {
      else
	       || error == WSAECONNABORTED || error == WSAENETRESET)
  handle_array[0] = hEvent;
  return happened;
  switch (GetFileType (h))
	  if (pfd[i].revents)
	    handle_array[nhandles++] = h;
      h = (HANDLE) _get_osfhandle (pfd[i].fd);
# define MSG_PEEK 0
	wait_timeout = INFINITE;
	}
	  && (sc_open_max != -1
  FD_ZERO (&xfds);
#include <time.h>
	happened |= POLLERR;

	return *p_sought & ~(POLLPRI | POLLRDBAND);
	}
# define WIN32_NATIVE
	  happened = win32_compute_revents (h, &sought);
  int happened = 0;
	    {
    {
    {
  return rc;
	 for some kinds of descriptors.  Detect if this descriptor is a
	      requested |= FD_OOB;
	FD_SET (pfd[i].fd, &rfds);

	  while ((bRet = PeekMessage (&msg, NULL, 0, 0, PM_REMOVE)) != 0)
      if (!(sought & (POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM | POLLWRBAND

	{
      ULONGLONG elapsed = GetTickCount64() - start;
	else
# include <winsock2.h>
  else
	    pfd[i].revents = 0;
}

      || (nfd > sc_open_max
# ifndef NO_SYS_SELECT_H
  WSANETWORKEVENTS ev;
  struct timeval tv;
#  define PIPE_BUF      512
	  if (!bRet || avail == 0)
	continue;
      ptv->tv_sec = timeout / 1000;
    }

      if (IsSocketHandle (h))
  /* create fd sets and determine max fd */
      /* There is a bug in Mac OS X that causes it to ignore MSG_PEEK

	    return 0;
	     bits for the "wrong" direction. */
   GNU General Public License for more details.
	  /* see above; socket handles are mapped onto select.  */
	  }
    return FALSE;
    {

# ifdef _SC_OPEN_MAX
	}
  rc = select (maxfd + 1, &rfds, &wfds, &efds, ptv);
    case FILE_TYPE_PIPE:

    }
      socket_errno = (r < 0) ? errno : 0;
  if (nfd < 0 || timeout < -1)
      if (PeekNamedPipe (h, NULL, 0, NULL, &avail, NULL) != 0)
      if (h != handle_array[nhandles])
       if ((pfd[i].revents |= happened) != 0)
      if (pfd[i].events & (POLLIN | POLLRDNORM))
    happened |= (POLLOUT | POLLWRNORM | POLLWRBAND) & sought;

  nfds_t i;
#ifndef WIN32_NATIVE
typedef struct _IO_STATUS_BLOCK
  ULONG_PTR Information;
	  /* Not a socket.  */
# endif
	    WSAEventSelect ((SOCKET) h, hEvent, requested);
#else
	if (happened)


/* To bump the minimum Windows version to Windows Vista */
    {
      if (timeout == INFTIM)

# include <sys/socket.h>
# else
      /* Distinguish hung-up sockets from other errors.  */
    /* wait forever */
      else if (/* (r == -1) && */ socket_errno == ENOTSOCK)

#include <errno.h>
	  if (FD_ISSET ((SOCKET) h, &wfds))
      if (r == 0 || socket_errno == ENOTSOCK)
  for (;;)
#  ifdef OPEN_MAX
  if (IsConsoleHandle (h))
	    {
  static int sc_open_max = -1;
      timeout = elapsed >= orig_timeout ? 0 : (int)(orig_timeout - elapsed);
  if (!hEvent)


	  if (maxfd > FD_SETSIZE)
  ev.lNetworkEvents = 0xDEADBEEF;
						   ev.lNetworkEvents);
	    }
    }
  MSG msg;
	  if (requested)

    }
     simplest case. */
      nbuffer = avail = 0;
    }
    case FILE_TYPE_CHAR:

#endif
      else
    DWORD Status;
    }

restart:
      pfd[i].revents = 0;
	    ev.lNetworkEvents |= FD_READ | FD_ACCEPT;
      h = (HANDLE) _get_osfhandle (pfd[i].fd);
	  {
  /* convert timeout number into a timeval structure */
    }
    }



	ioctl (fd, FIONREAD, &r);
	  if (nbuffer == 0)
  fd_set rfds, wfds, efds;
/* Convert fd_sets returned by select into revents values.  */
	    happened |= *p_sought & (POLLOUT | POLLWRNORM | POLLWRBAND);

# include <sys/ioctl.h>
compute_revents (int fd, int sought, fd_set *rfds, fd_set *wfds, fd_set *efds)
	  return *p_sought;
#endif
	  WSAEnumNetworkEvents ((SOCKET) h, NULL, &ev);
	       || socket_errno == ECONNABORTED || socket_errno == ENETRESET)
/* Specification.  */
      if (pfd[i].fd >= maxfd
	      return -1;

static int
      if (r == 0)
    else
	{
	 that's fine. */
	  int requested = FD_CLOSE;
      errno = EINVAL;
	      requested |= FD_READ | FD_ACCEPT;
}
   it under the terms of the GNU General Public License as published by
      assert (h != NULL);

    {
	      || nfd > (sc_open_max = sysconf (_SC_OPEN_MAX)))))
  if (!rc && timeout)
  ULONG NamedPipeConfiguration;
      /* see select(2): "the only exceptional condition detectable
/* Compute revents values for file handle H.  If some events cannot happen
	  *p_sought &= POLLOUT | POLLWRNORM | POLLWRBAND;
win32_compute_revents (HANDLE h, int *p_sought)
win32_compute_revents_socket (SOCKET h, int sought, long lNetworkEvents)
#else

      ret = MsgWaitForMultipleObjects (nhandles, handle_array, FALSE,
      /* If the event happened on an unconnected server socket,
#ifdef HAVE_SYS_IOCTL_H
	     reliable way of knowing if it can be written without blocking.

	return ret == WAIT_OBJECT_0 ? *p_sought & ~(POLLPRI | POLLRDBAND) : 0;
  return ev.lNetworkEvents != 0xDEADBEEF;
	{
	  if (avail)
	}

    }
	  /* Poll now.  If we get an event, do not poll again.  Also,
      if (pfd[i].events & (POLLOUT | POLLWRNORM | POLLWRBAND))
      else if (r == 0 || error == WSAESHUTDOWN || error == WSAECONNRESET
    {
#ifdef HAVE_SYS_FILIO_H
	  if (sought & (POLLIN | POLLRDNORM))
    happened |= (POLLPRI | POLLRDBAND) & sought;
      return happened;
      {
   You should have received a copy of the GNU General Public License along
    default:
  maxfd = -1;
	     screen buffer handles are waitable, and they'll block until
  for (i = 0; i < nfd; i++)
      return -1;





  /* Place a sentinel at the end of the array.  */

      int r;
# include <sys/filio.h>
      wait_timeout = 0;
{
	happened |= POLLERR;
/* Tell gcc not to warn about the (nfd < 0) tests, below.  */
# ifndef PIPE_BUF

#define IsConsoleHandle(h) (((long) (intptr_t) (h) & 3) == 3)
	  {
	}
	 is out-of-band data received on a socket", hence we push
	    ev.lNetworkEvents |= FD_OOB;
	    {

#endif
      if (pfd[i].fd < 0)
	continue;
      socket_errno = (r < 0) ? errno : 0;
    ptv = NULL;
# define INFTIM (-1)
#  define _WIN32_WINNT 0x0502
	 0-byte recv, and use ioctl(2) to detect POLLHUP.  */
	  if (sought)
	happened |= POLLHUP;
	  BOOL bRet;
  if (!rc && orig_timeout && timeout != INFTIM)
      ret = WaitForSingleObject (h, 0);
  handle_array[nhandles] = NULL;
	FD_SET (pfd[i].fd, &wfds);
int
  ULONG NamedPipeState;
}
	     a character is available.  win32_compute_revents eliminates
# endif /* !_SC_OPEN_MAX */
	{
	 no need to call select again.  */

	  return 0;
      return -1;
	  if (!*p_sought)
      if (pfd[i].fd < 0)

	  /* It was the write-end of the pipe. Unfortunately there is no


# endif
	    timeout = 0;
	      return *p_sought;
# include <windows.h>
    {
    {
      errno = EFAULT;
      int happened;
	  /* new input of some other kind */
      r = recv (fd, NULL, 0, MSG_PEEK);
  FD_ZERO (&wfds);

   This program is free software; you can redistribute it and/or modify
      /* some systems can't use recv() on non-socket, including HP NonStop */
{

	  }

    PVOID Pointer;
      char data[64];
  FD_ZERO (&rfds);
	continue;
IsSocketHandle (HANDLE h)
	happened |= POLLHUP;

#else /* !MinGW */
/* Emulation for poll(2)
  DWORD avail, nbuffer;
  return happened;
      else if (r > 0 || ( /* (r == -1) && */ socket_errno == ENOTCONN))
	wait_timeout = timeout;
# endif

	}

	  /* Input buffer.  */
  INPUT_RECORD *irbuffer;
  else if (timeout > 0)
	{

      poll_again = TRUE;
  else if (timeout == INFTIM)
      return *p_sought & (POLLOUT | POLLWRNORM | POLLWRBAND);
	      FD_SET ((SOCKET) h, &rfds);
	  && (pfd[i].events & (POLLIN | POLLOUT | POLLPRI
#include "poll.h"
    {
	  for (i = 0; i < avail; i++)
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
      else
  FD_ZERO (&rfds);
#endif
      return -1;
  if (select (0, &rfds, &wfds, &xfds, &tv0) > 0)
static int
  for (i = 0; i < nfd; i++)


# if defined (_MSC_VER) && !defined(_WIN32_WINNT)
  if ((lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE)) == FD_ACCEPT)
{
   but WITHOUT ANY WARRANTY; without even the implied warranty of
    {
    }
  if (nfd < 0
	    {
#include <assert.h>
      poll_again = FALSE;
   with this program; if not, see <http://www.gnu.org/licenses/>.  */
  ULONGLONG start = 0;
# endif
# include <conio.h>
	     to distinguish FD_READ and FD_ACCEPT; this saves a recv later.  */
    {
}
    {

    }
  if (FD_ISSET (fd, wfds))

      errno = EINVAL;
  /* EFAULT is not necessary to implement, but let's do it in the
  } u;

  if (lNetworkEvents & (FD_WRITE | FD_CONNECT))
      else if (GetLastError () == ERROR_BROKEN_PIPE)
  else if (lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE))

	{
	  pfd[i].revents = win32_compute_revents (h, &sought);
	  /* It's a socket.  */
      error = WSAGetLastError ();
	happened |= (POLLIN | POLLRDNORM) & sought;
# include <unistd.h>

  int maxfd, rc;

#endif /* !MinGW */
  ULONG MaximumInstances;
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  return rc;

      /* Distinguish hung-up sockets from other errors.  */
      ptv->tv_usec = 0;
      if (!(pfd[i].events & (POLLIN | POLLRDNORM |
	happened |= (POLLIN | POLLRDNORM) & sought;
    if (pfd[i].fd < 0)
  nhandles = 1;
	{

#  include <sys/select.h>

			     POLLOUT | POLLWRNORM | POLLWRBAND)))
      pfd[i].revents = 0;
	happened |= POLLHUP;
  /* establish results */

  if (poll_again)
}
				       wait_timeout, QS_ALLINPUT);
			       | POLLWRNORM | POLLWRBAND)))
  union {
  int happened = 0;
	      errno = EOVERFLOW;
  struct timeval *ptv;
  ULONG NamedPipeEnd;
  HANDLE h, handle_array[FD_SETSIZE + 2];
      if (ret == WAIT_OBJECT_0 + nhandles)
  ULONG OutboundQuota;
  FD_ZERO (&efds);

    select (0, &rfds, &wfds, &xfds, &tv0);
      ret = WaitForSingleObject (h, 0);
	}
	{
  for (i = 0; i < nfd; i++)
      /* Do MsgWaitForMultipleObjects anyway to dispatch messages, but
	    {
	  if (sought & (POLLOUT | POLLWRNORM | POLLWRBAND))
      if (bRet)
    }
    {
	  /* If we're lucky, WSAEnumNetworkEvents already provided a way
	  irbuffer = (INPUT_RECORD *) alloca (nbuffer * sizeof (INPUT_RECORD));
	    if (irbuffer[i].EventType == KEY_EVENT)
{

#if (defined _WIN32 || defined __WIN32__) && ! defined __CYGWIN__
  else
  /* examine fd sets */
      start = GetTickCount64();
    }

	 POLLWRBAND events onto wfds instead of efds. */
    }
  for (i = 0; i < nfd; i++)

	      FD_SET ((SOCKET) h, &wfds);
      if (pfd[i].fd < 0)
  ULONG InboundQuota;
	continue;
  if (rc < 0)
    }
	      TranslateMessage (&msg);
  fd_set rfds, wfds, xfds;
      if (pfd[i].events & (POLLPRI | POLLRDBAND))
#endif
	    happened |= *p_sought & (POLLIN | POLLRDNORM);


	 (HANDLE, IO_STATUS_BLOCK *, VOID *, ULONG, FILE_INFORMATION_CLASS);
	  if (FD_ISSET ((SOCKET) h, &rfds)
		      | POLLPRI | POLLRDBAND)))
  if (FD_ISSET (fd, efds))
    happened |= (POLLOUT | POLLWRNORM | POLLWRBAND) & sought;
poll (struct pollfd *pfd, nfds_t nfd, int timeout)
	     Just say that it's all good. */
	}
/* Declare data structures for ntdll functions.  */

  WSAEnumNetworkEvents ((SOCKET) h, NULL, &ev);
  if (nfd < 0 || nfd > OPEN_MAX)
    {
# pragma GCC diagnostic ignored "-Wtype-limits"
{
#ifndef MSG_PEEK

	  int sought = pfd[i].events;
    {
	 connected socket, a server socket, or something else using a
  WSANETWORKEVENTS ev;
	  nhandles++;
	break;
      int r, error;
   for the handle, eliminate them from *P_SOUGHT.  */
#if defined(WIN32)
/* BeOS does not have MSG_PEEK.  */
	happened |= POLLHUP;
      SleepEx (1, TRUE);
  if (timeout != INFTIM)
  ULONG WriteQuotaAvailable;
      if (ret == WAIT_OBJECT_0)
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
	rc++;

      errno = EINVAL;
# include <sys/time.h>
      if (!IsConsoleHandle (h))
    hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);
  FD_ZERO (&wfds);
	  /* Screen buffer.  */



    {
  if (timeout == 0)
  static struct timeval tv0;
static BOOL
      orig_timeout = timeout;
			       | POLLRDNORM | POLLRDBAND
	  if (sought & (POLLPRI | POLLRDBAND))
	{
# include <malloc.h>
      else
      return -1;
      ptv = &tv;
  BOOL poll_again;
	    }
      else
# include <io.h>
      }
  if (lNetworkEvents & FD_OOB)

      else if (socket_errno == ESHUTDOWN || socket_errno == ECONNRESET
	    ev.lNetworkEvents |= FD_WRITE | FD_CONNECT;
   This file is part of gnulib.
	    }
	    }

{

  DWORD ret, wait_timeout, nhandles, orig_timeout = 0;

	FD_SET (pfd[i].fd, &efds);
#endif

