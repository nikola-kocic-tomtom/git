}
			if (value_ptr)

}
 * Pthreads API, without lots of other features that Git doesn't use.
int win32_pthread_join(pthread_t *thread, void **value_ptr)
				*value_ptr = thread->arg;
		return errno;
	else
	pthread_t *thread = arg;
		   void *(*start_routine)(void*), void *arg)
		return 0;
{
	if (!thread->handle)
/*
	thread->arg = arg;
{
	t.tid = GetCurrentThreadId();
	}
{
	thread->tid = GetCurrentThreadId();
	pthread_t t = { NULL };
static unsigned __stdcall win32_start_routine(void *arg)
		_beginthreadex(NULL, 0, win32_start_routine, thread, 0, NULL);

}
 *
		case WAIT_ABANDONED:
 */
			return EINVAL;
#include <errno.h>
		default:


#include "../../git-compat-util.h"
	thread->start_routine = start_routine;
	thread->arg = thread->start_routine(thread->arg);
	thread->handle = (HANDLE)
pthread_t pthread_self(void)
			return 0;
	return t;

	return 0;
		case WAIT_OBJECT_0:
 * Copyright (C) 2009 Andrzej K. Haczewski <ahaczewski@gmail.com>
	switch (result) {
 * DISCLAIMER: The implementation is Git-specific, it is subset of original
			return err_win_to_posix(GetLastError());
#include "pthread.h"

 * no need for double-checking.
{
#include <limits.h>
}
 * Git also makes sure that the passed arguments are valid, so there's

	DWORD result = WaitForSingleObject(thread->handle, INFINITE);
int pthread_create(pthread_t *thread, const void *unused,
