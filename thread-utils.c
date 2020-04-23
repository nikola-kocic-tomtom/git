	return ENOSYS;

	 *
	int ret;
#ifndef NO_PTHREADS
#else
int dummy_pthread_join(pthread_t pthread, void **retval)
	if ((ncpus = (long)sysconf(_SC_NPROCESSORS_ONLN)) > 0)
int dummy_pthread_create(pthread_t *pthread, const void *attr,
#endif
#elif defined(hpux) || defined(__hpux) || defined(_hpux)
}
#endif
	 */
#ifdef GIT_WINDOWS_NATIVE
	int cpucount;
#ifdef NO_PTHREADS
#endif
	mib[0] = CTL_HW;


#endif
	mib[1] = HW_AVAILCPU;
{
int init_recursive_mutex(pthread_mutex_t *m)
{
#else
	if ((int)info.dwNumberOfProcessors > 0)
#endif
	 *
}
#elif defined(HAVE_BSD_SYSCTL) && defined(HW_NCPU)

#if defined(hpux) || defined(__hpux) || defined(_hpux)

#  ifdef _SC_NPROC_ONLN
	struct pst_dynamic psd;
#endif

}
{
	if (!sysctl(mib, 2, &cpucount, &len, NULL, 0))
	 * The main purpose of this function is to break compiler's
			ret = pthread_mutex_init(m, &a);
		return (int)ncpus;
	 * variable is not used/initialized at all and trigger
	int mib[2];
	if (!sysctl(mib, 2, &cpucount, &len, NULL, 0))

	GetSystemInfo(&info);


	/*
	size_t len;
#  endif /* HW_AVAILCPU */
	return 0;

	mib[1] = HW_NCPU;
#ifdef _SC_NPROCESSORS_ONLN

#include "cache.h"
		return cpucount;
 * the function to be somewhat coherent, even
int dummy_pthread_init(void *data)
	 * Do nothing.
	 * Do nothing.

int online_cpus(void)
	ret = pthread_mutexattr_init(&a);
	 *
	 */
#  include <sys/pstat.h>
			 void *(*fn)(void *), void *data)
	return ENOSYS;
	/*
	 * flow analysis and avoid -Wunused-variable false warnings.
		return cpucount;
#endif /* defined(HAVE_BSD_SYSCTL) && defined(HW_NCPU) */
	 * flow analysis and avoid -Wunused-variable false warnings.
	if (!pstat_getdynamic(&psd, sizeof(psd), (size_t)1, 0))
		pthread_mutexattr_destroy(&a);
#  ifdef HW_AVAILCPU
	return ENOSYS;
		return (int)psd.psd_proc_cnt;
#  elif defined _SC_CRAY_NCPU
 */
	 * pthread_mutex_init() is no-op, which means the (static)
}
	SYSTEM_INFO info;
#  endif
#ifdef _SC_NPROCESSORS_ONLN
/*
	if (!ret) {
#include "thread-utils.h"
	return 1;
 * By doing this in two steps we can at least get
	/*
	 * -Wunused-variable
	return ret;
#endif

#ifdef NO_PTHREADS

		if (!ret)
	 * Do nothing.
	 */
		ret = pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
	long ncpus;
	len = sizeof(cpucount);
	return 1;
		return (int)info.dwNumberOfProcessors;
	 * The main purpose of this function is to break compiler's

#    define _SC_NPROCESSORS_ONLN _SC_NPROC_ONLN
	 * flow analysis or it may realize that functions like
#    define _SC_NPROCESSORS_ONLN _SC_CRAY_NCPU
	len = sizeof(cpucount);
{
{
 * with this disgusting nest of #ifdefs.
	}
}
	pthread_mutexattr_t a;
#ifndef _SC_NPROCESSORS_ONLN
	 * The main purpose of this function is to break compiler's
