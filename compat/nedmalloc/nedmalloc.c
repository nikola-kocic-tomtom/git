			{
void * nedpmemalign(nedpool *p, size_t alignment, size_t bytes) THROWSPEC
this license (the "Software") to use, reproduce, display, distribute,
	}
		{	/* Drat, must destroy it now */
			goto badexit;

	      ret=mspace_independent_calloc(m, elemsno, elemsize, chunks));
			for(; *tcb && tc->frees-(*tcb)->lastUsed>=age; )
#endif
extern "C" {
	      USAGE_ERROR_ACTION(fm, p);
		mspace_free(0, mem);
/*#define USE_SPIN_LOCKS 0*/
{
	*binsptr=tck;

		RELEASE_LOCK(&p->mutex);
#endif
}
#endif
#endif
	int mymspace;
	    }
	else
	int mycache;
#else
 #define DEBUG 0
#ifdef FULLSANITYCHECKS
			end++;
#endif
#endif
#endif
{
	    mstate fm = get_mstate_for(p);
	if(p->mycache)
	assert(tck==tc->bins[idx*2]);
#ifdef FULLSANITYCHECKS
					(*tcb)->next=0;
	p->m[0]->extp=p;
	threadcache *tc;
		if(TLSSET(p->mycache, (void *)(size_t)(-(n+1)))) abort();
err:
			(float) tc->successes/tc->mallocs, tc->frees, (float) tc->successes/tc->frees, (unsigned int) tc->freeInCache);
#else
		x = x | (x >>16);
{
#ifdef NDEBUG               /* Disable assert checking on release builds */
	{
void   nedmalloc_stats(void) THROWSPEC					{ nedpmalloc_stats(0); }
 #ifdef DEBUG
void * nedpmalloc(nedpool *p, size_t size) THROWSPEC
	if(tc && size<=THREADCACHEMAX)
#include "nedmalloc.h"
    RELEASE_LOCK(&m->mutex);                    \
		mstate temp;
		if(TLSSET(p->mycache, (void *)-1)) abort();
	threadcache *tc;
	tc=p->caches[n]=(threadcache *) mspace_calloc(p->m[0], 1, sizeof(threadcache));
static NOINLINE int InitPool(nedpool *p, size_t capacity, int threads) THROWSPEC
		destroy_mspace(p->m[n]);
		assert(!tc->freeInCache);
		x = x | (x >> 1);
	return ret;
					*tcbptr=0;
		if(!(temp=(mstate) create_mspace(size, 1)))
#ifndef USE_LOCKS
		  ret=mspace_calloc(m, 1, rsize));
/*#define FULLSANITYCHECKS*/
		x = x | (x >> 4);
	assert(mem);
namespace nedalloc {
		{	/* Disable */

{
			memset(ret, 0, rsize);
	GetThreadCache(&p, &tc, &mymspace, &rsize);
static FORCEINLINE unsigned int size2binidx(size_t _size) THROWSPEC
		x = (x + (x >> 4)) & 0x0F0F0F0F;
	if(blk)
	if(!p) { p=&syspool; if(!syspool.threads) InitPool(&syspool, 0, -1); }
	if(tc && rsize<=THREADCACHEMAX)
Boost Software License - Version 1.0 - August 17th, 2003
 #define TLSFREE(k)		pthread_key_delete(k)
	{	/* Use the thread cache */
		if(idx<THREADCACHEMAXBINS)
{
	if(TLSALLOC(&p->mycache)) goto err;
	if(p->threads) goto done;


	}
DEALINGS IN THE SOFTWARE.
		n=end;
	return tc;
		if(!*binsptr)
 #define TLSFREE(k)		(!TlsFree(k))
#if defined(__cplusplus)
{
	{
		ret=threadcache_malloc(p, tc, &size);
#if 0
		if(TLSFREE(p->mycache)) abort();
	void *ret=0;
#endif
	tc->threadid=(long)(size_t)CURRENT_THREAD;
		if(*(unsigned int *)"NEDMALC1"!=(*tc)->magic1 || *(unsigned int *)"NEDMALC2"!=(*tc)->magic2)
			threadcacheblk **tcb=tcbptr+1;		/* come from oldest end of list */
			assert(!ob || ob->next==b);
	}
		ret.hblkhd+=t.hblkhd;
}
}
}

		size=bestsize;
	if(ret)
				threadcacheblk *f=*tcb;
		ret.ordblks+=t.ordblks;
#endif
void * nedmalloc(size_t size) THROWSPEC				{ return nedpmalloc(0, size); }
		/* Now we're ready to modify the lists, we lock */
			blk=*binsptr;
{

void   nedpfree(nedpool *p, void *mem) THROWSPEC
				if(*tcb)
{
		return 0;
	RELEASE_LOCK(&p->mutex);

		{
#endif
	    unsigned long bsrTopBit;
#if 0
  #define TLSGET(k) ChkedTlsGetValue(k)
	    mchunkptr p  = mem2chunk(mem);
	}
	size_t ret=0;
	tc->magic1=*(unsigned int *)"NEDMALC1";
	if(*size>bestsize)

	*lastUsed=n;
	p->threads=(threads<1 || threads>MAXTHREADSINPOOL) ? MAXTHREADSINPOOL : threads;
	      return;
		tc->threadid=0;
/* The number of cache entries for finer grained bins. This is (topbitpos(THREADCACHEMAX)-4)*2 */
	tc->magic2=*(unsigned int *)"NEDMALC2";
	if(tc)
		idx++;
	}
	}
#endif
	{
	}
	return ret;
    action;                                     \
	}
	int n;
	{
 #define TLSSET(k, a)	pthread_setspecific(k, a)
}
		if(!syspool.threads) InitPool(&syspool, 0, -1);
	if(!ret)
	for(n=end=*lastUsed+1; p->m[n]; end=++n)
	for(n=0; p->m[n]; n++)
 #define TLSVAR			pthread_key_t
	size_t memsize;
	/* Finer grained bin fit */
	RELEASE_MALLOC_GLOBAL_LOCK();
#if 0
	if(threads<0)
		}
	/*printf("free: %p, %p, %p, %lu\n", p, tc, mem, (long) size);*/
	for(n=0; n<THREADCACHEMAXCACHES && p->caches[n]; n++);
		if(blk->next)
	}
void nedpsetvalue(nedpool *p, void *v) THROWSPEC
	if(!mycache)
		tck->next->prev=tck;
	threadcache *tc;
	size_t freeInCache;					/* How much free space is stored in this cache */
#define GETMSPACE(m,p,tc,ms,s,action)           \
#endif
			RELEASE_LOCK(&p->mutex);
 #undef DEBUG
		*p=&syspool;
{
	    if (!ok_magic(fm)) {
		ACQUIRE_LOCK(&p->mutex);
  do                                            \
#define THREADCACHEMAXBINS (13-4)
		assert(binsptr[0]!=blk && binsptr[1]!=blk);
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
  #undef TLSGET
}
	threadcacheblk *next, *prev;
	if(!(ret=(nedpool *) nedpcalloc(0, 1, sizeof(nedpool)))) return 0;
			if((tc=p->caches[n]))
		if(ptr[0]==ptr[1])
	    topbit = bsrTopBit;
		}
	size_t i, *adjustedsizes=(size_t *) alloca(elems*sizeof(size_t));
{	/* Gets called when thread's last used mspace is in use. The strategy
	{
	{	/* List exhausted, so disable for this thread */
#endif
	{
	tcfullsanitycheck(tc);
	for(n=0; p->m[n]; n++)
	for(end=0; p->m[end]; end++);
	}
	int mycache;
	if(!fm->extp) return 0;
{
	return ret;
		return 0;
{
		assert(blksize>=*size);
	np=(nedpool *) fm->extp;
}
		}
	assert(*size<=THREADCACHEMAX);
	}
the above license grant, this restriction and the following disclaimer,
		mspace_free(0, p->caches[mycache-1]);
	{
	    _BitScanReverse(&bsrTopBit, size);
	{	/* Use this thread's mspace */
		threadcache *tc=p->caches[mycache-1];
#ifndef DEFAULT_GRANULARITY
	{
#endif
	}

		assert(!ptr[0]->prev);
			volatile struct malloc_state **_m=(volatile struct malloc_state **) &p->m[end];
}
	{	/* Use this thread's mspace */
	size_t blksize=0;
	assert((ptr[0] && ptr[1]) || (!ptr[0] && !ptr[1]));
	mycache=(int)(size_t) TLSGET((*p)->mycache);
	threadcacheblk *bins[(THREADCACHEMAXBINS+1)*2];
	is to run through the list of all available mspaces looking for an
		x = ~x;
#include "malloc.c.h"
	p->uservalue=v;
}
			}
	nedpool *ret;
#if defined(__cplusplus)
	tck->magic=*(unsigned int *) "NEDN";
	tck->size=(unsigned int) size;
	bestsize=1<<(idx+4);

			memcpy(ret, mem, memsize<size ? memsize : size);
 #define TLSALLOC(k)	pthread_key_create(k, 0)
		*tc=(*p)->caches[mycache-1];
		x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	{
#endif
#undef DEBUG				/* dlmalloc wants DEBUG either 0 or 1 */
			*_m=(p->m[end]=temp);
execute, and transmit the Software, and to prepare derivative works of the
do so, all subject to the following:
	GetThreadCache(&p, &tc, &mymspace, &size);
	unsigned int bestsize;
void * nedpcalloc(nedpool *p, size_t no, size_t size) THROWSPEC
		for(b=tcbptr[0]; b; ob=b, b=b->next)
			assert(!ob || b->prev==ob);
			*mymspace=0;
}
#endif
		/*printf("*** Removing cache entries older than %u (%u)\n", age, (unsigned int) tc->freeInCache);*/
		have to be careful of breaking aliasing rules, so write it twice */
			assert(!ptr[1]->prev);
}
				mspace_free(0, f);
	assert(idx<=THREADCACHEMAXBINS);
#ifdef FULLSANITYCHECKS

		fprintf(stderr, "Attempt to free already freed memory block %p - aborting!\n", tck);
	if(!next_pinuse(mcp)) return 0;
};
		ret=(void *) blk;
	{
	nedpool *np=0;
		if(next_chunk(prev_chunk(mcp))!=mcp) return 0;
void neddestroypool(nedpool *p) THROWSPEC
	ACQUIRE_LOCK(&p->mutex);
void **nedpindependent_calloc(nedpool *p, size_t elemsno, size_t elemsize, void **chunks) THROWSPEC
#ifdef FULLSANITYCHECKS
		tc->frees++;
	int n;
	int n;
		x = x - ((x >> 1) & 0x55555555);
		destroy_mspace(p->m[0]);
	threadcacheblk **binsptr, *tck=(threadcacheblk *) mem;
#define THREADCACHEMAXFREESPACE (512*1024)
	assert(bestsize>=*size);
				RemoveCacheEntries(p, tc, 0);
	}
				*tcb=(*tcb)->prev;
#endif
		topbit=31 - (x >> 24);
				assert(blksize<=nedblksize(f));
#ifdef NDEBUG               /* Disable assert checking on release builds */
	}
	{	/* Use the thread cache */
#endif
static NOINLINE void RemoveCacheEntries(nedpool *p, threadcache *tc, unsigned int age) THROWSPEC
	void *ret=0;
{	/* Keep less than 16 bytes on 32 bit systems and 32 bytes on 64 bit systems */
	{	/* Set to mspace 0 */
The copyright notices in the Software and this entire statement, including
	void **ret;
	}
/* The maximum number of threadcaches which can be allocated */
done:
			assert(!ptr[0]->next);
	}
	if(end<p->threads)
}
		bestsize+=bestsize>>1;
#endif
#ifdef FULLSANITYCHECKS
		printf("*** threadcache=%u, mallocs=%u (%f), free=%u (%f), freeInCache=%u\n", (unsigned int) tc->threadid, tc->mallocs,
#endif
			blk->next->prev=0;
	{	/* Make sure this is a valid memory block */
		assert(*(unsigned int *) "NEDN"==ptr[1]->magic);
	++tc->mallocs;
	return ret;
	assert(S_OK==GetLastError());
#define THREADCACHEMAXCACHES 256
	ACQUIRE_LOCK(&p->mutex);
	/*assert(IS_LOCKED(&p->m[mymspace]->mutex));*/
#if defined(WIN32)
	}
	unsigned int magic;
	long threadid;
	{

				assert(*(unsigned int *) "NEDN"==(*tcb)->magic);
	else if(mycache>0)
	assert(memsize);
/* The number of cache entries. This is (topbitpos(THREADCACHEMAX)-4) */
	{
	else
		threadcache_free(p, tc, mymspace, mem, memsize);
	GetThreadCache(&p, &tc, &mymspace, 0);
		locking the preferred mspace for this thread */
static FORCEINLINE mstate GetMSpace(nedpool *p, threadcache *tc, int mymspace, size_t size) THROWSPEC
void   nedfree(void *mem) THROWSPEC					{ nedpfree(0, mem); }
		if(!syspool.threads) InitPool(&syspool, 0, -1);
	{
		if(TLSSET(p->mycache, (void *)(size_t)(-tc->mymspace))) abort();
	if(mem)

	int mymspace;						/* Last mspace entry this thread used */
void **nedindependent_comalloc(size_t elems, size_t *sizes, void **chunks) THROWSPEC	{ return nedpindependent_comalloc(0, elems, sizes, chunks); }
 #undef DEBUG
	      ret=mspace_independent_comalloc(m, elems, adjustedsizes, chunks));
	if(p->m[0])
		int n;
			else
#ifdef FULLSANITYCHECKS
		abort();			/* If you can't allocate for system pool, we're screwed */

	assert(tc->bins[idx*2+1]==tck || binsptr[0]->next->prev==tck);
			abort();
struct mallinfo nedpmallinfo(nedpool *p) THROWSPEC
/* Point at which the free space in a thread cache is garbage collected */
#ifdef FULLSANITYCHECKS
	if(!mem) return nedpmalloc(p, size);
/* Only enable if testing with valgrind. Causes misoperation */
	}
	{
				else
	return ret;
	unsigned int lastUsed, size;
	locking the preferred mspace for this thread */
}
#if THREADCACHEMAX
int    nedmalloc_trim(size_t pad) THROWSPEC			{ return nedpmalloc_trim(0, pad); }
{
		assert(!ptr[1]->next);
{
		ret.uordblks+=t.uordblks;
{

	int n, ret=0;
				/*tcsanitycheck(tcbptr);*/
	RELEASE_MALLOC_GLOBAL_LOCK();
void **nedpindependent_comalloc(nedpool *p, size_t elems, size_t *sizes, void **chunks) THROWSPEC
#define DEFAULT_GRANULARITY (1*1024*1024)
	}
	}
#define FOOTERS 1           /* Need to enable footers so frees lock the right mspace */
	LPVOID ret=TlsGetValue(idx);
	if(!ok_address(fm, mcp)) return 0;
	mstate m=p->m[mymspace];
	if(TLSSET(p->mycache, (void *)(size_t)(n+1))) abort();
	void *ret=0;
	if(!TRY_LOCK(&p->m[mymspace]->mutex)) m=FindMSpace(p, tc, &mymspace, size);\
	return p->m[*lastUsed];
		nedpfree(0, ret);
*/
	}
#else
	{
		}
}
#ifdef FULLSANITYCHECKS
{
		if(!*tc)
	if(*size>bestsize)
	if(size && *size<sizeof(threadcacheblk)) *size=sizeof(threadcacheblk);
	if(!blk || blk->size<*size)
#endif
struct mallinfo nedmallinfo(void) THROWSPEC			{ return nedpmallinfo(0); }
	if(!ret)
 #define TLSVAR			DWORD
	if(p) *p=np;
	tcfullsanitycheck(tc);
	ACQUIRE_LOCK(&p->m[*lastUsed]->mutex);
	return ret;
	int n, end;
		p->caches[mycache-1]=0;
		assert(nedblksize(blk)>=blksize);
#endif
	if(!p) { p=&syspool; if(!syspool.threads) InitPool(&syspool, 0, -1); }
	}
		ret.keepcost+=t.keepcost;
		}
}
		  ret=mspace_memalign(m, alignment, bytes));
	MLOCK_T mutex;
		ret.fordblks+=t.fordblks;
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	if(!ret)
nedpool *nedcreatepool(size_t capacity, int threads) THROWSPEC
{
			}
{
	topbit = sizeof(size)*__CHAR_BIT__ - 1 - __builtin_clz(size);
found:
#ifndef THREADCACHEMAXFREESPACE
#endif
		{

		assert((long) tc->freeInCache>=0);
	TLSVAR mycache;						/* Thread cache for this thread. 0 for unset, negative for use mspace-1 directly, otherwise is cache-1 */
		x = x | (x >> 8);
	{
		x = x + (x << 8);
  {                                             \
		ret.arena+=t.arena;
			100.0*tc->successes/tc->mallocs, 100.0*((double) tc->mallocs-tc->frees)/tc->mallocs);
typedef struct threadcache_t
#endif
		unsigned asInt[2];
{
		printf("Threadcache utilisation: %lf%% in cache with %lf%% lost to other threads\n",
	}
		{
	while(age && tc->freeInCache>=THREADCACHEMAXFREESPACE)
		}
#endif
#endif
		RELEASE_LOCK(&p->mutex);
		ret=mspace_realloc(0, mem, size);
	unsigned int magic1;
 #define TLSGET(k)		TlsGetValue(k)
		x = x | (x >> 2);
		threadcache *tc;

	/* Only enable if testing with valgrind. Causes misoperation */
#ifndef MAXTHREADSINPOOL
		/* We really want to make sure this goes into memory now but we
	topbit = (asInt[!FOX_BIGENDIAN] >> 20) - 1023;
void * nedcalloc(size_t no, size_t size) THROWSPEC	{ return nedpcalloc(0, no, size); }
{
	if(!(p->m[0]=(mstate) create_mspace(capacity, 1))) goto err;
	{

{	/* Returns a locked and ready for use mspace */
#endif
		*tc=0;
	for(n=0; p->m[n]; n++)
	threadcache *tc;
	}
#else
#define mspace_realloc(p, m, s) realloc(m, s)
	for(i=0; i<elems; i++)
	int mymspace;
				size_t blksize=f->size; /*nedblksize(f);*/
	return topbit;
		idx++;
	ACQUIRE_MALLOC_GLOBAL_LOCK();
}
	return np->uservalue;
			destroy_mspace((mspace) temp);
	ensure_initialization();
		binsptr[1]=tck;
		{
		idx++;
	{
	if(tc && size && size<=THREADCACHEMAX)
	{
		while(p->m[end] && end<p->threads)
#else
		if((ret=threadcache_malloc(p, tc, &rsize)))
	if(tck->next)
	tc->mymspace=tc->threadid % end;
	GetThreadCache(&p, &tc, &mymspace, 0);
		p=&syspool;
	blk=*binsptr;
				p->caches[n]=0;
	tcfullsanitycheck(tc);
}
	unsigned int bestsize;
	}
#ifdef FULLSANITYCHECKS

	if(THREADCACHEMAXCACHES==n)
static FORCEINLINE void GetThreadCache(nedpool **p, threadcache **tc, int *mymspace, size_t *size) THROWSPEC
 #define USE_LOCKS 1
	{

#define mspace_malloc(p, s) malloc(s)
	if(!tc)
}
void * nedrealloc(void *mem, size_t size) THROWSPEC	{ return nedprealloc(0, mem, size); }

	}
		  ret=mspace_malloc(m, size));
	/*ACQUIRE_LOCK(&p->m[mymspace]->mutex);*/
}
Permission is hereby granted, free of charge, to any person or organization
#endif
	}
	binsptr=&tc->bins[idx*2];

  } while (0)
#ifndef THREADCACHEMAXCACHES
		int n;
	for(n=0; n<=THREADCACHEMAXBINS; n++, tcbptr+=2)
		threadcacheblk *b, *ob=0;
	/*RELEASE_LOCK(&p->m[mymspace]->mutex);*/
		ret+=mspace_footprint(p->m[n]);
		assert(nedblksize(blk)>=sizeof(threadcacheblk) && nedblksize(blk)<=THREADCACHEMAX+CHUNK_OVERHEAD);
}
	fm=get_mstate_for(mcp);
		assert(memsize);
	void **ret;
	return 0;
	{
#endif
		ReleaseFreeInCache(p, tc, mymspace);
void * nedprealloc(nedpool *p, void *mem, size_t size) THROWSPEC
		assert(blksize>=*size);
	{
int    nedpmallopt(nedpool *p, int parno, int value) THROWSPEC
#endif
static LPVOID ChkedTlsGetValue(DWORD idx)

	tcfullsanitycheck(tc);
#ifdef _MSC_VER
}
	idx<<=1;
	return ret;
	{
	tcfullsanitycheck(tc);
	tcfullsanitycheck(tc);
	{	/* Bump it up a bin */
		struct mallinfo t=mspace_mallinfo(p->m[n]);
#if defined(DEBUG)
		p->m[0]=0;
	if(!p) { p=&syspool; if(!syspool.threads) InitPool(&syspool, 0, -1); }
}
		for(n=0; n<=THREADCACHEMAXBINS; n++, tcbptr+=2)
#endif
		ret.usmblks+=t.usmblks;
#endif
void nedsetvalue(void *v) THROWSPEC					{ nedpsetvalue(0, v); }

#endif
struct nedpool_t
	unsigned int idx=size2binidx(*size);
	threadcache *tc=0;
	for(n=0; n<*lastUsed && p->m[n]; n++)
	{
	int n;
#ifdef WIN32
#if THREADCACHEMAX
size_t nedmalloc_footprint(void) THROWSPEC				{ return nedpmalloc_footprint(0); }
	int mymspace;
			idx++;
		unsigned int x=size;
				mspace_free(0, tc);
		mspace_malloc_stats(p->m[n]);
size_t nedpmalloc_footprint(nedpool *p) THROWSPEC
	/* Calculate best fit bin size */
#ifdef DEBUG
	{
must be included in all copies of the Software, in whole or in part, and
}
#else
	if(!InitPool(ret, capacity, threads))
	if(mycache>0)
obtaining a copy of the software and accompanying documentation covered by
			{
		if(TRY_LOCK(&p->m[n]->mutex)) goto found;

	mycache=(int)(size_t) TLSGET(p->mycache);
	unsigned int mallocs, frees, successes;

	{
	unsigned int age=THREADCACHEMAXFREESPACE/8192;
#ifdef FULLSANITYCHECKS
		mchunkptr p=mem2chunk(mem);
	DestroyCaches(p);
				assert(!tc->freeInCache);
static NOINLINE void ReleaseFreeInCache(nedpool *p, threadcache *tc, int mymspace) THROWSPEC
} threadcache;
#define THREADCACHEMAX 8192
	GETMSPACE(m, p, tc, mymspace, rsize,
		p->mycache=0;
#if THREADCACHEMAX
	if(!p) { p=&syspool; if(!syspool.threads) InitPool(&syspool, 0, -1); }
	int n, end;
		RELEASE_LOCK(&p->mutex);
			goto badexit;
void *nedgetvalue(nedpool **p, void *mem) THROWSPEC
#define MAXTHREADSINPOOL 16
#if defined(__GNUC__)
}
	}
		}
	if(bestsize!=size)	/* dlmalloc can round up, so we round down to preserve indexing */
	if(!is_mmapped(mcp) && !pinuse(mcp))
		if((ret=threadcache_malloc(p, tc, &size)))
		*mymspace=-mycache-1;
		*binsptr=blk->next;
	if(!adjustedsizes) return 0;
	}
	threadcache *tc;
#endif

	if(size>bestsize)
lock contention based on dlmalloc. (C) 2005-2006 Niall Douglas
	GetThreadCache(&p, &tc, &mymspace, &bytes);
	for(n=0; p->m[n]; n++)
		abort();
void **nedindependent_calloc(size_t elemsno, size_t elemsize, void **chunks) THROWSPEC	{ return nedpindependent_calloc(0, elemsno, elemsize, chunks); }
	{
		adjustedsizes[i]=sizes[i]<sizeof(threadcacheblk) ? sizeof(threadcacheblk) : sizes[i];
}
#else
	}
	assert((long)(size_t)CURRENT_THREAD==(*tc)->threadid);
	if(INITIAL_LOCK(&p->mutex)) goto err;

	GetThreadCache(&p, &tc, &mymspace, &elemsize);
		{
	memsize=nedblksize(mem);
	}
static void threadcache_free(nedpool *p, threadcache *tc, int mymspace, void *mem, size_t size) THROWSPEC
				tc->threadid=0;
	if(tc->freeInCache>=THREADCACHEMAXFREESPACE)
#endif
	{
			if(TLSSET((*p)->mycache, (void *)-1)) abort();
	{	/* Reallocs always happen in the mspace they happened in, so skip
	tc->freeInCache+=size;
	void *uservalue;
#endif
		if(TRY_LOCK(&p->m[n]->mutex)) goto found;
		double asDouble;
	threadcache *caches[THREADCACHEMAXCACHES];
	}
static void *threadcache_malloc(nedpool *p, threadcache *tc, size_t *size) THROWSPEC
	RELEASE_LOCK(&p->mutex);
				mspace_free(0, mem);
		/*printf("malloc: %p, %p, %p, %lu\n", p, tc, blk, (long) size);*/
#endif
{
#endif
	int mymspace;
#endif
#ifndef THREADCACHEMAX
}
	mchunkptr mcp=mem2chunk(mem);
		{
	nedpfree(0, p);
			if(memsize<=THREADCACHEMAX)
	}
	/* Calculate best fit bin size */
	int mymspace;
void neddisablethreadcache(nedpool *p) THROWSPEC
		assert(cinuse(p));	/* If this fails, someone tried to free a block twice */
		tc->mymspace=-1;
	/* Finer grained bin fit */
		return 0;
		x = x + (x << 16);
#define mspace_calloc(p, n, s) calloc(n, s)
Software, and to permit third-parties to whom the Software is furnished to
	int threads;						/* Max entries in m to use */
		RemoveCacheEntries(p, tc, 0);
		if(size>=biggerbestsize)
	if(tc->freeInCache)
#ifdef FULLSANITYCHECKS
	}
	size_t rsize=size*no;
	return ret;
static NOINLINE mstate FindMSpace(nedpool *p, threadcache *tc, int *lastUsed, size_t size) THROWSPEC
		else
			binsptr[1]=0;
}
				assert(blksize);
#else
	mstate fm;
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#define THREADCACHEMAXBINS ((13-4)*2)
				assert((long) tc->freeInCache>=0);
	mstate m[MAXTHREADSINPOOL+1];		/* mspace entries for this pool */
	unlocked one and if we fail, we create a new one so long as we don't
	if(!(tc->mallocs & 0xfff))
		bestsize<<=1;
	return p->m[n];
}
		ret+=mspace_trim(p->m[n], pad);
{	/* threads is -1 for system pool */
		bestsize=1<<(4+(idx>>1));
#if 0
	unsigned int topbit, size=(unsigned int)(_size>>4);
#if THREADCACHEMAX
static nedpool syspool;
	}
	}
	/* Let it lock on the last one it used */
all derivative works of the Software, unless such copies or derivative
	idx<<=1;

#endif
		for(n=0; n<THREADCACHEMAXCACHES; n++)
struct threadcacheblk_t;
				tc->freeInCache-=blksize;
	tck->lastUsed=++tc->frees;
{
	threadcacheblk **tcbptr=tc->bins;
	}

};
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
	if(tck==*binsptr)
	GETMSPACE(m, p, tc, mymspace, 0,

	tck->next=*binsptr;
	int mymspace;
{	/* Frees always happen in the mspace they happened in, so skip
	GETMSPACE(m, p, tc, mymspace, bytes,
	}
	asDouble = (double)size + 0.5;
	threadcache *tc;
	else if(!mycache)
	else
	/* Try to match close, but move up a bin if necessary */
{
			binsptr+=2;
#endif
		RemoveCacheEntries(p, tc, age);
int    nedpmalloc_trim(nedpool *p, size_t pad) THROWSPEC
		goto found;
{
	if(!ok_magic(fm)) return 0;
	int n;
	tck->prev=0;
{	/* 8=1000	16=10000	20=10100	24=11000	32=100000	48=110000	4096=1000000000000 */

#ifdef _DEBUG
	if(*size<bestsize) *size=bestsize;
	}
		assert(nedblksize(ptr[0])>=sizeof(threadcacheblk));
		size_t memsize=nedblksize(mem);
	}
				tc->frees++;
		tcsanitycheck(tcbptr);
	if(!*p)
	{
	DestroyCaches(p);
#if 0
#endif

			bestsize=biggerbestsize;
	assert(m);
#define mspace_free(p, m) free(m)
{
size_t nedblksize(void *mem) THROWSPEC
 #include <malloc.h>
	};
	void *ret=0;
	}
	{
		}
	int mymspace;
#ifdef FULLSANITYCHECKS
    mstate m = GetMSpace((p),(tc),(ms),(s));    \
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
		age>>=1;
			/*tcsanitycheck(tcbptr);*/
		ACQUIRE_LOCK(&p->m[end]->mutex);
	return mspace_mallopt(parno, value);
/* Enable full aliasing on MSVC */
static NOINLINE threadcache *AllocCache(nedpool *p) THROWSPEC
			idx++;
	if(p->caches)

	GetThreadCache(&p, &tc, &mymspace, &size);
	assert(!*binsptr || (*binsptr)->size==tck->size);
}
	{
	struct mallinfo ret={0};
	}
}
badexit:
	return ret;
struct threadcacheblk_t
	threadcacheblk *blk, **binsptr;
}
	return THREADCACHEMAX;
#elif defined(_MSC_VER) && _MSC_VER>=1300
	/* 16=1		20=1	24=1	32=10	48=11	64=100	96=110	128=1000	4096=100000000 */
		assert(*(unsigned int *) "NEDN"==ptr[0]->magic);
		blksize=blk->size; /*nedblksize(blk);*/
		*mymspace=(*tc)->mymspace;
#define ONLY_MSPACES 1
    GETMSPACE(m, p, tc, mymspace, elemsno*elemsize,
		{
{
				tc->mymspace=-1;
/* The maximum size to be allocated from the thread cache */
	return 0;
	if(*tc)
{
		threadcacheblk **tcbptr=tc->bins;
	{
	{	/* Set to last used mspace */
	GETMSPACE(m, p, tc, mymspace, size,
		tc->mymspace=n;
			*mymspace=(*tc)->mymspace;
{
	if(*size>bestsize)
void   nedpmalloc_stats(nedpool *p) THROWSPEC
#ifdef FULLSANITYCHECKS
	}
	union {

	return 1;
	bestsize=1<<(idx+4);
}
 #define DEBUG 1
		p->m[n]=0;
	assert(idx<=THREADCACHEMAXBINS);
	if(TLSFREE(p->mycache)) abort();
	{	/* Use the thread cache */
	if(!(is_aligned(chunk2mem(mcp))) && mcp->head != FENCEPOST_HEAD) return 0;
/*#define FORCEINLINE*/
	return ret;
		{
 #define TLSALLOC(k)	(*(k)=TlsAlloc(), TLS_OUT_OF_INDEXES==*(k))
	{	/* Use this thread's mspace */
}
	int n;
	assert(size>=sizeof(threadcacheblk) && size<=THREADCACHEMAX+CHUNK_OVERHEAD);
int    nedmallopt(int parno, int value) THROWSPEC	{ return nedpmallopt(0, parno, value); }
		if(cinuse(p))
typedef struct threadcacheblk_t threadcacheblk;
	void *ret;
	return ret;
	}
		blk->magic=0;
#endif
works are solely in the form of machine-executable object code generated by
			assert(*(unsigned int *) "NEDN"==b->magic);
		if(end>=p->threads)
#if !defined(NO_NED_NAMESPACE)
#if defined(DEBUG) && 0
{
#if !NO_MALLINFO
	else
{
/* The default of 64Kb means we spend too much time kernel-side */
	exceed p->threads */
	}

		{
#endif
	{
	return ret;
		}
	}

static void tcfullsanitycheck(threadcache *tc) THROWSPEC
	if(mem && tc && memsize<=(THREADCACHEMAX+CHUNK_OVERHEAD))
		}
#endif
		/*printf("Created mspace idx %d\n", end);*/
/* The maximum concurrent threads in a pool possible */
	}
		*tc=AllocCache(*p);
/* Alternative malloc implementation for multiple threads without
static void tcsanitycheck(threadcacheblk **ptr) THROWSPEC
		tc->freeInCache-=blksize;
	if(!p) { p=&syspool; if(!syspool.threads) InitPool(&syspool, 0, -1); }
	if(!p)
void * nedmemalign(size_t alignment, size_t bytes) THROWSPEC { return nedpmemalign(0, alignment, bytes); }
		unsigned int biggerbestsize=bestsize+bestsize<<1;
	if(ptr[0] && ptr[1])
	for(n=0; p->m[n]; n++)

	unsigned int magic2;
		}
				threadcache_free(p, tc, mymspace, mem, memsize);
 #endif
#ifdef FULLSANITYCHECKS
#define MSPACES 1
#if 0
#endif
	if(!cinuse(mcp)) return 0;
	threadcache *tc;
	return m;
	assert(*mymspace>=0);
			return chunksize(p)-overhead_for(p);
a source language processor.
		++tc->successes;
static void DestroyCaches(nedpool *p) THROWSPEC
	{
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
		assert(nedblksize(ptr[1])>=sizeof(threadcacheblk));
	{
/*#pragma optimize("a", on)*/
	}
#if !NO_MALLINFO
 #define TLSSET(k, a)	(!TlsSetValue(k, a))
 #define TLSGET(k)		pthread_getspecific(k)
#endif
#if 1
#ifdef FULLSANITYCHECKS
	unsigned int idx=size2binidx(size);
	binsptr=&tc->bins[idx*2];
	{
