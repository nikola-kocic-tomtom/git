      struct trie *last, *next[NCHAR];
  obstack_free(&kwset->obstack, NULL);
	      end += d;
  struct trie *trie;		/* Trie node pointed to by this edge. */
    {
  struct trie *parent;		/* Parent of this node. */
	  return;

	  if (i > len)
	 shift exceeds their inherited maxshift. */
#include "kwset.h"
	   struct trie *recourse)
		 than the difference of their depths. */
  kwset->trie->shift = 0;
struct tree
	{
  kwset->mind = INT_MAX;
  kwset = (struct kwset *) kws;
	next[i] = NULL;
	      if (dirs[depth - 1] == L)
  free(kws);
      if (!d)
	  }
      if (trie->accepting)
	{
      return NULL;
   the Free Software Foundation; either version 2, or (at your option)
		}
	    return tp - len - text;
  int maxd;			/* Maximum depth of any node. */
      if (lmch)
	    }
	  d = trie->shift;
  next = kwset->next;
	{
  tree->trie->fail = recourse;
  if (trie->depth < kwset->mind)
   keyword matched. */
	      end += delta[U(*end)];


	    d = d1[U(tp[-1])], tp += d;
  /* Now we have only a few characters left to search.  We
static void
  struct trie *fail;		/* Aho-Corasick failure function. */
      if (U(tp[-2]) == gc)
	    {
	    {
	  for (fail = curr->fail; fail; fail = fail->fail)
  /* Given a known match, find the longest possible match anchored
  register struct tree const *tree;
		}
    {
	}
     of the hairy commentz-walter algorithm. */
  unsigned char const *trans;  /* Character translation table. */
/* Written August 1989 by Mike Haertel.
}
	      return "memory exhausted";
  gc = U(sp[-2]);
      size_t ret = bmexec (kws, text, size);
		fail->maxshift = curr->depth - fail->depth;

      dirs[0] = L;
  md2 = kwset->mind2;
	tp += md2;
    return -1;
      register struct trie *fail;
#define U(c) ((unsigned char) (c))


  if (lim - mch > kwset->maxd)
	    dirs[depth++] = L, link = link->llink;
  enqueue(tree->llink, last);
		      r = links[depth], l = r->llink, t = l->rlink;

	 computing the delta table, failure function, and shift function. */
/* Node of a trie representing a set of reversed keywords. */
	  if (curr->maxshift > curr->parent->maxshift)
  char const *beg, *lim, *mch, *lmch;
  if (len > size)
	 struct kwsmatch *kwsmatch)
	    if (d == 0)
		case (char) -2:
		    {
  kwset->trie->depth = 0;

  int words;			/* Number of words in the trie. */
/* adapter for `xmalloc()`, which takes `size_t`, not `long` */
   any later version.
}
      while (beg > text)
  kwset = (struct kwset *) kws;
   for success, an error message otherwise. */
      if (!link)
    }
{
  delta = kwset->delta;
	}
      if (kwsmatch != NULL && ret != (size_t) -1)
		links[depth - 1]->llink = t;
  trans = kwset->trans;
struct trie
	      trie = tree->trie;
  kwset->trans = trans;
	  if (dirs[--depth] == L)
      d = trie->shift;
	  curr->maxshift = kwset->mind;

	  while (depth && !links[depth]->balance)
  trie = kwset->trie;
/*
	  enqueue(curr->links, &last);
    {
	  mch = beg;
    return;

	  link->trie->next = NULL;
		      t->llink = l, l->rlink = lr, t->rlink = r, r->llink = rl;
      for (i = kwset->mind - 1, curr = kwset->trie; i >= 0; --i)
  d = d1[U(tp[-1])];
  lmch = NULL;
	  if (tree)
  /* Keep track of the longest and shortest string of the keyword set. */
  register int depth;
		      l = links[depth], t = l->rlink, lr = t->llink;
	  link->trie->links = NULL;
      c = kwset->target[kwset->mind - 1];
    {
		      l->balance = t->balance != 1 ? 0 : -1;
	  /* Update the shifts at each node in the current node's chain
	for (i = 0; i < NCHAR; ++i)
  int maxshift;			/* Max shift of self and descendants. */

      else
   This program is distributed in the hope that it will be useful,
  /* Check if we can use the simple boyer-moore algorithm, instead
						     sizeof (struct trie));
  obstack_init(&kwset->obstack);
  if (!trie->accepting)
	      if (curr->accepting && fail->maxshift > curr->depth - fail->depth)
		      abort ();
kwsexec (kwset_t kws, char const *text, size_t size,


		  fail->shift = curr->depth - fail->depth;
      treenext(kwset->trie->links, next);
      return tp ? tp - text : -1;
{
	{
      while (link && tree->label != link->label)
      kwsfree((kwset_t) kwset);
/* Balanced tree of edges and labels leaving a given trie node. */
/* Compute the Aho-Corasick failure function for the trie nodes referenced
	  d = 1;
		      t->balance = 0;
  if (!tree)
treefails (register struct tree const *tree, struct trie const *fail,
  if (kwset->words == 1 && kwset->trans == NULL)
  len = kwset->mind;
/* Hairy multiple string search. */
	      /* If the current node has some outgoing edge that the fail
{
static size_t
   but WITHOUT ANY WARRANTY; without even the implied warranty of
	      if (trie->accepting)
  return mch - text;
	  accept = trie;
  struct kwset *kwset;
    {

	  link->llink = NULL;

	  c = trans ? trans[U(*--beg)] : *--beg;

	continue;
      /* Find the minimal delta2 shift that we might make after
   is non-NULL store in the referenced location the length of the
{
/* Enqueue the trie nodes referenced from the given tree in the
		  accept = trie;
   well as a last resort failure node. */
    }
		default:
kwsprep (kwset_t kws)
	      goto found;
		      abort ();
  unsigned char delta[NCHAR];	/* Delta table for rapid search. */
   from the given tree, given the failure function for their parent as
/* Allocate and initialize a keyword set object, returning an opaque
	 this trie node, so build a new trie node and install
	      else
	     of fails back to the root. */

  kwset->trie->links = NULL;
  return NULL;
    }
}
};
    {
   along with this program; if not, see <http://www.gnu.org/licenses/>. */

	    curr->maxshift = curr->parent->maxshift;
		    }

		  mch = beg;
    }

/* Structure returned opaquely to the caller, containing everything. */
  else
	  while (tree && c != tree->label)
/* Return true if A has every label in B. */
	  /* Update the delta table for the descendants of this node. */
    {
	    }
  while (lim - end >= d)
}
      kwset->target = obstack_alloc(&kwset->obstack, kwset->mind);
	  for (i = 3; i <= len && U(tp[-i]) == U(sp[-i]); ++i)

  struct tree *llink;		/* Left link; MUST be first field. */
		      t->rlink = r, r->llink = rl;
	      trie = tree->trie;
	  goto match;
size_t
      a = a->rlink;
	    if (c < tree->label)
	    {
    }
	  kwsmatch->index = 0;
		  break;
	   unsigned char delta[])
	  link->trie->fail = NULL;
	return "memory exhausted";
	{
		      t->llink = l, l->rlink = lr;
	  ++end;
    lim = mch + kwset->maxd;
};
	  if (tree)
  memset(delta, kwset->mind < UCHAR_MAX ? kwset->mind : UCHAR_MAX, NCHAR);
  register int i;
	  treedelta(curr->links, curr->depth, delta);
	    break;
	  c = trans ? trans[U(*--beg)] : *--beg;
}
     installing new nodes when necessary. */
	}
	      end += delta[U(*end)];
		 difference of their depths. */
	  else
	while (tp <= ep)
      depth = 1;
      kwsmatch->offset[0] = mch - text;
	{
		{
	      ;

	  {
  end = text;
    qlim = NULL;
kwset_t
/* This upper bound is valid for CHAR_BIT >= 4 and
	    d = d1[U(tp[-1])], tp += d;
    }
	else
  register struct tree *link;
	      obstack_free(&kwset->obstack, link);
     index number of this word in the keyword set so far. */
	delta[U(kwset->target[i])] = kwset->mind - (i + 1);
{
	continue;
		links[depth - 1]->rlink = t;
		    default:
	      tree = tree->llink;
  if (len == 0)

  register unsigned char const *trans;
		++links[depth]->balance;
	break;
    qlim = lim - 4 * kwset->mind;
#include "compat/obstack.h"
  if ((d = kwset->mind) != 0)
/* Compute the shift for each trie node, as well as the delta
  enum { L, R } dirs[DEPTH_SIZE];
{

		      r->balance = t->balance != (char) -1 ? 0 : 1;
  treenext(tree->llink, next);
	    d = d1[U(tp[-1])], tp += d;
    for (ep = text + size - 11 * len;;)

	      else

    return 1;

  lim = text + len;
  if (trie->depth > kwset->maxd)
		      rl = t->rlink, lr = t->llink;
  struct obstack obstack;	/* Obstack for node allocation. */

	      /* If the current node is accepting then the shift at the
  d = 1;

     at or before its starting point.  This is nearly a verbatim
	  if (!link)
cwexec (kwset_t kws, char const *text, size_t len, struct kwsmatch *kwsmatch)
	  lmch = beg;

      /* Descend the tree of outgoing links for this trie node,
	  /* Rebalance the tree by pointer rotations if necessary. */

      else
  /* Mark the node we finally reached as accepting, encoding the
/* Add the given string to the contents of the keyword set.  Return NULL
      if (trie->accepting && beg <= mch)
	    d = d1[U(tp[-1])], tp += d;
  return NULL;
      links[0] = (struct tree *) &trie->links;
  struct kwset const *kwset;
      trie = next[c];
	    links[depth]->llink = link;

		BUG("Cannot allocate a negative amount: %ld", size);
const char *
  char *target;			/* Target string if there's only one. */
     node at which an outgoing edge is labeled by that character. */
/* Fast boyer-moore search. */
  register char const *end, *qlim;
    /* 11 is not a bug, the initial offset happens only once. */

      }
  struct trie const *trie;
 * repository. A few small changes have been made to adapt the code to
  int mind;			/* Minimum depth of an accepting node. */
  if (kwsmatch)
static size_t
 */
}
	 a link in the current trie node's tree. */
    {
	    d = d1[U(tp[-1])], tp += d;
		      l->balance = t->balance != 1 ? 0 : -1;
	}
}
bmexec (kwset_t kws, char const *text, size_t size)
		      t->balance = 0;
		    case L:
	 from the root node. */

  register int d, gc, i, len, md2;
		      lr = t->llink, rl = t->rlink;
      kwsmatch->index = accept->accepting / 2;
  return -1;


    }
	{
      return ret;
		    {
  struct trie *trie;		/* The trie itself. */
kwsalloc (unsigned char const *trans)
	if (U(tp[-2]) == gc)
    return 0;
	}
/* Compute a vector, indexed by character code, of the trie nodes
		case 2:
    {
	return xmalloc(size);
  unsigned int accepting;	/* Word index of accepted word, or zero. */
    }
  register int d;
	  continue;
{
		  accept = trie;
  struct trie *next;		/* List of all trie nodes in level order. */
  char balance;			/* Difference in depths of subtrees. */
  return (kwset_t) kwset;
	  else
      if (link)
	  treefails(curr->links, curr->fail, kwset->trie);
      /* The current character doesn't have an outgoing link at
					       sizeof (struct tree));

	    d = d1[U(tp[-1])], tp += d;
	{
    return 0;
  struct tree *links[DEPTH_SIZE];
      while (link && label != link->label)
  kwset->target = NULL;
	  while ((d = delta[c = *end]) && end < qlim)

  treedelta(tree->llink, depth, delta);
{
  register struct tree *link;
  register unsigned char c;
  kwset->trie->accepting = 0;
     delta entry for a given character is the smallest depth of any
	  {
  else
	  if (!link->trie)

kwsincr (kwset_t kws, char const *text, size_t len)
  accept = NULL;
	    d = d1[U(tp[-1])], tp += d;
  register unsigned char const *d1;
#define NCHAR (UCHAR_MAX + 1)
  next[tree->label] = tree->trie;
   Vol. 18, No. 6, which describes the failure function used below. */
		{
	  /* Install the new tree node in its parent. */
{
  struct tree *links;		/* Tree of edges leaving this node. */
  /* Initial values for the delta table; will be changed later.  The
  kwset = (struct kwset *) kws;

    return;
};
  kwset->trie->next = NULL;
	{
	  kwset->target[i] = curr->links->label;
	    if (c < tree->label)
   or (US mail) as Mike Haertel c/o Free Software Foundation. */
     carefully avoid ever producing an out-of-bounds pointer. */
enqueue (struct tree *tree, struct trie **last)
/* Set delta entries for the links of the given tree such that
    {
}
   the preexisting delta value is larger than the current depth. */
	  link->label = label;


  register struct trie *trie;
	 a backwards match has failed. */
	  while (tree && c != tree->label)

#define obstack_chunk_free free
	  curr->shift = kwset->mind;
static void
  while (lim - end >= d)
{
	}
	{
      /* Traverse the trie in level order again, fixing up all nodes whose
  kwset->maxd = -1;
    kwset->mind = trie->depth;
  kwset = (struct kwset *) kws;
  if (len >= 4 * kwset->mind)
	  tree = trie->links;
   This program is free software; you can redistribute it and/or modify
		      t->llink = l, l->rlink = lr, t->rlink = r, r->llink = rl;
    mch = NULL;
    return;
      if (qlim && end <= qlim)

	  link->trie->parent = trie;
		}
	{
  unsigned char label;		/* Label on this edge. */
	{
    return 0;
#define DEPTH_SIZE (CHAR_BIT + CHAR_BIT/2)
  treefails(tree->llink, fail, recourse);
  while (a && b->label != a->label)
	    else
   in the referenced location the index number of the particular
	    }
	}
		    }
	    links[depth]->rlink = link;
   it under the terms of the GNU General Public License as published by
	    break;
	}
   GNU General Public License for more details.
	 looking for the current character and keeping track
  if (!tree)
	  /* Compute the failure function for the descendants of this node. */
	}
   IBM-Germany, Scientific Center Heidelberg, Tiergartenstrasse 15, D-6900
   matching substring.  Similarly, if FOUNDIDX is non-NULL, store
  if (len < kwset->mind)
	  /* Back up the tree fixing the balance flags. */
    trie->accepting = 1 + 2 * kwset->words;
      trie = link->trie;
	      goto found;
	      if (trie->accepting && beg <= mch)
	  break;

	  mch = lmch;
	  kwsmatch->size[0] = kwset->mind;
  ep = text + size;
  treedelta(tree->rlink, depth, delta);
	    {
      if ((d = delta[c = (end += d)[-1]]) != 0)
		  break;
/* Search through the given text for a match of any member of the
  unsigned char delta[NCHAR];

      d = md2;
	  accept = trie;
	      tree = tree->llink;

	      --depth;
/* The algorithm implemented by these routines bears a startling resemblance
static void *obstack_chunk_alloc(long size)
static void
{
		    case R:
    return -1;
      for (i = 0; i < NCHAR; ++i)
	    {
      /* Looking for just one string.  Extract it from the trie. */
  struct kwset *kwset;
		--links[depth]->balance;
		      t->balance = l->balance = 0;
kwsfree (kwset_t kws)
	    if (i > len)
	      switch (links[depth]->balance)
  else
      d = trie->shift;

		if (curr->depth - fail->depth < fail->shift)
  if (!hasevery(a, b->rlink))
   exact for CHAR_BIT in { 4..11, 13, 15, 17, 19 }. */
	 of the path followed. */

   See "A String Matching Algorithm Fast on the Average," Technical Report,
	continue;
      char c;


   to one discovered by Beate Commentz-Walter, although it is not identical.
	  curr = curr->links->trie;
      if (mch)
  if (!b)
  struct kwset const *kwset;
    }
   the matching substring, or NULL if no match is found.  If FOUNDLEN
  /* Significance of 12: 1 (initial offset) + 10 (skip loop) + 1 (md2). */
	  if (label < link->label)
      /* Create a vector, indexed by character code, of the outgoing links
  kwset = (struct kwset *) xmalloc(sizeof (struct kwset));

		    case L:
      {
  else
	  tree = trie->links;
const char *
		      l = links[depth], r = l->rlink, t = r->llink;
	    }

  struct trie *next[NCHAR];	/* Table of children of the root. */
  (*last) = (*last)->next = tree->trie;
	}
	}
  kwset = (struct kwset const *) kws;
	    if (d == 0)
		{
      kwset->delta[i] = delta[U(trans[i])];
	      tree = tree->rlink;
     copy of the preceding main search loops. */
   referenced from the given tree. */
  int shift;			/* Shift function for search failures. */
  register unsigned char const *trans;
	goto match;
  /* Find, in the chain of fails going back to the root, the first
	  links[depth] = link;
  sp = kwset->target + len;
      for (i = kwset->mind - 2; i >= 0; --i)
    = (struct trie *) obstack_alloc(&kwset->obstack, sizeof (struct trie));
{
/* Free the components of the given keyword set. */
		  switch (dirs[depth + 1])
    kwset->maxd = trie->depth;
	    curr->shift = curr->maxshift;
 match:
	{
	    dirs[depth++] = R, link = link->rlink;

  if (!tree)
      beg = end - 1;
      tp = memchr (text, kwset->target[0], size);
	      if (dirs[depth] == L)
	}
static int
	  if (curr->shift > curr->maxshift)
		 doesn't, then the shift at the fail should be no larger
static void
   given queue. */
	  link = (struct tree *) obstack_alloc(&kwset->obstack,
	  link = link->llink;
      goto match;
	}
	  }
      if (!kwset->target)
	      goto found;
      beg = end - 1;
   Copyright 1989, 1998, 2000, 2005 Free Software Foundation, Inc.


  register unsigned char label;
   String Matching:  An Aid to Bibliographic Search," CACM June 1975,
      label = kwset->trans ? kwset->trans[U(*--text)] : *--text;
	  kwset->next[i] = next[U(trans[i])];
	    d = d1[U(tp[-1])], tp += d;
  while (fail)
  if (size > 12 * len)
  register char const *ep, *sp, *tp;
   given keyword set.  Return a pointer to the first character of
hasevery (register struct tree const *a, register struct tree const *b)
    }
		      r = links[depth], t = r->llink, rl = t->rlink;
    {
  while (d <= ep - tp)
      /* Traverse the nodes of the trie in level order, simultaneously
      kwsmatch->size[0] = accept->depth;
    if (b->label < a->label)
	if (kwset->target[i] == c)
 * This file has been copied from commit e7ac713d^ in the GNU grep git
	  link = link->rlink;
      if (d)
			|| (dirs[depth] == R && ++links[depth]->balance)))
	}
      for (curr = last = kwset->trie; curr; curr = curr->next)
      for (curr = kwset->trie->next; curr; curr = curr->next)
		    default:
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	  link->trie->shift = 0;
  kwset->trie->fail = NULL;
		  abort ();
  kwset->words = 0;
  enqueue(tree->rlink, last);
#include "cache.h"
     node that has a descendant on the current label. */


}
   You should have received a copy of the GNU General Public License

/* kwset.c - search for any of a set of keywords.
   The author may be reached (Email) at the address mike@ai.mit.edu,
   pointer to it.  Return NULL if memory is not available. */
		      r->balance = t->balance != (char) -1 ? 0 : 1;

	    }
  if (len == 1)
	    ;
  /* Fix things up for any translation table. */
    else
{
		      break;
	  /* Enqueue the immediate descendants in the level order queue. */

  return -1;
    for (i = 0; i < NCHAR; ++i)
  kwset->trie
	  link->rlink = NULL;
}
      d = d1[U((tp += d)[-1])];
	    return "memory exhausted";
      if ((trans = kwset->trans) != NULL)

	    d = d1[U(tp[-1])], tp += d;

	  else
  struct trie * const *next;
	  kwsmatch->offset[0] = ret;
  register struct kwset *kwset;

  if (depth < delta[tree->label])
		      break;
	    if (d == 0)
  return !!a;
  struct trie const *accept;
      while (beg > text)

      mch = text, accept = kwset->trie;
  ++kwset->words;
{
	    d = d1[U(tp[-1])], tp += d;
      link = trie->links;
	  link->trie = (struct trie *) obstack_alloc(&kwset->obstack,
	COPY_ARRAY(kwset->next, next, NCHAR);
	      if (!hasevery(fail->links, curr->links))
  d1 = kwset->delta;
	if (tree->label < link->label)
		 fail and its descendants should be no larger than the
      for (i = 0; i < kwset->mind; ++i)
  else
{
  if (kwset->words == 1 && kwset->trans == NULL)
  /* Descend the trie (built of reversed keywords) character-by-character,

		  switch (dirs[depth + 1])
	{
	  else
	  d = trie->shift;
    }
		    case R:
 * Git.
      kwset->mind2 = kwset->mind - (i + 1);
	    {
	      return tp - len - text;
   table and next cache for the given keyword set. */
	   register unsigned int depth,
	d = 1;
      fail = fail->fail;
	    }
	}
	  link->trie->depth = trie->depth + 1;
	if (size < 0)
      /* Build the Boyer Moore delta.  Boy that's easy compared to CW. */
	  tree->trie->fail = link->trie;
   Heidelberg, Germany.  See also Aho, A.V., and M. Corasick, "Efficient
	    {
  struct kwset *kwset;
  treenext(tree->rlink, next);

		  lmch = beg;

  if (!kwset->trie)
treedelta (register struct tree const *tree,
  struct kwset const *kwset = (struct kwset *) kws;
    {
	    else

  while (len--)
	d = delta[c = (end += d)[-1]];
	  end += d - 1;
    memcpy(kwset->delta, delta, NCHAR);
}

  int depth;			/* Depth of this node from the root. */
	{
  int mind2;			/* Used in Boyer-Moore search for one string. */
    delta[tree->label] = depth;
  struct tree *rlink;		/* Right link (to larger labels). */

		      break;
treenext (struct tree const *tree, struct trie *next[])
  treefails(tree->rlink, fail, recourse);
}
  kwset->trie->parent = NULL;
      if (!(trie = next[c]))
  struct tree *t, *r, *l, *rl, *lr;
	  link->balance = 0;
    return cwexec(kws, text, size, kwsmatch);
  if (!hasevery(a, b->llink))
      a = a->llink;
  tp = text + len;
struct kwset
      if (d != 0)

  /* Initialize register copies and look for easy ways out. */
	  if (depth && ((dirs[depth] == L && --links[depth]->balance)

	    }
{

  register unsigned char const *delta;
	      tree = tree->rlink;
  text += len;
  register struct trie *curr;
      found:
	  link->trie->accepting = 0;
		      break;
      link = fail->links;
    return;
		      t->balance = r->balance = 0;
	    for (i = 3; i <= len && U(tp[-i]) == U(sp[-i]); ++i)
void
  if ((trans = kwset->trans) != NULL)
  if (!tree)
    }
}
