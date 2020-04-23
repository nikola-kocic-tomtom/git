{
  return REG_NOERROR;
      return REG_NOERROR;

			    const re_dfa_t *dfa)
		    end_idx = (pstr->bufs_len > pstr->len)
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;

	    break;
		    else
	  dest->alloc = dest->nelem = 0;
      pstr->valid_len = 0;
}
	}
	  /* The buffer doesn't have enough space, finish to build.  */
		     byte other than 0x80 - 0xbf.  */
#ifdef DEBUG
		    unsigned int hash)
		      pstr->valid_len = pstr->offsets[mid] - offset;
		  memmove (pstr->mbs, pstr->mbs + offset, pstr->valid_len - offset);
    return 0;

/* Build wide character buffer PSTR->WCS.
     DOTLESS SMALL LETTER I.  The latter would confuse the parser,
    }
	else

  if (set->alloc == set->nelem)
    return NULL;
internal_function
      else
    {
	}
      if (dfa->mb_cur_max > 1)
		  memmove (pstr->wcs, pstr->wcs + offset,
  pstr->valid_raw_len = byte_idx;
	      pstr->tip_context = re_string_context_at (pstr, offset - 1,
	newstate->has_constraint = 1;
  if (set1 == NULL || set2 == NULL || set1->nelem != set2->nelem)
   built and starts from PSTR->VALID_LEN.  */
       rawbuf_idx < new_raw_idx;)
  err = re_node_set_alloc (&newstate->non_eps_nodes, newstate->nodes.nelem);
     mapped to wide characters with a simple cast.  */
	  while (1)
	    }
static reg_errcode_t
					? CONTEXT_NEWLINE : 0));
  /* There are no appropriate state in `dfa', create the new one.  */
}
	  else
	    }

      if (src1->elems[i1] == src2->elems[i2])
  /* Copy remaining SRC elements.  */
  re_free (pstr->wcs);
		if (BE (mbclen == mbcdlen, 1))
	  dest->elems[id + delta--] = dest->elems[is--];
{
		      delta * sizeof (int));
    return re_string_peek_byte (pstr, idx);
		pstr->tip_context
	    }
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      set->nelem = 2;
		pstr->wcs[byte_idx++] = WEOF;
    return NULL;
			      while (--i >= 0)
re_string_destruct (re_string_t *pstr)
    }
	newstate->has_backref = 1;
      set->elems = new_elems;
	    {
		  memcpy (pstr->mbs + byte_idx, p, mbclen);
		  /* We know the wchar_t encoding is UCS4, so for the simple
			      wc = wc2;
  *last_wc = (wint_t) wc;
    }

  re_dfastate_t *new_state;
    }
    }
	return REG_ESPACE;
			  /* XXX Don't use mbrtowc, we know which conversion
/* Insert the new element ELEM to the re_node_set* SET.
		  size_t mbcdlen;
    *err = REG_ESPACE;
		    high = mid;
/* Functions for string operation.  */
{

   version 2.1 of the License, or (at your option) any later version.
re_node_set_init_union (re_node_set *dest, const re_node_set *src1,

  hash = calc_state_hash (nodes, context);
    {
  if (input->mb_cur_max > 1)
			      ((const char *) pstr->raw_mbs + pstr->raw_mbs_idx
}
    {
   Note that this function assumes PSTR->VALID_LEN elements are already
	    {
re_node_set_compare (const re_node_set *set1, const re_node_set *set2)
  dfa->nexts[dfa->nodes_len] = -1;
	    /* Slide from the bottom.  */

	return -1;
    }
      if (bitset_contain (input->word_char, c))
	return CONTEXT_WORD;
	if (BE (pstr->trans != NULL, 0))
    {
	    {
{
			  if (raw + offset - p <= mbclen

	      ? CONTEXT_NEWLINE : 0);

      if (!pstr->mbs_allocated)
}
      re_string_skip_bytes (pstr,
      }
	    else
  if (! pstr->map_notascii && pstr->trans == NULL && !pstr->offsets_needed)
}
static reg_errcode_t
  newstate->hash = hash;
      if (src1->elems[i1] == src2->elems[i2])
  return REG_NOERROR;
			  break;
#endif /* RE_ENABLE_I18N  */
    }
      int *new_elems;
  if (elem < set->elems[0])
   License as published by the Free Software Foundation; either
  if (BE (dfa->nodes_len >= dfa->nodes_alloc, 0))
/* Create the new state which is independent of contexts.
  if (src == NULL || src->nelem == 0)
  if (len > 0)
		  /* Otherwise, just find out how long the partial multibyte
  ch = pstr->raw_mbs[pstr->raw_mbs_idx + off];
	  else
	      pstr->wcs[byte_idx++] = WEOF;
			if (pstr->offsets == NULL)
	    if (BE (pstr->trans != NULL, 0))
      dest->elems = new_buffer;
{
	    int ch = pstr->raw_mbs[pstr->raw_mbs_idx + src_idx];
   return -1 if an error has occurred, return 1 otherwise.  */
	return re_node_set_init_copy (dest, src2);
	    }
  return REG_NOERROR;
	    /* It is an invalid character or '\0'.  Just use the byte.  */
	    }
	return -1;
    /* In this case, we use the value stored in input->tip_context,

	    /* Copy from the top.  */
    }
	  wchar_t wc;
	  return REG_ESPACE;
}
		size_t mbcdlen;
	    {
		  if (BE (mbclen == mbcdlen, 1))
    {
		  pstr->offsets_needed = 0;
			      && mbclen < (size_t) -2)
	    for (i = 0; i < pstr->mb_cur_max && i < remain_len; ++i)
  mbstate_t prev_st;
re_acquire_state (reg_errcode_t *err, const re_dfa_t *dfa,
  if (idx < 0 || idx >= set->nelem)
  set->nelem = 1;
	  pstr->cur_state = prev_st;
static int
	right = mid;
      re_token_t *node = dfa->nodes + nodes->elems[i];
		    if (pstr->raw_stop > src_idx)
      int new_alloc = 2 * (src->nelem + dest->alloc);
      if (BE (new_elems == NULL, 0))

    return input->tip_context;
					const re_dfa_t *dfa) internal_function;
	      if (wc == WEOF)
    {
	      if (BE (ret != REG_NOERROR, 0))
/* Apply TRANS to the buffer in PSTR.  */
    return re_string_peek_byte (pstr, idx);
#endif
	{
  set->elems = re_malloc (int, 2);
   convert to upper case in case of REG_ICASE, apply translation.  */
{
#undef MAX	/* safety */
	    /* Write paddings.  */
		      ++mid;
	return REG_ESPACE;
  int i;
		mbcdlen = wcrtomb ((char *) buf, wcu, &prev_st);

	}
      /* Lower the highest of the two items.  */
  int idx;
			break;
	    if (BE (mbclen == (size_t) -1, 0))
    }
  return REG_NOERROR;
					 && pstr->newline_anchor)
  unsigned int hash;
		  if (end < pstr->raw_mbs)
static reg_errcode_t
  if (BE (nodes->nelem == 0, 0))
      re_dfastate_t *state = spot->array[i];
static inline unsigned int
  i1 = src1->nelem - 1;
  if (BE (set->nelem, 0) == 0)
      else
      ++set->nelem;
      newstate->accept_mb |= node->accept_mb;
	build_upper_buffer (pstr);
static void
  size_t mbclen;
    }
		pstr->tip_context = ((BE (pstr->word_ops_used != 0, 0)
#endif /* RE_ENABLE_I18N */
  return 1;
  if (BE (idx == input->len, 0))
		}
	  set->elems[0] = elem2;
    }
      pstr->valid_raw_len = byte_idx;
      if (BE (new_elems == NULL, 0))
	  if (BE (ret != REG_NOERROR, 0))
      return NULL;
{
	const char *p;
	{
      pstr->valid_raw_len = 0;
      else if (type == ANCHOR || node->constraint)
re_node_set_remove_at (re_node_set *set, int idx)
  if (src1 != NULL && src1->nelem > 0 && src2 != NULL && src2->nelem > 0)
      else if (BE (mbclen == (size_t) -1 || mbclen == 0, 0))
   Otherwise create the new one and return it.  In case of an error
static re_dfastate_t *
  return 1;

		    memcpy (pstr->mbs + byte_idx, buf, mbcdlen);

{
			   const re_node_set *src2)
  while (idx < right)

      else if (type == OP_BACK_REF)
    {
	return re_string_fetch_byte (pstr);
	      if (pstr->is_utf8)
      memcpy (dest->elems + id, src2->elems + i2,
  struct re_state_table_entry *spot;
  int byte_idx, end_idx, remain_len;
    {
  pstr->mbs_allocated = (trans != NULL || icase);
		++mid;
      c = re_string_byte_at (input, idx);
		  {
		  pstr->stop = pstr->raw_stop - idx + offset;
		}
		      }

	return REG_ESPACE;
{
  if (state->entrance_nodes != &state->nodes)
create_cd_newstate (const re_dfa_t *dfa, const re_node_set *nodes,

static int
  pstr->icase = icase ? 1 : 0;

      pstr->tip_context = ((eflags & REG_NOTBOL) ? CONTEXT_BEGBUF
	  if (pstr->mb_cur_max > 1)
internal_function __attribute ((pure))
	      {
			  int mlen = raw + pstr->len - p;
    {
#endif
re_string_allocate (re_string_t *pstr, const char *str, int len, int init_len,

      if (BE (new_nodes == NULL, 0))
{
/* Compare two node sets SET1 and SET2.
      re_dfastate_t *state = spot->array[i];
			    {
	  {
}
  if (dest->alloc < 2 * src->nelem + dest->nelem)
re_dfa_add_node (re_dfa_t *dfa, re_token_t token)
      if (BE (pstr->trans != NULL, 0))
}
    {
      off = pstr->offsets[pstr->cur_idx];
	    pstr->wcs[byte_idx++] = wcu;

    }
	   return value is NULL and ERR is REG_NOERROR.
    }

					      new_alloc);
		  while (mid < pstr->valid_len)
    init_len = dfa->mb_cur_max;

#ifdef RE_ENABLE_I18N
    }
  int i1, i2, id;
build_wcs_buffer (re_string_t *pstr)
}
    }
      for (idx = set->nelem; set->elems[idx - 1] > elem; idx--)
  newstate->context = context;
    {
	      re_node_set_remove_at (&newstate->nodes, i - nctx_nodes);
      /* We already guaranteed above that set->alloc != 0.  */
		     RE_TRANSLATE_TYPE trans, int icase, const re_dfa_t *dfa)
	return REG_ESPACE;
/* Build wide character buffer PSTR->WCS like build_wcs_buffer,
	}

{
	re_node_set_init_empty (dest);
	      if (BE (newstate->entrance_nodes == NULL, 0))
  int rawbuf_idx;
}
	      /* The next step uses the assumption that wchar_t is encoded
			      pstr->valid_len = mbclen - (raw + offset - p);
  sbase = dest->nelem + src1->nelem + src2->nelem;
}
	{
	}
	  else
      dest->elems[id++] = src1->elems[i1++];
	pstr->mbs[char_idx] = toupper (ch);
      int new_alloc = src1->nelem + src2->nelem + dest->alloc;
      int ch = pstr->raw_mbs[pstr->raw_mbs_idx + char_idx];
  if (BE (newstate == NULL, 0))
      else if (type == OP_BACK_REF)
      *err = REG_NOERROR;
#ifdef RE_ENABLE_I18N
			  memset (&cur_state, 0, sizeof (cur_state));
		    pstr->valid_len = 0;
/* This function allocate the buffers.  It is necessary to call
#endif /* RE_ENABLE_I18N  */
      sbase -= is + 1;
/* Functions for set operation.  */
static re_dfastate_t *
      free_state (newstate);
   return 1 if SET1 and SET2 are equivalent, return 0 otherwise.  */
   Note: - We assume NULL as the invalid state, then it is possible that
  pstr->valid_raw_len = src_idx;
      pstr->wcs[byte_idx++] = wc;
      if (re_node_set_compare (&state->nodes, nodes))
	    pstr->mbs[byte_idx] = ch;

  /* Now copy.  When DELTA becomes zero, the remaining
	      pstr->wcs[byte_idx] = (wchar_t) pstr->mbs[byte_idx];
   HASH put in the appropriate bucket of DFA's state table.  Return value
	    if (--id < 0)
	    return REG_ESPACE;
    for (;;)
#ifdef RE_ENABLE_I18N
re_string_translate_buffer (re_string_t *pstr)
  re_node_set_init_empty (dfa->eclosures + dfa->nodes_len);
{
		size_t i;
			   : CONTEXT_NEWLINE | CONTEXT_BEGBUF);
	      else
	      ch = pstr->trans [ch];
      newstate->accept_mb |= node->accept_mb;
  return newstate;
	    if (delta == 0)
	      else
   Copyright (C) 2002-2006, 2010 Free Software Foundation, Inc.
			 (pstr->valid_len - offset) * sizeof (wint_t));
    }
      if (BE (new_array == NULL, 0))

      re_token_type_t type = node->type;
  set->elems = re_malloc (int, 1);
   Return the index.  */
      if (!BE (pstr->mbs_allocated, 0))
  return ch;
	      if (pstr->offsets[mid] < offset)
  id = dest->nelem - 1;
  pstr->word_ops_used = dfa->word_ops_used;
	  if (BE (pstr->offsets_needed, 0))
	    }
	  {
			  const re_node_set *nodes, unsigned int context)
	      ++nctx_nodes;
		    pstr->wcs[byte_idx] = wcu;
	pstr->mbs += offset;
      {
      if (BE (SIZE_MAX / max_object_size < new_nodes_alloc, 0))
		    continue;
	{
  int offset = idx - pstr->raw_mbs_idx;
			       + byte_idx), remain_len, &pstr->cur_state);
	  build_upper_buffer (pstr);
  if (pstr->mbs_allocated)
	  pstr->offsets = new_offsets;
		 only the common and easy case where the character with
  pstr->mb_cur_max = dfa->mb_cur_max;

  dest->nelem += delta;
      pstr->len = pstr->raw_len;
  for (sbase = dest->nelem + 2 * src->nelem,
      if (islower (ch))
    {
      else if (src2 != NULL && src2->nelem > 0)
	  {
  dfa->nodes[dfa->nodes_len].accept_mb =
static void
	return -1;
	  else
  set->alloc = 2;
  else
  dfa->nodes[dfa->nodes_len] = token;

	{

	 [[: DOTLESS SMALL LETTER I return [[:I, as doing
		  pstr->valid_raw_len = pstr->valid_len;
	      pstr->valid_raw_len = pstr->bufs_len;
		ch = pstr->raw_mbs [pstr->raw_mbs_idx + src_idx + i];
internal_function


}
		  const re_node_set *nodes)
	    }
}
static reg_errcode_t
re_node_set_init_copy (re_node_set *dest, const re_node_set *src)
    {
	      pstr->valid_raw_len = pstr->valid_len;

#ifdef RE_ENABLE_I18N
  pstr->valid_raw_len = buf_idx;
    }
#ifdef RE_ENABLE_I18N
static void
      return NULL;
internal_function
re_node_set_add_intersect (re_node_set *dest, const re_node_set *src1,
  re_string_construct_common (str, len, pstr, trans, icase, dfa);
		    --mid;
{
#ifdef RE_ENABLE_I18N
	ch = pstr->trans[ch];
    return REG_ESPACE;
			  remain_len, &pstr->cur_state);
      /* Write paddings.  */
	  int *new_offsets = re_realloc (pstr->offsets, int, new_buf_len);
  unsigned char buf[MB_LEN_MAX];
	    re_string_translate_buffer (pstr);
     this function returns CAPITAL LETTER I instead of first byte of
		      goto offsets_needed;
#ifdef RE_ENABLE_I18N
		    for (; p >= end; --p)
			    pstr->wcs[low] = WEOF;
	      pstr->cur_state = prev_st;
#endif
		  else
       return REG_NOERROR;
	  /* Slide from the bottom.  */
  return REG_NOERROR;
    }
  /* In case the set is empty.  */
    }
	  if (BE (pstr->offsets_needed, 0))
internal_function

	      do
  if (BE (set->elems == NULL, 0))
#else
	    /* And also cast it to wide char.  */
	  /* Yes, move them to the front of the buffer.  */
      pstr->offsets_needed = 0;
{
		    size_t i;
	      }
   a first byte of a multibyte character.
}
		for (i = 0; i < mbclen; ++i)
  assert (MB_LEN_MAX >= pstr->mb_cur_max);
	  /* We treat these cases as a singlebyte character.  */
   If the byte sequence of the string are:
register_state (const re_dfa_t *dfa, re_dfastate_t *newstate,
	is--, id--;
  new_state = create_cd_newstate (dfa, nodes, context, hash);
	}
  pstr->word_char = dfa->word_char;

#endif
  re_free (state->word_trtable);
      pstr->wcs = new_wcs;
		memmove (pstr->mbs, pstr->mbs + offset,
		    end = pstr->raw_mbs;
      if (type == CHARACTER && !constraint)

      if (BE (mbclen == (size_t) -2, 0))
internal_function __attribute ((pure))
    {
		  if (pstr->offsets[mid] > offset)
/* Add the token TOKEN to dfa->nodes, and return the index of the token.

		    if (pstr->wcs[mid] != WEOF)
static reg_errcode_t
  return REG_NOERROR;
static int
		    }
		pstr->valid_len = re_string_skip_chars (pstr, idx, &wc) - idx;
	}
			  size_t mbclen;
				   : ((IS_NEWLINE (c) && pstr->newline_anchor)
#endif
	}
	return -1;
  pstr->trans = trans;
		  for (low = 0; low < pstr->valid_len; low++)
static reg_errcode_t
	    /* The buffer doesn't have enough space, finish to build.  */
	  else
{
re_node_set_init_2 (re_node_set *set, int elem1, int elem2)
  int i;
      *err = REG_NOERROR;
  int i;
	{
  spot = dfa->state_table + (hash & dfa->state_hash_mask);
	remain_len = end_idx - byte_idx;
  reg_errcode_t ret;
	    break;
  pstr->map_notascii = dfa->map_notascii;
	    {
	  }
  pstr->stop -= offset;
	   optimization.  */
	return REG_ESPACE;
				      sizeof (mbstate_t));
  pstr->valid_raw_len = pstr->valid_len;
		  pstr->len = pstr->raw_len - idx + offset;
		  else
		 case is present at or after offset.  */

      if (BE (dest->elems == NULL, 0))
#ifdef RE_ENABLE_I18N

	if (BE (mbclen + 2 > 2, 1))
  wint_t wc = WEOF;
	  if (--i2 < 0)
    (token.type == OP_PERIOD && dfa->mb_cur_max > 1) || token.type == COMPLEX_BRACKET;
  for (byte_idx = pstr->valid_len; byte_idx < end_idx;)
	      assert (pstr->valid_len > 0);
internal_function
  if (pstr->offsets_needed)
      else if (dest->elems[id] < src->elems[is])
	    if (iswlower (wc))
			  for (low = 0; low < pstr->valid_len; ++low)
  if (BE (ret != REG_NOERROR, 0))

	      ret = re_string_realloc_buffers (pstr, pstr->bufs_len * 2);
    {
      mbclen = __mbrtowc (&wc, p, remain_len, &pstr->cur_state);

      ch = pstr->raw_mbs[pstr->raw_mbs_idx + off];
{
	      if (iswlower (wc))
  /* There are no appropriate state in the dfa, create the new one.  */
      int elem = newstate->nodes.elems[i];
   */
		  if (pstr->mbs_allocated)
  if (delta == 0)
	      while (low < high);
	 - We never return non-NULL value in case of any errors, it is for
	  pstr->cur_state = prev_st;
   Return the pointer to the state, if we found it in the DFA.
    for (src_idx = pstr->valid_raw_len; byte_idx < end_idx;)
      /* If DEST is exhausted, the remaining items of SRC must be unique.  */
  int char_idx, end_idx;
	{
	  assert (wc_idx >= 0);
   The GNU C Library is distributed in the hope that it will be useful,
  size_t mbclen;
		{
	  if (delta == 0)
  for (i = 0; i < newstate->nodes.nelem; i++)
}
    {
	 in that case the whole multi-byte character and return
{
		      if ((*p & 0xc0) != 0x80)
internal_function
      int ch = pstr->raw_mbs[pstr->raw_mbs_idx + buf_idx];
  re_string_construct_common (str, len, pstr, trans, icase, dfa);
    }
      dest->elems = re_malloc (int, dest->alloc);
		  mid = low + (high - low) / 2;
/* Insert the new element ELEM to the re_node_set* SET.
		  raw = pstr->raw_mbs + pstr->raw_mbs_idx;
}
	}
  pstr->stop = pstr->len;

  if (BE (err != REG_NOERROR, 0))
			{
  /* Copy into the top of DEST the items of SRC that are not
/* Create the new state which is depend on the context CONTEXT.
	  }
	  /* We treat these cases as a single byte character.  */
	      int wcs_idx;

  return REG_NOERROR;
  int buf_idx, end_idx;
      else if (src1->elems[i1] < src2->elems[i2])
	--id;
  pstr->len -= offset;
static int
	    {
    if (set1->elems[i] != set2->elems[i])
  if (BE (spot->alloc <= spot->num, 0))
      new_edests = re_realloc (dfa->edests, re_node_set, new_nodes_alloc);
   Return the pointer to the state, if we found it in the DFA.
    }
    re_free (pstr->mbs);

	      /* Write paddings.  */
		  if (mid == pstr->valid_len)
internal_function
}
      /* Then proceed the next character.  */
internal_function __attribute ((pure))
      unsigned int constraint = node->constraint;
	      if (pstr->valid_len > offset

    }
      if (BE (new_nexts == NULL || new_indices == NULL
   Concretely, convert to wide character in case of pstr->mb_cur_max > 1,
	    ++src_idx;
  int is, id, sbase, delta;
			pstr->offsets_needed = 1;
	{
   * ADR: valgrind says size can be 0, which then doesn't
		{
	  /* It must not happen.  */
  if (pstr->mb_cur_max > 1)
re_node_set_contains (const re_node_set *set, int elem)
	      pstr->stop = pstr->raw_stop - idx + offset;
		    }
  int src_idx, byte_idx, end_idx, remain_len;
  else
    {
	    }
      memcpy (dest->elems, src->elems, src->nelem * sizeof (int));
	  p = (const char *) buf;
      wint_t *new_wcs;
   indicates the error code if failed.  */
	  remain_len = end_idx - byte_idx;
      re_free (newstate);
      re_free (newstate);
      dfa->nodes_alloc = new_nodes_alloc;
      else


			   (pstr->valid_len - offset) * sizeof (wint_t));
	      if (BE (ret != REG_NOERROR, 0))
      int new_alloc = 2 * spot->num + 2;

		    pstr->offsets[byte_idx] = src_idx;
		{
re_node_set_alloc (re_node_set *set, int size)
	    {
	    {
}

      dest->alloc = new_alloc;
		      wc = (wchar_t) *p;
     pstr->bufs_len.  */
  for (i = 0 ; i < spot->num ; i++)

   re_string_reconstruct before using the object.  */
	return -1;
      pstr->stop = pstr->raw_stop;
  unsigned int idx, right, mid;

	wc = (wint_t) wc2;
  memcpy (dest->elems, dest->elems + sbase, delta * sizeof (int));
}


static reg_errcode_t
/* This function re-construct the buffers.
	      ret = build_wcs_upper_buffer (pstr);
			pstr->offsets = re_malloc (int, pstr->bufs_len);
	{
#endif /* RE_ENABLE_I18N  */
  init_buf_len = (len + 1 < init_len) ? len + 1: init_len;

  spot = dfa->state_table + (hash & dfa->state_hash_mask);
    }
#ifdef RE_ENABLE_I18N
	     (src2->nelem - i2) * sizeof (int));
  ret = re_string_realloc_buffers (pstr, init_buf_len);
      spot->array = new_array;
  for (i = set1->nelem ; --i >= 0 ; )
  if (size == 0)
    }
    }


	newstate->halt = 1;
static reg_errcode_t
      if (BE (input->word_ops_used != 0, 0) && IS_WIDE_WORD_CHAR (wc))
	{
    {
      new_elems = re_realloc (set->elems, int, set->alloc);
  set->elems[idx] = elem;
      new_eclosures = re_realloc (dfa->eclosures, re_node_set, new_nodes_alloc);
      else
	  re_string_translate_buffer (pstr);
	      }
	    wc = pstr->trans[wc];
	set->elems[idx] = set->elems[idx - 1];
	      /* In case of a singlebyte character.  */
      pstr->valid_len = pstr->len;
internal_function
    return REG_ESPACE;
  unsigned int hash;
static reg_errcode_t
      new_indices = re_realloc (dfa->org_indices, int, new_nodes_alloc);

	      pstr->valid_raw_len -= offset;

	      pstr->mbs[byte_idx]
      /* If the state has the halt node, the state is a halt state.  */
  is = dest->nelem + src1->nelem + src2->nelem - 1;
			 pstr->valid_len - offset);
  pstr->valid_len = (pstr->mbs_allocated || dfa->mb_cur_max > 1) ? 0 : len;
/* Return the context at IDX in INPUT.  */


/* Return (idx + 1) if SET contains the element ELEM, return 0 otherwise.  */
	pstr->mbs[char_idx] = ch;

      /* Avoid overflow in realloc.  */
    }
   You should have received a copy of the GNU Lesser General Public
	  if (NOT_SATISFY_PREV_CONSTRAINT (constraint,context))
      else
#endif
#ifdef _LIBC
   Return the new state if succeeded, otherwise return NULL.  */
static void

	      wint_t wc = WEOF;
  return set->elems[idx] == elem ? idx + 1 : 0;
				      ? CONTEXT_NEWLINE : 0));
  mbstate_t prev_st;
  is = dest->nelem + 2 * src->nelem - 1;
      unsigned char *new_mbs = re_realloc (pstr->mbs, unsigned char,
      }
  return REG_NOERROR;
static reg_errcode_t
    }
	else if (mbclen == (size_t) -1 || mbclen == 0)
	return REG_ESPACE;
{
  if (delta > 0 && id >= 0)
  if (icase)
  if (BE (idx < 0, 0))
	  }
	continue;
  /* Realloc if we need.  */
      return REG_NOERROR;
re_node_set_insert (re_node_set *set, int elem)
	      int c = pstr->raw_mbs[pstr->raw_mbs_idx + offset - 1];
    off = pstr->offsets[off];
    {
	    dest->elems[--sbase] = src1->elems[i1];
  if (BE (set->elems == NULL, 0))
	      break;
  else
	      /* This can be quite complicated, so handle specially
	     (src1->nelem - i1) * sizeof (int));
	      ++byte_idx;
	  if (--id < 0)
    {
			  mbstate_t cur_state;

      if (src1 != NULL && src1->nelem > 0)
  for (i1 = i2 = id = 0 ; i1 < src1->nelem && i2 < src2->nelem ;)
internal_function
internal_function
{
      re_node_set *new_edests, *new_eclosures;
  return pstr->raw_mbs[pstr->raw_mbs_idx + pstr->cur_idx++];

	 the original letter.  On the other side, with
  re_dfastate_t *newstate;
      if (BE (offset < pstr->valid_raw_len, 1))
	  p = (const char *) pstr->raw_mbs + pstr->raw_mbs_idx + src_idx;
	    {
		      /* pstr->valid_len = 0; */
      if (BE (new_buffer == NULL, 0))
					      &cur_state);
    {
	{

      /* Write wide character and padding.  */
	      int ch = pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx];

		  pstr->offsets[byte_idx + i] = src_idx + i;
	    if (BE (pstr->offsets_needed != 0, 0))
      memcpy (dest->elems + id, src1->elems + i1,

     DEST elements are already in place; this is more or
re_string_construct (re_string_t *pstr, const char *str, int len,
}
			  pstr->offsets[i] = i;
  if (BE (offset < 0, 0))
	      pstr->valid_raw_len = 0;
		  pstr->valid_raw_len -= offset;
	      pstr->wcs[byte_idx++] = (wchar_t) ch;
      size_t new_nodes_alloc = dfa->nodes_alloc * 2;
	    }
      prev_st = pstr->cur_state;
	else

  if (BE (!pstr->mbs_allocated, 1))
      offset = idx;
    return;
	return CONTEXT_WORD;
  reg_errcode_t err;
   Otherwise create the new one and return it.  In case of an error
	{
#ifdef RE_ENABLE_I18N
		    {
	}
  if (BE (err != REG_NOERROR, 0))
      newstate = NULL;
  if (set->alloc == 0)
      int wc_idx = idx;
	}
#endif /* RE_ENABLE_I18N */

internal_function
MAX(size_t a, size_t b)
#ifdef RE_ENABLE_I18N
	return 1;
      newstate = NULL;
			for (i = 0; i < (size_t) byte_idx; ++i)
}
	 [[: CAPITAL LETTER I WITH DOT lower:]] in mbs.  Skip
	{
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;
    {
  ++set->nelem;
     since peek_byte_case doesn't advance cur_idx in any way.  */
    }
  err = register_state (dfa, newstate, hash);
	    }
	if (dest->elems[is] > dest->elems[id])
		    {

    {
	    int i, ch;
	{
	}


  if (BE (set->elems == NULL, 0))
{
    }
	      if (pstr->bufs_len > pstr->valid_len + dfa->mb_cur_max)
    {
		memmove (pstr->wcs, pstr->wcs + offset,
  return 1;
	  set->elems[0] = elem1;


#endif
internal_function
		      {
	  if (isascii (pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx])
	pstr->mbs = (unsigned char *) pstr->raw_mbs;
      /* For tr_TR.UTF-8 [[:islower:]] there is
    }
	return REG_ESPACE;

      dest->elems = new_elems;
		return ret;
		{
      rawbuf_idx += mbclen;
#ifdef RE_ENABLE_I18N
  memset (pstr, '\0', sizeof (re_string_t));
{
	{

	      /* It is an invalid character or '\0'.  Just use the byte.  */
	{



   Or return -1, if an error has occurred.  */
   Lesser General Public License for more details.
re_node_set_insert_last (re_node_set *set, int elem)
					   new_buf_len);
free_state (re_dfastate_t *state)
		  pstr->valid_len -= offset;
			    {
	build_wcs_buffer (pstr);
	    return input->tip_context;
		pstr->cur_state = prev_st;
{
			const re_node_set *src2)
		    if (pstr->offsets == NULL)
      prev_st = pstr->cur_state;
	  if (BE (mbclen + 2 > 2, 1))
		  free_state (newstate);
		}
    {
	   optimization.  */
      if (src1->elems[i1] > src2->elems[i2])
     found in DEST.  Maybe we could binary search in DEST?  */
	  }

  newstate = (re_dfastate_t *) calloc (sizeof (re_dfastate_t), 1);
      else
	 anything else would complicate things too much.  */
	      if (re_node_set_init_copy (newstate->entrance_nodes, nodes)
      if (hash != state->hash)
  for (buf_idx = pstr->valid_len; buf_idx < end_idx; ++buf_idx)

	      pstr->offsets[byte_idx] = src_idx;
  dest->nelem = src->nelem;
  /* Then build the buffers.  */
      remain_len = end_idx - byte_idx;
	    {

		      }
      re_dfastate_t **new_array = re_realloc (spot->array, re_dfastate_t *,
    {

		{
	      {
	      }
	      || new_edests == NULL || new_eclosures == NULL, 0))
  return dfa->nodes_len++;
    {
		      {
    {
      return REG_ESPACE;
static re_dfastate_t *
      if (pstr->mb_cur_max > 1)
	return re_node_set_init_copy (dest, src1);
					  unsigned int context,
    set->elems[idx] = set->elems[idx + 1];
      offsets_needed:
  /* Move the elements which follows the new element.  Test the
re_node_set_init_1 (re_node_set *set, int elem)
    {
      int *new_elems = re_realloc (dest->elems, int, new_alloc);
/* Skip characters until the index becomes greater than NEW_RAW_IDX.
/* Helper functions for re_string_allocate, and re_string_construct.  */
    {
	{
      return IS_NEWLINE (c) && input->newline_anchor ? CONTEXT_NEWLINE : 0;
      if (BE (new_elems == NULL, 0))
      pstr->raw_mbs_idx = 0;
  return new_state;
    {
	    --id;
    }
	{
      if (! isascii (ch))
      dfa->nodes = new_nodes;
   This function is used in case of REG_ICASE.  */
	  if (BE (new_offsets == NULL, 0))
			  mbclen = __mbrtowc (&wc2, (const char *) p, mlen,
  if (is >= 0)
      for (idx = set->nelem; idx > 0; idx--)
    }
{
      int *new_buffer = re_realloc (dest->elems, int, new_alloc);
	}
#ifdef GAWK
		    pstr->wcs[wcs_idx] = WEOF;
  if (BE (new_state == NULL, 0))

							eflags);
  pstr->bufs_len = new_buf_len;
  idx = 0;
	    }
		  while (mid > 0 && pstr->offsets[mid - 1] == offset)
  pstr->valid_len = buf_idx;

  new_state = create_ci_newstate (dfa, nodes, hash);
    {
      dest->alloc = dest->nelem;
      pstr->mbs[buf_idx] = pstr->trans[ch];
      set->alloc = set->nelem = 0;
      spot->alloc = new_alloc;
  /* Ensure at least one character fits into the buffers.  */
{
static unsigned char
			{
      return 0;
  /* The following optimization assumes that ASCII characters can be
  mbstate_t prev_st;
	      break;
	    {
  pstr->raw_mbs = (const unsigned char *) str;
	      /* Copy remaining SRC elements.  */
internal_function
	wchar_t wc;
internal_function
	  reg_errcode_t ret = build_wcs_upper_buffer (pstr);
  /* Realloc if we need.  */
      dest->elems = re_malloc (int, dest->alloc);
static reg_errcode_t
		      break;
	  return REG_ESPACE;
  struct re_state_table_entry *spot;
    }
create_ci_newstate (const re_dfa_t *dfa, const re_node_set *nodes,
  re_dfastate_t *new_state;
      if (state->hash == hash
		 ASCII-safe: all ASCII values can be converted like this.  */
		  wcu = towupper (wc);
static void re_string_construct_common (const char *str, int len,
  if (set->alloc == set->nelem)
  if (set->nelem <= 0)
static reg_errcode_t
     conservative estimate.  */
		 different length representation of lower and upper
/* Search for the state whose node_set is equivalent to NODES and

  dest->nelem += delta;
	      pstr->tip_context = re_string_context_at (pstr, mid - 1,
{
			}
	{

		    for (i = 1; i < mbcdlen; ++i)
			  if (BE (pstr->trans != NULL, 0))
	  set->elems[1] = elem2;

					  MAX (sizeof (re_node_set),
/* Calculate the intersection of the sets SRC1 and SRC2. And merge it to
      if (!IS_EPSILON_NODE (dfa->nodes[elem].type))
  int i1, i2, is, id, delta, sbase;
    *err = REG_ESPACE;
  i2 = src2->nelem - 1;

}
	      for (remain_len = byte_idx + mbclen - 1; byte_idx < remain_len ;)
	  --wc_idx;
  pstr->valid_len = byte_idx;
    return REG_NOERROR;
  else

      if (type == END_OF_RE)
      wchar_t wc;
#endif
  assert (MB_LEN_MAX >= pstr->mb_cur_max);
      dest->alloc = new_alloc;
    }
  if (init_len < dfa->mb_cur_max)
    return re_string_fetch_byte (pstr);
  else if (i2 < src2->nelem)
internal_function
}
      re_free (state->entrance_nodes);
      idx = 0;
  /*
  reg_errcode_t ret;

  if (BE (newstate == NULL, 0))
      if (BE (new_wcs == NULL, 0))
	  while (id >= 0 && dest->elems[id] > src1->elems[i1])
      if (!re_string_first_byte (pstr, pstr->cur_idx))
  dest->nelem = id;
	  if (id < 0 || dest->elems[id] != src1->elems[i1])
	else if (pstr->trans != NULL)
      mid = idx + (right - idx) / 2;

  if (BE (dest->nelem == 0, 0))
  for (i = 0 ; i < spot->num ; i++)
		      src_idx = byte_idx;
	  /* No, skip all characters until IDX.  */
		    RE_TRANSLATE_TYPE trans, int icase, const re_dfa_t *dfa)
	    pstr->cur_state = prev_st;

static unsigned int

  off = pstr->cur_idx + idx;
	    : CONTEXT_NEWLINE | CONTEXT_ENDBUF);

	  else if (mbclen == (size_t) -1 || mbclen == 0)
{


			pstr->wcs[byte_idx + i] = WEOF;
      memcpy (dest->elems + sbase, src->elems, (is + 1) * sizeof (int));
	  int prev_valid_len = pstr->valid_len;
      /* If the state has the halt node, the state is a halt state.  */
re_string_fetch_byte_case (re_string_t *pstr)
  pstr->mbs = pstr->mbs_allocated ? pstr->mbs : (unsigned char *) str;
	    {
	      {
      if (BE (re_node_set_init_1 (set, elem) == REG_NOERROR, 1))
  if (BE (err != REG_NOERROR, 0))
      if (dest->elems[id] == src->elems[is])
				     ? CONTEXT_WORD
	  }
    }
  return  newstate;

   Return -1 if an error has occurred, return 1 otherwise.  */
static void
#endif
  for (i = 0 ; i < nodes->nelem ; i++)
   Note: - We assume NULL as the invalid state, then it is possible that
      if (BE (new_mbs == NULL, 0))
     <mb1>(0), <mb1>(1), <mb2>(0), <mb2>(1), <sb3>
			     to use (UTF-8 -> UCS4).  */
      else
	      else
		}
  return REG_NOERROR;
      else /* if (dest->elems[id] > src->elems[is]) */
	  break;
		  return NULL;
				   ? CONTEXT_WORD
      if (BE (pstr->trans != NULL, 0))
	      break;
		    }
			  memset (pstr->mbs, 255, pstr->valid_len);
	  {
    return ret;
  re_free (state);
  pstr->valid_raw_len = char_idx;
		    unsigned int context, unsigned int hash)
static int
  dfa->nodes[dfa->nodes_len].constraint = 0;
	  /* Copy from the top.  */
re_string_skip_chars (re_string_t *pstr, int new_raw_idx, wint_t *last_wc)
   DEST. Return value indicate the error code or REG_NOERROR if succeeded.  */
	    if (BE (pstr->offsets_needed != 0, 0))
      new_elems = re_realloc (set->elems, int, set->alloc);
  /* Insert the new element.  */
      wint_t wc;

  return rawbuf_idx;
    }
					  const re_node_set *nodes,
	{
	}
	mbclen = __mbrtowc (&wc, p, remain_len, &pstr->cur_state);
		}
#endif /* RE_ENABLE_I18N */
/* Finish initialization of the new state NEWSTATE, and using its hash value
      mbclen = __mbrtowc (&wc2, (const char *) pstr->raw_mbs + rawbuf_idx,
      pstr->valid_len = byte_idx;
      set->alloc = set->alloc * 2;
	}
	      buf[i] = pstr->mbs[byte_idx + i] = pstr->trans[ch];
	    wc = *(unsigned char *) (pstr->raw_mbs + rawbuf_idx);
  hash = calc_state_hash (nodes, 0);
    {
{
}
		  if (isascii (*p) && BE (pstr->trans == NULL, 1))
#endif
internal_function
	newstate->has_backref = 1;
  re_free (state->trtable);
      /* Apply the translation if we need.  */
      set->elems[0] = elem1;
      dfa->eclosures = new_eclosures;
      const size_t max_object_size = MAX (sizeof (re_token_t),
  pstr->valid_len = char_idx;
    return REG_NOERROR;
      if (pstr->offsets != NULL)
      while(input->wcs[wc_idx] == WEOF)
				      && IS_WIDE_WORD_CHAR (wc))
#endif /* RE_ENABLE_I18N */

}
#endif /* RE_ENABLE_I18N  */
  else
		    low = mid + 1;
	    }
    {
  else
      /* Should the already checked characters be kept?  */
		  = re_string_context_at (pstr, prev_valid_len - 1, eflags);
	      pstr->cur_state = prev_st;
	  && re_node_set_compare (state->entrance_nodes, nodes))
  /* Binary search the element.  */

  /* We need dest->nelem + 2 * elems_in_intersection; this is a
       is = src->nelem - 1, id = dest->nelem - 1; is >= 0 && id >= 0; )
		  /* Special case UTF-8.  Multi-byte chars start with any
  set->nelem = 0;
    return 0;
	      break;
	p = (const char *) pstr->raw_mbs + pstr->raw_mbs_idx + byte_idx;
  spot->array[spot->num++] = newstate;
				     : ((IS_WIDE_NEWLINE (wc)
	continue;
			      memset (&pstr->cur_state, '\0',
re_string_peek_byte_case (const re_string_t *pstr, int idx)

	      pstr->offsets_needed = 0;

  err = re_node_set_init_copy (&newstate->nodes, nodes);
  right = set->nelem - 1;
  reg_errcode_t err;
	  pstr->cur_state = prev_st;
      re_token_t *node = dfa->nodes + nodes->elems[i];
     into the top of DEST those that are not already in DEST itself.  */
  re_dfastate_t *newstate;
/* Calculate the union set of the sets DEST and SRC. And store it to
	    return ret;

#endif
re_string_context_at (const re_string_t *input, int idx, int eflags)
	memset (&pstr->cur_state, '\0', sizeof (mbstate_t));
re_string_reconstruct (re_string_t *pstr, int idx, int eflags)
  unsigned int hash = nodes->nelem + context;
  int i;

			    }
    {
  delta = is - sbase + 1;
  re_node_set_free (&state->non_eps_nodes);
     less the same loop that is in re_node_set_merge.  */
}

	return state;
    hash += nodes->elems[i];
static re_dfastate_t *create_cd_newstate (const re_dfa_t *dfa,
{

     first element separately to skip a check in the inner loop.  */
  /* Handle the common (easiest) cases first.  */

      while (byte_idx < end_idx)
		  else
		  else
					re_string_t *pstr,
    }
					  const re_node_set *nodes,
		else if (mbcdlen != (size_t) -1)
      int *new_elems;
    }

		      {
		  mbcdlen = wcrtomb (buf, wcu, &prev_st);
  size_t mbclen;
	      /* The buffer doesn't have enough space, finish to build.  */

   This file is part of the GNU C Library.
  for (char_idx = pstr->valid_len; char_idx < end_idx; ++char_idx)
#ifdef RE_ENABLE_I18N
   License along with the GNU C Library; if not, see

    }
    {
{
    }
  reg_errcode_t err;
      memcpy (dest->elems, src->elems, src->nelem * sizeof (int));
	      if (BE (pstr->valid_len, 0))
#ifdef RE_ENABLE_I18N
		{
      else
re_string_realloc_buffers (re_string_t *pstr, int new_buf_len)
}
}
		      pstr->stop += mbcdlen - mbclen;
  if (nodes->nelem == 0)
			    re_string_char_size_at (pstr, pstr->cur_idx));
  if (pstr->mb_cur_max > 1
			}
	  wc = (wchar_t) pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx];
#endif
  if (BE (new_state == NULL, 0))
			pstr->offsets[byte_idx + i]

  pstr->is_utf8 = dfa->is_utf8;

	      if (BE (mbclen == (size_t) -1, 0))
	newstate->halt = 1;
  /* Find the items in the intersection of SRC1 and SRC2, and copy

internal_function
internal_function
		    if (!pstr->offsets_needed)

re_string_construct_common (const char *str, int len, re_string_t *pstr,
      dfa->nexts = new_nexts;
internal_function
    }

internal_function
   Return the new state if succeeded, otherwise return NULL.  */
		    memcpy (pstr->mbs + byte_idx, buf, mbclen);

	return state;


#ifdef RE_ENABLE_I18N
      if (set->elems[mid] < elem)
	  if (newstate->entrance_nodes == &newstate->nodes)
	return -1;
    }
      ret = re_string_realloc_buffers (pstr, len + 1);
	}
  err = re_node_set_init_copy (&newstate->nodes, nodes);
#endif /* RE_ENABLE_I18N */
	      if (pstr->trans)
      dest->alloc = src1->nelem + src2->nelem;
  pstr->mbs = pstr->mbs_allocated ? pstr->mbs : (unsigned char *) str;
      /* Avoid overflows in realloc.  */
  err = register_state (dfa, newstate, hash);
      return ch;
	  if (wc_idx < 0)
      dfa->org_indices = new_indices;
      re_token_type_t type = node->type;
      set->alloc = (set->alloc + 1) * 2;
   We use WEOF for padding, they indicate that the position isn't
    return REG_ESPACE;
      if (BE (SIZE_MAX / max_object_size < new_buf_len, 0))
		  p = raw + offset - 1;
    }
  struct re_state_table_entry *spot;
	  dest->elems[id++] = src2->elems[i2++];
					  unsigned int hash) internal_function;
  if (i1 < src1->nelem)
	      pstr->mbs[byte_idx] = ch;
					RE_TRANSLATE_TYPE trans, int icase,
   modify it under the terms of the GNU Lesser General Public

	dest->elems[--sbase] = src->elems[is--];
	  prev_st = pstr->cur_state;
			  = src_idx + (i < mbclen ? i : mbclen - 1);
  /* Now copy.  When DELTA becomes zero, the remaining

	  mbclen = 1;
    {
    {
		break;
    }
    return re_string_peek_byte (pstr, idx);
build_wcs_upper_buffer (re_string_t *pstr)
#ifdef RE_ENABLE_I18N

	    {
    }
			  return REG_ESPACE;
      else

  id = dest->nelem - 1;
      }
	{
		    {
      && ! re_string_is_single_byte_char (pstr, pstr->cur_idx + idx))
      return NULL;
calc_state_hash (const re_node_set *nodes, unsigned int context)
	  pstr->valid_len = 0;
	return re_string_fetch_byte (pstr);
      int *new_nexts, *new_indices;
	 - We never return non-NULL value in case of any errors, it is for
  --set->nelem;
      if (BE (ret != REG_NOERROR, 0))
	    dest->elems[id + delta] = dest->elems[id];
	return (a > b ? a : b);
      const size_t max_object_size = MAX (sizeof (wint_t), sizeof (int));
#ifdef _LIBC
	    for (remain_len = byte_idx + mbclen - 1; byte_idx < remain_len ;)
	      if (wc == WEOF)
		else
  set->elems[set->nelem++] = elem;
		= toupper (pstr->raw_mbs[pstr->raw_mbs_idx + byte_idx]);
  set->elems[0] = elem;
}
  else
    {
      int remain_len = pstr->len - rawbuf_idx;
	    }
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.
static int
#endif /* RE_ENABLE_I18N */
    return REG_NOERROR;

   Note: We assume dest->elems is NULL, when dest->alloc is 0.  */
{
		{
/* This function allocate the buffers, and initialize them.  */
#ifdef RE_ENABLE_I18N
	    p = (const char *) buf;
	      /* And also cast it to wide char.  */

		wcu = towupper (wc);
      new_wcs = re_realloc (pstr->wcs, wint_t, new_buf_len);
		memcpy (pstr->mbs + byte_idx,

	if (pstr->icase)
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;
	  if (--i1 < 0)
	pstr->wcs[byte_idx++] = WEOF;
internal_function
	  for (i = 0; i < pstr->mb_cur_max && i < remain_len; ++i)
/* Build the buffer PSTR->MBS, and apply the translation if we need.
  newstate->entrance_nodes = &newstate->nodes;
  int i;
		    byte_idx += mbcdlen;
{
      pstr->mbs = new_mbs;

      if (dfa->mb_cur_max > 1)
  set->elems = re_malloc (int, size);
    }
  if (pstr->mb_cur_max > 1)
	      if (BE (pstr->mbs_allocated, 0))
  for (; idx < set->nelem; idx++)
				buf[i] = pstr->trans[p[i]];
    {
  for (rawbuf_idx = pstr->raw_mbs_idx + pstr->valid_raw_len;
	continue;
	}
      /* Reset buffer.  */
    }
      if (BE (mbclen == (size_t) -2 || mbclen == (size_t) -1 || mbclen == 0, 0))
      if (type == END_OF_RE)
	    pstr->wcs[byte_idx++] = (wchar_t) ch;
    {


		  memcpy (pstr->mbs + byte_idx, buf, mbclen);
   <http://www.gnu.org/licenses/>.  */
	      pstr->valid_len = pstr->bufs_len;
     DEST elements are already in place.  */
      else
			      int i = mlen < 6 ? mlen : 6;
		    break;
	build_wcs_buffer (pstr);
  char buf[64];
  return REG_NOERROR;
#ifdef RE_ENABLE_I18N
		      }
  set->alloc = size;
#if DEBUG
internal_function
  pstr->raw_mbs_idx = idx;
/* Search for the state whose node_set is equivalent to NODES.
	}
	  if (trans != NULL)
    {
internal_function
  newstate = (re_dfastate_t *) calloc (sizeof (re_dfastate_t), 1);
  /* Insert the new element.  */
      if (elem1 < elem2)
		    pstr->offsets[low] = pstr->offsets[low + offset] - offset;
  for (;;)
	return ret;
	  if (BE (pstr->trans != NULL, 0))
      if (constraint)
  return REG_NOERROR;

  int i;
      re_token_t *new_nodes;
  newstate->entrance_nodes = &newstate->nodes;
	      nctx_nodes = 0;
	  {
	    wchar_t wcu = wc;
		buf[i] = pstr->trans[ch];
		}
	  {
       memset(set, 0, sizeof(*set));
#ifdef RE_ENABLE_I18N
	    break;
		      {
   DEST. Return value indicate the error code or REG_NOERROR if succeeded.  */
static void
    {
		  else if (pstr->offsets[mid] < offset)
       since we can't know the character in input->mbs[-1] here.  */
      set->elems[0] = elem;
      id += src1->nelem - i1;

      wc = input->wcs[wc_idx];
internal_function
      if (BE (dest->elems == NULL, 0))
  end_idx = (pstr->bufs_len > pstr->len) ? pstr->len : pstr->bufs_len;
      if (dest->elems[is] > dest->elems[id])
	      if (pstr->valid_raw_len >= len)
	      pstr->len = pstr->raw_len - idx + offset;
		  }
    return ((eflags & REG_NOTEOL) ? CONTEXT_ENDBUF
	}

    re_node_set_init_empty (dest);

  if (elem1 == elem2)
static re_dfastate_t *create_ci_newstate (const re_dfa_t *dfa,
      else
   SET should not already have any element greater than or equal to ELEM.
      return REG_NOERROR;
    {
    }
      {
     <wc1>   , WEOF    , <wc2>   , WEOF    , <wc3>
    {
      id += src2->nelem - i2;

  /* Build the buffers from pstr->valid_len to either pstr->len or
  if (src1->nelem == 0 || src2->nelem == 0)
      {
	    {

		  end = raw + (offset - pstr->mb_cur_max);
static void
   * free the block of size 0.  Harumph. This seems
	  mbclen = __mbrtowc (&wc,
}
		    if (byte_idx + mbcdlen > pstr->bufs_len)
      else
    {
    else
    {
  if (BE (offset != 0, 1))
  byte_idx = pstr->valid_len;
  return REG_NOERROR;
		  for (wcs_idx = 0; wcs_idx < pstr->valid_len; ++wcs_idx)
    }
  pstr->cur_idx = 0;
      re_node_set_free (state->entrance_nodes);
  int init_buf_len;
	}
      return 1;
static re_dfastate_t *
	  dest->elems[id + delta] = dest->elems[id];
static reg_errcode_t
  int c;
	  continue;
	if (re_node_set_insert_last (&newstate->non_eps_nodes, elem) < 0)
	    break;
#else
			  wchar_t wc2;
internal_function
  re_node_set_free (&state->nodes);
		c = pstr->trans[c];
  char buf[MB_LEN_MAX];
	  if (--i1 < 0 || --i2 < 0)
   but WITHOUT ANY WARRANTY; without even the implied warranty of

		    pstr->len += mbcdlen - mbclen;

  pstr->len = len;
      return (IS_WIDE_NEWLINE (wc) && input->newline_anchor
	  int i, ch;
build_upper_buffer (re_string_t *pstr)

  /* Ensure that e.g. for tr_TR.UTF-8 BACKSLASH DOTLESS SMALL LETTER I
  int i, nctx_nodes = 0;
		return ret;
		  != REG_NOERROR)
   SET should not already have ELEM.
	set->elems[idx] = set->elems[idx - 1];
re_acquire_state_context (reg_errcode_t *err, const re_dfa_t *dfa,
/* Calculate the union set of the sets SRC1 and SRC2. And store it to
	  /* Try to find the item in DEST.  Maybe we could binary search?  */
      if (pstr->icase)
  return REG_NOERROR;
		return NULL;
static int
internal_function
	    dest->elems[id + delta--] = dest->elems[is--];
	      newstate->entrance_nodes = re_malloc (re_node_set, 1);
	      wchar_t wcu = wc;
    {

			  unsigned char buf[6];
  if (src1->nelem + src2->nelem + dest->nelem > dest->alloc)
	      newstate->has_constraint = 1;

  re_free (pstr->offsets);

   Then wide character buffer will be:

	++i2;
	      ch = pstr->raw_mbs [pstr->raw_mbs_idx + byte_idx + i];
#endif
   * to work ok, though.

	   return value is NULL and ERR is REG_NOERROR.
}
{
		      memset (&pstr->cur_state, '\0', sizeof (mbstate_t));
	      && mbsinit (&pstr->cur_state))
}
internal_function __attribute ((pure))
	idx = mid + 1;
internal_function
    }
	      pstr->tip_context = (bitset_contain (pstr->word_char, c)



      new_nexts = re_realloc (dfa->nexts, int, new_nodes_alloc);

		      }
      set->nelem = 1;
	    {

			      ? pstr->len : pstr->bufs_len;

      if (type == CHARACTER && !node->constraint)
  pstr->raw_stop = pstr->stop;
	    src_idx += mbclen;


  pstr->valid_len = byte_idx;
      free_state (newstate);
  return new_state;
	  if (mbclen == 0 || remain_len == 0)
   whose context is equivalent to CONTEXT.
	    break;

static unsigned char
  else
   return NULL and set the error code in ERR.
		  && mid == offset && pstr->offsets[mid] == offset)
    {

			pstr->raw_mbs + pstr->raw_mbs_idx + byte_idx, mbclen);
    {
      return NULL;

	      pstr->wcs[byte_idx++] = wcu;
			    }
    }
      else
	      int low = 0, high = pstr->valid_len, mid;

    }
  pstr->raw_len = len;
  if (src->nelem > 0)
	}
	}
  spot = dfa->state_table + (hash & dfa->state_hash_mask);
      dfa->edests = new_edests;
      set->elems = new_elems;
  re_node_set_init_empty (dfa->edests + dfa->nodes_len);
	      memcpy (pstr->mbs + byte_idx, p, mbclen);
  if (pstr->offsets_needed && !isascii (ch))
	prev_st = pstr->cur_state;
      const char *p;
		    src_idx += mbclen;
}
		    memset (pstr->mbs, 255, pstr->valid_len);
internal_function
  if (BE (!pstr->mbs_allocated, 1))
	  mbclen = 1;

{
					       sizeof (int)));
    {
  id = dest->nelem - 1;
      for (remain_len = byte_idx + mbclen - 1; byte_idx < remain_len ;)
  re_node_set_free (&state->inveclosure);
  /* Skip the characters which are not necessary to check.  */
	      pstr->valid_len -= offset;

					  unsigned int hash) internal_function;
	else
  if (BE (err != REG_NOERROR, 0))
  delta = is - sbase + 1;

    {
  for (;;)
  if (BE (err != REG_NOERROR, 0))
	      memcpy (dest->elems, dest->elems + sbase,
    {
	      if (pstr->mb_cur_max > 1)
	  }

		     character at offset is and fill it with WEOF/255.  */
re_node_set_merge (re_node_set *dest, const re_node_set *src)
  int ch, off;
		break;
  for (i = 0 ; i < nodes->nelem ; i++)
    }
	    }
		  const unsigned char *raw, *p, *end;
		}
#ifdef _LIBC
  unsigned char buf[64];
	    wc = L'\0';
  return hash;
{
  for (i = 0 ; i < nodes->nelem ; i++)
   but for REG_ICASE.  */
	{

      dest->nelem = src->nelem;
/* Extended regular expression matching and search library.
#endif
   DEST. Return value indicate the error code or REG_NOERROR if succeeded.
   The GNU C Library is free software; you can redistribute it and/or
      wchar_t wc2;
			pstr->cur_state = prev_st;
	  set->elems[1] = elem1;
}
{
			    RE_TRANSLATE_TYPE trans, int icase,
	    }
	      continue;
		unsigned int hash)
  if (pstr->mbs_allocated)
		     case, ASCII characters, skip the conversion step.  */
    if (BE (pstr->mbs_allocated, 0))
}

		      if (pstr->valid_len)
							eflags);
    }
      int off, ch;
	  && state->context == context
#endif /* RE_ENABLE_I18N  */
    {
      new_nodes = re_realloc (dfa->nodes, re_token_t, new_nodes_alloc);
  if (pstr->offsets_needed)
   return NULL and set the error code in ERR.
  set->alloc = 1;
