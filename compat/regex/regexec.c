  if (length2 > 0)
					   re_sift_context_t *sctx)
      if (dfa->nodes[cur_node_idx].constraint)
      subtop->alasts = new_alasts;
     Note:
      if (prev_idx_match == NULL)
static reg_errcode_t
      if (BE (dests_alloc == NULL, 0))
	}
    }
  else
    }
			      re_node_set *cur_nodes, re_node_set *next_nodes)
	return 0;
							CONTEXT_NEWLINE);
		    goto free_return;
		{
					dest_state->entrance_nodes, new_nodes);

internal_function
	 ( <subexp1> <src> <subexp2> <dst> <subexp3> )  */
      err = REG_NOMATCH;

	    continue;
  else
    }
  for (lim_idx = 0; lim_idx < limits->nelem; ++lim_idx)
    *p_match_first += next_start_idx;
# ifdef _LIBC
			     int subexp_idx, int type) internal_function;



  return REG_NOERROR;
    {
					  struct re_backref_cache_entry *bkref_ents,
  mctx->sub_tops[mctx->nsub_tops++]->str_idx = str_idx;
	  sl_str_diff = sub_last->str_idx - sl_str;
  else
    }
	    {
# ifdef _LIBC
static reg_errcode_t check_subexp_matching_top (re_match_context_t *mctx,
      context = re_string_context_at (&mctx->input, dest_idx - 1,
    }
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.
      if (j == ndests)
	      if ((!preg->no_sub && nmatch > 1) || dfa->nbackref)
					re_sift_context_t *sctx,
    {
	    = re_string_context_at (&mctx->input,
    }
					   subexp_idx, dst_node, dst_idx,
		  && wcscoll (cmp_buf + 2, cmp_buf + 4) <= 0)
    {
	    {
      }
  const re_dfa_t *const dfa = mctx->dfa;
    {
internal_function
	{
						   re_sub_match_top_t *,
		  dst = dfa->edests[node].elems[0];
      assert (regs->num_regs >= nregs);
		    return err;
			     re_node_set *limits,
{
	    }
	  if (BE (err != REG_NOERROR, 0))
  mctx->last_node = halt_node;

				       re_node_set *states_node,
      if (dfa->nodes[node].accept_mb)
  else if (regs_allocated == REGS_REALLOCATE)

      if (BE (dest_states == NULL, 0))
			   start, 0, regs, stop, 1);
   must be allocated using the malloc library routine, and must each

  return -1;
	goto out_free;
      re_node_set_empty (&follows);
	    }
      /* Enumerate all single byte character this node can accept.  */
}
{
   The GNU C Library is free software; you can redistribute it and/or
	  pmatch[nmatch + reg_idx].rm_eo = -1;
  err = re_node_set_init_copy (&fs->stack[num].eps_via_nodes, eps_via_nodes);
     internal_function;
	  /* match with collating_symbol?  */
  re_node_set new_nodes;
  else if (BE (start + range < 0, 0))
	}
		  err = prune_impossible_nodes (&mctx);
}

					re_match_context_t *mctx,
	      else
	return err;
    {
	  if (constraint & NEXT_ENDBUF_CONSTRAINT)
	 nodes.
  return err != REG_NOERROR;
  if (__libc_use_alloca ((sizeof (re_node_set) + sizeof (bitset_t)) * SBC_MAX
static int re_search_2_stub (struct re_pattern_buffer *bufp,
		  re_node_set_free (&eps_via_nodes);
  for (j = 0; j < ndests; ++j)
    {
	    }
  /* Can the subexpression arrive the back reference?  */
      re_dfastate_t **new_array = re_realloc (mctx->state_log, re_dfastate_t *,
      else
}
      int subexp_idx;
	       int top_str, int last_node, int last_str, int type)
  if (candidates && mctx->state_log[str_idx]->has_backref)
  return err;
     internal_function;
      ent = bkref_ents + limits->elems[lim_idx];
	  if (next_node != -1)
	    {

	  re_free (fs->stack[fs_idx].regs);
    }
	{
  return err;
  else
      re_sub_match_top_t *top = mctx->sub_tops[st_idx];
#endif

  reg_errcode_t ret;
		  continue;
  unsigned int constraint = dfa->nodes[node].constraint;
      unsigned int context = re_string_context_at (&mctx->input, idx,
      if (check_node_accept (mctx, dfa->nodes + cur_node, cur_str_idx))
				    mctx->eflags);
		}
      /* We don't care about whether the following character is a word
	  context = re_string_context_at (&mctx->input, cur_str_idx,
	}
	}
	    }
	      err = sub_epsilon_src_nodes (dfa, ops_node, dest_nodes,
	  regmatch_t *pmatch, int fl_backtrack)
static int build_trtable (const re_dfa_t *dfa,
  re_node_set_free (&union_set);
						 candidates);
	      return NULL;
	      if (BE (err != REG_NOERROR, 0))
	      if (dfa->mb_cur_max > 1)
  re_string_destruct (&mctx.input);
      struct re_backref_cache_entry *entry;
      assert (dfa->nexts[node_idx] != -1);
	default:
internal_function
	      re_node_set dest_nodes;
#ifdef RE_ENABLE_I18N
	regmatch_t pmatch[],
  int num = fs->num++;
  return REG_NOERROR;
	{
	  memset (lim_states, '\0',
    }
      dest_state = mctx->state_log[dest_idx];
		{
}
			    dfa->nexts[node_idx]))
	    {
	  if (naccepted == 0)
      re_node_set_empty (&cur_dest);
{
      if (BE (new_array == NULL, 0))

	  err = re_node_set_init_copy (&next_nodes, &cur_state->nodes);
	      trtable[ch] = dest_states[j];
int
	  if (BE (sub_last == NULL, 0))
  if (BE (sifted_states == NULL, 0))
#endif
	 - It can epsilon transit to a node in CUR_DEST.
      if (ent->subexp_to == str_idx)

      regs->start = starts;
}
      if (match_last != -1)

	{
   and sift the nodes in each states according to the following rules.
      else if (type == OP_PERIOD)
      if (BE (err != REG_NOERROR, 0))
    err = re_search_internal (preg, string, length, start, length - start,
	      if (!fastmap[t ? t[ch] : ch])
	  if ((boundaries & 1) && subexp_idx == dfa->nodes[node].opr.idx)
		     struct re_backref_cache_entry *bkref_ents, int str_idx)
      int next_char_idx = re_string_cur_idx (&mctx->input) + 1;
  eflags |= (bufp->not_bol) ? REG_NOTBOL : 0;
   since initial states may have constraints like "\<", "^", etc..  */

		  match_len = char_len;
	  break;

/* Add a new backreference entry to MCTX.
	  if (naccepted > 1)
	}
/* Helper functions for transit_state.  */
  int i;
   modify it under the terms of the GNU Lesser General Public
		     infinite loop: a regex that exhibits this behavior
  int i, j, k;
static void sift_ctx_init (re_sift_context_t *sctx, re_dfastate_t **sifted_sts,
			  }
  if (NOT_SATISFY_NEXT_CONSTRAINT (constraint, context))
		      return err;
  int start, length;
	if (IS_EPSILON_NODE (dfa->nodes[cur_node].type))
}
	     character.  Then we use the constructed buffer instead.  */
      int sub_last_idx, sl_str, bkref_str_off;
	    {
	{
  mctx->bkref_ents[mctx->nbkref_ents++].more = 0;
  if (mctx->nbkref_ents > 0
	{
  reg_errcode_t err;
      length = pmatch[0].rm_eo;

					 size_t nmatch, regmatch_t pmatch[],
#endif
  reg_errcode_t err;
    = (from == to ? ~0 : 0);
		{
  int next_start_idx = cur_str_idx;

	  /* In this case, we can't determine easily the current byte,
  err = match_ctx_add_entry (mctx, bkref_node, bkref_str, sub_top->str_idx,
      for (; sl_str <= bkref_str_idx; ++sl_str)

  /* We must check the longest matching, if nmatch > 0.  */
  if (eflags & ~(REG_NOTBOL | REG_NOTEOL | REG_STARTEND))
	  rval = pmatch[0].rm_eo - start;
 free_return:
      int j;
	    goto error_return;
{
__compat_regexec (const regex_t *__restrict preg,
  /* Otherwise, it is sure that the node could accept
  boundaries |= (str_idx == lim->subexp_to) << 1;
# endif /* _LIBC */

							     match_last);
			       && (weights[equiv_class_idx + 1 + cnt]
  if (BE (start + range > length, 0))
		  const char *string2, int length2, int start,
		   int idx)
static reg_errcode_t
	    }
{
	    bitset_clear (accepts, '\0');
	  err = check_arrival (mctx, sub_top->path, sub_top->node,
			       size_t nmatch, regmatch_t *pmatch,
expand_bkref_cache (re_match_context_t *mctx, re_node_set *cur_nodes,
	  /* mctx->bkref_ents may have changed, reload the pointer.  */
     (with the epsilon nodes pre-filtered out).  */
  int node_idx, lim_idx;

	  else
  /* We assume front-end functions already check them.  */
	    const char *string1, int length1,
					int from_node, int bkref_idx)
#ifdef DEBUG
 free_return:
	= re_acquire_state_context (&err, dfa, &dest_nodes, context);
  bitset_word_t elem, mask;
	      if (BE (err != REG_NOERROR, 0))
  /* If the RE accepts NULL string.  */
		  buf = (const char *) re_string_get_buffer (&mctx->input);

  /* Build sifted state_log[str_idx].  It has the nodes which can epsilon
	      else if (type == OP_CLOSE_SUBEXP
	  ret = REG_NOMATCH;
      int node = eclosures->elems[node_idx];
	      if (prev_idx_match_malloced)
    }
      struct re_fail_stack_ent_t *new_array;
	      /* j-th destination accepts the word character ch.  */
{
	for (ch = i * BITSET_WORD_BITS, elem = acceptable[i], mask = 1;
  else
  if (nrules == 0)
		in_collseq = find_collation_sequence_value (pin, elem_len);
  int naccepted;
	    {
	goto free_return;

      /* Check OP_OPEN_SUBEXP in the initial state in case that we use them
	  /* Skip the byte sequence of the collating element.  */
      if (dst[st_idx] == NULL)
	  regs->start = new_start;
	    }
  int nregs, rval;
	 the buffers so that we could assume that the matching starts
	  int subexp_idx = dfa->nodes[node].opr.idx + 1;
					      re_sift_context_t *sctx,
	  regs->end = new_end;
   at BKREF_STR_IDX, and register them by match_ctx_add_entry().
	      err = check_subexp_limits (dfa, dest_nodes, candidates, &sctx->limits,
internal_function
  if (BE (SIZE_MAX / sizeof (re_dfastate_t *) <= match_last, 0))
#if defined _LIBC || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L)
  return 1;
		  struct re_registers *regs,
	}

  const re_dfa_t *const dfa = mctx->dfa;
/* Skip bytes in the input that correspond to part of a
   Note that we might collect inappropriate candidates here.
      /* Retry, we now have a transition table.  */
	  subexp_len = entry->subexp_to - entry->subexp_from;
			    goto check_node_accept_bytes_match;
	  /* match with range expression?  */
    nregs = 1;
	    free (dest_states);
static reg_errcode_t check_arrival_expand_ecl (const re_dfa_t *dfa,
		  return err;
static reg_errcode_t

    {
    }
  /* Then reconstruct the buffers.  */
	  *err = REG_ESPACE;
      if (BE (err != REG_NOERROR, 0))
		{
  return REG_NOERROR;
 out:
				       const re_dfastate_t *state,
    mctx->bkref_ents[mctx->nbkref_ents - 1].more = 1;
      dest_states_malloced = true;
	      if (BE (err != REG_NOERROR, 0))

    }
				      mctx->eflags);
      /* FIXME: I don't think this if is needed, as both '\n'
      if (BE (err != REG_NOERROR, 0))
		}

	      return -2;
					      dfa->edests[cur_node].elems[1],
	    {
  reg_errcode_t err = REG_NOERROR;
	{

		  cpos =
    return NULL;
     mctx->nsub_tops = 0;  */
						int str_idx) internal_function;

      int reg_idx;
  state->word_trtable = state->trtable = NULL;
      if (BE (dest_states[i] == NULL && err != REG_NOERROR, 0))
  bool dests_node_malloced = false;
      err = sift_states_bkref (mctx, sctx, str_idx, candidates);
	    {
	    {

		{
      if (BE (err != REG_NOERROR, 0))
  bitset_t accepts; /* Characters a node can accept.  */

      regs->start = regs->end = (regoff_t *) 0;
	      /* There must be exactly one destination which accepts
			   int str_idx)
		}
			 int cur_idx, int nmatch) internal_function;
	  return REG_NOERROR; /* We already checked it.  */

	  if (match_first < left_lim)
	  re_node_set_empty (eps_via_nodes);
	      const unsigned char *coll_sym = extra + cset->coll_syms[i];
	  goto free_return;
	      if (buf [bkref_str_off++] != buf[sl_str - 1])
      if (dfa->nodes[node].type == OP_OPEN_SUBEXP
	      if (BE (err != REG_NOERROR, 0))
static reg_errcode_t build_sifted_states (const re_match_context_t *mctx,
      mid = left + (right - left) / 2;
	}
	  || (BE (next_char_idx >= mctx->input.valid_len, 0)
      if (src_pos == dst_pos)
	    return err;
	      return err;

	  dest_states_word[i] = re_acquire_state_context (&err, dfa, &follows,
static reg_errcode_t
#ifdef HAVE_ALLOCA
	  to_idx = str_idx + subexp_len;
	  bitset_copy (dests_ch[ndests], accepts);
	  else
		    const char *string,
match_ctx_free (re_match_context_t *mctx)
internal_function
    }
      regs->end = re_malloc (regoff_t, need_regs);
   multi-byte match, then look in the log for a state

match_ctx_add_entry (re_match_context_t *mctx, int node, int str_idx, int from,
	    / (3 * sizeof (re_dfastate_t *)))
      if (naccepted == 0)
    }
  const re_dfa_t *const dfa = mctx->dfa;
      if (mctx->state_log[str_idx + 1])
	return REG_NOMATCH;
	    break;
	{
		     int str_idx, re_node_set *cur_dest)
      const re_token_t *node = dfa->nodes + node_idx;
{
  if (type != END_OF_RE)
  err = REG_NOERROR;
		      else /* if (boundaries & 2) */

	  err = re_node_set_merge (&new_nodes, eclosure);
#ifdef HAVE_ALLOCA
	    }
	  int subexp_len;
 free_return:
	    }
	    {
					re_dfastate_t *pstate)
internal_function
	      return err;
	{
  return 0 == regexec (&re_comp_buf, s, 0, NULL, 0);

					      re_node_set *dest_nodes)
	    {

  reg_errcode_t err = REG_NOERROR;
			     int src_idx) internal_function;
      lim_states = re_malloc (re_dfastate_t *, match_last + 1);
	    ++match_first;
   freeing the old data.  */
{
    - out of the sub expression whose number is EX_SUBEXP, if !FL_OPEN.
			while (cnt <= weight_len
re_search (struct re_pattern_buffer *bufp,
	      sub_top->path = calloc (sizeof (state_array_t),
	      err = re_node_set_insert (eps_via_nodes, node);

	    {
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
						   bkref_str_off
    goto free_return;

static reg_errcode_t
	      if (BE (err != REG_NOERROR, 0))
		       Remove it form the current sifted state.  */
      break;
  const re_node_set *cur_src = &mctx->state_log[str_idx]->non_eps_nodes;
  mctx->sub_tops[mctx->nsub_tops] = calloc (1, sizeof (re_sub_match_top_t));
	    need_word_trtable = 1;
	  if (BE (err != REG_NOERROR, 0))
	      {
#ifdef RE_ENABLE_I18N
		  sizeof (re_dfastate_t *) * str_idx);
group_nodes_into_DFAstates (const re_dfa_t *dfa, const re_dfastate_t *state,
	    {
      return state->nodes.elems[i];
	{
re_search_internal (const regex_t *preg,
  if (local_sctx.sifted_states != NULL)
check_arrival_expand_ecl (const re_dfa_t *dfa, re_node_set *cur_nodes,

	  buf = (const char *) re_string_get_buffer (&mctx->input);

	  err = check_arrival_expand_ecl_sub (dfa, dst_nodes,
static int
	     in the current context?  */

	      /* Otherwise, push the second epsilon-transition on the fail stack.  */
	  if (BE (err != REG_NOERROR, 0))
   <http://www.gnu.org/licenses/>.  */
		}
		found = 1;

	      mctx.match_last = match_last;
	yet isn't the head, of a multibyte character.  */
  /* Avoid arithmetic overflow in size calculation.  */
	    }
out_free:
   Updated state_log will be wrote to STATE_LOG.
	      /* j-th destination accepts the word character ch.  */
	    /* There must be only one destination which accepts
      while (1)
	  /* match with range expression?  */
get_subexp_sub (re_match_context_t *mctx, const re_sub_match_top_t *sub_top,
	{
  if (BE (err != REG_NOERROR, 0))
	      pmatch[reg_idx + 1].rm_eo
      else
  return err;
	return 0;
  if (!BE (need_word_trtable, 0))
	  idx = idx + sizeof (uint32_t) * (extra[idx] + 1);
    }

      if (match_first < left_lim || right_lim < match_first)
		   : mctx.input.offsets[pmatch[reg_idx].rm_eo]);
		goto free_return;
   PATTERN_BUFFER will allocate its own register data, without
	      if (type == CHARACTER && !node->word_char)
/* Helper functions for check_arrival.  */
   expression. And register them to use them later for evaluating the
	      free_fail_stack_return (fs);
	    struct re_registers *regs, int stop)
  err = update_cur_sifted_state (mctx, sctx, str_idx, &cur_dest);
	  /* And skip if the intersection set is empty.  */
	      for (mbs_cnt = 0; mbs_cnt < elem_mbs_len; ++mbs_cnt)
	    }
	    }
  re_sift_context_t local_sctx;
		return REG_ESPACE;
      if (str_idx + char_len > input->len)
 error_return:
  const re_dfa_t *dfa = (const re_dfa_t *) preg->buffer;
      goto free_return;
	  continue;
  if (node->type == OP_PERIOD)
{
}
  if (BE (err != REG_NOERROR, 0))
      re_dfastate_t **new_array;
    }
	= mctx->bkref_ents + cache_idx;
#endif
   Check incrementally the epsilon closure of TARGET, and if it isn't
     2. When 0 <= STR_IDX < MATCH_LAST and `a' accepts
  /* Fix MCTX.  */
					   re_string_cur_idx (&mctx->input));
	  re_free (last->path.array);
static int

	  && STATE_NODE_CONTAINS (sctx->sifted_states[str_idx + 1],
	    return err;
						   re_node_set *next_nodes)
int

	    {
      if (top->path)
#endif
  reg_errcode_t err;
    check_node_accept_bytes_match:
  if (((elem_len <= 1 && char_len <= 1) || char_len == 0) && (wc != WEOF && wc < SBC_MAX))
	      || (match && !fl_longest_match)
	{
				      int node, int str_idx,
  struct dests_alloc
    return REG_NOERROR;
	  sub_last = sub_top->lasts[sub_last_idx];
    re_node_set *inv_eclosure = dfa->inveclosures + node;
		}
	 discern by looking at the character code: allocate a
    }
		regmatch_t *regs, re_node_set *eps_via_nodes)
  assert (cur_nodes->nelem);
/* Update the state_log if we need */
	      if (dfa->mb_cur_max > 1)
  if (BE (subtop->nlasts == subtop->alasts, 0))

check_dst_limits_calc_pos (const re_match_context_t *mctx, int limit,
	  if (BE (err != REG_NOERROR, 0))
	{
versioned_symbol (libc, __regexec, regexec, GLIBC_2_3_4);
	goto free_return;
      mctx->bkref_ents = re_malloc (struct re_backref_cache_entry, n);
*/
    mctx.state_log = NULL;
			return -1;
      /* At last, add the offset to the each registers, since we slided
#ifdef RE_ENABLE_I18N
	      }
	memcpy (s, string1, length1);
   Return the destination node, and update EPS_VIA_NODES, return -1 in case
	     DEST_NODE.  */
static reg_errcode_t sift_states_backward (const re_match_context_t *mctx,
		goto out_free;
  for (;; match_first += incr)
      mctx->bkref_ents = new_entry;
	}
	      if (BE (err != REG_NOERROR || ret < 0, 0))

	char *s = re_malloc (char, len);
	   re_string_byte_at (input, str_idx) == '\n') ||
#endif /* RE_ENABLE_I18N */

    }
			       int fl_backtrack) internal_function;
   Return 1 if succeeded, otherwise return NULL.  */
  candidates = ((mctx->state_log[str_idx] == NULL) ? NULL
    range = length - start;
	    }
  *pidx = fs->stack[num].idx;
	    at_init_state = 0;
      if (BE (ret == -1, 0))
      start = 0;
   (START + RANGE >= 0 && START + RANGE <= LENGTH)  */

	      if (fastmap[t ? t[ch] : ch])
		break;
	    goto free_return;
					   context))
    return -1;
      new_array = re_realloc (path->array, re_dfastate_t *, path->alloc);
{



	  err = check_arrival_add_next_nodes (mctx, str_idx,
	  /* If we found the entry, return the sequence value.  */
	goto out_free;
	  || check_node_accept (mctx, dfa->nodes + cur_node, str_idx))
      else
      return char_len;
			  int ex_subexp, int type)
{
{
				       * fs->alloc * 2));
	    bitset_set_all (accepts);
{
	  if (cset->ncoll_syms)
  right_lim = (range < 0) ? start : start + range;

    {
	      if (dest_state)

	  re_dfastate_t *cur_state;
	  if (BE (result < 0, 0))
      /* match with multibyte character?  */
		{
	  /* Skip the collation sequence value.  */
      if (cur_state == NULL)
		     OP_CLOSE_SUBEXP cases below.  But, if the
check_node_accept_bytes (const re_dfa_t *dfa, int node_idx,
      int new_asub_tops = mctx->asub_tops * 2;
{
	    }
	}
/* Entry point for POSIX code.  */
	  /* No valid character.  Match it as a single byte character.  */
	  int candidate = edests->elems[i];
      switch (dfa->nodes[node].type)
					       str_idx);
		  sizeof (re_dfastate_t *) * (match_last + 1));
						   int str_idx,
     it is set, check_dst_limits_calc_pos_1 will recurse and try to find one
	      else
      /* Initialize registers.  */
	  if (found)
  else
	{
static void
int
static reg_errcode_t check_arrival_add_next_nodes (re_match_context_t *mctx,
	  err = get_subexp_sub (mctx, sub_top, sub_last, bkref_node,

	{
      unsigned int context;
	return 1;
	   re_string_byte_at (input, str_idx) == '\0'))
	    continue;

      cur_state = mctx->state_log[str_idx];
      else
    case CHARACTER:
      lim_states = NULL;
#ifdef RE_ENABLE_I18N

				   range >= 0 ? &match_first : NULL);
      reg_errcode_t err;

  else

		match_len = elem_len;
  const re_dfa_t *const dfa = mctx->dfa;
	      && mctx->state_log[cur_str_idx]->nodes.nelem > prev_nelem)
	   int length, int start, int range,
	str = s;

     internal_function;

			   : CONTEXT_NEWLINE | CONTEXT_BEGBUF;
		  if (BE (err != REG_NOERROR, 0))
				      int limit, int subexp_idx,
	  ret = re_node_set_insert (&local_sctx.limits, enabled_idx);
		  if (bkref_str_off >= mctx->input.len)

      int next_node;
  re_dfastate_t *cur_state;
     internal_function;
  for (lim_idx = 0; lim_idx < limits->nelem; ++lim_idx)
	      if (elem_len <= char_len)
		return err;
   Return the number of the bytes the node accepts.
  return REG_NOERROR;
      trtable = state->word_trtable;
	  if (BE (err != REG_NOERROR, 0))
     ? ((sb || !(preg->syntax & RE_ICASE || t) ? 4 : 0)
					    const re_node_set *candidates)
	}
	{
internal_function
	return 0;
  reg_errcode_t result;

	  err = expand_bkref_cache (mctx, &next_nodes, str_idx,

  return REG_NOERROR;
	      {
	continue;
internal_function
	    free (dests_alloc);
	  char_len = 5;
	  goto restart;
  /* Check the node can accept `multi byte'.  */
  if (first_idx == -1)
      err = check_arrival_expand_ecl (dfa, &next_nodes, subexp_num, type);
	     at the back reference?  */

  /* Check incrementally whether of not the input string match.  */

    naccepted = 0;


/* Compute the next node to which "NFA" transit from NODE("NFA" is a NFA
				       local_sctx.sifted_states,
	  || (ch == '\0' && (mctx->dfa->syntax & RE_DOT_NOT_NULL)))

			       const re_match_context_t *mctx,
	  else
   STR_IDX is the current index of the input string.
    for (ecl_idx = 0; ecl_idx < inv_eclosure->nelem; ++ecl_idx)
			 match_last);
		    break;
    {
  if (dfa->init_state->nodes.nelem == 0
	    return trtable[ch + SBC_MAX];
	If `a' isn't the LAST_NODE and `a' can't epsilon transit to
		int *p_match_first)
		  goto free_return;

    {
    {
  *err = re_node_set_alloc (&next_nodes, state->nodes.nelem + 1);
  if (pstr->icase)
		      }
  const re_node_set *cur_nodes = &state->nodes;
	      /* Compare the length of input collating element and
/* Group all nodes belonging to STATE into several destinations.
  if (BE (cur_state->halt, 0))
static void
      struct re_backref_cache_entry *ent;

#ifdef RE_ENABLE_I18N
		  (pmatch[reg_idx].rm_eo == mctx.input.valid_len
	return REG_ESPACE;
	ii. If 'b' is in the STATE_LOG[STR_IDX+strlen('s')] but 'b' is
check_dst_limits (const re_match_context_t *mctx, re_node_set *limits,
}

	    }
		  err = REG_NOMATCH;
     this function is next_state and ERR is already set.  */
		pmatch[reg_num].rm_eo = cur_idx;
	  err = re_node_set_merge (&state->inveclosure,
  if (BE (err != REG_NOERROR, 0))
	  if (bkref_ent->node != node_idx || bkref_ent->str_idx != cur_str_idx)
/* Search for the first entry which has the same str_idx, or -1 if none is
  if (BE (bufp->no_sub, 0))
		    && re_node_set_contains (dest_nodes, edst2)))
weak_alias (__re_search_2, re_search_2)
    /* don't use transition table  */
	      if (BE (result < 0, 0))
	    {
   them unless specifically requested.  */
	}
    {
	      if (wcscoll (cmp_buf, cmp_buf + 2) <= 0
		continue;
     such node.
      assert (!IS_EPSILON_NODE (type));
    re_node_set_free (dests_node + i);
	      else
	  regoff_t *new_start = re_realloc (regs->start, regoff_t, need_regs);
  mctx.input.stop = stop;
  re_node_set_free (&follows);
static reg_errcode_t
		      if (boundaries & 1)
  re_free (mctx->bkref_ents);
    }
      if (BE (err != REG_NOERROR, 0))
							  CONTEXT_WORD);
      assert (!IS_EPSILON_NODE (type));
      for (idx = 0; idx < extrasize;)
      regs->start[i] = pmatch[i].rm_so;
	  }
  struct re_fail_stack_t *fs;
  int top = mctx->state_log_top;
	  if (sub_top->path == NULL)
  return REG_NOERROR;
	{
      *err = check_subexp_matching_top (mctx, &next_state->nodes,
    {
  for (cur_node = target; !re_node_set_contains (dst_nodes, cur_node);)
   `regcomp', we ignore PMATCH.  Otherwise, we assume PMATCH has at
      re_node_set_free (&local_sctx.limits);
  const re_dfa_t *const dfa = mctx->dfa;
      regs->num_regs = num_regs;
	    }
      sctx->sifted_states[str_idx] = re_acquire_state (&err, dfa, dest_nodes);
  /* Else, we are on the boundary: examine the nodes on the epsilon

  const re_dfa_t *const dfa = mctx->dfa;
/* re_match, re_search, re_match_2, re_search_2
}
					  re_sift_context_t *sctx, int str_idx,
  if (BE (rval == 0, 1))
      int32_t extrasize = (const unsigned char *)
	      ch = (match_first >= length
{
	continue;
	return err;
	  if (constraint & NEXT_WORD_CONSTRAINT)
    {
  for (node_idx = 0; node_idx < eclosures->nelem; ++node_idx)
		  re_node_set_free (&union_set);
	      if (BE (offset >= (unsigned int) mctx.input.valid_raw_len, 0))
					  int str_idx, int from, int to)

      }
	  dest_states_nl[i] = re_acquire_state_context (&err, dfa, &follows,
static reg_errcode_t
   index of the buffer.  */
      context = re_string_context_at (&mctx->input,
				       bitset_t *states_ch) internal_function;
	      assert (err == REG_ESPACE);
      mctx->state_log[cur_str_idx] = cur_state;
      unsigned char c = re_string_byte_at (input, str_idx), d;
	  if (BE (err != REG_NOERROR, 0))
					 re_node_set *cur_nodes, int cur_str,
	  if (BE (result < 0, 0))
      int cur_str_idx = re_string_cur_idx (&mctx->input);
	return 0;
		/* We completed a subexpression, but it may be part of
      if (outside_node == -1)
	}
      dest_idx = re_string_cur_idx (&mctx->input) + naccepted;
	if (pmatch[reg_idx].rm_so != -1)
	  char_len = 6;
      if (BE (need_regs > regs->num_regs, 0))
      mctx->abkref_ents *= 2;
		  err = sub_epsilon_src_nodes (dfa, node, dest_nodes,

#endif
  mctx->bkref_ents[mctx->nbkref_ents].subexp_to = to;
	  if (BE (match_first == right_lim, 0))
      trtable = state->trtable =
/* Check SUB_LAST can arrive to the back reference BKREF_NODE at BKREF_STR.
	return REGS_UNALLOCATED;
				     const re_dfastate_t *state, int idx)
   length is LENGTH.  NMATCH, PMATCH, and EFLAGS have the same

	  at_init_state = 0;
	    }
	default:
	  re_free (top->path);
	    {
  int ndests; /* Number of the destinations from `state'.  */
	      else
      re_node_set next_nodes, *log_nodes, *table_nodes = NULL;

	      result = re_node_set_insert (&union_set, next_node);
  return REG_NOERROR;
	  || dfa->init_state_word == NULL || dfa->init_state_nl == NULL
  if (dests_node_malloced)
	  if (!not_consumed)
      if (reg_num < nmatch)
			 const re_string_t *input, int str_idx)
  if (regs_allocated == REGS_UNALLOCATED)
	}
{
transit_state (reg_errcode_t *err, re_match_context_t *mctx,
re_set_registers (struct re_pattern_buffer *bufp,
	  if (mbs_len == elem_mbs_len)
	    for (node_idx = 0; node_idx < dest_nodes->nelem; ++node_idx)
  if (BE (err != REG_NOERROR, 0))
build_trtable (const re_dfa_t *dfa, re_dfastate_t *state)

	    }
	      bitset_word_t any_set = 0;
      if (BE (err != REG_NOERROR, 0))
	    next_start_idx = next_char_idx;
  return REG_NOERROR;
	    if (BE (mctx.input.offsets_needed != 0, 0))
	  re_dfastate_t *dest_state;
	  bitset_t intersec; /* Intersection sets, see below.  */
	      if (reg_idx == nmatch)
			    re_node_set *dests_node, bitset_t *dests_ch)
  subexp_num = dfa->nodes[bkref_node].opr.idx;
  result = re_search_internal (bufp, string, length, start, range, stop,

	}
  fs->stack[num].idx = str_idx;
	return 0;
  backup_state_log = mctx->state_log;
    {
  if (BE (start < 0 || start > length, 0))
	    return 0;
	      if (BE (err != REG_NOERROR, 0))

					   dst_bkref_idx);
		}
static int sift_states_iter_mb (const re_match_context_t *mctx,
	_NL_CURRENT (LC_COLLATE, _NL_COLLATE_SYMB_EXTRAMB);
	}
	      int ret;
   version 2.1 of the License, or (at your option) any later version.
	{

    re_node_set_free (dests_node + j);


  const re_token_t *node = dfa->nodes + node_idx;
      return dest_node;
	  if (pmatch[reg_num].rm_so < cur_idx)

	  sift_ctx_init (&sctx, sifted_states, lim_states, halt_node,
   If NUM_REGS == 0, then subsequent matches should allocate their own
}
	  if (BE (err != REG_NOERROR, 0))
     internal_function;
  return 0;
		     || !mctx->state_log[match_last]->halt);
		goto free_return;
static reg_errcode_t get_subexp (re_match_context_t *mctx,

			       : mctx->max_mb_elem_len);
	  return REG_ESPACE;
	 OP_OPEN_SUBEXP and whose index is SUBEXP_IDX, we must check all
static int check_halt_state_context (const re_match_context_t *mctx,
  int i;

/* Enumerate all the candidates which the backreference BKREF_NODE can match
	  elem_mbs_len = extra[idx++];
	i. If 'b' isn't in the STATE_LOG[STR_IDX+strlen('s')], we throw
		    continue;
	  int cls_node = -1;
  reg_errcode_t err;
	{
					      pstr->bufs_len + 1);
  re_node_set next_nodes;

    default:
      struct re_backref_cache_entry *ent;
   the first STOP characters of the concatenation of the strings should be
					       re_node_set *cur_nodes,
      type = dfa->nodes[node].type;
    {
      else if (c < 0xfc)
     `cur_src' points the node_set of the old `state_log[str_idx]'
	}
find_collation_sequence_value (const unsigned char *mbs, size_t mbs_len)
      bitset_merge (acceptable, dests_ch[i]);
#endif
	{
	{
}
			     int dst_node, int dst_idx, int src_node,

	  /* Skip the name of collating element name.  */
	  /* Reached the invalid state or an error.  Try to recover a valid
	    calloc (sizeof (re_dfastate_t *), SBC_MAX);
  if (nmatch > 1 || dfa->has_mb_node)
      else
    { /* No.  So allocate them with malloc.  */
  return ret;
    {
	  if (pstr->trans != NULL)
sub_epsilon_src_nodes (const re_dfa_t *dfa, int node, re_node_set *dest_nodes,
	  next_node = dfa->edests[ent->node].elems[0];
	  if (constraint & NEXT_NEWLINE_CONSTRAINT)
	    {
		  {
  re_node_set_init_empty (&union_set);
#ifdef RE_ENABLE_I18N
    {
#endif
    case SIMPLE_BRACKET:
	  || check_halt_state_context (mctx, cur_state, cur_str_idx))
		      && err != REG_NOERROR, 0))

  ent = mctx->bkref_ents + cache_idx_start;
		continue;
  return next_state;
    {
#endif

					int str_idx, const re_node_set *candidates)
		  if (err == REG_NOERROR)
      cur_state = transit_state (&err, mctx, cur_state);
      err = re_node_set_init_1 (&next_nodes, top_node);
      int prev_node = cur_src->elems[i];
#ifdef DEBUG
      for (j = 0; j < ndests; ++j)
		if (!re_node_set_contains (dfa->inveclosures + node,
			 re_sift_context_t *sctx, int str_idx,
	    }
	      if (match_last < 0)

	 satisfies the constraints.  */
		re_sub_match_last_t *sub_last, int bkref_node, int bkref_str)
		{
  int char_len, elem_len;
      for (i = 1; i < char_len; ++i)
		return -2;
	  const int32_t *table, *indirect;
      /* Return 0 in case of an error, 1 otherwise.  */
					 str_idx, sctx->last_str_idx);
      if (next_nodes.nelem)
  sifted_states = NULL;

	      err = check_subexp_matching_top (mctx, new_dest_nodes,
					   dfa->init_state->entrance_nodes,
		   re_dfastate_t **src, int num)
      if (sifted_states[0] == NULL)
  /* We build DFA states which corresponds to the destination nodes
     internal_function;
	right = mid;
	    }
		struct re_registers *regs, int ret_len)
		  err = extend_buffers (mctx);
	  re_node_set_free (&merged_set);
  bitset_t *dests_ch;
	    {
	{
	continue;
		  any_set |= (accepts[j] &= dfa->word_char[j]);
static unsigned int
#endif /* RE_ENABLE_I18N */
		memcpy (pmatch, prev_idx_match, sizeof (regmatch_t) * nmatch);
  memcpy (regs, fs->stack[num].regs, sizeof (regmatch_t) * nregs);
	{
    }
   However, the cost of checking them strictly here is too high, then we
	   node `a'.
    sctx->sifted_states[str_idx] = NULL;
  if (mctx->state_log != NULL)
# ifdef _LIBC
      int fs_idx;
	  cur_state = local_sctx.sifted_states[str_idx];
	{
				      mctx->eflags);
	      bitset_empty (accepts);
	continue;
				       re_dfastate_t *pstate)
	 then we don't need to add them here.  */
			  dfa->has_plural_match && dfa->nbackref > 0);
	      sizeof (re_dfastate_t *) * (path->alloc - old_alloc));
				       OP_CLOSE_SUBEXP);
find_subexp_node (const re_dfa_t *dfa, const re_node_set *nodes,
#  include <locale/weight.h>
    {
/* Functions for matching context.  */

	| (range >= 0 ? 2 : 0)
  rval = 0;
	    return REG_ESPACE;
  if (eflags & REG_STARTEND)
  ndests = 0;
		pmatch[reg_idx].rm_so =
	    int edst2 = ((dfa->edests[cur_node].nelem > 1)
		   so that matches of an inner subexpression are undone as

	  re_string_skip_bytes (&mctx->input, 1);
	     the buffer.  */
  /* For each sub expression  */
				    subexp_num, type);
	      }
					       dest_node)))
    }
	    return *(uint32_t *) (extra + idx);
  __libc_lock_lock (dfa->lock);
	      int node = dest_nodes->elems[node_idx];
				      sl_str - sub_top->str_idx + 1);
  for (i = 0; i < cur_nodes->nelem; ++i)
      mctx->state_log[cur_idx] = next_state;
	  err = check_arrival_expand_ecl_sub (dfa, &new_nodes, cur_node,

  assert (mctx->sub_tops != NULL);
	  dest_str_idx = (cur_str_idx + bkref_ent->subexp_to
	    break;
  err = REG_NOERROR;
	      const unsigned char *cp = pin;
	  if (dest_states_malloced)

      if (BE (new_array == NULL, 0))
	    return trtable[ch];
	  if (cur_state->has_backref)
}
      int err;
      path->array = new_array;
      if (naccepted == 0)
	  if (!fl_longest_match)
   destination of the back references by the appropriate entry
  wc = __btowc(*(input->mbs+str_idx));
	{

      memset (new_array + old_alloc, '\0',
internal_function
	{
  else
  int null_cnt = 0;
  if (dest_nodes->nelem == 0)
  return REG_NOERROR;
		  break;
		  }
      /* '.' accepts any one character except the following two cases.  */
	      if (BE (err == -1, 0))
					&src[st_idx]->nodes);
   License along with the GNU C Library; if not, see
	}
#define STATE_NODE_CONTAINS(state,node) \
	rval = -2;
	   E.g. RE: (a){2}  */
		    break;
	     transit.  */
	      cmp_buf[4] = cset->range_ends[i];
	      break;
  re_node_set_free (eps_via_nodes);
    {
static reg_errcode_t check_subexp_limits (const re_dfa_t *dfa,
  const re_dfa_t *const dfa = mctx->dfa;
  dests_node = dests_alloc->dests_node;
  for (idx = 0; idx < cur_nodes->nelem; ++idx)

static re_dfastate_t *merge_state_with_log (reg_errcode_t *err,
	return NULL;
internal_function
     internal_function;
	  bkref_ent = mctx->bkref_ents + bkc_idx;
	| (t != NULL ? 1 : 0))

   You should have received a copy of the GNU Lesser General Public
	      if (type == OP_CLOSE_SUBEXP || type == OP_OPEN_SUBEXP)
  int cur_node;
static void match_ctx_clean (re_match_context_t *mctx) internal_function;
	   < ndests),
	    bitset_clear (accepts, '\n');
		= re_acquire_state_context (&err, dfa, new_dest_nodes,
   Unless this function is called, the first search or match using

	}

weak_alias (__re_set_registers, re_set_registers)
#endif
    dests_alloc = (struct dests_alloc *) alloca (sizeof (struct dests_alloc));
      int cur_node_idx = pstate->nodes.elems[i];
	goto free_return;
		goto error_return;
	}
   starting from index START + 1, and so on.  The last start position tried
		{

      else if (c < 0xf0)
	  int to_idx = str_idx + naccepted;
      if (BE (new_entry == NULL, 0))
   from which to restart matching.  */
		trtable[ch] = dest_states[j];
  if (dfa->nbackref)
static reg_errcode_t push_fail_stack (struct re_fail_stack_t *fs,
	      match_len = char_len;
	 with varying efficiency, so there are various possibilities:
	      goto free_return;
	return NULL;

      if (type == CHARACTER)
	  if (re_node_set_contains (cur_nodes, next_node))
	const char *__restrict string,
  mctx->abkref_ents = n;
      start = pmatch[0].rm_so;
    {

      if (cur_state)
	return REG_ESPACE;
      trtable = state->trtable;
static reg_errcode_t
		   ? mctx.input.valid_raw_len
static re_dfastate_t *
	      if (re_node_set_contains (eps_via_nodes, dest_node))
     1. When STR_IDX == MATCH_LAST(the last index in the state_log):
	  next_node = dfa->nexts[ent->node];
				     int bkref_node, int bkref_str)
static reg_errcode_t
  mctx.input.raw_stop = stop;
	    {

    }
				      int str_idx, int dest_node, int nregs,
	  if (BE (elem & 1, 0))
  return fs->stack[num].node;
	{
	    }
  int halt_node, match_last;
  /* If the current state can accept multibyte.  */
		  if (memcmp (buf + regs[subexp_idx].rm_so, buf + *pidx,
      mctx->state_log_top = cur_idx;
      ret = merge_state_array (dfa, sifted_states, lim_states,
  int idx, cur_node;
		  re_node_set_free (&union_set);
  for ( ; i < regs->num_regs; ++i)
    case OP_PERIOD:
      uint32_t nrules;
	  else
	    }
  assert (start + range >= 0 && start + range <= length);
    {
	return dfa->init_state;
{
static reg_errcode_t match_ctx_init (re_match_context_t *cache, int eflags,
	  err = re_node_set_init_1 (&new_dests, next_node);
	{
  memcpy (prev_idx_match, pmatch, sizeof (regmatch_t) * nmatch);
      re_free (top->lasts);
  assert (mctx->state_log != NULL);
  /* We will log all the DFA states through which the dfa pass,
    }
	  && check_node_accept (mctx, dfa->nodes + prev_node, str_idx)
	rval = pmatch[0].rm_so;
  else
    }
      int naccepted = 0;
  re_node_set follows, *dests_node;
		 character ch.  See group_nodes_into_DFAstates.  */
  return rval;
  /* If we are outside the range of the subexpression, return -1 or 1.  */
    {
	      err = re_node_set_init_1 (&union_set, next_node);
			  {
      /* Avoid overflow.  */
   strings.)
	      bitset_empty (accepts);
      fs->stack = new_array;
	    }
  return err;
	  local_sctx.last_str_idx = str_idx;

{
{
      re_token_type_t type = dfa->nodes[cur_node].type;

	}

		  const char *__restrict string, size_t nmatch,

	return 0;
   to NEXT_NODES.
  /* Avoid overflow.  */

static re_dfastate_t *
	  int to_idx;
  mctx->sub_tops[mctx->nsub_tops]->node = node;
	the LAST_NODE, we throw away the node `a'.
		    int cur_str, int subexp_num, int type)
   If REGS is not NULL, and BUFP->no_sub is not set, the offsets of the match
      if (BE (*err != REG_NOERROR, 0))



  sctx->last_node = last_node;
		return candidate;
    return 0;
  if (BE (ret != REG_NOERROR, 0))
    return err;
	      sizeof (re_dfastate_t *) * (next_state_log_idx - top));
     internal_function;
	    extra = (const unsigned char *)
	      not_consumed |= accepts[k] = accepts[k] & ~dests_ch[j][k];
	 character, and we are in a multi-byte character set: discern
  if (num_regs)
	 back reference.  Then the next state is the union set of

	naccepted = check_node_accept_bytes (dfa, node, &mctx->input, *pidx);
		  && prev_idx_match[reg_num].rm_so != -1)
		  offset = match_first - mctx.input.raw_mbs_idx;
      re_sub_match_last_t *sub_last;
		  if (dst == from_node)
	    {
	  break;
      /* If the next state has back references.  */
	  int length,
      /* If the node may accept `multi byte'.  */
	    return ret;

	       : &mctx->state_log[last_str]->nodes);
	      if (prev_idx_match_malloced)
	    if (need_word_trtable)
	  return REGS_UNALLOCATED;
void
		  err = err != REG_NOERROR ? err : REG_ESPACE;
#endif
  return REG_NOERROR;
	  {
      trtable = state->word_trtable =
	  int subexp_len;
     internal_function;
      subtop->lasts[subtop->nlasts] = new_entry;
	    return err;
#endif /* RE_ENABLE_I18N  */
			       sub_top->str_idx, cls_node, sl_str,
	  if (!re_node_set_contains (cur_nodes, candidate))
  return rval;
	return 0;
  int subexp_num, sub_top_idx;
      regs->start = re_malloc (regoff_t, need_regs);
      return UINT_MAX;

      return char_len;
  err = match_ctx_init (&mctx, eflags, dfa->nbackref * 2);
	  /* If all characters are consumed, go to next node. */
	{
	      int next_node = dfa->nexts[cur_node];
						   re_node_set *dst_nodes,
	    return REGS_UNALLOCATED;
internal_function
      /* Check OP_OPEN_SUBEXP in the current state in case that we use them
  /* Extend the buffer if we need.  */
	      {
			   start, range, regs, stop, 0);

  if (BE ((((SIZE_MAX - (sizeof (re_node_set) + sizeof (bitset_t)) * SBC_MAX)
   return the position of the start of the match.  Return value -1 means no
      else
		  if (subexp_idx < BITSET_WORD_BITS)
/* Entry points compatible with 4.2 BSD regex library.  We don't define
	 allocated, reallocate them.  If we need fewer, just
static int check_dst_limits_calc_pos (const re_match_context_t *mctx,
   at STR_IDX, whose corresponding OP_OPEN_SUBEXP is SUB_TOP.  */

	  sub_last = match_ctx_add_sublast (sub_top, cls_node, sl_str);
  mctx.input.tip_context = (eflags & REG_NOTBOL) ? CONTEXT_BEGBUF
      if (node->opr.c != ch)
		/* We transited through an empty match for an optional

	{
	      /* In order to avoid infinite loop like "(a*)*", return the second
    return REG_ESPACE;

	    break;
	      if (prev_idx_match_malloced)
    }
/* Check whether the node accepts the byte which is IDX-th
push_fail_stack (struct re_fail_stack_t *fs, int str_idx, int dest_node,
		goto free_return;
}
      new_entry->node = node;
     multi character collating element.  */
		{
    return REG_ESPACE;
      if (BE (lim_states == NULL, 0))
	  re_node_set union_set;
	  err = re_node_set_init_union (&merged_set, &dst[st_idx]->nodes,
}
      if (to_idx == cur_str)
		   : mctx.input.offsets[pmatch[reg_idx].rm_so]);
  int prev_idx_match_malloced = 0;

	      match_last = re_string_cur_idx (&mctx->input);
	     new group state, which has the `remains'. */
	  for (node_idx = 0; node_idx < dest_nodes->nelem; ++node_idx)
	}
  mctx->bkref_ents[mctx->nbkref_ents].subexp_from = from;
					    context);
      rval = REGS_FIXED;
	       re_dfastate_t **limited_sts, int last_node, int last_str_idx)
  *eps_via_nodes = fs->stack[num].eps_via_nodes;
				    &state->inveclosure);
      /* Check whether `node' is a backreference or not.  */
  re_dfastate_t **trtable;
	case OP_CLOSE_SUBEXP:
	      for (j = 0; (dests_ch[j][i] & mask) == 0; ++j)
  if (mctx->nbkref_ents >= mctx->abkref_ents)
     `sifted_states[str_idx]' with `cur_dest'.
      while (enabled_idx++, entry++->more);

		       OP_OPEN_SUBEXP);
#ifdef RE_ENABLE_I18N
      if (BE (trtable == NULL, 0))
	  halt_node = check_halt_state_context (mctx,
  re_free (mctx->state_log);
	  /* Check the limitation of the close subexpression.  */
	  if (check_dst_limits (mctx, &sctx->limits,
      to_idx = cur_str + ent->subexp_to - ent->subexp_from;
      memset (mctx->bkref_ents + mctx->nbkref_ents, '\0',
      if (candidates)
  /* Then build the next sifted state.
		  {

	{
      if (sub_last_idx < sub_top->nlasts)
					   bufp->regs_allocated);
	 to MCTX->STATE_LOG.  */

	  int cls_node, sl_str_off;

	  if (dfa->subexp_map[reg_idx] != reg_idx)
	    int idx = re_node_set_contains (dest_nodes, cur_node) - 1;
	  && dfa->nodes[cur_node].opr.idx == ex_subexp)
    }
   This function handles the nodes which can accept one character, or
  int node_idx;
      for (reg_idx = 0; reg_idx < nmatch; ++reg_idx)
#ifdef DEBUG
    {
	  err = expand_bkref_cache (mctx, &next_nodes, str_idx,
  reg_errcode_t err;
      nregs = regs->num_regs;
	  if (sl_str_diff > 0)
internal_function
	  /* Nothing can be copied to regs.  */
     internal_function;
	  ret = REG_ESPACE;
					       int ex_subexp, int type)
}
	      for (j = 0; (dests_ch[j][i] & mask) == 0; ++j)

      /* Some characters remain, create a new group. */
      && mctx->bkref_ents[mctx->nbkref_ents - 1].str_idx == str_idx)
}
	  bkref_str_off += sl_str_diff;

    else
     `cur_dest' is the sifted state from `state_log[str_idx + 1]'.
	    }
	continue;
		}
internal_function
	}
merge_state_with_log (reg_errcode_t *err, re_match_context_t *mctx,
			   int bkref_idx)
	}
  dest_states_word = dest_states + ndests;
		  buf = (const char *) re_string_get_buffer (&mctx->input);
  mctx->bkref_ents[mctx->nbkref_ents].eps_reachable_subexps_map
		  match_len = j;
      if (!bitset_contain (node->opr.sbcset, ch))
#endif
	return REG_ESPACE;
#endif
    bitset_t dests_ch[SBC_MAX];
	  if (BE (cur_node == -2, 0))
      for (i = 0; i < BITSET_WORDS; ++i)
	  goto forward_match_found_start_or_reached_end;
      re_dfastate_t *pstate;
		  || err3 != REG_NOERROR, 0))
   Note: We assume that pmatch[0] is already set, and

	  if (type == CHARACTER && !bitset_contain (dests_ch[j], node->opr.c))

		  eflags & (REG_NOTBOL | REG_NOTEOL));
   re_search() first tries matching at index START, then it tries to match
	  result = re_node_set_insert (&dests_node[j], cur_nodes->elems[i]);
}
check_arrival_add_next_nodes (re_match_context_t *mctx, int str_idx,
	      err = transit_state_bkref (mctx, new_dest_nodes);
	    continue;
  return match_last;
	  if (err == REG_NOMATCH)
      ret = REG_ESPACE;
  int node_cnt, cur_str_idx = re_string_cur_idx (&mctx->input);
static re_sub_match_last_t *
    }
	      || sctx->sifted_states[to_idx] == NULL
internal_function
	    {
	     state using the state log, if available and if we have not
   The former two functions operate on STRING with length LENGTH,
}
		  || dfa->nbackref)
    {
	  if (BE (new_start == NULL, 0))
					  re_node_set *dest_nodes,
	  /* The matched string by the sub expression match with the substring
      match_last = check_matching (&mctx, fl_longest_match,
	    {

    }
		goto free_return;
	     const char *string2, int length2, int start,
      int cur_node = cur_nodes->elems[cur_idx];
      if (BE (SIZE_MAX / sizeof (re_dfastate_t *) <= mctx.input.bufs_len, 0))
	  sl_str_off = sl_str - sub_top->str_idx;
	  cmp_buf[2] = wc;
	}
	 however this function has many additional works.
      err = get_subexp (mctx, node_idx, cur_str_idx);
		    ent->eps_reachable_subexps_map
		{
      if (BE (c < 0xc2, 1))
      if (BE (dfa->nbackref, 0))
		   && range && !preg->can_be_null) ? preg->fastmap : NULL;
    }
      else if (IS_NEWLINE_CONTEXT (context))
	    }
	}
	  int start,
  context = re_string_context_at (&mctx->input, idx, mctx->eflags);
				     int n) internal_function;
	  int sl_str_diff;
internal_function
	    if (cset->range_starts[i] <= in_collseq
    /* The node can't accept the `multi byte', or the
    }
      if (BE (regs->end == NULL, 0))

	     int range, struct re_registers *regs,  int stop)
  return rval;
	      {
	  idx = idx + extra[idx] + 1;
	{
internal_function
			idx &= 0xffffff;
  return next_state;
	  if (local_sctx.sifted_states == NULL)
		return dest_node;
  int sb, ch;
  regmatch_t *pmatch;
			      mctx->abkref_ents * 2);
{
	    }

      for (j = 0; j < dests_node[i].nelem; ++j)
  /* For all the nodes belonging to `state',  */
					   src_bkref_idx);
  else
		    break;
	      err = transit_state_bkref (mctx, &cur_state->nodes);
	      err = merge_state_array (dfa, sctx->limited_states,
	}
	re_node_set_init_empty (&next_nodes);
static reg_errcode_t get_subexp_sub (re_match_context_t *mctx,
      if (char_len <= 1)
      if (cur_state && cur_state->has_backref)
  if (next_state_log_idx >= mctx->input.bufs_len
	  *err = re_node_set_merge (&next_nodes,
re_search_stub (struct re_pattern_buffer *bufp,
      for (fs_idx = 0; fs_idx < fs->num; ++fs_idx)
      /* Calculate the destination of the back reference, and append it
	    } while (mctx->state_log[match_last] == NULL
	{
      if (str_idx <= ent->subexp_from || ent->str_idx < str_idx)
	  /* Fastmap without translation, match forward.  */
	}
	  && mctx->input.valid_len < mctx->input.len))
  match_first = start;
			   const char *string, int length, int start,
internal_function
			   & ((bitset_word_t) 1 << subexp_idx)))
    {
  const re_dfa_t *const dfa = mctx->dfa;
	  return collseq[mbs[0]];
	      if (sub_top->path == NULL)
	 allocation fail we have no indication that the state_log array
  const re_dfa_t *const dfa = mctx->dfa;

	 save on code size.  We use a switch statement for speed.  */

		= pmatch[dfa->subexp_map[reg_idx] + 1].rm_eo;
	  /* Reload buf, since the preceding call might have reallocated
	      re_node_set_free (&next_nodes);
  /* We need at least 1 register.  */
		}
      if (mctx->bkref_ents[mid].str_idx < str_idx)
	      re_dfastate_t *dest_state;
    return dfa->init_state;
	}
	}
		  goto check_node_accept_bytes_match;

  const re_dfa_t *const dfa = mctx->dfa;
  /* If we are within the subexpression, return 0.  */
		goto free_return;
	  dest_state = mctx->state_log[dest_str_idx];
	    }
	  if (type == OP_CLOSE_SUBEXP)
	    {
      new_nodes = dfa->eclosures + dfa->nexts[cur_node_idx];
static re_dfastate_t *find_recover_state (reg_errcode_t *err,

	  break;
{
	  /* match with equivalence_class?  */
	 And update state_log.  */
    {
	left = mid + 1;

				re_sift_context_t *sctx,


  assert (mctx->state_log != NULL);
  return -1;

    {
	  dest_states_nl[i] = dest_states[i];
    range = -start;
check_arrival_expand_ecl_sub (const re_dfa_t *dfa, re_node_set *dst_nodes,
internal_function
	  }
	  if (BE (err != REG_NOERROR, 0))
	    {
  if (fs)
    {
	    return NULL;
					   re_string_cur_idx (&mctx->input)))
	return err;
	  while (BE (match_first < right_lim, 1)
	{
internal_function
static reg_errcode_t sift_states_bkref (const re_match_context_t *mctx,
  ret = re_string_realloc_buffers (pstr, pstr->bufs_len * 2);
	    return err;
	case 7:
  if (0)
	  local_sctx.sifted_states[str_idx] = cur_state;
      mctx.state_log = re_malloc (re_dfastate_t *, mctx.input.bufs_len + 1);
		  && err != REG_NOERROR, 0))
   ENDS.  Subsequent matches using PATTERN_BUFFER and REGS will use
      ret = re_node_set_insert (cur_dest, prev_node);
	  idx += sizeof (uint32_t);
  int result;
__attribute ((always_inline)) internal_function
      !STATE_NODE_CONTAINS (sctx->sifted_states[str_idx + naccepted],
  int num = --fs->num;
		       const re_node_set *candidates)
      if (BE (ret != REG_NOERROR, 0))
	next_nodes = *log_nodes;
int
/* Functions for state transition.  */
  re_node_set eps_via_nodes;
						   size_t name_len)
	    continue;
				    &eps_via_nodes, fs);
	  return dest_node;
	    {
		continue;
      dests_node_malloced = true;
				int node_idx, int str_idx, int max_str_idx)
	  if (ops_node >= 0)
			  re_dfastate_t *state) internal_function;
	 match it the context.  */

#endif /* RE_ENABLE_I18N */
					    re_dfastate_t *next_state)

		       && push_fail_stack (fs, *pidx, candidate, nregs, regs,
	     Check the halt state can satisfy the current context.  */

      if (constraint)
  re_node_set union_set;
      /* At first, check the last node of sub expressions we already
    {
  re_node_set_init_empty (&sctx->limits);


      if (BE (nregs < 1, 0))
		}
  int ndests; /* Number of the destination states from `state'.  */
{
/* Check the halt state STATE match the current context.
	  /* There are problematic nodes, re-calculate incrementally.  */
  int cur_str_idx = re_string_cur_idx (&mctx->input);
    }

      ret = sift_states_backward (mctx, &sctx);

			  any more.  */
	      if (j == *coll_sym)
	      /* There must be exactly one destination which accepts
	      return REG_ESPACE;
					re_dfastate_t **src, int num)
		 Note that MATCH_FIRST must not be smaller than 0.  */
      int dest_node;
      mctx->sub_tops = new_array;
  int node_idx;

      new_array = realloc (fs->stack, (sizeof (struct re_fail_stack_ent_t)
  if (cache_idx_start == -1)
#endif
					      &cur_state->non_eps_nodes,
   string STRING.
					  mctx->eflags);
	}
	{
	}
  next_state = re_acquire_state_context (err, dfa, &next_nodes, context);

      re_token_type_t type = node->type;
	return REG_ESPACE;
  /* Initialize transition table.  */
	{
    if (check_halt_node_context (mctx->dfa, state->nodes.elems[i], context))
	    }
	    }
	  if (BE (err != REG_NOERROR, 0))
		{
    {
   OP_OPEN_SUBEXP and which have corresponding back references in the regular
  int cur_idx;
  re_dfastate_t **trtable;

  do
    {
  for (st_idx = 0; st_idx < num; ++st_idx)
   found.  Note that MCTX->BKREF_ENTS is already sorted by MCTX->STR_IDX.  */
      /* Update counters.  */
	{
   byte of the INPUT.  */
	return cls_node;
internal_function
      next_state = mctx->state_log[cur_idx]
			     int subexp_idx, int from_node, int bkref_idx)
   problematic append it to DST_NODES.  */
    }
#endif
			return 0;
  unsigned int context;

static int

  if (mctx->state_log != NULL)
	{
  for (idx = pmatch[0].rm_so; idx <= pmatch[0].rm_eo ;)
	      if (type == CHARACTER && node->word_char)
  cur_nodes = (mctx->state_log[last_str] == NULL ? NULL
	    {
	      || !STATE_NODE_CONTAINS (sctx->sifted_states[to_idx], dst_node)
      if (mbs_len == 1)
      sift_ctx_init (&sctx, sifted_states, lim_states, halt_node, match_last);
      /* For all characters ch...:  */

  for (i = 0; i < state->nodes.nelem; ++i)
      mctx->asub_tops = new_asub_tops;
	return 0;
    {
		break;
	    return err;
	    }
	      if (BE (err < 0, 0))
  if (__libc_use_alloca (sizeof (struct dests_alloc)))
  while (ent++->more);
      assert (err == REG_ESPACE);
		_NL_CURRENT (LC_COLLATE, _NL_COLLATE_WEIGHTMB);
	{
	  return -2;
/* regexec searches for a given pattern, specified by PREG, in the
		 && !fastmap[t[(unsigned char) string[match_first]]])
      err = clean_state_log_if_needed (mctx, dest_idx);
    {
      && dfa->init_state_word->nodes.nelem == 0
	  for (i = 0; i < ndests; ++i)
       destination was already thrown away, then the node
    }
	     elem;
{

      /* It seems to be appropriate one, then use the matcher.  */

    }
	    return -1;
		    re_node_set_free (&except_nodes);
      int match_len = 0;

  memset (&mctx, '\0', sizeof (re_match_context_t));
    return 0;
		  if (cpos == -1 /* && (boundaries & 1) */)

					 &eps_via_nodes);
  eflags |= (bufp->not_eol) ? REG_NOTEOL : 0;
      if (start != 0 && start + range != 0)
    {
  sifted_states = re_malloc (re_dfastate_t *, match_last + 1);
	  bitset_empty (accepts);
get_subexp (re_match_context_t *mctx, int bkref_node, int bkref_str_idx)
  int st_idx;
	 and '\0' are char_len == 1.  */
			   int subexp_idx, int from_node, int str_idx,
		}
      int cur_node = cur_nodes->elems[idx];
	      re_node_set_free (&next_nodes);
						    new_alasts);

  reg_errcode_t err;
		      && err != REG_NOERROR, 0))
internal_function
	if (entry->node == bkref_node)
	}
     characters which i-th destination state accepts.  */
    }

      mctx->state_log[cur_idx] = next_state;
  re_match_context_t mctx = { .dfa = dfa };
      re_free (fs->stack);
	  re_node_set_free (&next_nodes);
		  /* Match if every bytes is equal.  */
  mctx.input.newline_anchor = preg->newline_anchor;
      /* Check the `accepts' and sift the characters which are not
    }
	      /* If MATCH_FIRST is out of the valid range, reconstruct the
	}
	  for (i = 0; i < cset->nranges; ++i)


     A backreference does not epsilon-transition unless it is empty, so set
				dfa->nexts[prev_node], to_idx,
	}
	  re_node_set_free (&fs->stack[fs_idx].eps_via_nodes);
	{
proceed_next_node (const re_match_context_t *mctx, int nregs, regmatch_t *regs,
      if (c < 0xe0)
      /* We don't check backreferences here.
attribute_compat_text_section
static int check_dst_limits_calc_pos_1 (const re_match_context_t *mctx,
{
  else
	    }
	  pmatch[reg_num].rm_eo = -1;
	}
	    {
					    re_match_context_t *mctx,
  if (BE (*err != REG_NOERROR, 0))


	return 0;

/* Find the first node which is '(' or ')' and whose index is SUBEXP_IDX.
	      ch = match_first >= length
   one collating element like '.', '[a-z]', opposite to the other nodes
	  bitset_word_t has_intersec, not_subset, not_consumed;
	    }
	}
      else
}
		      && err != REG_NOERROR, 0))
	  re_sub_match_last_t *last = top->lasts[sl_idx];
	case 5:
	}
  if (BE (err != REG_NOERROR, 0))
	  ((dfa->syntax & RE_DOT_NOT_NULL) &&
  context = re_string_context_at (&mctx->input, str_idx - 1, mctx->eflags);

    {
	  while (BE (match_first < right_lim, 1)
	    pmatch[reg_idx].rm_eo += match_first;
  halt_node = mctx->last_node;
internal_function
		re_free (prev_idx_match);
  return REG_NOERROR;

	 Because there might be more than one nodes whose types are
clean_state_log_if_needed (re_match_context_t *mctx, int next_state_log_idx)
    }
	  /* Note that (ent->subexp_to = str_idx != ent->subexp_from).  */
	      if (!any_set)
				     re_dfastate_t *state) internal_function;
}

				prev_node, str_idx))
		{
		  bitset_empty (accepts);
	  re_node_set_remove (&local_sctx.limits, enabled_idx);
    dest_states = (re_dfastate_t **)
  /* Compile fastmap if we haven't yet.  */
	      indirect = (const int32_t *)
	    {
	int cur_node = inv_eclosure->elems[ecl_idx];
    {
		}
internal_function
  __libc_lock_lock (dfa->lock);

	      re_node_set_free (&union_set);


re_copy_regs (struct re_registers *regs,
	      return err;
      int old_alloc = path->alloc;
      /* Set the points where matching start/end.  */
   Return REG_NOERROR if it can arrive, or REG_NOMATCH otherwise.  */
	  int ret;
	{
#ifdef _LIBC
   otherwise the position of the match is returned.  */

static reg_errcode_t
	  return REG_NOERROR;
  if (range > 0 && bufp->fastmap != NULL && !bufp->fastmap_accurate)
	return trtable[ch];

	  goto free_return;

      re_sub_match_top_t *sub_top = mctx->sub_tops[sub_top_idx];
/* Free all the memory associated with MCTX.  */
	{
      err = re_node_set_insert (eps_via_nodes, node);
    }
	      return err;
			      int nregs, int regs_allocated);
	  if (BE (err != REG_NOERROR, 0))
#endif
    {
	  memset (sctx->sifted_states, '\0',
  /* Avoid overflow.  */
}

      if (null_cnt > mctx->max_mb_elem_len)
  re_node_set_free (cur_nodes);
		= pmatch[dfa->subexp_map[reg_idx] + 1].rm_so;
}
	  memset (accepts, '\xff', sizeof (bitset_t) / 2);
  last = right = mctx->nbkref_ents;
	 256-entry transition table.  */
		  goto check_node_accept_bytes_match;
  err = REG_NOERROR;
		  if (cpos == 0 && (boundaries & 2))
				bkref_str_idx);
	  if (BE (*err != REG_NOERROR, 0))
#endif /* RE_ENABLE_I18N */
    }
    {
  cur_node = dfa->init_node;
#endif
			equiv_class_idx &= 0xffffff;

  dests_ch = dests_alloc->dests_ch;
internal_function
  int match_last = -1;
  match_kind =
   at STR_IDX.  */
	}

    }
		cls_node = node;
  for (sub_top_idx = 0; sub_top_idx < mctx->nsub_tops; ++sub_top_idx)
  return REG_NOERROR;


	    {
	      if (dfa->nodes[cur_node].opt_subexp
	  if (BE (err != REG_NOERROR, 0))
     uses.  */
  for (;;)
}
			    : dfa->eclosures + dfa->nexts[node_idx]);
		       ? 0 : (unsigned char) string[match_first];

{
internal_function
  /* Already zero-ed by the caller.
	  if (old_state == cur_state)

internal_function
static int search_cur_bkref_entry (const re_match_context_t *mctx, int str_idx)
    }
     back-reference or a node which can accept multibyte character or
      if (next_state != NULL)
 free_return:
			     int start, int range, struct re_registers *regs,
	      while (ent++->more);
    - inside the sub expression whose number is EX_SUBEXP, if FL_OPEN.

		  if (BE (err != REG_NOERROR, 0))

#ifdef DEBUG
		       const re_node_set *candidates)
	pmatch[reg_idx].rm_so = pmatch[reg_idx].rm_eo = -1;
		  re_dfastate_t *state)
      if (str_idx + 2 > input->len)
      /* `node' is a backreference.
	    }
  else if (mctx->state_log[cur_idx] == NULL)
# endif /* _LIBC */
	  err = sift_states_backward (mctx, &local_sctx);
  int cache_idx_start = search_cur_bkref_entry (mctx, cur_str);
}
	    }
	  if (NOT_SATISFY_NEXT_CONSTRAINT (node->constraint, context))

	{
  int cur_str_idx = re_string_cur_idx (&mctx->input);
	goto out_free;
	    {
	   nodes.
	    return -1;
	  if (err == REG_NOMATCH)
{
	continue;
  mctx->bkref_ents[mctx->nbkref_ents].node = node;
  for (st_idx = 0; st_idx < mctx->nsub_tops; ++st_idx)
	return err;
    {
		continue;
    {
  /* I hope we needn't fill their regs with -1's when no match was found.  */
      if (BE (mctx->bkref_ents == NULL || mctx->sub_tops == NULL, 0))
      if (BE (regs->start == NULL, 0))
#ifdef RE_ENABLE_I18N
   We must select appropriate initial state depending on the context,

      if (dest_states[i]->has_constraint)
   otherwise return the error code.
	    return cur_str_idx;
	  /* No fastmap.  */
static reg_errcode_t
      regs->num_regs = need_regs;
	      return REG_NOERROR;
	    return err;
    return ret;
	re_node_set_free (&dest_nodes);
static int
  re_node_set_free (&eps_via_nodes);
				    const re_string_t *input, int idx)
      if (reg_num < nmatch)
	continue;
	    }
    {
	      return err;
    goto free_return;
  mctx->nsub_tops = 0;
#ifdef DEBUG
      else
  while (!re_string_eoi (&mctx->input))

      if (IS_WORD_CONTEXT (context))
	naccepted = 1;
	      return REG_NOMATCH;
add_epsilon_src_nodes (const re_dfa_t *dfa, re_node_set *dest_nodes,

	  naccepted = check_node_accept_bytes (dfa, cur_node, &mctx->input,
				bkref_str_idx);
	}
  else
      regs->end = ends;
  return REG_NOERROR;
      const re_charset_t *cset = node->opr.mbcset;
  if (BE (state->accept_mb, 0))
	  for (k = 0; k < BITSET_WORDS; ++k)
     internal_function;
#ifdef RE_ENABLE_I18N
      if (BE (err != REG_NOERROR, 0))
   update the destination of STATE_LOG.  */
	++sl_str;
     const char *s;
	      _NL_CURRENT (LC_COLLATE, _NL_COLLATE_SYMB_EXTRAMB);
      else /* (ent->subexp_to != str_idx)  */

  for (null_cnt = 0; str_idx < last_str && null_cnt <= mctx->max_mb_elem_len;)
   and SUB_LAST.  */
#endif
    {
	  do
#endif
					     log_nodes);
	      unsigned int offset = match_first - mctx.input.raw_mbs_idx;
  str_idx = path->next_idx ? path->next_idx : top_str;
	  err = set_regs (preg, &mctx, nmatch, pmatch,
static re_dfastate_t *
  const re_dfa_t *const dfa = mctx->dfa;
	    continue; /* No.  */
	}
}
    {
    {
	      extra = (const unsigned char *)
	  if (BE (err != REG_NOERROR, 0))
      int ret;
	  else
   and all groups is stroed in REGS.  (For the "_2" variants, the offsets are
				   &mctx->state_log[str_idx + 1]->nodes);
	  if (cls_node == -1)
static reg_errcode_t
	    }
   TODO: This function is similar to the functions transit_state*(),
	    goto free_return;
	    return err;
  int dst_bkref_idx = search_cur_bkref_entry (mctx, dst_idx);

	   struct re_registers *regs)
	      if (BE (mctx->state_log[dest_str_idx] == NULL
	  else
				      regmatch_t *regs,
					re_dfastate_t **dst,
}
  if (dfa->init_state->has_constraint)
	  for (;;)
/* Helper function for check_arrival_expand_ecl.
   Additional parameters:
      while (mctx->state_log[cur_str_idx] == NULL);
  const re_dfa_t *const dfa = mctx->dfa;
     internal_function;
						   + sl_str_diff);
     `naccepted' bytes input.  */
	      local_sctx = *sctx;
    {
      /* Then divide `accepts' into DFA states, or create a new
		goto check_node_accept_bytes_match;
      const struct re_backref_cache_entry *entry
	}
static int
    }
/* Set the positions where the subexpressions are starts/ends to registers

			  - bkref_ent->subexp_from);
	  re_free (mctx->bkref_ents);
      start = range = 0;
	      continue;
						    re_sub_match_last_t *,
	  if (c == 0xfc && d < 0x84)
compat_symbol (libc, __compat_regexec, regexec, GLIBC_2_0);
	    {
      else if (IS_ORDINARY_CONTEXT (context))
	}
	    {
	   OP_OPEN_SUBEXP and whose index is SUBEXP_IDX, we must check all

{

	int eflags)
		  const char *string1, int length1,


check_arrival (re_match_context_t *mctx, state_array_t *path, int top_node,

	  wchar_t cmp_buf[] = {L'\0', L'\0', wc, L'\0', L'\0', L'\0'};
    goto out_free;
      if (ndests == 0)
  reg_errcode_t err;
		for (i = 0; i < cset->nequiv_classes; ++i)
		err = re_node_set_add_intersect (&except_nodes, candidates,
  else
	      err = re_node_set_init_union (&dest_nodes,
#endif
 restart:
      const re_node_set *eclosure = dfa->eclosures + cur_node;
	      goto free_return;
		     int to)
	}
	{
	      regmatch_t *pmatch,
}

		    size_t weight_len = weights[idx & 0xffffff];
      /* This function may not be called with REGS_FIXED and nregs too big.  */
static int
      fs->stack = re_malloc (struct re_fail_stack_ent_t, fs->alloc);
{
		    re_free (prev_idx_match);
  for (cls_idx = 0; cls_idx < nodes->nelem; ++cls_idx)
}
	{
	    thrown away, we throw away the node `a'.
  reg_errcode_t err;
{
    }
      dests_alloc = re_malloc (struct dests_alloc, 1);
  int at_init_state = p_match_first != NULL;
	  re_node_set_free (&sctx.limits);

}
	  if (BE (err != REG_NOERROR, 0))
	    }
	  /* TODO: It is still inefficient...  */
#endif
}
	}


#ifdef RE_ENABLE_I18N
					  re_string_cur_idx (&mctx->input),
  const re_dfa_t *const dfa = mctx->dfa;
							    &union_set);
	  subexp_len = bkref_ent->subexp_to - bkref_ent->subexp_from;
	      re_node_set_free (&eps_via_nodes);
   be at least NUM_REGS * sizeof (regoff_t) bytes long.
		  goto free_return;
    {
	  return NULL;
      else
    return err;
match_ctx_add_sublast (re_sub_match_top_t *subtop, int node, int str_idx)
  re_free (sifted_states);
	    {
  for (i = 0; i < ndests; ++i)
  if (cur_idx > mctx->state_log_top)
    }

  re_dfastate_t **lim_states = NULL;
  int i;

  const re_dfa_t *const dfa = mctx->dfa;
    if (length1 > 0)
      str = string2;
static reg_errcode_t check_arrival_expand_ecl_sub (const re_dfa_t *dfa,
		= re_acquire_state_context (&err, dfa, &dest_nodes, context);

		  collseqwc = _NL_CURRENT (LC_COLLATE, _NL_COLLATE_COLLSEQWC);
      int naccepted = 0;
static int group_nodes_into_DFAstates (const re_dfa_t *dfa,
  if (BE (pmatch == NULL, 0))

					   int str_idx) internal_function;
      regs->end[i] = pmatch[i].rm_eo;
{
	return err;
  struct re_backref_cache_entry *lim = mctx->bkref_ents + limit;
	  ++ndests;
      else
	  int mbs_cnt, found = 0;

	  if (dfa->mb_cur_max > 1)
/* Check how many bytes the node `dfa->nodes[node_idx]' accepts.
		if (pmatch[reg_idx].rm_so > -1 && pmatch[reg_idx].rm_eo == -1)
}
	  if (BE (err != REG_NOERROR || err2 != REG_NOERROR
	  if (BE (*err != REG_NOERROR, 0))
	  if (dest_states[i] != dest_states_word[i] && dfa->mb_cur_max > 1)
		      re_dfastate_t *next_state)
      /* In case of:
	  const unsigned char *collseq = (const unsigned char *)
    return -1;
  int subexp_num, backup_cur_idx, str_idx, null_cnt;
	  if (BE (err != REG_NOERROR, 0))
    }
	    return 0;
# endif /* _LIBC */
		re_free (prev_idx_match);
  return cur_state;
		       && subexp_idx == dfa->nodes[node].opr.idx)
	      trtable[NEWLINE_CHAR + SBC_MAX] = dest_states_nl[j];
		    size_t nmatch, regmatch_t pmatch[],
	{
	      goto free_return;
      if (new_array == NULL)
	  err = re_node_set_init_union (&dest_nodes,
	  if (!cur_state->has_constraint
    regs = NULL;
      re_dfastate_t *old_state = cur_state;
      *err = transit_state_mb (mctx, state);
  if (IS_EPSILON_NODE (dfa->nodes[node].type))
			int cnt = 0;
	  if (__iswctype (wc, wt))
  if (lim->subexp_to < str_idx)
	  /* Then check if this state is a subset of `accepts'.  */
		  if (subexp_idx != dfa->nodes[node].opr.idx)
					int boundaries, int subexp_idx,
	  idx += sizeof (uint32_t);
		  return err;
	{
	  if (match_len > 0)
    }
  /* Copy the regs.  */
      /* For all characters ch...:  */
		  if (BE (err != REG_NOMATCH, 0))
						match_last);
	{
  const re_node_set *eclosures = dfa->eclosures + from_node;
	  if (BE (new_end == NULL, 0))
{
      else if (type == SIMPLE_BRACKET)
	}
#endif /* RE_ENABLE_I18N  */

      ++str_idx;
    }
    {
	  int ops_node = -1;
      struct re_backref_cache_entry* new_entry;
	{
static int
	return (d < 0x80 || d > 0xbf) ? 0 : 2;
    free (dests_alloc);
   match the context, return the node.  */
#endif

      int dest_str_idx, prev_nelem, bkc_idx;
	 does not have the right size.  */
      /* Is this entry ENT is appropriate?  */
   LAST_NODE at LAST_STR.  We record the path onto PATH since it will be
	return 0;
			 re_node_set *dest_nodes)
     if nmatch > 1, or this dfa has "multibyte node", which is a
	int cur_node = inv_eclosure->elems[ecl_idx];
      if (BE (next_char_idx >= mctx->input.bufs_len, 0)
	      re_node_set_free (&eps_via_nodes);
	  err = re_node_set_init_1 (dests_node + ndests, cur_nodes->elems[i]);

sift_states_backward (const re_match_context_t *mctx, re_sift_context_t *sctx)
      unsigned int context;
      src_pos = check_dst_limits_calc_pos (mctx, limits->elems[lim_idx],
  if (node->constraint)
	}

      /* And double the length of state_log.  */

      d = re_string_byte_at (input, str_idx + 1);
static int check_matching (re_match_context_t *mctx, int fl_longest_match,
      mctx->state_log = new_array;
	    re_string_translate_buffer (pstr);
	    re_node_set_remove_at (dest_nodes, idx);

		 character ch.  See group_nodes_into_DFAstates.  */
  fs->stack[num].node = dest_node;
  reg_errcode_t err;
}

	  err3 = re_node_set_merge (cur_nodes, &new_dests);
	      }
	}
		    {
	return REG_ESPACE;
					   context);
		  err = clean_state_log_if_needed (mctx,
	 these destinations and the results of the transition table.  */
	      p_match_first = NULL;
   CUR_NODES, however exclude the nodes which are:
	  entry = mctx->bkref_ents + enabled_idx;
  elem_len = re_string_elem_size_at (input, str_idx);
#if __GNUC__ >= 2
  new_entry = calloc (1, sizeof (re_sub_match_last_t));
	      if (fastmap[ch])
	}

#endif

    }
	forward_match_found_start_or_reached_end:
  return re_search_stub (bufp, string, length, start, range, length, regs, 0);
	  if (c == 0xe0 && d < 0xa0)
	  if (!has_intersec)
	  if (BE (err != REG_NOERROR, 0))
      dst_pos = check_dst_limits_calc_pos (mctx, limits->elems[lim_idx],
		 && re_node_set_contains (dest_nodes, edst1))
      re_token_t *node = &dfa->nodes[cur_nodes->elems[i]];
	  /* We are at the last node of this sub expression.  */


      if (!dfa->nodes[cur_node_idx].accept_mb)
	  if (cls_node >= 0)
  reg_errcode_t err;
  if (bitset_contain (acceptable, NEWLINE_CHAR))
	    trtable[NEWLINE_CHAR] = dest_states_nl[j];

	}
	}
		    if (BE (err != REG_NOERROR, 0))
      switch (match_kind)
check_halt_node_context (const re_dfa_t *dfa, int node, unsigned int context)
	    }
static reg_errcode_t transit_state_mb (re_match_context_t *mctx,
					next_node))
      if (nrules != 0)
internal_function
sift_states_iter_mb (const re_match_context_t *mctx, re_sift_context_t *sctx,
	  cls_node = find_subexp_node (dfa, nodes, subexp_num,
   register data.
int

  /* Then check the current node set has the node LAST_NODE.  */
   If RET_LEN is nonzero the length of the match is returned (re_match style);
					    dest_state->entrance_nodes,
	}
	  }
	  wctype_t wt = cset->char_classes[i];
		}
    }
  err = check_arrival (mctx, &sub_last->path, sub_last->node,
		  if (ent->node != node)
   pmatch[i].rm_so == pmatch[i].rm_eo == -1 for 0 < i < nmatch.  */
	  return 1;
		    int length, int start, int range, int stop,
  *cur_nodes = new_nodes;
#endif /* RE_ENABLE_I18N */
  char_len = re_string_char_size_at (input, str_idx);
     from `state'.  `dests_node[i]' represents the nodes which i-th
	 only the most common of them are specialized, in order to
      re_token_type_t type = dfa->nodes[prev_node].type;
			   int *p_match_first) internal_function;
      if (!preg->no_sub && nmatch > 1)
  mctx.dfa = dfa;
static reg_errcode_t update_cur_sifted_state (const re_match_context_t *mctx,
	 by looking at the character code: build two 256-entry
  assert (nmatch > 1);
  assert (err == REG_NOERROR);
	  if (cset->nranges)
	      match = 1;
  re_free (lim_states);
#if !(defined _LIBC || (defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L))

{
	{
	continue; /* It isn't related.  */
	}

	  if (cset->nequiv_classes)
static int
  int match = 0;
					 const char *string, int length,
}
  if (BE (mctx->nsub_tops == mctx->asub_tops, 0))
    }
		  /* Recurse trying to reach the OP_OPEN_SUBEXP and
    }
		    --node_idx;
		  if (BE (err != REG_NOERROR, 0))
   which are against limitations from DEST_NODES. */
	    {
static int
  int idx, outside_node;
		break; /* We don't need to search this sub expression
	      if (type == OP_OPEN_SUBEXP
    return REG_ESPACE;

      goto out;
	  /* Put the position in the current group. */
   corresponding back references.  */
  for (i = 0; i < nregs; ++i)
  else if (type == OP_CLOSE_SUBEXP)
{
    {
	  for (i = 0; i < cset->nranges; ++i)

	  if (dest_state == NULL)
	    return -2;
      if (dest_state == NULL)
	      else
    return REG_ESPACE;
     destination state contains, and `dests_ch[i]' represents the
      if (!build_trtable (mctx->dfa, state))
	  regs->num_regs = need_regs;
	      err = (err != REG_NOERROR ? err
	  {
	  char_len = 4;
static void
/* Calculate the destination nodes of CUR_NODES at STR_IDX, and append them
  int i;
						mctx->state_log[match_last],
	 later.  E.g. Processing back references.  */
	dest_nodes = *new_nodes;
	      if (BE (err != REG_NOERROR, 0))
	    return err;
  err = re_node_set_alloc (&new_nodes, cur_nodes->nelem);
    int ecl_idx;
      wchar_t wc = ((cset->nranges || cset->nchar_classes || cset->nmbchars)
		break;
  reg_errcode_t err = REG_NOERROR;
  else if (BE (bufp->regs_allocated == REGS_FIXED &&
   Note: We assume front end functions already check ranges.
		    }
		  err = re_node_set_merge (&union_set, &dest_state->nodes);
	      table = (const int32_t *)
  return 0;
  /* Create a new node set NEW_NODES with the nodes which are epsilon
		   first match.  Copy back the old content of the registers

      if (BE (at_init_state, 0))

      naccepted = check_node_accept_bytes (dfa, cur_node_idx, &mctx->input,
    return left;
	  for (node_idx = 0; node_idx < dest_nodes->nelem; ++node_idx)
			if (cnt > weight_len)
      /* FALLTHROUGH */
     mctx->nbkref_ents = 0;
		  return REG_ESPACE;
		    check_dst_limits_calc_pos_1 (mctx, boundaries, subexp_idx,
  /* This is a cache that saves negative results of check_dst_limits_calc_pos.
   corresponding matched substrings.
	  /* Add `new_dest_node' to state_log.  */
      /* The current state accepts newline character.  */
  if (BE (mctx->sub_tops[mctx->nsub_tops] == NULL, 0))
static int re_search_stub (struct re_pattern_buffer *bufp,
	    bitset_clear (accepts, '\0');
	  while (match_first >= left_lim)
			     const char *string1, int length1,
  mctx->bkref_ents[mctx->nbkref_ents].str_idx = str_idx;
  /* new line */
  const re_dfa_t *const dfa = mctx->dfa;

static unsigned int find_collation_sequence_value (const unsigned char *mbs,
	      re_node_set_free (&new_nodes);
#ifdef RE_ENABLE_I18N
    }
      entry = mctx->bkref_ents + first_idx;
    {
		{
			    ? dfa->eclosures + dfa->edests[node_idx].elems[0]
/* Return the next state to which the current state STATE will transit by
				      re_string_cur_idx (&mctx->input) - 1,
static reg_errcode_t expand_bkref_cache (re_match_context_t *mctx,
      re_sub_match_top_t **new_array = re_realloc (mctx->sub_tops,
	    if ((!re_node_set_contains (inv_eclosure, edst1)
      cur_node = proceed_next_node (mctx, nmatch, pmatch, &idx, cur_node,
      int32_t idx;
      path->alloc += last_str + mctx->max_mb_elem_len + 1;
    }

	  if (BE (err != REG_NOERROR, 0))

	return err;
}
	return REG_ESPACE;
{
    {
    {
  return clean_state_log_if_needed (mctx, to_idx);
  if (BE (INT_MAX / 2 / sizeof (re_dfastate_t *) <= pstr->bufs_len, 0))

      pstate = mctx->state_log[cur_idx];
  regmatch_t *prev_idx_match;
static reg_errcode_t set_regs (const regex_t *preg,


      bufp->regs_allocated = REGS_UNALLOCATED;
internal_function
			       nregs, pmatch, eflags);
transit_state_mb (re_match_context_t *mctx, re_dfastate_t *pstate)
}
	continue;
    mctx->max_mb_elem_len = to - from;
    {
static reg_errcode_t
      if (pstr->mb_cur_max > 1)
      return -2;

	  /* Skip the wide char sequence of the collating element.  */
  const re_dfa_t *const dfa = mctx->dfa;
	}
		  if (prev_idx_match_malloced)
	{
					cur_idx);
  subexp_num = dfa->nodes[top_node].opr.idx;

	if (cur_node == node)
				    re_string_cur_idx (&mctx->input) - 1,
      for (sub_last_idx = 0; sub_last_idx < sub_top->nlasts; ++sub_last_idx)
	    {
    return REG_NOERROR;
    {
	free (dests_alloc);
prune_impossible_nodes (re_match_context_t *mctx)
			    int idx)
	}


		  bitset_empty (accepts);
	  char_len = 3;
	    }
      if (naccepted != 0
	{
				     re_sub_match_last_t *sub_last,
  re_node_set_free (&next_nodes);
  extra_nmatch = (nmatch > preg->re_nsub) ? nmatch - (preg->re_nsub + 1) : 0;
	  int dest_node = dfa->nexts[node];
re_match (struct re_pattern_buffer *bufp,
#ifdef DEBUG
}
# ifdef _LIBC
	     already found a valid (even if not the longest) match.  */
}
	build_upper_buffer (pstr);
  return REG_NOERROR;

static inline re_dfastate_t *
	      if (BE (mctx->state_log[dest_str_idx] == NULL
	      return err;
}
		   subexpression, like (a?)*, and this is not the subexp's
    {
	  if (mctx->state_log[sl_str] == NULL)
	 the backreference to appropriate state_log.  */
   On success, re_match* functions return the length of the match, re_search*
  if (__libc_use_alloca (nmatch * sizeof (regmatch_t)))
	  nodes = &mctx->state_log[sl_str]->nodes;
		ops_node = node;
    {


      outside_node = find_subexp_node (dfa, eclosure, ex_subexp, type);
  else

      int reg_num = dfa->nodes[cur_node].opr.idx + 1;
  return REG_NOERROR;
	  }
    }
merge_state_array (const re_dfa_t *dfa, re_dfastate_t **dst,
	case OP_BACK_REF:
  for (cur_idx = 0; cur_idx < cur_nodes->nelem; ++cur_idx)
		 subexpression.  Accept this right away.  */
	    {
  } *dests_alloc;
      subexp_idx = dfa->nodes[ent->node].opr.idx;
/* Helper functions for get_subexp().  */
  const char *buf = (const char *) re_string_get_buffer (&mctx->input);
					      ex_subexp, type);
static void update_regs (const re_dfa_t *dfa, regmatch_t *pmatch,

      node = candidates->elems[node_idx];
  re_string_t *pstr = &mctx->input;
free_fail_stack_return (struct re_fail_stack_t *fs)
    }
       mctx->bkref_ents = NULL;
      int new_alasts = 2 * subtop->alasts + 1;
  unsigned int context;
# if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_3_4)
   If P_MATCH_FIRST is not NULL, and the match fails, it is set to the
{
     internal_function;
	      if (memcmp (buf + bkref_str_off, buf + sl_str, sl_str_diff) != 0)
				    int top_str, int last_node, int last_str,
{
	break;
	}
	{
static unsigned re_copy_regs (struct re_registers *regs, regmatch_t *pmatch,
	free_str = 1;
      do
	  bitset_merge (accepts, node->opr.sbcset);
	    continue;

	  re_node_set_free (&next_nodes);
		|| (edst2 > 0
	  re_node_set_free (&next_nodes);
	      if (BE (err != REG_NOERROR, 0))
  return (boundaries & 2) ? 1 : 0;
						   mctx->eflags);
				 int bkref_node, int bkref_str_idx)
}
#ifdef HAVE_ALLOCA
/* From the node set CUR_NODES, pick up the nodes whose types are
	  const char *collseqwc;

		     const re_node_set *candidates, re_node_set *limits,
		    goto free_return;
	return 0;
	  ret = sift_states_backward (mctx, &sctx);
	  idx = (idx + 3) & ~3;
			     int stop, int ret_len);
     internal_function;

		{
      null_cnt = (sctx->sifted_states[str_idx] == NULL) ? null_cnt + 1 : 0;
	  re_free (last);
#endif
#if defined _REGEX_RE_COMP || defined _LIBC
  mctx->match_last = -1;
      if (table_nodes != NULL)
	{

    return err;
	  /* Then, check the limitations in the current sift_context.  */
    {
      sl_str = sub_top->str_idx;
{
		  }
	  assert (pmatch[0].rm_so == start);
	}
	      || check_halt_state_context (mctx, cur_state,
	    dest_node = candidate;
	  /* Does this state have a ')' of the sub expression?  */
}
	  || dfa->init_state_begbuf == NULL, 0))
	    {
weak_alias (__re_search, re_search)
	  int32_t elem_mbs_len;
    re_node_set except_nodes;
  ch = re_string_fetch_byte (&mctx->input);
	    {
    {
	      continue;
{
   Return 0 if not match, if the node, STATE has, is a halt node and
  if (regs == NULL)

	      return REG_ESPACE;
	    int edst1 = dfa->edests[cur_node].elems[0];
  if (fs->num == fs->alloc)
		}
		  int dst_node, int dst_idx, int src_node, int src_idx)
      /* We don't need to check errors here, since the return value of
	  free_fail_stack_return (fs);
  while (str_idx > 0)
      fs->alloc *= 2;
	{
     internal_function;
    {

	for (reg_idx = 0; reg_idx + 1 < nmatch; reg_idx++)
   heavily reused.
      prev_idx_match_malloced = 1;
	      --match_first;
  else
		trtable[ch] = dest_states_word[j];
{
static int check_node_accept_bytes (const re_dfa_t *dfa, int node_idx,
	  pmatch[reg_num].rm_so = cur_idx;
	  return err;
	   Because there might be more than one nodes whose types are
	    goto free_return;
		/* Found the entry.  */
	      if (BE (bkref_str_off + sl_str_diff > mctx->input.valid_len, 0))
	 <src> <dst> ( <subexp> )
  uint32_t nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
{

	  if (BE (err != REG_NOERROR, 0))
    err = re_search_internal (preg, string, length, start, length - start,
      regs->num_regs = 0;
	  if (BE (err != REG_NOERROR, 0))
	 Can't we unify them?  */
      else
	      struct re_backref_cache_entry *ent = mctx->bkref_ents + bkref_idx;
  path->next_idx = str_idx;

}
    return REG_NOERROR;
						 dst, bkref_idx);
static unsigned
	  if (BE (dest_states_nl[i] == NULL && err != REG_NOERROR, 0))
      for (; bkc_idx < mctx->nbkref_ents; ++bkc_idx)
	      match_first += incr;
internal_function

	}
    {
    {
{
      int naccepted = 0;
      /* Advance as rapidly as possible through the string, until we
  if (BE (node->type == OP_UTF8_PERIOD, 0))
	{
		_NL_CURRENT (LC_COLLATE, _NL_COLLATE_INDIRECTMB);
	      if (BE (mctx->state_log[next_idx] == NULL

  if (type == OP_OPEN_SUBEXP)
	return 0;
	{
  re_dfastate_t **dest_states = NULL, **dest_states_word, **dest_states_nl;
      for (i = 0; i < BITSET_WORDS; ++i)
	      re_node_set_free (&dest_nodes);
      --str_idx;
  else
    {
internal_function
internal_function
    }
		;
  /* Set pmatch[] if we need.  */
#endif
		      return err;
  return 1;
    }
  struct re_fail_stack_t fs_body = { 0, 2, NULL };
	  unsigned int context;
		    err = sub_epsilon_src_nodes (dfa, node, dest_nodes,
static reg_errcode_t prune_impossible_nodes (re_match_context_t *mctx);
      if (node->type != OP_BACK_REF)
	 next state might use them.  */

	 - It is in CUR_SRC.
	  *err = re_node_set_init_union (&next_nodes, table_nodes,
			      length, nmatch, pmatch, eflags);
  mctx->eflags = eflags;
#ifdef RE_ENABLE_I18N
    fs = NULL;
    re_compile_fastmap (bufp);
	  /* Flags, see below.  */
      length = strlen (string);
	  && dfa->nodes[node].opr.idx < BITSET_WORD_BITS

	}
	    {
	{
      mctx->state_log[dest_idx]
  err = re_node_set_init_1 (&cur_dest, sctx->last_node);
      re_dfastate_t *dest_state;
sift_ctx_init (re_sift_context_t *sctx, re_dfastate_t **sifted_sts,
   Note that we assume that caller never call this function with duplicate
  if (BE (ndests <= 0, 0))
				   == weights[idx + 1 + cnt]))
	      match = 1;
# include <shlib-compat.h>
     internal_function;
	  *err = transit_state_bkref (mctx, &next_state->nodes);
  return re_search_2_stub (bufp, string1, length1, string2, length2,

check_node_accept (const re_match_context_t *mctx, const re_token_t *node,
	    return 0;
weak_alias (__re_match, re_match)
		/* We don't need to search this sub expression any more.  */
{
  unsigned int context;
  int first_idx = search_cur_bkref_entry (mctx, str_idx);
	bitset_set (accepts, node->opr.c);
# ifdef _LIBC
   in MCTX->BKREF_ENTS.  */
#ifdef RE_ENABLE_I18N
      do
	  *pidx = (naccepted == 0) ? *pidx + 1 : *pidx + naccepted;
    }
match_ctx_add_subtop (re_match_context_t *mctx, int node, int str_idx)
	{
      if (dest_state != NULL)
      if (type != OP_BACK_REF)
  /* Setup initial node set.  */
  if (result != REG_NOERROR)
   We return 0 if we find a match and REG_NOMATCH if not.  */
	{
	}
   Note that the matcher assume that the matching starts from the current
		break;
  left_lim = (range < 0) ? start + range : start;
	  else
	}
      log_nodes = pstate->entrance_nodes;
      match_ctx_clean (&mctx);
   TODO: This function isn't efficient...
	    }
	      if (BE (err != REG_NOERROR, 0))
      /* Merge the follows of this destination states.  */

  dest_states_nl = dest_states_word + ndests;
#endif
					   candidates);
	  path->alloc = old_alloc;
	      else
internal_function
      unsigned int constraint = node->constraint;

static reg_errcode_t re_search_internal (const regex_t *preg,
      if (mctx->state_log[str_idx])
	  re_node_set_free (&union_set);
					       eflags);
	      /* Compare each bytes.  */
    goto out_free;
	      }
  if (nmatch > 0)
  if (BE (preg->used == 0 || dfa->init_state == NULL
      int max = mctx->state_log_top;
    {
#ifdef DEBUG

	      if (regs[subexp_idx].rm_so == -1 || regs[subexp_idx].rm_eo == -1)
		    /* It is against this limitation.

      fs = &fs_body;
	  if (sifted_states[0] != NULL || lim_states[0] != NULL)
	      & ((bitset_word_t) 1 << dfa->nodes[node].opr.idx)))
      if (BE (trtable != NULL, 1))
			 regmatch_t *prev_idx_match, int cur_node,
     internal_function;
  return -1;
/* Check whether the regular expression match input string INPUT or not,
    goto free_return;
{
	  if (BE (ret != REG_NOERROR, 0))
      if ((ch == '\n' && !(mctx->dfa->syntax & RE_DOT_NEWLINE))
      if (BE (trtable == NULL, 0))
		return -2;
transit_state_bkref (re_match_context_t *mctx, const re_node_set *nodes)
	  idx += elem_mbs_len;
  /* Use transition table  */
	      re_node_set_free (&next_nodes);

  if (fl_backtrack)
	  err = build_sifted_states (mctx, sctx, str_idx, &cur_dest);
#ifdef _LIBC
		const char *string, int length, int start,
  /* If initial states with non-begbuf contexts have no elements,
      if (dfa->edests[cur_node].nelem == 2)
	      dest_state = mctx->state_log[next_idx];
     an OP_OPEN_SUBEXP or OP_CLOSE_SUBEXP for the N+1-th subexpression.  If
	    has_intersec |= intersec[k] = accepts[k] & dests_ch[j][k];
	}
    }
	    _NL_CURRENT (LC_COLLATE, _NL_COLLATE_COLLSEQMB);
      /* The node has constraints.  Check whether the current context
    }
      re_node_set *new_dest_nodes;
		}
	  state->trtable = (re_dfastate_t **)
/* Check NODE match the current context.  */
      else
static re_dfastate_t *
					dest_node))
  const re_dfa_t *dfa = (const re_dfa_t *) preg->buffer;
static int check_dst_limits (const re_match_context_t *mctx,
	    }
    {
	ii. If 'b' is in the STATE_LOG[STR_IDX] but 'b' is thrown away,
		  err = re_string_reconstruct (&mctx.input, match_first,
				    state_array_t *path, int top_node,
	{
	    {
	  dest_states_word[i] = dest_states[i];
		    ? 0 : re_string_byte_at (&mctx.input, offset));
      /* How many bytes the node can accept?  */
	    }
  boundaries = (str_idx == lim->subexp_from);
	}
#endif /* RE_ENABLE_I18N */
}
		     Remove it form the current sifted state.  */
      break;
		{
	}

	  if (dest_node == -1)
	      for (reg_idx = 0; reg_idx < nmatch; ++reg_idx)
      if (ret_len)
		  if (subexp_idx < BITSET_WORD_BITS

    }
      for (i = 0; i < cset->nmbchars; ++i)
	    continue;
	    goto error_return;
	goto free_return;
    rval = -1;
		for (j = 0; j < BITSET_WORDS; ++j)
		   int str_idx, const re_node_set *candidates)
	    {
	    return 0;
   but WITHOUT ANY WARRANTY; without even the implied warranty of
__typeof__ (__regexec) __compat_regexec;
    }
	{
		  return free_fail_stack_return (fs);
	  break;
{
  re_sub_match_last_t *new_entry;
	  result = re_node_set_insert (next_nodes, dfa->nexts[cur_node]);
	      goto check_node_accept_bytes_match;
  int need_regs = nregs + 1;

	{
	    return 0;
	  reg_errcode_t err2, err3;
	  if (to_idx > sctx->last_str_idx

  if (BE (dfa->nbackref, 0) && next_state != NULL)
	  bitset_t remains;
      if (dests_node_malloced)

	  context
	{
	  if (err == REG_NOMATCH)
{
	    {
{
	  else
   next place where we may want to try matching.
    re_node_set_init_empty (&except_nodes);
  return ndests;
	    }
search_cur_bkref_entry (const re_match_context_t *mctx, int str_idx)
	    {
   EFLAGS specifies `execution flags' which affect matching: if
  do
  return re_node_set_add_intersect (dest_nodes, candidates,
    {
  struct re_backref_cache_entry *ent;
  int eflags = 0;
		return err;
	  if (c == 0xf0 && d < 0x90)
	return REG_ESPACE;

	     const char *string1, int length1,
	    re_node_set_free (dests_node + i);
  incr = (range < 0) ? -1 : 1;
    {
		       ? 0 : (unsigned char) string[match_first];
	    continue;
	  for (k = 0; k < BITSET_WORDS; ++k)
	  if (BE (ret < 0, 0))
	  err = add_epsilon_src_nodes (dfa, dest_nodes, candidates);
match_ctx_init (re_match_context_t *mctx, int eflags, int n)
			      const re_token_t *node, int idx)
			  ++cnt;
	      re_free (new_start);
		     int node_idx, int str_idx, int max_str_idx)
	      bool accepts_newline = bitset_contain (accepts, NEWLINE_CHAR);
		  any_set |= (accepts[j] &= ~(dfa->word_char[j] & dfa->sb_char[j]));
	}
  if (free_str)
					  mctx->eflags);
      update_regs (dfa, pmatch, prev_idx_match, cur_node, idx, nmatch);
	    {
      if (pstr->mb_cur_max > 1)

					  re_node_set *cur_dest)
    }
	  if (BE (mctx->state_log[to_idx] == NULL


static int find_subexp_node (const re_dfa_t *dfa, const re_node_set *nodes,

	    }
	    {
	{
    {
    return 0;
   The GNU C Library is distributed in the hope that it will be useful,
	      int32_t idx = findidx (&cp);
      if (next_nodes.nelem)
	      mctx->state_log[dest_str_idx]

	case 4:
    {
  sctx->last_str_idx = last_str_idx;
		  (pmatch[reg_idx].rm_so == mctx.input.valid_len
	  if (entry->node != node)
  int node_idx, node;
    return transit_state_sb (err, mctx, state);
	{
}
		    return 0;
	  prev_nelem = ((mctx->state_log[cur_str_idx] == NULL) ? 0
      re_token_type_t type = dfa->nodes[node].type;
  if (!state->inveclosure.alloc)
      if (BE (err == -1, 0))
	    {
internal_function
}
      if (BE (cur_node < 0, 0))
	  if (sl_str_off > 0)
	      cur_node = pop_fail_stack (fs, &idx, nmatch, pmatch,
  mctx->state_log = path->array;
{
internal_function
	     since it might be a component byte of a multibyte
	  /* Fastmap with single-byte translation, match forward.  */
      err = re_node_set_insert (dst_nodes, cur_node);
	 leave it alone.  */
		  char *buf = (char *) re_string_get_buffer (&mctx->input);
		      &= ~((bitset_word_t) 1 << subexp_idx);
	    return err;
   This file is part of the GNU C Library.
	  return err;

      prev_idx_match = re_malloc (regmatch_t, nmatch);
		  && subexp_idx == dfa->nodes[node].opr.idx)
	      weights = (const unsigned char *)
  /* We don't need to check errors here, since the return value of
	  && node->opr.idx == subexp_idx)
	  /* Reached a halt state.
	      cmp_buf[0] = cset->range_starts[i];
static int
  if (BE (new_entry != NULL, 1))
    {
	  return REG_ESPACE;
    {
	    }
	cur_state = merge_state_with_log (&err, mctx, cur_state);
    }
    re_free ((char *) str);
static reg_errcode_t
sift_states_bkref (const re_match_context_t *mctx, re_sift_context_t *sctx,
  int lim_idx, src_pos, dst_pos;
  re_dfastate_t *next_state;
	  else
	    cur_node = pop_fail_stack (fs, &idx, nmatch, pmatch,
	    {
regexec (
	  /* Fastmap without multi-byte translation, match backwards.  */
	    }
	}
#ifdef RE_ENABLE_I18N
      /* Avoid infinite loop for the REs like "()\1+".  */
  int cls_idx;
	      re_token_type_t type = dfa->nodes[node].type;

	      err = re_node_set_init_copy (dests_node + ndests, &dests_node[j]);
#ifdef DEBUG
      {
}

		  re_node_set_free (&dest_nodes);
      /* We care about whether the following character is a word
update_regs (const re_dfa_t *dfa, regmatch_t *pmatch,
    }
	  0))
      ++subtop->nlasts;
      if (cur_state->halt)

{
      /* If the node may accept `multi byte'.  */
   PMATCH.

static int
		goto free_return;
#endif
	{
		    return err;
					   eps_via_nodes))
    return REG_NOMATCH;
      memset (mctx->state_log + top + 1, '\0',
	  struct re_backref_cache_entry *bkref_ent;
    {
					 int eflags);
	      return err;
  switch (node->type)
      re_sub_match_last_t **new_array = re_realloc (subtop->lasts,
	string `s' and transit to `b':
	if (bitset_contain (dests_ch[j], NEWLINE_CHAR))
  /* Have the register data arrays been allocated?  */

     internal_function;
    }
  reg_errcode_t err;
      alloca (ndests * 3 * sizeof (re_dfastate_t *));
  return 0;
      int naccepted, dest_idx;
	    {
	  const re_node_set *nodes;
      context = re_string_context_at (&mctx->input, str_idx - 1, mctx->eflags);
		&& in_collseq <= cset->range_ends[i])
		 && !fastmap[(unsigned char) string[match_first]])
	      if (BE (err != REG_NOERROR, 0))
{

	 from 0.  */
  bool dest_states_malloced = false;
      unsigned int context;
static reg_errcode_t

	      err = re_node_set_merge (&follows, dfa->eclosures + next_node);
    }
{
	  else
match_ctx_clean (re_match_context_t *mctx)
  /* Check for out-of-range.  */
	      if (re_node_set_contains (&mctx->state_log[*pidx]->nodes,
  reg_errcode_t err;
static int
		   ? mctx.input.valid_raw_len
	    }
		     : (err2 != REG_NOERROR ? err2 : err3));
   accepting the current input byte.  */
	  else
	  re_node_set new_dests;
	  if (BE (err != REG_NOERROR, 0))

      if (naccepted
    }
	{
#endif

		  regoff_t *starts,
static reg_errcode_t add_epsilon_src_nodes (const re_dfa_t *dfa,
  int to_idx;
     internal_function;
/* Searches for a compiled pattern PREG in the string STRING, whose
		 buffers.  */
      /* We assume that the matching starts from 0.  */
	  return REG_ESPACE;
		    continue;
/* Extended regular expression matching and search library.
		int range, int stop,
      if (BE (err != REG_NOERROR, 0))
  for (node_cnt = 0; node_cnt < state->nodes.nelem; ++node_cnt)

}
	}
    }
	  /* The backreference did epsilon transit, we must re-check all the
		pmatch[reg_idx].rm_eo =
	  {
internal_function
     to all zeros if FROM != TO.  */
  const re_dfa_t *const dfa = mctx->dfa;
      mctx->state_log_top = next_state_log_idx;
static re_sub_match_last_t * match_ctx_add_sublast (re_sub_match_top_t *subtop,
	      if (BE (bkref_str_off >= mctx->input.valid_len, 0))
	{
		{
		  int dst, cpos;
	      if (BE (err != REG_NOERROR, 0))
				    int type) internal_function;
  const char *str;
    }
     the regex must be anchored.  If preg->newline_anchor is set,
	    ++match_first;
	  int reg_idx;
  re_node_set_init_empty (&eps_via_nodes);
						   new_asub_tops);
      if (dfa->nodes[cur_node].accept_mb)

					      ex_subexp, type);
	    {

   accepting the current input byte, and update STATE_LOG if necessary.
	    {
      for (i = 0; i < dest_nodes->nelem; i++)
	  /* Skip the collation sequence value.  */
	return REG_ESPACE;
     : 8);


  re_dfastate_t *cur_state;

  if (left < last && mctx->bkref_ents[left].str_idx == str_idx)
	    continue;
  else
      /* And add the epsilon closures (which is `new_dest_nodes') of
    return err;
  /* Double the lengths of the buffers.  */
      /* match with character_class?  */
  else if (regs != NULL)
  if (node->type == COMPLEX_BRACKET)

#if 0
		   struct re_fail_stack_t *fs)
  bitset_empty (acceptable);
	  re_free (regs->start);
						   int node, int str_idx)
	  has_intersec = 0;
    {

  return naccepted;
  assert (mctx->state_log != NULL && mctx->state_log[str_idx] != NULL);
	    return REG_ESPACE;
	      return err;
    regs->start[i] = regs->end[i] = -1;
  reg_errcode_t err;
	  if (dests_node_malloced)
	  context = re_string_context_at (&mctx->input,
	    return 0;
    nregs = bufp->re_nsub + 1;
      do
	continue; /* No.  */
      return 0;
  match_ctx_clean (mctx);
#if 0
			   int range, int stop, struct re_registers *regs,


	  /* Can the OP_OPEN_SUBEXP node arrive the OP_CLOSE_SUBEXP node
		  re_dfastate_t *pstate = mctx.state_log[match_last];
   or return -2 in case of an error.
  re_sift_context_t sctx;
    {
		    return -1;
	for (ch = i * BITSET_WORD_BITS, elem = acceptable[i], mask = 1;
						   int target, int ex_subexp,
  const re_dfa_t *const dfa = mctx->dfa;
#if 0
	}
internal_function
		      {
			&& (idx >> 24) == (equiv_class_idx >> 24))
		    if (weight_len == weights[equiv_class_idx & 0xffffff]
  err = re_string_allocate (&mctx.input, string, length, dfa->nodes_len + 1,
	      bitset_copy (dests_ch[j], intersec);
   match was found and -2 indicates an internal error.  */
	}
	     regmatch_t *prev_idx_match, int cur_node, int cur_idx, int nmatch)
		{
#ifdef _LIBC
	     at the back reference?  */
    {
   re_match() matches the compiled pattern in BUFP against the string,
		  }
	  break;
	i. If 'b' isn't in the STATE_LOG[STR_IDX], we throw away the
		return err;
	 Check the substring which the substring matched.  */
  int extra_nmatch;
	    continue;
			    match_len = elem_len;
	  /* Adjust for the alignment.  */
	{
  if (cur_nodes != NULL && re_node_set_contains (cur_nodes, last_node))
	  new_end = re_realloc (regs->end, regoff_t, need_regs);
# endif
	    }
	      match_last = cur_str_idx;
static reg_errcode_t match_ctx_add_entry (re_match_context_t *cache, int node,
	      re_node_set_free (&next_nodes);
      /* We are at the first node of this sub expression.  */
      re_node_set *edests = &dfa->edests[node];
    }

      pmatch[0].rm_so = 0;
	    }
   Lesser General Public License for more details.
  mctx->state_log = sifted_states;

						   re_node_set *cur_nodes,
#endif
  re_node_set cur_dest;
	return -2;
/* The parameters have the same meaning as those of re_search.
  if (naccepted > 0 && str_idx + naccepted <= max_str_idx &&
	      bitset_copy (dests_ch[ndests], remains);
	      trtable[ch + SBC_MAX] = dest_states_word[j];
build_sifted_states (const re_match_context_t *mctx, re_sift_context_t *sctx,
	      else
					       candidates);
	  const char *string,
  if (BE (err != REG_NOERROR, 0))
internal_function
}
#endif /* RE_ENABLE_I18N */
			 ? dfa->edests[cur_node].elems[1] : -1);
      break;
   This function must be invoked when the matcher changes the start index
    }
      subexp_idx = dfa->nodes[ent->node].opr.idx;
	      pmatch[reg_num].rm_eo = cur_idx;
	  }
    return 0;
internal_function
     closures of the node in CUR_NODES.  */
	}
  re_token_type_t type = dfa->nodes[node].type;
	dst[st_idx] = src[st_idx];
	{


			   re_dfastate_t **limited_sts, int last_node,
      dest_states[i] = re_acquire_state_context (&err, dfa, &follows, 0);
	goto free_return;
				    dfa->eclosures + dfa->nexts[cur_node]);
				      from_node, bkref_idx);
    {
      if (sub_last_idx > 0)
	  if (NOT_SATISFY_NEXT_CONSTRAINT (dfa->nodes[cur_node_idx].constraint,
  __libc_lock_unlock (dfa->lock);
    {
    }
	re_node_set_free (&next_nodes);
	      if (!any_set)
		return REG_ESPACE;
    }
   Return REG_NOERROR if we find a match, and REG_NOMATCH if not,
	  if (BE (ret != REG_NOERROR, 0))
  context = re_string_context_at (&mctx->input, cur_str_idx, mctx->eflags);
      && (dfa->init_state_nl->nodes.nelem == 0
/* Build transition table for the state.
      if (node == sctx->last_node && str_idx == sctx->last_str_idx)
		   int *pidx, int node, re_node_set *eps_via_nodes,
   of errors.  */
      bufp->regs_allocated = REGS_REALLOCATE;
      int sl_idx;
{
	      else if (naccepted)
      unsigned int context;

   with re_search.
      if (BE (bufp->regs_allocated == REGS_UNALLOCATED, 0))
      {
  char *fastmap = (preg->fastmap != NULL && preg->fastmap_accurate

	}

	    return NULL;
}
			      int target, int ex_subexp, int type)
  int st_idx;
	malloc (ndests * 3 * sizeof (re_dfastate_t *));
	    return err;
	 ( <subexp> ) <src> <dst>
     internal_function;
      if (!cur_state->has_constraint
	  re_node_set merged_set;
	  int dst_node;
	  goto free_return;

	if (!re_node_set_contains (&except_nodes, cur_node))
      re_node_set_free (&sctx.limits);
	(re_dfastate_t **) calloc (sizeof (re_dfastate_t *), SBC_MAX);
  unsigned char ch;
  else
    {
		   an optional one, so do not update PREV_IDX_MATCH.  */
      for (reg_idx = 1; reg_idx < nmatch; ++reg_idx)
	{

     internal_function;
      const unsigned char *pin
  re_node_set *cur_nodes, next_nodes;
internal_function
  nmatch -= extra_nmatch;

	       newline.  See group_nodes_into_DFAstates.  */
			     sub_last->str_idx);
check_subexp_matching_top (re_match_context_t *mctx, re_node_set *cur_nodes,
      if (dfa->nodes[prev_node].accept_mb)
	}
	goto free_return;
static reg_errcode_t
  for (node_idx = 0; node_idx < cur_nodes->nelem; ++node_idx)
}
  return re_search_2_stub (bufp, string1, length1, string2, length2,
      re_free (lim_states);
	}
	  || check_node_accept (mctx, dfa->nodes + node, *pidx))
      pmatch[0].rm_eo = mctx.match_last;
	      memcpy (prev_idx_match, pmatch, sizeof (regmatch_t) * nmatch);
	  if (!(dfa->syntax & RE_DOT_NEWLINE))
	      re_node_set_empty (&union_set);
  for (left = 0; left < right;)
	    goto out_free;
      if (node->constraint)
  int rval;
static reg_errcode_t
	    bitset_clear (accepts, '\n');
  sctx->limited_states = limited_sts;
	      int nregs, int regs_allocated)
	    match_len = char_len;
	 the matching starts from the beginning of the buffer.  */
      if (BE (trtable != NULL, 1))
      bkc_idx = mctx->nbkref_ents;
	    }
      if (next_state->has_backref)
  re_free (pmatch);
  if (dfa->nbackref)
static int
  memcpy (fs->stack[num].regs, regs, sizeof (regmatch_t) * nregs);
		  in_collseq = __collseq_table_lookup (collseqwc, wc);
		  int stop, int ret_len)
   while the later two operate on concatenation of STRING1 and STRING2
check_halt_state_context (const re_match_context_t *mctx,
	  if (BE (*err != REG_NOERROR, 0))


  return 1;
		  match_last = -1;
/* For all the nodes in CUR_NODES, add the epsilon closures of them to
int
    for (ecl_idx = 0; ecl_idx < inv_eclosure->nelem; ++ecl_idx)
		    int32_t equiv_class_idx = cset->equiv_classes[i];
	      /* If MATCH_FIRST is out of the buffer, leave it as '\0'.
   Copyright (C) 2002-2005, 2007, 2009, 2010 Free Software Foundation, Inc.
/* Return the next state to which the current state STATE will transit by
	      || check_dst_limits (mctx, &sctx->limits, node,
}
	  if (dfa->syntax & RE_DOT_NOT_NULL)
      int cls_node = nodes->elems[cls_idx];
	    {
  for (i = 0; i < ndests; ++i)

		  /* If we are at the end of the input, we cannot match.  */
	  /* Check the limitation of the open subexpression.  */
static int
  return REG_NOERROR;
 	}
{
	    const char *string2, int length2, int start,
  re_free (fs->stack[num].regs);
		  /* It is against this limitation.
	{
	  re_free (top->path->array);
	       regs->num_regs < bufp->re_nsub + 1, 0))
      if (dfa->edests[cur_node].nelem == 0)

static reg_errcode_t
      if (BE (cur_state == NULL && err != REG_NOERROR, 0))
  int str_idx = sctx->last_str_idx;
static reg_errcode_t merge_state_array (const re_dfa_t *dfa,
	  if (c == 0xf8 && d < 0x88)
	  dst_node = (subexp_len ? dfa->nexts[node]
	case OP_OPEN_SUBEXP:
	    }
static reg_errcode_t
	   away the node `a'.
    free (dest_states);

      /* XXX We have no indication of the size of this buffer.  If this
   string; if REG_NOTEOL is set, then $ does not match at the end.
	      --match_last;
/* Clean the entries which depend on the current input in MCTX.
static re_dfastate_t *transit_state_sb (reg_errcode_t *err,
				       &eps_via_nodes);
{
      new_entry->str_idx = str_idx;

					      &next_nodes);

	  if (BE (err != REG_NOERROR, 0))
	}
    return -1;
			  const re_dfastate_t *state, int idx)
	  /* Optimization, skip if this state doesn't accept the character.  */

	  err2 = check_arrival_expand_ecl (dfa, &new_dests, subexp_num, type);
  if (dest_states_malloced)

    }
  else
  int cache_idx = search_cur_bkref_entry (mctx, bkref_str_idx);
     internal_function;
	  regoff_t *new_end;
    {

	{
      if (BE (*err != REG_NOERROR, 0))
      if (BE (err < 0, 0))
}
      int reg_num = dfa->nodes[cur_node].opr.idx + 1;
	      re_token_type_t type = dfa->nodes[node].type;
#else

static int check_node_accept (const re_match_context_t *mctx,
		     node, don't recurse because it would cause an
   this memory for recording register information.  STARTS and ENDS
    }
      if (dfa->nodes[sub_top->node].opr.idx != subexp_num)
	   const char *string,

      cur_state = re_acquire_state_context (&err, dfa, &next_nodes, context);
  if (top < next_state_log_idx)
internal_function
		if (pin[j] != coll_sym[1 + j])
					    new_dest_nodes);

{

	 E.g. RE: (a){2}  */
		  unsigned num_regs,
  int i;
   FL_LONGEST_MATCH means we want the POSIX longest matching.
  re_free (mctx->sub_tops);

	 the destination of a multibyte char/collating element/
	 transition tables, one starting at trtable[0] and one
	continue; /* This is unrelated limitation.  */
		    && !re_node_set_contains (inv_eclosure, edst2)
  int cur_idx = re_string_cur_idx (&mctx->input);
    str = string1;
  /* TODO: This isn't efficient.
     internal_function;
}
	= ((const unsigned char *) re_string_get_buffer (input) + str_idx);
     If bit N is clear, means that this entry won't epsilon-transition to
static reg_errcode_t

	    }
  reg_errcode_t err = REG_NOERROR;
   least NMATCH elements, and we set them to the offsets of the
  assert (num >= 0);

	  if (mctx->state_log == NULL
static re_dfastate_t *transit_state (reg_errcode_t *err,
	{
  cur_state = acquire_init_state_context (&err, mctx, cur_str_idx);
}
					      int str_idx,
     transit to the last_node and the last_node itself.  */
      /* Then, search for the other last nodes of the sub expression.  */
	  err = check_arrival_expand_ecl (dfa, &next_nodes, subexp_num, type);
					  const re_node_set *nodes)
	  for (i = 0; i < cset->ncoll_syms; ++i)
	  /* If this state isn't a subset of `accepts', create a
     internal_function;
      /* Proceed to next node.  */
#ifdef RE_ENABLE_I18N
	}
      else
  fl_longest_match = (nmatch != 0 || dfa->nbackref);
	      err = REG_ESPACE;
		  break;
	    goto out_free;
	      if (idx > 0)
  assert (state->halt);
internal_function


	      || (cur_state = find_recover_state (&err, mctx)) == NULL)
   starting at index START.
	return dfa->init_state;
      cur_state = re_acquire_state_context (&err, dfa, &next_nodes, context);
  backup_cur_idx = mctx->input.cur_idx;
   Search '(' if FL_OPEN, or search ')' otherwise.
				   dfa->inveclosures + dest_nodes->elems[i]);
      bufp->regs_allocated = re_copy_regs (regs, pmatch, nregs,
   If NMATCH is zero or REG_NOSUB was set in the cflags argument to
      if (!naccepted
      for (dest_node = -1, i = 0; i < edests->nelem; ++i)
#ifdef RE_ENABLE_I18N
      if (mctx->state_log != NULL)
	  if (++cur_str_idx > max)
	    {
{
	    }
  if (mctx->max_mb_elem_len < to - from)
	      else if (fs != NULL
  if (p_match_first)
	       re_dfastate_t *state)

      while (entry++->more);
		  if (bkref_str_off + sl_str_diff > mctx->input.len)
/* Helper functions.  */
	{
	      mctx->state_log[next_idx] = re_acquire_state (&err, dfa,
  /* We need one extra element beyond `num_regs' for the `-1' marker GNU code
	{
	      do
	}
			     const char *string2, int length2,
      reg_errcode_t err;
  if (cache_idx != -1)
	    goto free_return;
      if (ch >= 0x80)
static reg_errcode_t

	  mctx->state_log[to_idx] = re_acquire_state (&err, dfa, &union_set);

     internal_function;
#endif

  const re_dfa_t *const dfa = mctx->dfa;
	  err = extend_buffers (mctx);
	  return err;
#ifdef DEBUG
	  next_node = dfa->nexts[dests_node[i].elems[j]];
	case 6:
      if (!sb && !re_string_first_byte (&mctx.input, 0))
   of the input, or changes the input string.  */

  int i, err;
      /* If the new state has context constraint,
/* Check the limitations of sub expressions LIMITS, and remove the nodes
     internal_function;
  /* Return if we have already checked BKREF_NODE at BKREF_STR_IDX.  */
   The parameter STOP of re_{match,search}_2 specifies that no match exceeding
     we'll never use init_state_nl, so do not check it.  */
      re_node_set dest_nodes, *new_nodes;
      if ((!(dfa->syntax & RE_DOT_NEWLINE) &&
      /* If caller wants register contents data back, copy them.  */
	}
      if (BE (new_array == NULL, 0))
  for (node_idx = 0; node_idx < candidates->nelem; ++node_idx)
	return NULL;
	  if (sctx->limits.nelem)
    {


    re_node_set_free (&except_nodes);
	}
  match_last = mctx->match_last;


/* For all the back references in the current state, calculate the
	  break;
  RE_TRANSLATE_TYPE t = preg->translate;
  mctx->nbkref_ents = 0;
static reg_errcode_t match_ctx_add_subtop (re_match_context_t *mctx, int node,
    {
{
	    }
					 int subexp_num, int type)
      /* The node can accepts `naccepted' bytes.  */
  return free_fail_stack_return (fs);
re_match_2 (struct re_pattern_buffer *bufp,
   delay these checking for prune_impossible_nodes().  */
   License as published by the Free Software Foundation; either
					 re_match_context_t *mctx) internal_function;
	  if (IS_WORD_CONTEXT (context))
			    preg->translate, preg->syntax & RE_ICASE, dfa);
	      bitset_word_t any_set = 0;
	     mask <<= 1, elem >>= 1, ++ch)
  mctx->max_mb_elem_len = 1;
	    }
  if (boundaries == 0)
		 epsilon-transition if the first was already considered.  */
	  sl_str += sl_str_diff;
    }
    return -2;
   entry, and call with STR_IDX which isn't smaller than any existing entry.
{
    { /* Yes.  If we need more elements than were already
      if (NOT_SATISFY_NEXT_CONSTRAINT (node->constraint, context))
}
check_matching (re_match_context_t *mctx, int fl_longest_match,
	  unsigned int in_collseq = 0;
    }
  re_node_set_free (&next_nodes);
       couldn't accept the current input `multi byte'.   */

      cur_state = merge_state_with_log (err, mctx, NULL);
		return err;
	  /* The matched string by the sub expression match with the substring
  re_free (mctx.state_log);
	      if ((!preg->no_sub && nmatch > 1 && dfa->has_plural_match)
internal_function

	      mctx->state_log[dest_str_idx]
	return dfa->init_state_word;
}
      assert (regs_allocated == REGS_FIXED);

	     elem;
			 + ndests * 3 * sizeof (re_dfastate_t *)))
re_exec (s)
  if (str_idx == top_str)
#ifdef DEBUG
  reg_errcode_t err;
	  || !preg->newline_anchor))

  else
internal_function
	}

		re_free (prev_idx_match);
	      not_subset |= remains[k] = ~accepts[k] & dests_ch[j][k];
  reg_errcode_t err;
	 this function is next_state and ERR is already set.  */
	      dest_node = dfa->edests[node].elems[0];
}
	    continue;
		  break;
  while (*err == REG_NOERROR && cur_state == NULL);
	continue;
  int boundaries;
					   &mctx->state_log[to_idx]->nodes);
	      /* This is a non-empty match or we are not inside an optional
set_regs (const regex_t *preg, const re_match_context_t *mctx, size_t nmatch,
	const regex_t *__restrict preg,
	      /* We found a match, do not modify match_first below.  */
      /* Reconstruct the buffers so that the matcher can assume that
			   int last_str_idx)
	  /* It is relatively rare case, then calculate on demand.  */
      else if (c < 0xf8)
	     node in the current state.  */
	    bitset_merge (accepts, dfa->sb_char);
transit_state_sb (reg_errcode_t *err, re_match_context_t *mctx,
weak_function
	  err = REG_ESPACE;

    }
     /* Don't consider this char as a possible match start if it part,
  else
	      ++ndests;
      if (BE (ret != REG_NOERROR, 0))
internal_function
	  /* At first, add the nodes which can epsilon transit to a node in
	    {
  if (preg->no_sub)
  bitset_empty (accepts);

	{
	  d = re_string_byte_at (input, str_idx + i);
extend_buffers (re_match_context_t *mctx)
      /* If (state_log[cur_idx] != 0), it implies that cur_idx is
   concerned.
		  /* Not enough chars for a successful match.  */
	 later.  We must check them here, since the back references in the
		  re_node_set_free (&union_set);
	{
    }
	  dst[st_idx] = re_acquire_state (&err, dfa, &merged_set);
  ch = re_string_byte_at (&mctx->input, idx);
	    assert (mctx.input.offsets_needed == 0);
static int


  rval = re_search_stub (bufp, str, len, start, range, stop, regs, ret_len);
					  mctx->eflags);
	}
check_dst_limits_calc_pos_1 (const re_match_context_t *mctx, int boundaries,
      for (sl_idx = 0; sl_idx < top->nlasts; ++sl_idx)
	    {
  if (BE (length1 < 0 || length2 < 0 || stop < 0, 0))
    }
  re_dfastate_t **backup_state_log;
	      err = re_node_set_init_copy (&union_set,
  local_sctx.sifted_states = NULL; /* Mark that it hasn't been initialized.  */
      const re_token_t *node = dfa->nodes + cls_node;
	    /* k-th destination accepts newline character.  */
      mctx->state_log[str_idx] = cur_state;
	  if (BE (match_last == -2, 0))
      {
	    }

	}
  re_dfastate_t **sifted_states;
      mctx->state_log[str_idx] = cur_state;
pop_fail_stack (struct re_fail_stack_t *fs, int *pidx, int nregs,
	    {
	}
	}
internal_function
static reg_errcode_t
  mctx->input.cur_idx = backup_cur_idx;
		}
     3. When 0 <= STR_IDX < MATCH_LAST and 'a' epsilon transit to 'b':
		}
	    continue;
      if (BE (cur_state == NULL && err != REG_NOERROR, 0))
	{
	  if (BE (elem & 1, 0))
					  re_node_set *limits,
  if (fs->stack[num].regs == NULL)
   is START + RANGE.  (Thus RANGE = 0 forces re_search to operate the same
		;
  ndests = group_nodes_into_DFAstates (dfa, state, dests_node, dests_ch);
	  nregs = 1;
	      int dest_node;
  /* Check if the DFA haven't been compiled.  */
		}
internal_function
#ifdef DEBUG
    {
static void
  int left_lim, right_lim, incr;
    }
      cur_node = dfa->edests[cur_node].elems[0];
	  if (constraint & NEXT_NOTWORD_CONSTRAINT)
	    break;
{
  for (i = 0; i < pstate->nodes.nelem; ++i)

     closure.  */
    re_free (prev_idx_match);

		for (j = 0; j < BITSET_WORDS; ++j)
      int node_idx = nodes->elems[i];
#endif /* RE_ENABLE_I18N */
	  if (sctx->limited_states != NULL)
	    }

	}
      int cur_node = state->nodes.elems[node_cnt];
	  break;
  if (BE (path->alloc < last_str + mctx->max_mb_elem_len + 1, 0))
		}
	      if (match_first < left_lim || match_first > right_lim)
      if (!cset->non_match)
	      re_node_set_free (&eps_via_nodes);
  re_node_set_free (&cur_dest);
		for (j = 0; j < BITSET_WORDS; ++j)
    }
internal_function
  sctx->sifted_states = sifted_sts;
weak_alias (__re_match_2, re_match_2)
	      /* We know we are going to exit.  */
   Then for all destinations, set the nodes belonging to the destination
		  continue;
		break; /* We found a match.  */
				     const re_sub_match_top_t *sub_top,
	{
      new_entry = re_realloc (mctx->bkref_ents, struct re_backref_cache_entry,
  /* At first, group all nodes belonging to `state' into several
   Rules: We throw away the Node `a' in the STATE_LOG[STR_IDX] if...
      else if (c < 0xfe)
	}
#endif
				       str_idx + 1);
  mctx->match_last = match_last;
      if (BE (err != REG_NOERROR, 0))
     We build the next sifted state on `cur_dest', and update
    }
	 state.  Above, we make sure that accepts is not empty.  */
  /* Then decide the next state with the single byte.  */
    }

  /* Else, examine epsilon closure.  */
      else if (IS_BEGBUF_CONTEXT (context) && IS_NEWLINE_CONTEXT (context))
      else
		    int eflags)
					       cur_str_idx);
#else
	      return REGS_UNALLOCATED;
	size_t nmatch,
  /* Temporary modify MCTX.  */
  int i, j, ch, need_word_trtable = 0;
    return REG_BADPAT;
  re_match_context_t mctx;
	  const unsigned char *weights, *extra;
  return err;
static reg_errcode_t transit_state_bkref (re_match_context_t *mctx,
		    continue;
    (fastmap
		       sub_last->str_idx, bkref_node, bkref_str,
#ifdef _LIBC
  /* First, free all the memory associated with MCTX->SUB_TOPS.  */
      err = re_node_set_alloc (&state->inveclosure, dest_nodes->nelem);
    {
		return -1;
	}
      if (type == OP_BACK_REF)
	}
	build_wcs_buffer (pstr);
	  regs = NULL;
			   int ret_len);
#endif /* RE_ENABLE_I18N */
    {
		   well, like in ((a?))*.  */
}
					  int str_idx) internal_function;
	      pmatch[reg_idx + 1].rm_so
    return 1;
	    return NULL;
#endif
  mctx->state_log = backup_state_log;
		      : dfa->edests[node].elems[0]);
	      if (!fl_longest_match)
    {
      int enabled_idx;

     internal_function;
				    subexp_num, type);
		  int range, struct re_registers *regs,
	  err = get_subexp_sub (mctx, sub_top, sub_last, bkref_node,
	    we throw away the node `a'.  */
static int
					      cls_node))
      err = re_string_reconstruct (&mctx.input, match_first, eflags);

	{
	return match_len;
					  const re_node_set *candidates,
  mctx->input.cur_idx = str_idx;
	  if (BE (err != REG_NOERROR, 0))
    {
internal_function
      /* Pick up a valid destination, or return -1 if none is found.  */
}
/* Register the node NODE, whose type is OP_OPEN_SUBEXP, and which matches
  ((state) != NULL && re_node_set_contains (&(state)->nodes, node))
	}
					 mctx->bkref_ents, str_idx);
	  if (fs)
#else
  return new_entry;
			      naccepted) != 0)
	  && (dfa->used_bkref_map
    re_node_set dests_node[SBC_MAX];
      int node = cur_nodes->elems[node_idx];
	  break;
      if (BE (mctx->state_log[dest_idx] == NULL && err != REG_NOERROR, 0))
		goto free_return;
	{
	  if (mctx->state_log[to_idx])

    {
    match_ctx_free (&mctx);
	(re_dfastate_t **) calloc (sizeof (re_dfastate_t *), 2 * SBC_MAX);
	{
		  mctx.last_node = check_halt_state_context (&mctx, pstate,
	  re_node_set_free (&cur_dest);
	{
	  err = check_subexp_matching_top (mctx, &cur_state->nodes, 0);
      /* Add all the nodes which satisfy the following conditions:
   can only accept one byte.  */
}
	memcpy (s + length1, string2, length2);
  assert (mctx->asub_tops > 0);
	return dfa->init_state_begbuf;
		if (extra[idx + mbs_cnt] != mbs[mbs_cnt])
internal_function
		    ? re_string_wchar_at (input, str_idx) : 0);
{
		 int nregs, regmatch_t *regs, re_node_set *eps_via_nodes)
  /* Concatenate the strings.  */
	  wchar_t cmp_buf[] = {L'\0', L'\0', L'\0', L'\0', L'\0', L'\0'};
		  regmatch_t pmatch[], int eflags)
	  err = match_ctx_add_subtop (mctx, node, str_idx);
     destinations.  */
  bitset_t acceptable;
	    }
		     is ()\1*\1*  */

		    }
	    goto check_node_accept_bytes_match;
	      err = REG_ESPACE;
      if (BE (err != REG_NOERROR, 0))
	    return 0;
	{
	      /* We found an appropriate halt state.  */
	      if (*coll_sym != elem_len)
				   str_idx, dst_node, to_idx))
	  err = REG_ESPACE;
		{
	  pmatch[nmatch + reg_idx].rm_so = -1;
	{
	  table_nodes = next_state->entrance_nodes;
	  re_node_set_free (&follows);
#endif /* _REGEX_RE_COMP */
  ret = REG_NOERROR;
	      ch = match_first >= length
	}
      else
	    {
		     destination node is the same node as the source
  if (n > 0)
  int left, right, mid, last;
  if (!constraint)

#endif /* RE_ENABLE_I18N */
	  ret = build_wcs_upper_buffer (pstr);
    prev_idx_match = (regmatch_t *) alloca (nmatch * sizeof (regmatch_t));
	  if (fs && (*pidx > mctx->match_last || mctx->state_log[*pidx] == NULL


   mingings with regexec.  START, and RANGE have the same meanings
		  any_set |= (accepts[j] &= ~dfa->word_char[j]);
  if (prev_idx_match_malloced)
}
			       match_last + 1);
static reg_errcode_t extend_buffers (re_match_context_t *mctx)
		  if (BE (err != REG_NOERROR, 0))
	  if (BE (dest_states_word[i] == NULL && err != REG_NOERROR, 0))
      if (node->type == type
  /* Then check each states in the state_log.  */
	{
	{
    case OP_UTF8_PERIOD:
static reg_errcode_t
    return err;
  if (BE (err != REG_NOERROR, 0))
      subtop->lasts = new_array;

      /* Note: We already add the nodes of the initial state,
      if (BE (mctx.state_log == NULL, 0))
      else

   computed relative to the concatenation, not relative to the individual
	}
					   subexp_idx, src_node, src_idx,
	      ret = re_node_set_insert (&union_set, next_node);

	      re_node_set_free (&new_nodes);
		 the length of current collating element.  */
	case 8:
static int
  sb = dfa->mb_cur_max == 1;
      return UINT_MAX;
  return check_dst_limits_calc_pos_1 (mctx, boundaries, subexp_idx,
	  if (dfa->syntax & RE_DOT_NOT_NULL)

				  dfa->nexts[prev_node]))
   If STATE can accept a multibyte char/collating element/back reference
find_recover_state (reg_errcode_t *err, re_match_context_t *mctx)
	      re_node_set_free (&next_nodes);
    }
static reg_errcode_t
      const unsigned char *extra = (const unsigned char *)
	      return err;
	    }
int
      assert (dfa->nexts[cur_node_idx] != -1);
#endif
		     || !re_node_set_contains (&mctx->state_log[*pidx]->nodes,
  wint_t wc;
  err = re_node_set_alloc (&follows, ndests + 1);
check_subexp_limits (const re_dfa_t *dfa, re_node_set *dest_nodes,

	{
   to DESTS_NODE[i] and set the characters accepted by the destination
	    {

static reg_errcode_t
  if (BE (cur_state == NULL, 0))
	  err = re_node_set_merge (&next_nodes,
		{

  {
	  /* This #include defines a local function!  */
	}
    }
	    }
static reg_errcode_t free_fail_stack_return (struct re_fail_stack_t *fs)
  mctx->asub_tops = n;
#ifdef RE_ENABLE_I18N

    return REG_NOERROR;
						   int type) internal_function;
{
  if (str_idx == top_str || (cur_state && cur_state->has_backref))
	  context = re_string_context_at (&mctx->input, dest_str_idx - 1,
      null_cnt = cur_state == NULL ? null_cnt + 1 : 0;
	 character, or we are in a single-byte character set so we can
   way as re_match().)
{
	return dfa->init_state_nl;
  return REG_NOMATCH;
		{
  int src_bkref_idx = search_cur_bkref_entry (mctx, src_idx);
		}

  /* Then build the states for all destinations.  */
	{
  int len = length1 + length2;
	}
	  /* There are no problematic nodes, just merge them.  */
      }
    }
		}
	  naccepted = regs[subexp_idx].rm_eo - regs[subexp_idx].rm_so;
#ifdef DEBUG
	    {
	  local_sctx.last_node = node;
      else
/* Check whether the node TOP_NODE at TOP_STR can arrive to the node

/* Entry points for GNU code.  */
      if (idx == pmatch[0].rm_eo && cur_node == mctx->last_node)
  fs->stack[num].regs = re_malloc (regmatch_t, nregs);
	  if ((boundaries & 2) && subexp_idx == dfa->nodes[node].opr.idx)
	 starting at trtable[SBC_MAX].  */
	    {
  if (str_idx < lim->subexp_from)
	    pmatch[reg_idx].rm_so += match_first;
		  int subexp_idx, int type)

		    && !re_node_set_contains (dfa->eclosures + node,
      for (j = 0; j < ndests; ++j)
{
	    return (elem_len > char_len) ? elem_len : char_len;
    {
	continue; /* This is unrelated limitation.  */
{
	if (wc == cset->mbchars[i])
      int to_idx, next_node;
	      re_node_set_free (&next_nodes);
	 evaluated.  */
	      err = re_node_set_insert (dst_nodes, cur_node);
						 dfa->inveclosures + cur_node);



    {
}
   REG_NOTBOL is set, then ^ does not match at the beginning of the
    }

		    return err;
    }
      else if (IS_BEGBUF_CONTEXT (context))
   with lengths LENGTH1 and LENGTH2, respectively.

	  struct re_registers *regs)
		    {
	  return re_acquire_state_context (err, dfa,

/* Extend the buffers, if the buffers have run out.  */
   to DEST_CH[i].  This function return the number of destinations.  */
      mctx->max_mb_elem_len = ((mctx->max_mb_elem_len < naccepted) ? naccepted
	  if (fs)
   and return the index where the matching end, return -1 if not match,
  unsigned char ch;
	  if (BE (err != REG_NOERROR, 0))
		{
						re_node_set *cur_nodes,

  err = REG_NOERROR;
	{
  if (err != REG_NOERROR)
{
#ifdef _LIBC
      mctx.state_log_top = mctx.nbkref_ents = mctx.max_mb_elem_len = 0;
		_NL_CURRENT (LC_COLLATE, _NL_COLLATE_EXTRAMB);

	    {
*/
	  if (d < 0x80 || d > 0xbf)
	      && mctx->input.valid_len < mctx->input.len))
	{
      else if (type == OP_UTF8_PERIOD)
  re_dfastate_t *state = re_acquire_state (&err, dfa, dest_nodes);
  int result;
static void match_ctx_free (re_match_context_t *cache) internal_function;
static reg_errcode_t
      for (i = 0; i < cset->nchar_classes; ++i)
	}
	      if (mbs_cnt == elem_mbs_len)
	}
	}
		  if (BE (err != REG_NOERROR, 0))
      if (dfa->subexp_map)
  if (BE (err != REG_NOERROR, 0))
	  goto free_return;
	  if (BE (err != REG_NOERROR, 0))
    return 1;
	    continue;
      err = extend_buffers (mctx);
	      if (accepts_newline)
  re_string_skip_bytes (&mctx->input, 1);
/* This function checks the STATE_LOG from the SCTX->last_str_idx to 0
  to_idx = bkref_str + sub_last->str_idx - sub_top->str_idx;
		    return err;
		      re_node_set_free (&union_set);
	    }
	  else
}
      free (top);
				     re_match_context_t *mctx,

	      sizeof (struct re_backref_cache_entry) * mctx->abkref_ents);
#ifdef RE_ENABLE_I18N
  reg_errcode_t ret;
			      length, 0, NULL, eflags);
      dest_states = (re_dfastate_t **)
      if (dfa->nodes[cur_node].type == type

  reg_errcode_t err;
	      if (re_node_set_contains (&mctx->state_log[to_idx]->nodes,



update_cur_sifted_state (const re_match_context_t *mctx,
	  new_dest_nodes = (subexp_len == 0
      if (fs->stack == NULL)
					    re_node_set *dest_nodes,
					   cls_node)
      if (sctx->limits.nelem)
    }
# endif
  /* An initial state must not be NULL (invalid).  */
      if (BE (new_array == NULL, 0))
		if (BE (err != REG_NOERROR, 0))
    }
	{
      || (next_state_log_idx >= mctx->input.valid_len
  int free_str = 0;

	    {
#endif
	= re_acquire_state_context (err, dfa, &next_nodes, context);
acquire_init_state_context (reg_errcode_t *err, const re_match_context_t *mctx,
      bkref_str_off = bkref_str_idx;
      err = update_cur_sifted_state (mctx, sctx, str_idx, &cur_dest);
internal_function
  int i;
	  /* Enumerate the intersection set of this state and `accepts'.  */
	  /* We need to check recursively if the backreference can epsilon
  return REG_NOERROR;
  for (i = 0; i < nodes->nelem; ++i)
{
			: mctx->state_log[cur_str_idx]->nodes.nelem);
      rval = -2;

		int node = dest_nodes->elems[node_idx];
/* Initialize MCTX.  */
		  {
      re_node_set *cur_nodes = &mctx->state_log[*pidx]->nodes;

  return regexec (preg, string, nmatch, pmatch,
		  regoff_t *ends)
    }
	  if (!(dfa->syntax & RE_DOT_NEWLINE))
static reg_errcode_t
  pmatch = re_malloc (regmatch_t, nregs);
		continue;
					 int start, int range, int stop,
#ifdef RE_ENABLE_I18N
		}
		  goto free_return;
  int i;
#endif
	  re_node_set_free (&new_dests);
		    return -1;
   corresponding to the DFA).
      re_token_type_t type;
  naccepted = check_node_accept_bytes (dfa, node_idx, &mctx->input, str_idx);
  assert (match_last != -1);

	  if (fs != NULL)
  re_dfastate_t *cur_state = NULL;
	      int next_idx = str_idx + naccepted;
	    {
    reg_errcode_t err;
	  {
   If it can arrive, register the sub expression expressed with SUB_TOP
/* Set REGS to hold NUM_REGS registers, storing them in STARTS and
/* Register the node NODE, whose type is OP_CLOSE_SUBEXP, and which matches
  return re_search_stub (bufp, string, length, start, 0, length, regs, 1);
  for (i = 0; i < cur_src->nelem; i++)
		      && !(ent->eps_reachable_subexps_map
	      int node = dest_nodes->elems[node_idx];
      if (!re_node_set_contains (cur_nodes, ent->node))
	    {

     else
	 See update_cur_sifted_state().  */
	      err = re_node_set_init_copy (&local_sctx.limits, &sctx->limits);
		bitset_set (accepts, NEWLINE_CHAR);

 free_return:
static reg_errcode_t check_arrival (re_match_context_t *mctx,
}
	    break;
				      re_node_set *eps_via_nodes)
      context = re_string_context_at (&mctx->input, idx - 1, mctx->eflags);
  __libc_lock_unlock (dfa->lock);
	    }
static reg_errcode_t
    }
    {
	 find a plausible place to start matching.  This may be done

#ifdef RE_ENABLE_I18N
     internal_function;
      else if (src[st_idx] != NULL)
    }
	{
    {
re_search_2 (struct re_pattern_buffer *bufp,
	      if (dfa->word_char[i] & mask)
	{
    {
      enabled_idx = first_idx;
			       OP_CLOSE_SUBEXP);
	naccepted = sift_states_iter_mb (mctx, sctx, prev_node,
	  {
				      int bkref_idx) internal_function;
	/* Must not happen?  */
		  ret = REG_NOMATCH;
      re_node_set_empty (&next_nodes);
	     mask <<= 1, elem >>= 1, ++ch)
	}
  const re_node_set *candidates;
	  next_state = mctx->state_log[cur_idx];
      nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
	 build appropriate states for these contexts.  */
}
/* Internal entry point.  */
	  return 0;

	  not_subset = not_consumed = 0;
      int subexp_idx;
	    }
	  if (not_subset)
  int rval = REGS_REALLOCATE;
		: &mctx->state_log[str_idx]->nodes);
	  if (BE (err != REG_NOERROR, 0))
#ifdef _LIBC
	_NL_CURRENT (LC_COLLATE, _NL_COLLATE_SYMB_EXTRAMB + 1) - extra;
}
	if (BE (s == NULL, 0))
		_NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);

	  if (subexp_len == 0

re_search_2_stub (struct re_pattern_buffer *bufp,
      return 0;
  int type = dfa->nodes[cur_node].type;
	    }
	  if (bkref_idx != -1)
      for (reg_idx = 0; reg_idx < extra_nmatch; ++reg_idx)
  int fl_longest_match, match_first, match_kind, match_last = -1;
		for (j = 0; j < BITSET_WORDS; ++j)
	    {
		  any_set |= (accepts[j] &= (dfa->word_char[j] | ~dfa->sb_char[j]));
      ent = mctx->bkref_ents + limits->elems[lim_idx];

      mctx->sub_tops = re_malloc (re_sub_match_top_t *, n);
# endif /* _LIBC */
/* Acquire an initial state and return it.

	      for (j = 0; j < *coll_sym; j++)
	    continue;
