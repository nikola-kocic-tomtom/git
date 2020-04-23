	    {
{
      }
	}

    REG_ESUBREG_IDX,
  reg_errcode_t err;
  preg->buffer = NULL;
#endif /* RE_ENABLE_I18N */

    {
      break;
	  *err = REG_EBRACK;

		 use it to avoid infinite loop.  */
{
			     &state) == p - buf
  bin_tree_t *node, *prev;
     `buffer' to the compiled pattern;
	  /* Check the space of the arrays.  */


      int new_char_class_alloc = 2 * mbcset->nchar_classes + 1;
      case COMPLEX_BRACKET:
	  dfa->nodes[node].type = OP_UTF8_PERIOD;
     EQUIV_CLASS_ALLOC is the allocated size of mbcset->equiv_classes,

	return err;

    case OP_DUP_ASTERISK:
	    mbcset->range_starts = new_array_start;
      !re_string_first_byte (input, re_string_cur_idx (input)))
static void
    {
      token->type = OP_PERIOD;
    old_tree = NULL;
{
		  /* Yep, this is the entry.  */
		     == weights[(idx2 & 0xffffff) + 1 + cnt])
      (*p_new)->token.duplicated = 1;
    goto parse_dup_op_espace;
      wctype_t *new_char_classes = re_realloc (mbcset->char_classes, wctype_t,
}
{
  const unsigned char *collseqmb;
duplicate_node_closure (re_dfa_t *dfa, int top_org_node, int top_clone_node,

   are set in BUFP on entry.  */
	    }

	re_node_set_free (dfa->inveclosures + i);
	  /* See if we have to try all bytes which start multiple collation

   tmp[0] = c;
	case '=':
  if (BE (ret != REG_NOERROR, 0))

	      break;
					  re_token_t *token);
      free_charset (mbcset);
btowc (int c)
  {
/* Pass 1 in building the NFA: compute FIRST and create unlinked automaton
      int *elems = dfa->eclosures[src].elems;

    BUILD_CHARCLASS_LOOP (isalpha);
  mbcset = (re_charset_t *) calloc (sizeof (re_charset_t), 1);
#if !defined(__GNUC__) || __GNUC__ < 3

	  if (!(syntax & RE_LIMITED_OPS) && (syntax & RE_BK_PLUS_QM))
      re_token_t token2;
      token_len = peek_token_bracket (token, regexp, syntax);
#ifdef _LIBC
	{
  if (BE (*err != REG_NOERROR && tree == NULL, 0))
	  if (dfa->nodes[node].opr.sbcset[i])
	if (dfa->nodes[node].opr.c >= 0x80)
static bin_tree_t *create_tree (re_dfa_t *dfa,
    start_ch = ((start_elem->type == SB_CHAR ) ? start_elem->opr.ch
  int icase = (dfa->mb_cur_max == 1 && (bufp->syntax & RE_ICASE));
    }
      end_collseq = lookup_collation_sequence_value (end_elem);
  re_free (cset->mbchars);
		*err = REG_BADBR;
     registers.
	    {
      token->type = OP_DUP_ASTERISK;
      br_token.type = SIMPLE_BRACKET;
      else if (br_elem->type == MB_CHAR)
	{
internal_function

  /* Try to allocate space for the fastmap.  */
	      *err = REG_EBRACK;
   Copyright (C) 2002-2007,2009,2010 Free Software Foundation, Inc.
}

      fastmap = re_comp_buf.fastmap;
	    {
      bin_tree_t *mbc_tree;
  re_token_t current_token;
wchar_t 
	     destination of the node.  */
static reg_errcode_t calc_next (void *extra, bin_tree_t *node);
      if (!(syntax & RE_LIMITED_OPS) && !(syntax & RE_BK_PLUS_QM))
	      *p++ = dfa->nodes[node].opr.c;
{
      end = 0;
  dfa->has_mb_node = dfa->nbackref > 0 || has_period;
static bin_tree_t *
      *err = ret;
  ret = postorder (dfa->str_tree, lower_subexps, preg);
{
		   int *equiv_class_alloc, const unsigned char *name)
      if (ch == delim && re_string_peek_byte (regexp, 0) == ']')
    {
     const char *s;
# else
	  if (nrules == 0)
	{
	  if (BE (*coll_sym_alloc == mbcset->ncoll_syms, 0))
static void
		: ((start_elem->type == COLL_SYM) ? start_elem->opr.name[0]
static void

  preg->buffer = NULL;
	      *err = build_collating_symbol (sbcset,
      re_free (sbcset);
static bin_tree_t *parse_branch (re_string_t *regexp, regex_t *preg,
/* re_compile_pattern is the GNU regular expression compiler: it
    }
  cls = create_tree (dfa, NULL, NULL, OP_CLOSE_SUBEXP);
	{
      token->type = ANCHOR;
	    }
      if (BE (tree == NULL, 0))

	      memset (&state, '\0', sizeof (state));
	  if (BE (tree_first == NULL || tree_last == NULL || tree == NULL, 0))
  re_free (dfa->state_table);
    }
  return err;

		  memset (&mbs, 0, sizeof (mbs));
  unsigned int table_size;
build_charclass (RE_TRANSLATE_TYPE trans, bitset_t sbcset,
	    re_node_set_free (&eclosure_elem);
    goto re_compile_internal_free_return;
		{
	  break;
	  work_tree = create_tree (dfa, work_tree, mbc_tree, OP_ALT);
	  /* Then join them by ALT node.  */
	memcpy (errbuf, msg, msg_size);
#ifdef RE_ENABLE_I18N
    right->parent = tree;
	if (dfa->eclosures[edest].nelem == -1)
	 enough space.  This loses if buffer's address is bogus, but
       /   \
      unsigned char end_name_buf[BRACKET_NAME_BUF_SIZE];

						   _NL_COLLATE_SYMB_EXTRAMB);
		wint_t wch = __btowc (ch);
	    new_array_end = re_realloc (mbcset->range_ends, wchar_t,
    }
  /* Local function for parse_bracket_exp used in _LIBC environment.
}
   pointer argument since we may update it.  */
# ifdef _LIBC
    {

#endif
    }
#ifdef RE_ENABLE_I18N
	assert (right > -1);
    bitset_set (sbcset, *extra);
      else if (type == COMPLEX_BRACKET)
# ifdef _LIBC
static int
      syntax &= ~RE_DOT_NEWLINE;


	    }
      dfa->nexts[idx] = node->next->node_idx;
      break;
	  if (idx2 == 0)
    {
static int
      re_free (storage);
      (void) peek_token_bracket (&token2, regexp, syntax);
    case ANCHOR:
#ifdef RE_ENABLE_I18N
	  incomplete = 0;

      *err = REG_ESPACE;
	  if (syntax & RE_CHAR_CLASSES)
		if (isascii (ch) && wch != ch)
    "\0"
	      if (BE (mbc_remain == NULL || tree == NULL, 0))

  dfa->str_tree = parse (&regexp, preg, syntax, &err);
	      if (!node)
  return (char *) gettext (__re_error_msgid + __re_error_msgid_idx[(int) ret]);
  while (1)
      elem->type = MB_CHAR;
  if (token->type == OP_OPEN_COLL_ELEM || token->type == OP_OPEN_CHAR_CLASS
  re_node_set_free (&init_nodes);
      exp = parse_expression (regexp, preg, token, syntax, nest, err);
     is a pointer argument since we may update it.  */
# endif /* not RE_ENABLE_I18N */
#endif /* RE_ENABLE_I18N */
  /* Analyze the tree and create the nfa.  */
  {
	    incomplete = 1;
	      return REG_NOERROR;
	    {
	token->type = OP_CLOSE_SUBEXP;
	  while (node->right == prev || node->right == NULL)

	     it must not be "<ANCHOR(^)><REPEAT(*)>".  */
  fetch_token (&current_token, regexp, syntax | RE_CARET_ANCHORS_HERE);
	      /* We found the entry.  */

	for (clexp_idx = 0; clexp_idx < init_nodes.nelem; ++clexp_idx)
			 reg_syntax_t syntax);

   Build the collating element which is represented by NAME.
  collseqmb = (const unsigned char *)
  dfa->str_tree = NULL;
#endif /* RE_ENABLE_I18N */
     * Fedora Core 2, maybe others, have broken `btowc' that returns -1
    {
	      /* +1 in case of mbcset->nranges is 0.  */
      first_round = 0;
  __attribute ((always_inline))
      if (dfa->edests != NULL)
    case OP_WORD:
  for (org_node = top_org_node, clone_node = top_clone_node;;)
  if (dfa->subexp_map != NULL)
				 bin_tree_t *node);
	      && strlen ((char *) end_elem->opr.name) > 1), 0))
      /* Build a tree for simple bracket.  */
	  clone_dest = duplicate_node (dfa, org_dest, constraint);
		  return NULL;
	    {
			     syntax & RE_ICASE, dfa);

    {
  /* Initialize the pattern buffer.  */

}
	      *err = ret;
	int left, right;
  re_compile_fastmap_iter (bufp, dfa->init_state, fastmap);
	  memset (fastmap, '\1', sizeof (char) * SBC_MAX);
		    goto parse_bracket_exp_espace;
	  break;
static reg_errcode_t calc_inveclosure (re_dfa_t *dfa);
	}
	bitset_set (sbcset, '\n');
   Parse the regular expression REGEXP and return the structure tree.
  return REG_NOERROR;
				   unsigned int constraint);
	  if (next.type != OP_ALT && next.type != OP_CLOSE_SUBEXP)
	  dfa->nexts[clone_node] = dfa->nexts[org_node];

  if (tree != NULL)
  tree->token.opr.idx = cur_nsub;
static bin_tree_t *parse_dup_op (bin_tree_t *dup_elem, re_string_t *regexp,

/* Initialize DFA.  We use the length of the regular expression PAT_LEN
      dfa->nodes[dup_idx].duplicated = 1;
      table_size = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_SYMB_HASH_SIZEMB);
	  ret = parse_bracket_element (&end_elem, regexp, &token2, token_len2,
	    bitset_set (sbcset, i);		\
}
    case OP_OPEN_COLL_ELEM:
    REG_ERPAREN_IDX

    "\0"
		}
	  	utf8_sb_map_inited = 0;


  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
    /* see comments above */
      /* Go to the left node, or up and to the right.  */
}
  if (node->left && node->left->token.type == SUBEXP)

    return REG_ECTYPE;
  else if (strcmp (class_name, "space") == 0)
{
	  break;
      unsigned char c2;
				 "space",

	}
	     edests of the back reference.  */
      if (dfa->nodes[org_node].type == OP_BACK_REF)
      if (br_elem->type == SB_CHAR)
			reg_syntax_t syntax) internal_function;
  else
      /* Got valid collation sequence values, add them as a new entry.

	node->left->parent = node;
    "\0"
{
  re_free (cset->coll_syms);
      if (dfa->eclosures[node_idx].nelem == 0)
  /* Check the space of the arrays.  */

   re_search_internal to map the inner one's opr.idx to this one's.  Adjust

  if (BE (token->type == OP_CHARSET_RANGE, 0) && !accept_hyphen)
						   _NL_COLLATE_EXTRAMB);
      else
      if (node->right)
#ifdef RE_ENABLE_I18N
	  {
						   new_coll_sym_alloc);
      if (is_range_exp == 1)
	{
  switch (token->type)
/* Returns a message corresponding to an error code, ERRCODE, returned
	  if (BE (ret < 0, 0))
#if __GNUC__ >= 3
		  /* Skip the byte sequence of the collating element.  */
  /* The search can be in single byte locale.  */
  if (dfa->mb_cur_max > 1)
   such as [:<character_class>:], [.<collating_element>.], and
  if ((syntax & RE_ICASE)
      bitset_set (sbcset, name[0]);
	   return intermediate result.  */
	 bitset_t sbcset;
  if (ret == REG_ERPAREN)
  dfa->subexp_map = re_malloc (int, preg->re_nsub);
       that we build below suffices.  parse_bracket_exp passes
	  p_new = &dup_node->left;
  if (BE (err != REG_NOERROR, 0))
	 re_charset_t *mbcset;
						     CONTEXT_NEWLINE);
    }
  for (; *extra; extra++)
#define BRACKET_NAME_BUF_SIZE 32
	  /* Invalid sequence.  */
  int dup_idx = re_dfa_add_node (dfa, dfa->nodes[org_idx]);

      if (syntax & RE_CONTEXT_INVALID_OPS)
/* Entry points for GNU code.  */
	*err = REG_EPAREN;
	ch = re_string_fetch_byte_case (regexp);
    }
  preg->translate = NULL;
	  right = node->next->node_idx;
      /* Do not check for ranges if we know they are not allowed.  */
	      if (BE (*err != REG_NOERROR, 0))
	    && dfa->nodes[node].opr.c >= 0x80)
  preg->re_nsub = 0;
#endif
  if (dfa->init_state->has_constraint)
				  re_token_t *token, reg_syntax_t syntax,
		  /* Skip the wide char sequence of the collating element.  */
	 |
    {
   Assumes the `allocated' (and perhaps `buffer') and `translate' fields
	      while (++node < dfa->nodes_len
      /* Equivalence Classes and Character Classes can't be a range
#ifdef _LIBC
  int non_match = 0;
	  if (! utf8_sb_map_inited)
	case ')':
      {
{
  if (BE (tree == NULL, 0))
#define REG_BADRPT_IDX	(REG_ESPACE_IDX + sizeof "Memory exhausted")
  bin_tree_storage_t *storage, *next;
	  org_dest = dfa->edests[org_node].elems[0];
      if (BE (err != REG_NOERROR, 0))
    return ret;
  /* An epsilon closure includes itself.  */
	if (dfa->eclosures[edest].nelem == 0)
  /* In case of REG_ICASE "upper" and "lower" match the both of
  reg_errcode_t err = REG_NOERROR;
	}
	  token_len = peek_token_bracket (token, regexp, syntax);
int


  int alloc = 0;
 typedef long intptr_t;
	  size_t sym_name_len = strlen ((char *) br_elem->opr.name);
	    }


      }
static reg_errcode_t calc_eclosure (re_dfa_t *dfa);
	{
/* Calculate epsilon closure of NODE.  */
							 | CONTEXT_BEGBUF);
	  node = node->left;
	       goto parse_bracket_exp_free_return;
	      node = node->parent;
	      /* There is a duplicated node which satisfies the constraint,
      case OP_PERIOD:
    }
  size_t cur_nsub;
	{
      {
re_set_syntax (reg_syntax_t syntax)
      if (dfa->mb_cur_max > 1)
   defined in regex.h.  We return the old syntax.  */
/* Create initial states for all contexts.  */
	      return REG_ESPACE;
	  work_tree = mbc_tree;
				      mbcset, &char_class_alloc,
      if (dfa->is_utf8)

      if (BE (msg_size > errbuf_size, 0))
#else
	{

}


	      for (j = 0; j < BITSET_WORD_BITS; ++j, ++ch)
	  tree = create_tree (dfa, tree_first, tree_last, OP_ALT);
      dfa->has_mb_node = 1;
#ifdef _LIBC
      syntax |= RE_HAT_LISTS_NOT_NEWLINE;
  /* Allocate arrays.  */

{
/* This is intended for the expressions like "a{1,3}".
	      re_string_skip_bytes (regexp, token_len); /* Skip '-'.  */
}
    }
   them unless specifically requested.  */
	      if (BE (new_array_start == NULL || new_array_end == NULL, 0))
	   void *extra)
	}
    case '|':
	}
	      else
      return REG_ERANGE;

    for (i = 0; i < init_nodes.nelem; ++i)
      if (*p_new == NULL)
      bin_tree_storage_t *storage = re_malloc (bin_tree_storage_t, 1);
/* Create a tree node.  */
    dfa->is_utf8 = 1;
optimize_subexps (void *extra, bin_tree_t *node)
/* If it is possible to do searching in single byte encoding instead of UTF-8
	      bitset_set (sbcset, start_elem.opr.ch);
   ALT means alternative, which represents the operator `|'.  */
	  if (BE (ret != REG_NOERROR, 0))
  if (left != NULL)
#ifdef RE_ENABLE_I18N
      return 0;
      dfa->init_state_nl = re_acquire_state_context (&err, dfa, &init_nodes,
  if (token->type == OP_NON_MATCH_LIST)
}


#endif
	  !(syntax & RE_UNMATCHED_RIGHT_PAREN_ORD))
  while (1)
	{
      tree = parse_bracket_exp (regexp, dfa, token, syntax, err);
	 bitset_t sbcset;
	    }
	      if (BE (ret < 0, 0))

    }
	default:

  return REG_NOERROR;
/* regcomp takes a regular expression as a string and compiles it.
		       re_token_t *token, int token_len, re_dfa_t *dfa,
  re_free (preg->translate);
			 char *fastmap)
link_nfa_nodes (void *extra, bin_tree_t *node)
				bin_tree_t *left, bin_tree_t *right,
      unsigned char c2;
    BUILD_CHARCLASS_LOOP (isalnum);
    case CHARACTER:
	  *err = build_range_exp (sbcset, &start_elem, &end_elem);
    return REG_EBRACK;
		  /* Not enough, realloc it.  */
    {

/* This function build the following tree, from regular expression a*:
  int token_len;
  elem->opr.ch = token->opr.c;
#endif /* RE_ENABLE_I18N */
    }
{
		  for (i = 0; i < SBC_MAX; ++i)

#endif /* not RE_ENABLE_I18N */
    dfa->eclosures[node] = eclosure;
}
	  return parse_expression (regexp, preg, token, syntax, nest, err);
static reg_errcode_t
  dfa->mb_cur_max = MB_CUR_MAX;
	    free_state (state);
regerror(int errcode, const regex_t *__restrict preg,
	    token->type = OP_DUP_QUESTION;
	  free (dfa->subexp_map);
    {
    {
	case '.':
	}
	  /   \
  if (dfa->mb_cur_max > 1)
    dfa->eclosures[node].nelem = 0;
	  break;
static reg_errcode_t
    codeset_name = getenv ("LANG");
    "\0"
  dfa->init_state = re_acquire_state_context (&err, dfa, &init_nodes, 0);
      /* Then we can these characters as normal characters.  */
  dfa->state_table = calloc (sizeof (struct re_state_table_entry), table_size);
analyze (regex_t *preg)
 parse_bracket_exp_espace:
#define REG_ERANGE_IDX	(REG_BADBR_IDX + sizeof "Invalid content of \\{\\}")
	 is a simple allocation.  */
  dfa->is_utf8 = 0;
# ifdef RE_ENABLE_I18N
      {						\
  else
	}
  re_node_set init_nodes;
      if (symb_table[2 * elem] != 0)
      if (type == CHARACTER)



    return NULL;
	   && strlen ((char *) start_elem->opr.name) > 1)
      return err;
    }
    case OP_BACK_REF:
      /* Go to the left node, or up and to the right.  */
    default:
	{
  return REG_NOERROR;
	if (sbcset[sbc_idx])
  return tree;
re_compile_pattern (const char *pattern,
    else					\
    wchar_t wc;
    {
    case '^':
	      unsigned char c = 0;

/* Functions for token which are used in the parser.  */
	  }
	return REG_ERANGE;
	}
      if (BE (*equiv_class_alloc == mbcset->nequiv_classes, 0))
   You should have received a copy of the GNU Lesser General Public
	  break;
	  for (i = 0, ch = 0; i < BITSET_WORDS; ++i)

	      break;
{
  dfa->map_notascii = (_NL_CURRENT_WORD (LC_CTYPE, _NL_CTYPE_MAP_TO_NONASCII)
    }
static reg_errcode_t
     pointer argument since we may update it.  */
	  break;
	      if (BE (token2.type == END_OF_RE, 0))
      /* Duplicate ELEM before it is marked optional.  */
      int32_t idx1, idx2;
		  break;
	}
				      const char *class_name,
}
    unsigned int ch;
  int node_idx, incomplete;
# ifdef RE_ENABLE_I18N
	    return;
	  br_token.type = SIMPLE_BRACKET;
  if (re_string_eoi(regexp))

    gettext_noop ("Invalid back reference") /* REG_ESUBREG */
	re_node_set eclosure_elem;
      goto parse_bracket_exp_free_return;
     If REG_ICASE is set, then we considers upper- and lowercase
	 && (nest == 0 || token->type != OP_CLOSE_SUBEXP))
	return gettext ("No previous regular expression");
    {
}
  token->type = CHARACTER;
	    return REG_ESPACE;
     The result are written to MBCSET and SBCSET.
  bin_tree_t *tree, *eor, *root;
    {
	return NULL;
	/* If the epsilon closure of `edest' is incomplete,
    tree = NULL;
# endif
    {
		 character.  */
	      p = buf;
  else
#ifdef _LIBC
  /* We have already checked preg->fastmap != NULL.  */
	      uint32_t *new_array_start;

      preg->allocated = 0;
      if (syntax & RE_CONTEXT_INVALID_DUP)
	goto parse_bracket_exp_espace;
create_tree (re_dfa_t *dfa, bin_tree_t *left, bin_tree_t *right,
#endif
  mbcset = (re_charset_t *) calloc (sizeof (re_charset_t), 1);
		  mbstate_t mbs;
	}

#endif
     upper and lower cases.  */
#endif
#ifdef RE_ENABLE_I18N
    REG_EEND_IDX,
  token->word_char = 0;
						_NL_COLLATE_INDIRECTMB);
  re_free (cset->char_classes);
    REG_EBRACE_IDX,
    case OP_OPEN_SUBEXP:
{
{
      if (BE (start_collseq == UINT_MAX || end_collseq == UINT_MAX, 0))
	      goto parse_bracket_exp_free_return;
/* Peek a token from INPUT, and return the length of the token.
		    re_set_fastmap (fastmap, false, (int) c);
    for (ch = 0; ch < SBC_MAX; ++ch)
	    /* Use realloc since mbcset->range_starts and mbcset->range_ends
					    re_string_t *regexp,
  if (c == '[') /* '[' is a special char in a bracket exps.  */
    }
    {
      return 0;
      /* +1 in case of mbcset->nchar_classes is 0.  */
  preg->re_nsub = 0;
{
calc_first (void *extra, bin_tree_t *node)
			       / sizeof (__re_error_msgid_idx[0])), 0))
	return err;
static bin_tree_t *
	   case is undefined.  But ERANGE makes good sense.  */
    if (node->type == SIMPLE_BRACKET && node->duplicated == 0)
	  return NULL;
	}
# endif /* not RE_ENABLE_I18N */
      break;
    REG_BADRPT_IDX,
    for (j = 0; j < BITSET_WORD_BITS; ++j, ++ch)
build_charclass (RE_TRANSLATE_TYPE trans, bitset_t sbcset,
	    goto parse_bracket_exp_free_return;
/* Size of the names for collating symbol/equivalence_class/character_class.
}
	}
      token->opr.c = c2;
	  }
      if (BE (token->type == END_OF_RE, 0))
	      token->type = ANCHOR;
     `fastmap_accurate' to zero;
  tree->token.duplicated = 0;
   compiles PATTERN (of length LENGTH) and puts the result in BUFP.
  switch (c)
	token->type = OP_DUP_PLUS;
	return REG_ERANGE;
  int i, j, ch;
#ifdef RE_ENABLE_I18N
#endif
	init_word_char (dfa);
	  char_buf[0] = ch;
    for (i = 0; i < dfa->edests[node].nelem; ++i)
    }
  cur_char_size = re_string_char_size_at (regexp, re_string_cur_idx (regexp));

static reg_errcode_t
    }
  {
	}
#endif /* RE_ENABLE_I18N */
#endif /* RE_ENABLE_I18N */
#endif
		  && (cset->ncoll_syms || cset->nranges))
				 "",
#define REG_EPAREN_IDX	(REG_EBRACK_IDX + sizeof "Unmatched [ or [^")
  preg->regs_allocated = REGS_UNALLOCATED;

{
	  do
	  {
}
		      if (__wcrtomb (buf, towlower (cset->mbchars[i]), &state)
	break;
build_range_exp (bitset_t sbcset, re_charset_t *mbcset, int *range_alloc,
}
   become read-only after dumping.  */

		 : 0));
  return work_tree;
}
}

				     int nest, reg_errcode_t *err);
    end_ch = ((end_elem->type == SB_CHAR) ? end_elem->opr.ch

	{
	  /* Build a tree for simple bracket.  */
		i = 0;
	token->word_char = IS_WORD_CHAR (c2) != 0;
/* This function parse bracket expression like "[abc]", "[a-c]",
  unsigned int start_ch, end_ch;
      bitset_set (sbcset, *name);
     COLL_SYM_ALLOC is the allocated size of mbcset->coll_sym, is a
      while (node->left || node->right)
							 &init_nodes,
	    {
    BUILD_CHARCLASS_LOOP (isxdigit);
		 if *alloc == 0.  */
		{

    {
  reg_errcode_t err = REG_NOERROR;
	    }
static bin_tree_t *
static reg_errcode_t mark_opt_subexp (void *extra, bin_tree_t *node);
	  node_idx = 0;
	 by peek_token.  */
						       dfa->eclosures

#define REG_NOMATCH_IDX (REG_NOERROR_IDX + sizeof "Success")
     at END_ELEM.  The result are written to MBCSET and SBCSET.
	{
	  if (BE (clone_dest == -1, 0))
      token->type = END_OF_RE;

	  while (!re_string_eoi (regexp)
  return 1;
      break;
  fetch_token (token, regexp, syntax | RE_CARET_ANCHORS_HERE);
      re_comp_buf.fastmap = NULL;
# endif
parse_bracket_element (bracket_elem_t *elem, re_string_t *regexp,
	    return;
      else if (dfa->edests[org_node].nelem == 0)
   If an error has occurred, ERR is set by error code, and return NULL.
postorder (bin_tree_t *root, reg_errcode_t (fn (void *, bin_tree_t *)),
	case '<':
	      tree = create_tree (dfa, tree, mbc_remain, CONCAT);

static bin_tree_t *
	  if (org_node == root_node && clone_node != org_node)
    case '.':
      if (BE (work_tree == NULL, 0))
/* BSD has one and only one pattern buffer.  */
}
#endif
	}
#ifdef RE_ENABLE_I18N
	  token->word_char = IS_WIDE_WORD_CHAR (wc) != 0;
{
	{
				 token->type == OP_NOTSPACE, err);
  c = re_string_peek_byte (input, 0);
	      token->opr.ctx_type = BUF_LAST;
    re_compile_fastmap_iter (bufp, dfa->init_state_begbuf, fastmap);

    }
	      break;
#endif
  fetch_token (token, regexp, syntax);
		for (i = 0; i <= 0x80 / BITSET_WORD_BITS - 1; i++)

	    {


	    new_nranges = 2 * mbcset->nranges + 1;
preorder (bin_tree_t *root, reg_errcode_t (fn (void *, bin_tree_t *)),
      bin_tree_t *mbc_tree;
				  dfa->mb_cur_max > 1 ? mbcset : NULL,
      *p_new = create_token_tree (dfa, NULL, NULL, &node->token);
      switch (c2)
  if (input->mb_cur_max > 1 &&
		  /* +1 in case of mbcset->nmbchars is 0.  */
      /* Build the table for single byte characters.  */

  seek_collating_symbol_entry (name, name_len)
    /* Build the table for single byte characters.  */
  /* For each nodes, calculate epsilon closure.  */
      preorder (dfa->str_tree, optimize_subexps, dfa);
  /* Extract "<re>{n,m}" to "<re><re>...<re><re>{0,<m-n>}".  */
  re_string_skip_bytes (regexp, token_len); /* Skip a token.  */
  if (incomplete && !root)
    {
	  int i, j, ch;
      c2 = re_string_peek_byte_case (input, 1);
	/* Check the space of the arrays.  */
    dfa->init_state_word = dfa->init_state_nl
	      if (token2.type == OP_CLOSE_BRACKET)
				 re_dfa_t *dfa, re_token_t *token,
   UTF-8 is used.  Otherwise we would allocate memory just to initialize
  token_len = peek_token_bracket (token, regexp, syntax);
    {
      node = node->right;
					    reg_syntax_t syntax,
			re_set_fastmap (fastmap, false, *(unsigned char *) buf);
      if (node->right)
	node->left->next = node->next;
      free_workarea_compile (preg);
	      token->type = ANCHOR;
		}
	if (type != OP_BACK_REF)
	    int new_nranges;
  if (BE (preg->allocated < sizeof (re_dfa_t), 0))
    gettext_noop ("Invalid character class name") /* REG_ECTYPE */
   It returns 0 if it succeeds, nonzero if it doesn't.  (See regex.h for
	    token->type = OP_NOTSPACE;

	}
	ch = re_string_fetch_byte (regexp);
static reg_errcode_t build_equiv_class (bitset_t sbcset,

free_dfa_content (re_dfa_t *dfa)
    }
    }

	{
    REG_ESIZE_IDX,
      case OP_OPEN_SUBEXP:
      break;
  if (re_comp_buf.fastmap == NULL)

    case '{':
	  && constraint == dfa->nodes[idx].constraint)
      /* In this case, '\' escape a character.  */
      free_dfa_content (dfa);
      {						\
	  /* Got valid collation sequence, add it as a new entry.  */

#endif /* RE_ENABLE_I18N */
#endif /* not RE_ENABLE_I18N */
#endif /* not RE_ENABLE_I18N */
    {
/* Free dynamically allocated space used by PREG.  */
	  bin_tree_t *tree_first, *tree_last;
}
  dfa->str_tree_storage = NULL;
  /* Initialize the dfa.  */
	  ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	{
#endif /* RE_ENABLE_I18N */

parse_dup_op (bin_tree_t *elem, re_string_t *regexp, re_dfa_t *dfa,
	if (dfa->nodes[node].type == CHARACTER
	  *err = REG_BADRPT;
  preg->fastmap_accurate = 0;
		return REG_ESPACE;
{
#define REG_EESCAPE_IDX	(REG_ECTYPE_IDX + sizeof "Invalid character class name")
internal_function
re_compile_fastmap_iter (regex_t *bufp, const re_dfastate_t *init_state,
	  /* If the node is root_node itself, it means the epsilon clsoure
      re_string_destruct (&regexp);
#endif /* not RE_ENABLE_I18N */
      && re_string_cur_idx (input) + 1 < re_string_length (input))
/* Parse an element in the bracket expression.  */
	      unsigned char *buf = re_malloc (unsigned char, dfa->mb_cur_max), *p;
	  0))
  unsigned char ch, delim = token->opr.c;
	  *err = ret;
regfree (regex_t *preg)
#define REG_NOERROR_IDX	0

      int org_dest, clone_dest;
		  dfa->sb_char[i] |= (bitset_word_t) 1 << j;
      else
	  if (start_collseq <= ch_collseq && ch_collseq <= end_collseq)
     is a pointer argument since we may update it.  */
  re_syntax_options = syntax;

internal_function

  tree = create_tree (dfa, tree, NULL, SUBEXP);
	{
  /* Match anchors at newline.  */

		  idx = (idx + 3) & ~3;
      }
		    }
  if (BE (err != REG_NOERROR, 0))

       character set is single byte, the single byte character set
  preg->not_bol = preg->not_eol = 0;
  else if (node->token.type == SUBEXP
	return;
{
		      != (size_t) -1))
	      if (BE (new_coll_syms == NULL, 0))
	      return __collseq_table_lookup (collseqwc, wc);
  while (token->type == OP_DUP_ASTERISK || token->type == OP_DUP_PLUS
	  /*

	break;
# else

	  clone_dest = search_duplicated_node (dfa, org_dest, constraint);
	  org_dest = dfa->edests[org_node].elems[1];
    {
      br_token.type = COMPLEX_BRACKET;

  	  if (ctype_func (i))			\
	if (dfa->eclosures[edest].nelem == 0)
      {
  re_free (cset->range_starts);
const char __re_error_msgid[] attribute_hidden =
  if (IS_EPSILON_NODE(dfa->nodes[node].type))
      re_string_skip_bytes (regexp, cur_char_size);
      if (start == -1)
		 bracket_elem_t *start_elem, bracket_elem_t *end_elem)
    return err;
  op->token.opr.idx = cls->token.opr.idx = node->token.opr.idx;

      bracket_elem_t start_elem, end_elem;
      if (node->left)
/* Optimization pass: if a SUBEXP is entirely contained, strip it and tell
    {
    gettext_noop ("Regular expression too big") /* REG_ESIZE */
/* Pass 2: compute NEXT on the tree.  Preorder visit.  */
/* This has no initializer because initialized variables in Emacs
  re_free (dfa->edests);
reg_syntax_t
      break;
	  *err = REG_BADRPT;
		    (1 + *(unsigned int *) (extra + idx));
  else
   these names if they don't use our functions, and still use
		&& clexp_node->opr.idx == dfa->nodes[node_idx].opr.idx)

}
  re_free (dfa->eclosures);
       no MBCSET if dfa->mb_cur_max == 1.  */
    if (BE (trans != NULL, 0))			\
    }
	      prev = node;
	  {
  return err;
	      }
      && !dfa->nodes[dfa->edests[node].elems[0]].duplicated)
    fastmap[tolower (ch)] = 1;
	  || !(dfa->used_bkref_map
	       || type == END_OF_RE)
      elem->type = EQUIV_CLASS;
    dfa->completed_bkref_map |= 1 << cur_nsub;
	{
	{
const size_t __re_error_msgid_idx[] attribute_hidden =
	      if (!node)
  char *fastmap;
{
    }
	    }
#ifndef _LIBC

build_charclass_op (re_dfa_t *dfa, RE_TRANSLATE_TYPE trans,
	  dfa->nexts[clone_node] = dfa->nexts[org_node];
	    }
	       created by ORing one or more opr.ctx_type values.  */
 /* This is currently duplicated from git-compat-utils.h */
static bin_tree_t *
  if (dfa->init_state != dfa->init_state_nl)

	dfa->has_mb_node = 1;

#define REG_ECTYPE_IDX	(REG_ECOLLATE_IDX + sizeof "Invalid collation character")
  return REG_NOERROR;
  return ret;
      && (codeset_name[3] == '-'
	token->type = OP_ALT;
/* For ZOS USS we must define btowc */

static reg_errcode_t
    {
	    case CHAR_CLASS:
    case '[':
static bin_tree_t *
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;

#endif
      dfa->has_mb_node = 1;
    }
weak_alias (__regerror, regerror)
    default:
      re_comp_buf.fastmap = fastmap;
	     destinations. In the bin_tree_t and DFA, that's '|' and '*'.   */
	  }
      break;
    REG_NOMATCH_IDX,
  int first, i;
	{
    return NULL;
	  node = node->left;
	{
      token->type = END_OF_RE;
      /* In BRE consecutive duplications are not allowed.  */
{

      tree = create_token_tree (dfa, NULL, NULL, token);
      if (re_string_cur_idx (input) + 1 < re_string_length (input))
    }
	  re_string_skip_bytes (input, 1);
				      int *char_class_alloc,

  if (node->right && node->right->token.type == SUBEXP)
    "\0"
	      mbstate_t state;
free_tree (void *extra, bin_tree_t *node)
  if (cflags & REG_NEWLINE)
    }
    {
	}
	      int32_t elem, idx;
    return err;
static void
	    case MB_CHAR:
     The result are written to MBCSET and SBCSET.
}

    case OP_ALT:
  	  if (ctype_func (i))			\
		}
      if (BE (err != REG_NOERROR, 0))
		    ? fetch_number (regexp, token, syntax) : -2));

      }						\
	 build below suffices. */

				      reg_syntax_t syntax);
	{
    {
	   ALT
{
  re_free (dfa->inveclosures);
  return tree;

      {
static reg_errcode_t lower_subexps (void *extra, bin_tree_t *node);

      node->first = node->left->first;
{
  re_free (dfa->nexts);
  if (   (codeset_name[0] == 'U' || codeset_name[0] == 'u')
	    return REG_ESPACE;
#endif /* RE_ENABLE_I18N */
{
static void
    "\0"
static reg_errcode_t build_charclass (RE_TRANSLATE_TYPE trans,
#ifdef RE_ENABLE_I18N
	    break;
	  elem = seek_collating_symbol_entry (name, name_len);
static reg_errcode_t

  reg_syntax_t ret = re_syntax_options;
	    }
  for (node = 0; node < dfa->nodes_len; ++node)
	      reg_syntax_t syntax, int nest, reg_errcode_t *err)
   DFA nodes where needed.  */
		bitset_set (sbcset, ch);
search_duplicated_node (const re_dfa_t *dfa, int org_node,
	    {
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
		  dfa->map_notascii = 1;
	      || token->type == OP_OPEN_DUP_NUM))


		  mbchar_alloc = 2 * mbcset->nmbchars + 1;
	  dfa->subexp_map = NULL;
      return tree;
}
       reg_errcode_t *err)
duplicate_tree (const bin_tree_t *root, re_dfa_t *dfa)
{
  elem->type = SB_CHAR;
					const unsigned char *name);
   The GNU C Library is free software; you can redistribute it and/or
	}
  err = create_initial_state (dfa);
#ifdef RE_ENABLE_I18N
}
     mbcset->range_ends, is a pointer argument since we may
				      reg_syntax_t syntax);
  __regfree (&re_comp_buf);
			unsigned int constraint)
      if (BE (mbc_tree == NULL, 0))
  /* Note: length+1 will not overflow since it is checked in init_dfa.  */
    {

	}
      {
fetch_token (re_token_t *result, re_string_t *input, reg_syntax_t syntax)
#endif /* RE_ENABLE_I18N */
		    const char *class_name,
		  collation element, and don't catch 'b' since 'b' is
static void
  auto inline reg_errcode_t
     routine will report only success or failure, and nothing about the
    {
  /* Initial states have the epsilon closure of the node which is
	dfa->word_char[i] |= (bitset_word_t) 1 << j;
     * unsigned, so we don't have sign extension problems.
		    if (table[i] < 0)
    case BACK_SLASH:

  return tree;
      unsigned char start_name_buf[BRACKET_NAME_BUF_SIZE];
	 is single byte, the single byte character set that we
	    if (clexp_node->type == OP_CLOSE_SUBEXP
static reg_errcode_t
  dfa->eclosures = re_malloc (re_node_set, dfa->nodes_alloc);
	  if (BE (token->type == END_OF_RE, 0))
	      /* Check whether the array has enough space.  */
  if (BE ((start_elem->type == COLL_SYM
      if (syntax & RE_NEWLINE_ALT)
      break;
      if (tree != NULL && exp != NULL)
    {
      break;
	  else
  if (BE (ret == REG_NOERROR, 1))
		    re_set_fastmap (fastmap, icase, *(unsigned char *) buf);
      return 1;
};
#else  /* not RE_ENABLE_I18N */

  re_free (dfa->org_indices);
  re_string_destruct (&regexp);
   tmp[1] = 0;
      break;
	  if (!(syntax & RE_NO_BK_PARENS))
  sbcset = (re_bitset_ptr_t) calloc (sizeof (bitset_t), 1);
	}
parse_reg_exp (re_string_t *regexp, regex_t *preg, re_token_t *token,
      weights = (const unsigned char *) _NL_CURRENT (LC_COLLATE,
	  if ((syntax & RE_INTERVALS) && (!(syntax & RE_NO_BK_BRACES)))

	  re_free (sbcset);
	  if (dfa->mb_cur_max > 1
  } while (0)
   To be called from preorder or postorder.  */
  msg_size = strlen (msg) + 1; /* Includes the null.  */
#define REG_BADPAT_IDX	(REG_NOMATCH_IDX + sizeof "No match")
	      ret = re_node_set_insert (dfa->edests + clone_node, org_dest);
}
  dfa->org_indices = NULL;
{
	      token->type = ANCHOR;
      if (dfa->eclosures != NULL)
/* Make these definitions weak in libc, so POSIX programs can redefine
/* Duplicate the node SRC, and return new node.  This is a preorder
      /*
	      /* Next entry.  */
				 "alnum",
	{
}
      else if (br_elem->type == COLL_SYM)
	  dfa->sb_char = (re_bitset_ptr_t) calloc (sizeof (bitset_t), 1);
    {
	  /* In case of the node can epsilon-transit, and it has only one
	token->type = OP_OPEN_DUP_NUM;
      start = (token->type == OP_DUP_PLUS) ? 1 : 0;


#ifdef DEBUG
static reg_errcode_t optimize_subexps (void *extra, bin_tree_t *node);
}
      mbcset->non_match = 1;
  *err = REG_ESPACE;
    case OP_DUP_ASTERISK:
	}
#else /* not RE_ENABLE_I18N */
      preg->fastmap = NULL;
{
	    return REG_ESPACE;
}
	  int32_t *new_equiv_classes = re_realloc (mbcset->equiv_classes,
					  re_string_t *regexp,
  if (BE (tree == NULL, 0))
      /* We do not optimize empty subexpressions, because otherwise we may
    }
	return NULL;
		{
	      goto parse_bracket_exp_free_return;

  return dup_idx;
  return create_token_tree (dfa, left, right, &t);
  bin_tree_t *tree;
		  || cset->nequiv_classes
      fetch_token (token, regexp, syntax | RE_CARET_ANCHORS_HERE);
    gettext_noop ("Memory exhausted") /* REG_ESPACE */
	  right = node->right->first->node_idx;
	      tree_first = create_token_tree (dfa, NULL, NULL, token);
  return REG_NOERROR;
{
  bin_tree_t *node;
	  bin_tree_t *prev = NULL;
	  return NULL;
    codeset_name = getenv ("LC_CTYPE");

     update it.  */
# endif
      /* Go up while we have a node that is reached from the right.  */
  /* Helper function for parse_bracket_exp.
  return root;
	    }

	}
		 : 0));
# ifdef _LIBC
  else if (strcmp (class_name, "blank") == 0)
  else
      /* Create a new tree and link it back to the current parent.  */
		  the only collation element which starts from 'b' (and
  /* Set the first 128 bits.  */
      re_node_set eclosure_elem;
	/* If calculating the epsilon closure of `edest' is in progress,
  else

  switch (node->token.type)


  /* POSIX doesn't distinguish between an unmatched open-group and an
  /* Helper function for parse_bracket_exp.
	  re_string_skip_bytes (input, -1);
  regex_t *preg = (regex_t *) extra;
	    {
    {
	      int new_coll_sym_alloc = 2 * mbcset->ncoll_syms + 1;
  return tree;
  if (re_string_eoi (input))
  eor = create_tree (dfa, NULL, NULL, END_OF_RE);
      token->type = OP_CLOSE_BRACKET;
	    for (j = 0; j < BITSET_WORD_BITS; ++j, ++ch)
   mbtowc (wtmp, tmp, 1);

      else
#ifdef RE_ENABLE_I18N
  re_string_skip_bytes (regexp, 1);
    {
    }
  for (src = 0; src < dfa->nodes_len; ++src)
		      re_set_fastmap (fastmap, icase, i);
static inline void
	  static short utf8_sb_map_inited = 0;
  else
 parse_dup_op_espace:
	{
		return dup_root;
    start_wc = ((start_elem->type == SB_CHAR || start_elem->type == COLL_SYM)
  if (dfa->mb_cur_max == 6
  return REG_NOERROR;
/* This function parse repetition operators like "*", "+", "{1,3}" etc.  */
   the return codes and their meanings.)  */

      re_free (node->opr.sbcset);
      return REG_NOERROR;
      if (node->left)
	  case BUF_FIRST:
static reg_errcode_t
	  /   \
  else if (strcmp (class_name, "lower") == 0)
      if (re_string_eoi(regexp))
  br_token.type = SIMPLE_BRACKET;
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
		     && dfa->nodes[node].mb_partial)
      token->type = OP_OPEN_BRACKET;
#endif /* __GNUC__ >= 3 */
		    reg_errcode_t *err)
	    {
    "\0"
/* Helper function for parse_bracket_exp only used in case of NOT _LIBC..
	}
			       void *extra);
      ++dfa->nbackref;
    return ret;
#ifdef RE_ENABLE_I18N
      token_len = 2;
      next = storage->next;
      if (dfa == NULL)

     since they must inherit the constraints.  */
  if (BE (*char_class_alloc == mbcset->nchar_classes, 0))
  dfa->org_indices = re_malloc (int, dfa->nodes_alloc);
    {
	}

		}
  int num = -1;
/* Set by `re_set_syntax' to the current regexp syntax to recognize.  Can
      break;
    {
  /* We don't care the syntax in this case.  */
      if (BE (token->type == END_OF_RE, 0))
   to speed things up, set dfa->mb_cur_max to 1, clear is_utf8 and change
      && (codeset_name[2] == 'F' || codeset_name[2] == 'f')
    {
  strncpy (dfa->re_str, pattern, length + 1);
				     char *fastmap);
	case 'w':
	}
    }
      break;
      dfa->nodes[dup_idx].constraint = constraint;
  else
  re_charset_t *mbcset;
	  node = node->right;
	if (node->left != NULL)
	      *err = build_charclass (regexp->trans, sbcset,
	if (clexp_idx == init_nodes.nelem)
	{
	      && (cset->nchar_classes || cset->non_match || cset->nranges
      re_token_type_t type = dfa->nodes[node].type;
    }
{
	    {
		 const char *class_name, reg_syntax_t syntax)
	  eclosure_elem = dfa->eclosures[edest];
  if (!s)
      || dfa->nbackref)
    }
#ifdef RE_ENABLE_I18N
}
#ifdef DEBUG
	    mbcset->range_ends = new_array_end;

}
  if (BE (*err != REG_NOERROR && tree == NULL, 0))
		: ((start_elem->type == COLL_SYM) ? start_elem->opr.name[0]
		   : 0));
    for (i = 0; i <= dfa->state_hash_mask; ++i)
	    }
   "eclosure", and "inveclosure".  */
	      for (i = 0; i < cset->nmbchars; ++i)
    }
    REG_EPAREN_IDX,
	    token->type = OP_WORD;
	    if (BE (err != REG_NOERROR, 0))
      unsigned int ch;
      if (node_idx == dfa->nodes_len)
   The GNU C Library is distributed in the hope that it will be useful,
	    {
	  mbcset->range_ends[mbcset->nranges++] = end_collseq;
      if (!(syntax & (RE_CONTEXT_INDEP_ANCHORS | RE_CARET_ANCHORS_HERE)) &&
	  break;
      else if (type == SIMPLE_BRACKET)
    case '(':
     to rewrite <re>{0,n} as (<re>(<re>...<re>?)?)?...  We have
  if (BE (eor == NULL || root == NULL, 0))
      break;
	      mbcset->mbchars[mbcset->nmbchars++] = start_elem.opr.wch;
  if (BE (errbuf_size != 0, 1))
    BUILD_CHARCLASS_LOOP (isblank);
  dfa->str_tree_storage_idx = BIN_TREE_STORAGE_SIZE;
	  token_len = 1;

	dfa->subexp_map[i] = i;
      if (node->left)
  if (BE (ret != REG_NOERROR, 0))
      if (input->mb_cur_max > 1)
    {
    {
	      do
    return err;
  re_token_t br_token;
      indirect = (const int32_t *) _NL_CURRENT (LC_COLLATE,
	  int new_equiv_class_alloc = 2 * mbcset->nequiv_classes + 1;
    }
      /* else fall through  */

	node->left->parent = node;
		return REG_ESPACE;
  switch (token->type)
    {
	  void *extra)


	  clone_dest = duplicate_node (dfa, org_dest, constraint);
     Then we add epsilon closures of the nodes which are the next nodes of
	  int32_t second = hash % (table_size - 2) + 1;


	    return REG_ECOLLATE;
		  *err = REG_ESPACE;
{
	  p_new = &dup_node->right;

	}
	    }

	{
	    }
    free_dfa_content (dfa);
    }
	      {
		  mbstate_t state;
  auto inline unsigned int
  /* This indicates that we are calculating this node now.
	  if (BE (name_len != 1, 0))
#endif /* RE_ENABLE_I18N */
      else if (tree == NULL)
	    if (!re_node_set_contains (&init_nodes, dest_idx))
		  /* We found the entry.  */
		{
#endif /* RE_ENABLE_I18N */
     CHAR_CLASS_ALLOC is the allocated size of mbcset->char_classes,

	cmp_buf[2] = wc;
	  break;
static reg_errcode_t
		     reg_syntax_t syntax)
  int node_cnt;
	    }
#endif
     If REG_NEWLINE is set, then . and [^...] don't match newline.
	return NULL;
  op = create_tree (dfa, NULL, NULL, OP_OPEN_SUBEXP);
      */
	case '?':
  return num;
  if (dfa->init_state != dfa->init_state_word)

  /* Ensure only single byte characters are set.  */
	  re_string_set_index (regexp, start_idx);
{
  preg->used = sizeof (re_dfa_t);

      if (storage == NULL)
	  break;
  size_t msg_size;
	      if (BE (ret < 0, 0))
	node->right->next = node->next;
  reg_errcode_t ret;
  br_token.opr.sbcset = sbcset;
#ifdef RE_ENABLE_I18N
{
	      break;

	    return collseqmb[br_elem->opr.name[0]];
		     && dfa->nodes[node].type == CHARACTER
	return NULL;

}
# ifdef NO_INTPTR_T
	  return err;
#ifdef _LIBC
		}
      start = fetch_number (regexp, token, syntax);
	    {
   nodes.  Requires a postorder visit.  */
#define REG_ESUBREG_IDX	(REG_EESCAPE_IDX + sizeof "Trailing backslash")
  int cur_char_size;
	  break;
					     start_elem.opr.name);
    {
  memcpy ((void *) &start_token, (void *) token, sizeof start_token);
	}

	bitset_set (sbcset, ch);
	case 'W':
      int32_t elem = hash % table_size;
						  sym_name_len);
      if (BE (start != -2, 1))
	    {
	branch = NULL;
  fetch_token (token, regexp, syntax);
		  token->type = CHARACTER;

	  */

      return REG_ERANGE;
  /* We check exhaustively in the loop below if this charset is a
	{
#endif
#define REG_ECOLLATE_IDX (REG_BADPAT_IDX + sizeof "Invalid regular expression")
	}
#ifdef RE_ENABLE_I18N
# else /* not RE_ENABLE_I18N */
	      prev = node;
      if (BE (tree == NULL, 0))
	struct re_state_table_entry *entry = dfa->state_table + i;
static bin_tree_t *
	}
    {
	}
    end_wc = ((end_elem->type == SB_CHAR || end_elem->type == COLL_SYM)
      || mbcset->nranges || (dfa->mb_cur_max > 1 && (mbcset->nchar_classes
	    token->type = OP_ALT;
		reg_errcode_t err = re_node_set_merge (&init_nodes,
				       const char *extra,
    {
    BUILD_CHARCLASS_LOOP (isgraph);
*/
		  wchar_t *new_mbchars;
    case OP_OPEN_SUBEXP:
  };
	      if (cnt > len)
  elem->opr.name[i] = '\0';
          ? codeset_name[4] == '8' && codeset_name[5] == '\0'
    {
	     elements.
    {
build_equiv_class (bitset_t sbcset, const unsigned char *name)
  if (!ret)
      else if (syntax & RE_CONTEXT_INDEP_OPS)
      break;
}
  tree = parse_reg_exp (regexp, preg, &current_token, syntax, 0, err);
  if (BE (ret != REG_NOERROR, 0))
      if (!(syntax & RE_CONTEXT_INDEP_ANCHORS) &&
      ret = calc_inveclosure (dfa);
	      /* ... Else catch all bytes which can start the mbchars.  */
    goto re_compile_internal_free_return;
    dfa->is_utf8 = 1;
#endif /* RE_ENABLE_I18N */
  else if (strcmp (class_name, "digit") == 0)
	}
}
	  /* See if we have to start the match at all multibyte characters,

static bin_tree_t *create_token_tree (re_dfa_t *dfa,
	    continue;
  for (node = root; ; )
	      if (BE (mbchar_alloc == mbcset->nmbchars, 0))
    case OP_DUP_PLUS:
	      || dfa->init_state_begbuf == NULL, 0))
static bin_tree_t *
		  /* Compare the name.  */
	 very common, so we do not lose much.  An example that triggers
	  break;
    "\0"
    return NULL;
      if (BE (ret != REG_NOERROR, 0))

static reg_errcode_t parse_bracket_symbol (bracket_elem_t *elem,
#ifdef RE_ENABLE_I18N
	}
   version 2.1 of the License, or (at your option) any later version.
	case '6': case '7': case '8': case '9':
	      mbcset->range_starts = new_array_start;
	  *equiv_class_alloc = new_equiv_class_alloc;
{

      if ((syntax & RE_INTERVALS) && (syntax & RE_NO_BK_BRACES))
  if (BE (err != REG_NOERROR, 0))
#endif
		return err;
		{
	      /* Skip the name of collating element name.  */
      case OP_BACK_REF:
	      new_array_start = re_realloc (mbcset->range_starts, uint32_t,
     * for any value > 127. Sigh. Note that `start_ch' and `end_ch' are
re_compile_internal (regex_t *preg, const char * pattern, size_t length,
    if (table_size > pat_len)
      elem = duplicate_tree (elem, dfa);
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
	if (node->right != NULL)
      token->opr.ctx_type = LINE_LAST;
	    return REG_ESPACE;
	else
      if (other_idx < BITSET_WORD_BITS)
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  free_token (&node->token);
	    return REG_ESPACE;
   regcomp/regexec above without link errors.  */
	 SUBEXP
	  if (BE (ret == -1, 0))

      /* Not enough, realloc it.  */
  c = re_string_peek_byte (input, 0);
	    {
{
#ifdef RE_ENABLE_I18N
      else
      memset (&re_comp_buf, '\0', sizeof (re_comp_buf));
    abort ();
    }
    for (node = 0; node < dfa->nodes_len; ++node)
      tree = create_token_tree (dfa, NULL, NULL, token);
	assert (0x80 % BITSET_WORD_BITS == 0);
{
	    }
    case OP_OPEN_CHAR_CLASS:
    {

	  errbuf[errbuf_size - 1] = 0;
     the first node of the regular expression.  */
	       & ((bitset_word_t) 1 << node->token.opr.idx))))
    return REG_ECOLLATE;
  else if (strchr (codeset_name, '.') !=  NULL)
    return node->left;
	return NULL;
	  if (!(syntax & RE_NO_GNU_OPS))
	}
      return REG_NOERROR;
  /* Convert the SUBEXP node to the concatenation of an
  /* Local function for parse_bracket_exp used in _LIBC environment.
static int duplicate_node (re_dfa_t *dfa, int org_idx, unsigned int constraint);
	{
      preg->buffer = NULL;
    gettext_noop ("Invalid content of \\{\\}") /* REG_BADBR */
    codeset_name = strchr (codeset_name, '.') + 1;
  else if (strcmp (class_name, "alpha") == 0)
      /* This #include defines a local function!  */
#else /* not RE_ENABLE_I18N */
  __attribute ((always_inline))
    {
	    }

   as the initial length of some arrays.  */
}
   <branch1> <branch2>
  for (node_idx = 0; ; ++node_idx)
      break;
   We must not use this function inside bracket expressions.  */

      if (token->type == OP_CLOSE_DUP_NUM || c == ',')

	goto parse_dup_op_espace;
  bin_tree_t *work_tree;
      if (token->type != OP_ALT && token->type != END_OF_RE
      /* If zero allocated, but buffer is non-null, try to realloc

	for (j = 0; j < entry->num; ++j)
  else
	      *err = REG_ESPACE;
    (void) re_compile_fastmap (preg);
	      mbcset->coll_syms = new_coll_syms;
  if (re_comp_buf.buffer)
	      || end_elem->type == EQUIV_CLASS || end_elem->type == CHAR_CLASS,
      token->type = CHARACTER;
     We reference this value to avoid infinite loop.  */
#ifndef GAWK
	  }
    "\0"
    gettext_noop ("Unmatched ( or \\(") /* REG_EPAREN */
	      re_token_t *token, reg_syntax_t syntax, reg_errcode_t *err)
	    {
    }
      return NULL;
	  *err = REG_ESPACE;
  int node, i, mb_chars = 0, has_period = 0;
	/* This isn't a valid character.  */
	  if (token->opr.ctx_type == WORD_DELIM)

	  /* We treat "{n}" as "{n,n}".  */
      if ((token->opr.ctx_type
#endif
  preorder (dfa->str_tree, calc_next, dfa);

	int node_idx = init_nodes.elems[i];
	    }
  if (strcmp (class_name, "alnum") == 0)
    {
#endif /* not RE_ENABLE_I18N */
		  goto parse_bracket_exp_free_return;
   wchar_t wtmp[2];
}
  /* Parse the regular expression, and build a structure tree.  */
  re_dfa_t *dfa = (re_dfa_t *) bufp->buffer;
	  /* Search for a duplicated node which satisfies the constraint.  */
	      node = node->parent;
    optimize_utf8 (dfa);
      if (BE (tree == NULL, 0))
static int peek_token (re_token_t *token, re_string_t *input,
	 char *__restrict errbuf, size_t errbuf_size)
#ifdef RE_ENABLE_I18N

	  *err = REG_ESPACE;
      node->left->next = node->right->first;
  if (codeset_name == NULL || codeset_name[0] == '\0')
	      if (BE (ret < 0, 0))
	/* If we haven't calculated the epsilon closure of `edest' yet,
static const bitset_t utf8_sb_map = {
      fetch_token (token, input, syntax);
{
# ifdef _LIBC
    class_name = "alpha";
  nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
	      /* Use realloc since mbcset->coll_syms is NULL
				       RE_TRANSLATE_TYPE trans,
	if (BE (err != REG_NOERROR, 0))
    {

      case OP_CLOSE_SUBEXP:
static reg_errcode_t

fetch_number (re_string_t *input, re_token_t *token, reg_syntax_t syntax)
	}
  if (BE (dfa->nodes == NULL || dfa->state_table == NULL, 0))
#ifdef RE_ENABLE_I18N
	}
	    /* +1 in case of mbcset->nranges is 0.  */
	  /* +1 in case of mbcset->nequiv_classes is 0.  */
      break;
      int idx = node->token.opr.idx;
	    return REG_ESPACE;
/* Analyze the structure tree, and calculate "first", "next", "edest",
re_comp (s)

  int i;
  if (dfa->nodes[node].constraint
      wint_t wc = re_string_wchar_at (input, re_string_cur_idx (input));
	  if (BE (*range_alloc == mbcset->nranges, 0))
      if (syntax & RE_NO_BK_PARENS)
		  *err = REG_EBRACK;
  else
	  goto parse_bracket_exp_free_return;
  return REG_NOERROR;
	    }
      else
    }
  if (BE (dfa->str_tree_storage_idx == BIN_TREE_STORAGE_SIZE, 0))
					  new_nranges);
#ifdef RE_ENABLE_I18N
  int src, idx, ret;
      break;
#ifdef ZOS_USS
#endif
  if (dfa->mb_cur_max > 1)
      case END_OF_RE:
      break;
	{
	break;
    }
  if (strcasecmp (codeset_name, "UTF-8") == 0

  re_free (dfa->nodes);
static reg_errcode_t
      break;
      unsigned int ch;

      postorder (elem, free_tree, NULL);
  for (storage = dfa->str_tree_storage; storage; storage = next)
      const int32_t *table, *indirect;
      case OP_ALT:
	{
    }
  err = analyze (preg);
	      elem = seek_collating_symbol_entry (br_elem->opr.name,
      if (re_string_cur_idx (input) + 1 >= re_string_length (input))
		return REG_ESPACE;
	      while (cnt <= len &&
	return NULL;
	/* Merge the epsilon closure of `edest'.  */

      if (syntax & RE_NO_BK_PARENS)
    REG_BADPAT_IDX,
      case OP_DUP_ASTERISK:
		  /* Use realloc since array is NULL if *alloc == 0.  */
create_token_tree (re_dfa_t *dfa, bin_tree_t *left, bin_tree_t *right,
libc_freeres_fn (free_mem)
    token->type = CHARACTER;
  re_free (cset->equiv_classes);
	  /* In case of the node can't epsilon-transit, don't duplicate the
static reg_errcode_t free_tree (void *extra, bin_tree_t *node);
static bin_tree_t *parse_reg_exp (re_string_t *regexp, regex_t *preg,
      if (node->token.type == OP_BACK_REF)
    }
static bin_tree_t *parse_bracket_exp (re_string_t *regexp, re_dfa_t *dfa,
__attribute ((always_inline))
							 CONTEXT_NEWLINE
  reg_errcode_t err = REG_NOERROR;
	    {
/* Functions for parser.  */
    {
  re_token_t br_token;
#ifdef RE_ENABLE_I18N

  re_comp_buf.newline_anchor = 1;
    /* Build the table for single byte characters.  */
	      token->type = ANCHOR;
     Look up the collation sequence value of BR_ELEM.
    }
{
      dfa->init_state_begbuf = re_acquire_state_context (&err, dfa,
	 this case is the sed "script" /\(\)/x.  */
  switch (node->token.type)
}
static bin_tree_t *lower_subexp (reg_errcode_t *err, regex_t *preg,
	goto parse_bracket_exp_espace;
    REG_ECTYPE_IDX,
      break;
}
      break;
      if (!re_comp_buf.buffer)
/* This static array is used for the map to single-byte characters when
      else /* dfa->edests[org_node].nelem == 2 */

	      idx = symb_table[2 * elem + 1];
	else
  if (dfa->nodes)
	  if (BE (ret < 0, 0))
	      int new_nranges;
    "\0"
      return NULL;
  ret = postorder (dfa->str_tree, calc_first, dfa);
      if ((token->type == OP_CLOSE_SUBEXP) &&
/* Internal entry point.
	    ch_collseq = __collseq_table_lookup (collseqwc, __btowc (ch));

	  if (!(syntax & RE_NO_GNU_OPS))
	}
  __libc_lock_init (dfa->lock);
  return REG_NOERROR;
      return NULL;

    BUILD_CHARCLASS_LOOP (isspace);
	CAT
      /* Descend down the tree, preferably to the left (or to the right
/*
      }
	      if (BE (*err != REG_NOERROR, 0))
  if (elem->token.type == SUBEXP)
      if (token->type == OP_OPEN_CHAR_CLASS)
  bufp->no_sub = !!(re_syntax_options & RE_NO_SUB);
	  if (nrules == 0)
  if (non_match)
				    dfa->nodes[node].constraint);
  re_free (dfa->re_str);

      && node->left != NULL
  int equiv_class_alloc = 0, char_class_alloc = 0;
  /*  table_size = 2 ^ ceil(log pat_len) */
      re_token_t token2;
	  return NULL;
					    new_nranges);
#if defined __TANDEM
#endif /* RE_ENABLE_I18N */
    bitset_mask (sbcset, dfa->sb_char);
  re_free (sbcset);
#ifdef GAWK
    }
	break;


/* This function build the following tree, from regular expression
      break;
	    return REG_ECOLLATE;
	return REG_ESPACE;
      dfa->init_state_word = re_acquire_state_context (&err, dfa, &init_nodes,
  /* If it is non-matching list.  */
	    {
	return REG_ERANGE;
      return err;
  if (BE (start == 0 && end == 0, 0))
	  break;
	    case SB_CHAR:
      token->word_char = IS_WIDE_WORD_CHAR (wc) != 0;
  token->opr.c = c;
    "\0"
	  *err = REG_ESPACE;
	  mbcset->equiv_classes = new_equiv_classes;
  free_charset (mbcset);
  return tree;
	      break;
     `fastmap' to an allocated space for the fastmap;
    case END_OF_RE:
    {
/* Peek a token from INPUT, and return the length of the token.
      node->node_idx = node->left->node_idx;
  return 0;

	for (i = 0x80 / BITSET_WORD_BITS; i < BITSET_WORDS; ++i)
	    token->type = OP_SPACE;
static void
    }
			     name_len) == 0)
   Return the index of the new node, or -1 if insufficient storage is
	      reg_errcode_t err;
		    const char *extra, int non_match,
      preg->buffer = NULL;
  codeset_name = nl_langinfo (CODESET);
	case ':':
	  if (!(syntax & RE_NEWLINE_ALT) || prev != '\n')
      return NULL;


      /* Build single byte matching table for this equivalence class.  */
  bin_tree_t **p_new = &dup_root, *dup_node = root->parent;
parse_bracket_exp (re_string_t *regexp, re_dfa_t *dfa, re_token_t *token,
	  if (BE (ret < 0, 0))


static void
	    return err;

    return ret;
      return NULL;
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
    gettext_noop ("Premature end of regular expression") /* REG_EEND */
      *err = REG_BADPAT;
    case OP_CLOSE_SUBEXP:
   but WITHOUT ANY WARRANTY; without even the implied warranty of
# endif /* not RE_ENABLE_I18N */
		  /* Skip the name of collating element name.  */
		  re_set_fastmap (fastmap, icase, ch);
    tree = create_tree (dfa, old_tree, tree, CONCAT);
					const unsigned char *name);
      if (node->token.type == ANCHOR)
  tree = create_tree (dfa, op, tree1, CONCAT);
    dfa->is_utf8 = 1;
static reg_errcode_t
		  if (__wcrtomb (buf, cset->mbchars[i], &state) != (size_t) -1)

reg_syntax_t re_syntax_options;
      /* Use realloc since array is NULL if *alloc == 0.  */
	  uint32_t ch_collseq;
static reg_errcode_t parse_bracket_element (bracket_elem_t *elem,
    }
      re_string_skip_bytes (regexp, token_len); /* Skip a token.  */

  while (token->type != OP_ALT && token->type != END_OF_RE
  if (BE (sbcset == NULL || mbcset == NULL, 0))
	      if (symb_table[2 * elem] == hash
	    }


	/* Just double check.  The non-ASCII range starts at 0x80.  */
    case '*':

		 ))
		    struct re_pattern_buffer *bufp)
      token->type = CHARACTER;

    REG_EESCAPE_IDX,
      if (BE (tree == NULL, 0))

calc_inveclosure (re_dfa_t *dfa)
			  reg_syntax_t syntax, reg_errcode_t *err);
  if (node->token.type == OP_BACK_REF && dfa->subexp_map)
  int first_round = 1;
  int i, j;
static int
    {
#ifdef RE_ENABLE_I18N
      /* It also changes the matching behavior.  */
     unmatched close-group: both are REG_EPAREN.  */
#endif
	  goto parse_bracket_exp_free_return;
  if (c == '\\')

    case CONCAT:
	      elem += second;
  token->mb_partial = 0;
	  while (symb_table[2 * elem] != 0);
      elem->opr.name[i] = ch;
      start_elem.opr.name = start_name_buf;
      *err = REG_ESPACE;

      dfa->org_indices[dup_idx] = org_idx;

		  /* Return the collation sequence value.  */
	{
	    {
	     also have the constraint.  Then duplicate the epsilon closure
/* Calculate "eclosure" for all the node in DFA.  */
	<reg_exp>
      break;
  *err = REG_ESPACE;
		  /* Skip the multibyte collation sequence value.  */
	}
  tree->token = *token;
   for compatibility for various utilities which historically have
		is_range_exp = 1;
   (<reg_exp>):

		++cnt;
  codeset_name = getenv ("LC_ALL");

	    {
      re_comp_buf.fastmap = (char *) malloc (SBC_MAX);
      case CHARACTER:
#endif /* RE_ENABLE_I18N */
	  if (symb_table[2 * elem] != 0)
static reg_errcode_t init_dfa (re_dfa_t *dfa, size_t pat_len);

	return -2;
      do
	    token->type = OP_NOTWORD;
    case '$':
lower_subexps (void *extra, bin_tree_t *node)
{
	     applies to multibyte character sets; for single byte character
      if (re_comp_buf.fastmap == NULL)
	token->type = OP_ALT;
  if (mbcset->nmbchars || mbcset->ncoll_syms || mbcset->nequiv_classes
#endif /* not RE_ENABLE_I18N */
  for (;; ++i)
      extra = (const unsigned char *) _NL_CURRENT (LC_COLLATE,

      free_charset (mbcset);
	     re_token_type_t type)
internal_function
	break;
	goto build_word_op_espace;
  msg = gettext (__re_error_msgid + __re_error_msgid_idx[errcode]);
#else
     `used' to the length of the compiled pattern;
		int i;
	  cp = char_buf;
		  if ((bufp->syntax & RE_ICASE) && dfa->mb_cur_max > 1)
  return REG_NOERROR;
	  }
	}
	}
    }
   Fetch a number from `input', and return the number.
  re_node_set eclosure;
 typedef unsigned long uintptr_t;
	 bracket_elem_t *start_elem, *end_elem;
	return err;
	 However, if we have no collation elements, and the character set
      mbc_tree = create_token_tree (dfa, NULL, NULL, &br_token);

  reg_errcode_t ret;
		  return collseqmb[br_elem->opr.name[0]];
    {
	  break;
	      return NULL;
	  else
#ifdef RE_ENABLE_I18N
      *err = REG_ESPACE;
  if (BE (sbcset == NULL || mbcset == NULL, 0))
	  break;
#ifdef RE_ENABLE_I18N
}

      if (nrules != 0)

  const int32_t *symb_table;
mark_opt_subexp (void *extra, bin_tree_t *node)
 build_word_op_espace:
        {
				 token->type == OP_NOTWORD, err);
      token->type = OP_NON_MATCH_LIST;

      /* Calculate the index for equivalence class.  */

  free_workarea_compile (preg);
  if (codeset_name == NULL)

	  if (BE (*err != REG_NOERROR && branch == NULL, 0))
	return (char *) gettext (__re_error_msgid
     Build the range expression which starts from START_ELEM, and ends
  const char *msg;
	for (i = 0; i < SBC_MAX; ++i)		\
      *err = REG_ESPACE;
	    token->type = OP_OPEN_SUBEXP;
  }
	{

	      *err = REG_ESPACE;
    }
  tree1 = body ? create_tree (dfa, body, cls, CONCAT) : cls;
						     || mbcset->non_match)))
      break;
      return REG_ECOLLATE;
    bitset_not (sbcset);

  re_dfa_t *dfa = (re_dfa_t *) extra;
					       _NL_COLLATE_WEIGHTMB);

	 int cflags)
      tree = create_tree (dfa, tree, branch, OP_ALT);
	    {
	    }
      if (BE (*err == REG_NOERROR && token->type != OP_CLOSE_SUBEXP, 0))
  if (cur_char_size > 1)
#ifdef _LIBC
      break;

  re_dfa_t *dfa = (re_dfa_t *) extra;
#else /* not RE_ENABLE_I18N */
	      int j;
  bin_tree_t *tree;
    BUILD_CHARCLASS_LOOP (ispunct);
#define REG_BADBR_IDX	(REG_EBRACE_IDX + sizeof "Unmatched \\{")
      tree = create_token_tree (dfa, NULL, NULL, token);
  err = init_dfa (dfa, length);
	}

	      token->type = OP_OPEN_CHAR_CLASS;
static bin_tree_t *
  do {						\
  if (BE (tree == NULL || tree1 == NULL || op == NULL || cls == NULL, 0))
    "\0"
		       != 0);
  dfa->init_node = first;
	      if (token->type == END_OF_RE)
      node->first = node;
	    {
    root = create_tree (dfa, tree, eor, CONCAT);
      dfa->str_tree_storage_idx = 0;
      reg_errcode_t ret;
				  &range_alloc, &start_elem, &end_elem);
	     i.e. where we would not find an invalid sequence.  This only
      || token->type == OP_OPEN_EQUIV_CLASS)
	 have bad CONCAT nodes with NULL children.  This is obviously not
	    {
	  return NULL;
	      ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
      node->right->next = node->next;
    return REG_ESPACE;
	       reg_syntax_t syntax, int nest, reg_errcode_t *err)
     The result are written to MBCSET and SBCSET.
	    start = 0; /* We treat "{,m}" as "{0,m}".  */
	dfa->has_plural_match = 1;
	    {
	{
   implement parse tree visits.  Instead, we use parent pointers and
	    clexp_node = dfa->nodes + init_nodes.elems[clexp_idx];
      tree = create_token_tree (dfa, NULL, NULL, token);
	  else

	  /* If the syntax bit is set, rollback.  */
  if (BE (elem == NULL, 0))
}
      free_charset (mbcset);
  if (icase)
#else /* ! (__GNUC__ >= 3) */
    }
  ret = re_compile_internal (bufp, pattern, length, re_syntax_options);
	  return NULL;
      /* We treat it as a normal character.  */
#ifdef RE_ENABLE_I18N

  if (BE (ret != REG_NOERROR, 0))
      *err = REG_ESPACE;
  dfa = (re_dfa_t *) preg->buffer;
    }

	    {
    case ANCHOR:
	  if (!(syntax & RE_NO_BK_PARENS))
    wint_t end_wc;
    {
	  bitset_set (sbcset, wc);
      preg->buffer = NULL;
	     index is the same.  */
      /* Calculate epsilon closure of `node_idx'.  */
  re_token_t start_token = *token;
      mbcset->char_classes = new_char_classes;
	      if (symb_table[2 * elem] != 0)
  return NULL;
						       + dest_idx);

	  break;
    /* Got valid collation sequence values, add them as a new entry.
      || strcasecmp (codeset_name, "UTF8") == 0)
				      re_charset_t *mbcset,
	  else
  char *fastmap = bufp->fastmap;
  tree->node_idx = -1;
   SYNTAX indicate regular expression's syntax.  */
	{
}
     versions of letters to be equivalent when matching.
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
static reg_errcode_t calc_eclosure_iter (re_node_set *new_set, re_dfa_t *dfa,
  ret = re_node_set_insert (&eclosure, node);
  int i = 0;

  dfa->mb_cur_max = 1;
					int *equiv_class_alloc,
      else if (dfa->edests[org_node].nelem == 1)
	      0))
      else
		*err = REG_EBRACE;

  if (BE (start_elem->type == EQUIV_CLASS || start_elem->type == CHAR_CLASS
     RANGE_ALLOC is the allocated size of mbcset->range_starts, and
      }
    { /* REG_NEWLINE implies neither . nor [^...] match newline.  */
			 : RE_SYNTAX_POSIX_BASIC);
    gettext_noop ("Invalid range end")	/* REG_ERANGE */
  tree = parse_expression (regexp, preg, token, syntax, nest, err);
    if (start_ch > end_ch)
	    *range_alloc = new_nranges;
  *new_set = eclosure;
	      token_len2 = peek_token_bracket (&token2, regexp, syntax);


	  work_tree = create_token_tree (dfa, NULL, NULL, &br_token);
	   the epsilon closure of this node is also incomplete.  */
    gettext_noop ("Invalid regular expression") /* REG_BADPAT */
	  || (end_elem->type == COLL_SYM
      int other_idx = node->left->token.opr.idx;
				      (const char *) start_elem.opr.name, syntax);
  if (BE (ret < 0, 0))
	  default:
    case ')':
   of OP_OPEN_SUBEXP, the body of the SUBEXP (if any) and OP_CLOSE_SUBEXP.  */
static bin_tree_t *parse_sub_exp (re_string_t *regexp, regex_t *preg,
	  break;
      if (!(syntax & RE_LIMITED_OPS) && (syntax & RE_NO_BK_VBAR))
  re_dfa_t *dfa = (re_dfa_t *) extra;
peek_token_bracket (re_token_t *token, re_string_t *input, reg_syntax_t syntax)
      token_len = peek_token_bracket (token, regexp, syntax);

	 that is the user's responsibility.  If ->buffer is NULL this
free_token (re_token_t *node)
static int fetch_number (re_string_t *input, re_token_t *token,
static reg_errcode_t create_initial_state (re_dfa_t *dfa);
	  break;
  return 1;
	      break;
  int32_t table_size;
    ret = REG_EPAREN;
    goto build_word_op_espace;
    codeset_name = "";
      break;
  for (i = 0, ch = 0; i < BITSET_WORDS; ++i)
      if (BE (*err != REG_NOERROR && tree == NULL, 0))

	  if (token->type == OP_CHARSET_RANGE)
	  if (MB_CUR_MAX == 1)
*/
      if (BE (*err != REG_NOERROR && exp == NULL, 0))
	  return NULL;
	 size_t name_len;
	  ret = re_node_set_insert_last (dfa->inveclosures + elems[idx], src);
  re_token_t start_token;
	      int32_t *new_coll_syms = re_realloc (mbcset->coll_syms, int32_t,
/* Helper function for re_compile_fastmap.
		  utf8_sb_map[i] = BITSET_WORD_MAX;
#ifdef _LIBC
	  mbcset->range_starts[mbcset->nranges] = start_collseq;

	  case LINE_LAST:
weak_function
  /* If the current node has constraints, duplicate all nodes
			 class_name, 0);
	else
#ifdef RE_ENABLE_I18N
	 *
	    wchar_t *new_array_start, *new_array_end;
      token->type = CHARACTER;
      return NULL;
  int incomplete = 0;

    {
	    {
{
	      break;

    BUILD_CHARCLASS_LOOP (isdigit);
	{
    gettext_noop ("Unmatched ) or \\)") /* REG_ERPAREN */
	 const unsigned char *name;
  /* We treat the first ']' as a normal character.  */

	}

		? __btowc (start_ch) : start_elem->opr.wch);
	return REG_EBRACK;
	  */
     superset of ASCII.  */
	/ \
    case '\n':

  preg->can_be_null = 0;
      if (isalnum (ch) || ch == '_')
      uint32_t end_collseq;
#else
      if (MB_CUR_MAX > 1)
	  }
	return NULL;
	      token->opr.ctx_type = INSIDE_WORD;
static bin_tree_t *parse (re_string_t *regexp, regex_t *preg,
   character used by some operators like "\<", "\>", etc.  */
}
# else /* not RE_ENABLE_I18N */
   backreferences as well.  Requires a preorder visit.  */
	  /* Compare only if the length matches and the collation rule
      err = re_node_set_init_1 (dfa->edests + idx, node->next->node_idx);
  if (BE (sbcset == NULL, 0))
    }
  return NULL;
      ret = parse_bracket_element (&start_elem, regexp, token, token_len, dfa,
      if (node->left)
    case OP_SPACE:
    default:
	    incomplete = 1;
	  re_node_set_empty (dfa->edests + clone_node);

    }
free_workarea_compile (regex_t *preg)

	    return collseqmb[br_elem->opr.ch];

  dfa->str_tree_storage_idx = BIN_TREE_STORAGE_SIZE;

	      *err = REG_BADBR; /* <re>{} is invalid.  */
static bin_tree_t *parse_expression (re_string_t *regexp, regex_t *preg,
    }
      else
      size_t name_len = strlen ((const char *) name);
    }
    wint_t start_wc;
      for (i = 2; i <= start; ++i)
	    return NULL;
      break;
	  const bin_tree_t *prev = NULL;
  /* Since `re_exec' always passes NULL for the `regs' argument, we
  /* We only need this during the prune_impossible_nodes pass in regexec.c;
      if (BE (start_elem->type == EQUIV_CLASS || start_elem->type == CHAR_CLASS

				 int nest, reg_errcode_t *err);


       buffer.  This function never fails in this implementation.  */
	}
      for (i = 0; i < preg->re_nsub; i++)
#ifdef _LIBC
  else
      break;
	{
  return -1; /* Not found.  */

     the back-references.  */
	      uint32_t *new_array_end;
      if (!BE (dfa->completed_bkref_map & (1 << token->opr.idx), 1))
   <exp1> <exp2>
#ifndef RE_TOKEN_INIT_BUG
      work_tree = create_token_tree (dfa, NULL, NULL, &br_token);
  if (dfa->nbackref > 0)
# endif
	  char prev = re_string_peek_byte (input, -1);
build_equiv_class (bitset_t sbcset, re_charset_t *mbcset,
	     of the destination of the back reference, and store it in
	    return __collseq_table_lookup (collseqwc, br_elem->opr.wch);
   Lesser General Public License for more details.
  dfa->eclosures[node].nelem = -1;
	return REG_ECOLLATE;

{
	{

}
static bin_tree_t *
  sbcset = (re_bitset_ptr_t) calloc (sizeof (bitset_t), 1);
				       dfa, syntax, 1);
      else
      {
      elem = duplicate_tree (elem, dfa);
  reg_errcode_t err;
   COLL_SYM_ALLOC is the allocated size of mbcset->coll_sym, is a
	      bin_tree_t *mbc_remain;
  re_free (dfa);

	}
      && (node->token.opr.idx >= BITSET_WORD_BITS
    gettext_noop ("Unmatched \\{") /* REG_EBRACE */
		  re_string_skip_bytes (regexp, -token_len);
	    {
	    {

	{
	re_node_set_free (dfa->eclosures + i);
   "word".  In this case "word" means that it is the word construction
      }
	    {
    REG_NOERROR_IDX,
      if (token2.type != OP_CLOSE_BRACKET)
}
static reg_errcode_t
      if ((syntax & RE_CONTEXT_INVALID_DUP)
  unsigned char c;
{
  /* If it is non-matching list.  */
	{
		  new_mbchars = re_realloc (mbcset->mbchars, wchar_t,
/* Search for a node which is duplicated from the node ORG_NODE, and
    gettext_noop ("Success")	/* REG_NOERROR */
  dfa->re_str = re_malloc (char, length + 1);
      c = token->opr.c;
     `syntax' to RE_SYNTAX_POSIX_EXTENDED if the
  /* We can handle no multi character collating elements without libc
   from either regcomp or regexec.   We don't use PREG here.  */
				      re_token_t *token, reg_syntax_t syntax,
/* Free the allocated memory inside NODE. */
    BUILD_CHARCLASS_LOOP (isprint);
	  return 1;
					       new_char_class_alloc);
  return REG_NOERROR;
      cp = name;
	return tree;

      old_tree = tree;
re_set_fastmap (char *fastmap, int icase, int ch)
   I'm not sure, but maybe enough.  */
    node->token.opt_subexp = 1;
	  return NULL;
	case '(':
	  end_elem.opr.name = end_name_buf;
       However, for !_LIBC we have no collation elements: if the

				      const re_token_t *token);
  return REG_NOERROR;

    gettext_noop ("Invalid preceding regular expression") /* REG_BADRPT */
  if (token->type == OP_CLOSE_SUBEXP)
      node->right = lower_subexp (&err, preg, node->right);
  else
static bin_tree_t *build_charclass_op (re_dfa_t *dfa,
	  if ((syntax & RE_INTERVALS) && (!(syntax & RE_NO_BK_BRACES)))
      dfa = re_realloc (preg->buffer, re_dfa_t, 1);
build_range_exp (bitset_t sbcset, bracket_elem_t *start_elem,
  return gettext (__re_error_msgid + __re_error_msgid_idx[(int) ret]);
{
      table = (const int32_t *) _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);
  reg_errcode_t ret;
#else /* not RE_ENABLE_I18N */
    case ']':
	    }
      case ANCHOR:
    postorder (elem, mark_opt_subexp, (void *) (intptr_t) elem->token.opr.idx);
	  return;
      break;

  int i;
  reg_syntax_t syntax = ((cflags & REG_EXTENDED) ? RE_SYNTAX_POSIX_EXTENDED
#ifdef RE_ENABLE_I18N

	      if (BE (clone_dest == -1, 0))
	    }
     Build the character class which is represented by NAME.
init_dfa (re_dfa_t *dfa, size_t pat_len)
    {
#endif
				      const char *class_name,
#endif /* RE_ENABLE_I18N */
	    token->type = OP_CLOSE_SUBEXP;
	{
				void *extra);
      return UINT_MAX;
		  /* We treat the last '-' as a normal character.  */
      br_token.type = COMPLEX_BRACKET;
	if (type == OP_BACK_REF)
#endif
	  {
      token->opr.c = c2;

      if (BE (idx1 == 0 || cp < name + strlen ((const char *) name), 0))
static reg_errcode_t analyze (regex_t *preg);
	  prev = node;
	      wint_t wc = __btowc (br_elem->opr.ch);
	  token->type = CHARACTER;

	    new_array_start = re_realloc (mbcset->range_starts, wchar_t,
}
    }

      clone_node = clone_dest;
	  /* Not enough, realloc it.  */
#ifndef _LIBC
    case OP_CLOSE_SUBEXP:
      if (BE ((syntax & RE_NO_EMPTY_RANGES) && start_collseq > end_collseq, 0))
	 int *range_alloc;
		  idx += 1 + extra[idx];
    {

  bufp->newline_anchor = 1;
	case 'b':
	  if (!(syntax & RE_NO_GNU_OPS))
	    if (BE (new_array_start == NULL || new_array_end == NULL, 0))
#endif
	}
      if (org_node == dfa->org_indices[idx]
  incomplete = 0;
	    ch_collseq = collseqmb[ch];
  if (token->type == OP_CLOSE_BRACKET)
      preg->allocated = sizeof (re_dfa_t);
	  *err = REG_BADBR;
#ifdef RE_ENABLE_I18N
					  re_string_cur_idx (input) + 1);
	    {
    /* Only error codes returned by the rest of the code should be passed
	  return REG_NOERROR;
      elem->opr.wch = re_string_wchar_at (regexp, re_string_cur_idx (regexp));
      }						\
{
      switch (c2)
{
    if (mbcset)
      return token_len;
	    case COLL_SYM:
      return elem;
      tree = build_charclass_op (dfa, regexp->trans,
	  clone_dest = duplicate_node (dfa, org_dest, constraint);
    }

  if (nrules != 0)
{
		}
parse_expression (re_string_t *regexp, regex_t *preg, re_token_t *token,
  if (dfa->state_table)
      /* mb_partial and word_char bits should be initialized already
      org_node = org_dest;
  bin_tree_t *tree, *branch = NULL;
   EOR means end of regular expression.  */
# ifdef HAVE_LANGINFO_CODESET
    }
/* Entry point of the parser.
  unsigned int constraint = init_constraint;
   This file is part of the GNU C Library.
	      token->opr.ctx_type = WORD_FIRST;

		if (w & ((bitset_word_t) 1 << j))
				re_token_type_t type);
	    }
	{
	  if (!(syntax & RE_LIMITED_OPS) && (syntax & RE_BK_PLUS_QM))
      return NULL;
	      /* +1 in case of mbcset->ncoll_syms is 0.  */

  else if (strcmp (class_name, "print") == 0)
	}
	 the closing bracket.  Everything else is an error.  */
  if (BE (dfa->str_tree == NULL, 0))
				      bitset_t sbcset,

      token->type = ANCHOR;
   CAT means concatenation.
      tree = parse_dup_op (tree, regexp, dfa, token, syntax, err);
internal_function
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
  re_token_t t;
/* Entry points compatible with 4.2 BSD regex library.  We don't define

    {
    switch (dfa->nodes[node].type)
    }
	  else
#endif /* _REGEX_RE_COMP */
  preg->no_sub = !!(cflags & REG_NOSUB);
		  /* Adjust for the alignment.  */
      return NULL;
{
  assert (dfa->nodes_len > 0);
{
  for (node = root; ; )
	      token->opr.ctx_type = BUF_FIRST;



  tree->next = NULL;
parse_bracket_symbol (bracket_elem_t *elem, re_string_t *regexp,
    default:
  if (BE (err != REG_NOERROR, 0))
    {
    }
       REG_EXTENDED bit in CFLAGS is set; otherwise, to
	  /*
	  {
/* Parse a bracket symbol in the bracket expression.  Bracket symbols are
    }
   syntax, so it can be changed between regex compilations.  */
      dfa->nodes[dup_idx].constraint |= dfa->nodes[org_idx].constraint;
  /* Force allocation of str_tree_storage the first time.  */
      /* Must not happen?  */
					re_charset_t *mbcset,
					     mbcset, &coll_sym_alloc,
    return parse_bracket_symbol (elem, regexp, token);
    }

      if (BE (start == -2 || end == -2, 0))
	  /* else fall through.  */
    gettext_noop ("Invalid collation character") /* REG_ECOLLATE */
#endif /* not _LIBC */
			  != (size_t) -1)
     don't need to initialize the pattern buffer fields which affect it.  */
      if (BE (token->type == END_OF_RE, 0))
  /* Expand each epsilon destination nodes.  */
  op->token.opt_subexp = cls->token.opt_subexp = node->token.opt_subexp;
		   : 0));
  uint32_t nrules;
	  /* mb_partial and word_char bits should be already initialized by
	 re_charset_t *mbcset;
	  token->type = OP_OPEN_COLL_ELEM;
				 reg_syntax_t syntax, reg_errcode_t *err);
      tree = elem;
  if (BE (sbcset == NULL, 0))
      break;
    case OP_OPEN_BRACKET:
weak_alias (__regcomp, regcomp)
	      : ((end_elem->type == COLL_SYM) ? end_elem->opr.name[0]
	  if (BE (*err != REG_NOERROR, 0))
      if (BE (tree == NULL, 0))
      return NULL;

      fetch_token (token, regexp, syntax);
						   new_equiv_class_alloc);
/* This function build the following tree, from regular expression
    case OP_NOTWORD:
	  mb_chars = 1;
  re_free (cset);
	  re_node_set_empty (dfa->edests + clone_node);
  re_string_skip_bytes (input, peek_token (result, input, syntax));
}
      if (syntax & RE_HAT_LISTS_NOT_NEWLINE)
				reg_errcode_t (fn (void *, bin_tree_t *)),
      dfa->subexp_map[other_idx] = dfa->subexp_map[node->token.opr.idx];
   PREG is a regex_t *.  We do not expect any fields to be initialized,
  if (BE (tree == NULL, 0))

#ifdef RE_ENABLE_I18N
      break;

    }
  /* We don't check ERR here, since the initial state must not be NULL.  */
	  else
	  break;
  syntax |= (cflags & REG_ICASE) ? RE_ICASE : 0;
      len = weights[idx1 & 0xffffff];
    }
	    }

    if (start_wc == WEOF || end_wc == WEOF)
	  if (!(syntax & RE_NO_GNU_OPS))
      default:

  if (BE (dfa != NULL, 1))

{
static int
  for (idx = 0; idx < dfa->nodes_len; ++idx)
    case OP_PERIOD:
	  tree = create_token_tree (dfa, NULL, NULL, token);
		       reg_syntax_t syntax, int accept_hyphen)
		  return *(unsigned int *) (extra + idx);
	    bitset_set (sbcset, trans[i]);	\

      if (BE (dfa->inveclosures == NULL, 0))
	case '>':
		  it is caught by SIMPLE_BRACKET).  */
   [=<equivalent_class>=].  */
      break;
      {

				      bitset_t sbcset,
      /* else fall through  */
/* Our parse trees are very unbalanced, so we cannot use a stack to
     `newline_anchor' to REG_NEWLINE being set in CFLAGS;
  /* Build a tree for simple bracket.  */
	  node = node->right;
}
      mbc_tree = create_token_tree (dfa, NULL, NULL, &br_token);
      *char_class_alloc = new_char_class_alloc;
		{
	    }
    re_free (dfa->sb_char);
#define REG_ERPAREN_IDX	(REG_ESIZE_IDX + sizeof "Regular expression too big")
	{
    {
    {
	  {
  build_collating_symbol (sbcset, mbcset, coll_sym_alloc, name)
	   calculate now. Otherwise use calculated epsilon closure.  */
	      /* There is no such duplicated node, create a new one.  */
      free_dfa_content (dfa);
	  token->type = OP_OPEN_EQUIV_CLASS;
	else
	      /* No valid character, treat it as a normal
    }
#endif
    {
    {
/* Fetch a token from INPUT.
      if (start == end)
	/* The actual error value is not standardized since this whole
	      bitset_set (sbcset, name[0]);
	}
static reg_errcode_t link_nfa_nodes (void *extra, bin_tree_t *node);
     Seek the collating symbol entry correspondings to NAME.
	for (i = 0; i < SBC_MAX; ++i)		\
	  return NULL;
      preg->buffer = (unsigned char *) dfa;
#endif
	      new_nranges = 2 * mbcset->nranges + 1;
#endif
	    }

  while (token->type == OP_ALT)
	  re_token_t next;
      node->left->next = node;

	  if (!(syntax & RE_NO_GNU_OPS))
	  tree = create_tree (dfa, tree, exp, CONCAT);
static reg_errcode_t
      else
	  /* Check the space of the arrays.  */
				 + __re_error_msgid_idx[(int) REG_ESPACE]);
  return REG_NOERROR;
	 || token->type == OP_DUP_QUESTION || token->type == OP_OPEN_DUP_NUM)
		 re_charset_t *mbcset, int *char_class_alloc,
	   && node->left && node->left->token.type == SUBEXP)
	  peek_token (&next, input, syntax);
  t.type = type;
  else if (strcmp (class_name, "punct") == 0)
  return err;
static bitset_t utf8_sb_map;
   to their own constraint.  */
  dfa->nodes_alloc = pat_len + 1;

*/
	  break;
	  tree_last = create_token_tree (dfa, NULL, NULL, token);
	    && wcscoll (cmp_buf + 2, cmp_buf + 4) <= 0)
     setting no_sub, unless RE_NO_SUB is set.  */
	      while (++c != 0);
	      return REG_NOERROR;
const char *
  re_free (sbcset);
	  end = ((token->type == OP_CLOSE_DUP_NUM) ? start
	continue;
	case '+':
build_collating_symbol (bitset_t sbcset, re_charset_t *mbcset,
    return NULL;
	  return NULL;
  if (dfa->mb_cur_max > 1)
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;

	{
	tree = exp;
	c2 = re_string_peek_byte (input, 1);
char *
      && strcmp (_NL_CURRENT (LC_CTYPE, _NL_CTYPE_CODESET_NAME), "UTF-8") == 0)
      if (BE (elem == NULL || tree == NULL, 0))
    }
      tree = parse_reg_exp (regexp, preg, token, syntax, nest, err);
    BUILD_CHARCLASS_LOOP (is_blank);
      non_match = 1;
	       opr.ctx_type since constraints (for all DFA nodes) are
  return tree;
#endif /* RE_ENABLE_I18N */
#endif /* RE_ENABLE_I18N */
static bin_tree_t *
	  *err = REG_ESPACE;
   "[[.a-a.]]" etc.  */
  const bin_tree_t *node;
	      *err = REG_ESPACE;
	 of having both SIMPLE_BRACKET and COMPLEX_BRACKET.  */
	token->type = OP_OPEN_SUBEXP;
	  elem = duplicate_tree (elem, dfa);
	  else if (sym_name_len == 1)
  int i, start, end, start_idx = re_string_cur_idx (regexp);
	  if (!incomplete)
      break;
    return REG_ESPACE;
	{
      if (BE (tree == NULL, 0))
void
	      ? __btowc (end_ch) : end_elem->opr.wch);
      token->type = CHARACTER;
      reg_errcode_t err;
       to this routine.  If we are given anything else, or if other regex
    case OP_DUP_QUESTION:
#if defined _REGEX_RE_COMP || defined _LIBC

	case '|':
   Note that duplicated nodes have constraint INIT_CONSTRAINT in addition

    REG_BADBR_IDX,
      if (dfa->inveclosures != NULL)
#endif
	return REG_ECOLLATE;
  if (BE (err != REG_NOERROR, 0))
	return REG_ESPACE;
	  {

	token->type = OP_DUP_QUESTION;
	  if (clone_dest == -1)
  tree->parent = NULL;
#ifdef DEBUG
    return REG_ESPACE;
     Build the equivalence class which is represented by NAME.
weak_alias (__re_set_syntax, re_set_syntax)
#endif
	  || dfa->eclosures == NULL, 0))
	     destination.  */
    }
	{
      re_free (preg->fastmap);
   modify it under the terms of the GNU Lesser General Public
  if (codeset_name == NULL || codeset_name[0] == '\0')
      br_token.opr.sbcset = sbcset;

				  int nest, reg_errcode_t *err);
  int coll_sym_alloc = 0, range_alloc = 0, mbchar_alloc = 0;
#endif
	{
internal_function
   <exp1><exp2>:
  /* Ensure only single byte characters are set.  */
    return REG_ESPACE;
	{
	{
  return REG_NOERROR;
	return idx; /* Found.  */
parse_branch (re_string_t *regexp, regex_t *preg, re_token_t *token,
{
  /* Yes, we're discarding `const' here if !HAVE_LIBINTL.  */
#endif
  /* Release work areas.  */
#define REG_ESIZE_IDX	(REG_EEND_IDX + sizeof "Premature end of regular expression")
	  return NULL;

   return wtmp[0];
    /*
#endif /* not _LIBC */
  re_charset_t *mbcset;
	  continue;
  reg_errcode_t ret;
		    _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);
}
{
      c2 = re_string_peek_byte (input, 0);
    {
  }
      tree = build_charclass_op (dfa, regexp->trans,
	  wint_t wc = re_string_wchar_at (input,
  if (mb_chars || has_period)
      break;


      if (start_ch <= ch  && ch <= end_ch)
	case '}':
	   CAT
  tree->token.opt_subexp = 0;
	break;


#endif
    }

    case '+':
	}
      if (dfa->mb_cur_max > 1)
				      reg_errcode_t *err);
      preg->allocated = 0;
      unsigned char c2;
    case '}':
    }
      node->left = node->left->left;
    preg->newline_anchor = 0;
	    {

			int root_node, unsigned int init_constraint)
create_initial_state (re_dfa_t *dfa)
#ifdef RE_ENABLE_I18N
    {
	    goto parse_dup_op_espace;
    }
      dfa->nexts[idx] = node->next->node_idx;
    start_ch = ((start_elem->type == SB_CHAR) ? start_elem->opr.ch
  /* The subexpression may be a null string.  */
    {
  return tree;
  if (!ret)
	      clone_dest = duplicate_node (dfa, org_dest, constraint);
      /* Get information about the next token.  We need it in any case.  */
  memset (dfa, '\0', sizeof (re_dfa_t));
					  size_t length, reg_syntax_t syntax);
      else
}
    re_compile_fastmap_iter (bufp, dfa->init_state_word, fastmap);
  dfa->map_notascii = 0;
    }
static void free_token (re_token_t *node);
    {
  if (BE (errcode < 0
	case '1': case '2': case '3': case '4': case '5':

calc_next (void *extra, bin_tree_t *node)


	node->right->parent = node;
   since POSIX says we shouldn't.  Thus, we set
  if (dfa->sb_char != utf8_sb_map)
#ifdef RE_ENABLE_I18N
lower_subexp (reg_errcode_t *err, regex_t *preg, bin_tree_t *node)
				  int nest, reg_errcode_t *err);

      /* FALLTHROUGH */
      dfa->used_bkref_map |= 1 << token->opr.idx;
    }
     mbcset->range_ends, is a pointer argument since we may
  tree = &dfa->str_tree_storage->data[dfa->str_tree_storage_idx++];
	switch (dfa->nodes[node].opr.ctx_type)
  token->opr.c = c;
      tree = create_tree (dfa, tree, NULL, OP_ALT);
  unsigned char c;

	}

	  re_string_cur_idx (input) != 0)
					    int accept_hyphen);
	  continue;
# endif
      unsigned char char_buf[2];
    }
	}
    re_compile_internal_free_return:
}
      while (node->right == prev || node->right == NULL);
      if (start_elem.type != CHAR_CLASS && start_elem.type != EQUIV_CLASS)
    case CONCAT:
	  idx2 = findidx (&cp);

    REG_ESPACE_IDX,
  const char *collseqwc;
      int32_t hash = elem_hash ((const char *) name, name_len);
static reg_errcode_t
    {
	  /* First number greater than second.  */
      preg->newline_anchor = 1;
      break;
}
	return REG_ESPACE;
	  re_set_fastmap (fastmap, icase, dfa->nodes[node].opr.c);
	  *err = REG_ESPACE;
}
		 && !re_string_first_byte (regexp, re_string_cur_idx (regexp)))
	  org_dest = dfa->nexts[org_node];
	      if (_NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES) != 0
					    root_node, constraint);
	  if (len == weights[idx2 & 0xffffff] && (idx1 >> 24) == (idx2 >> 24))

	  org_dest = dfa->edests[org_node].elems[0];

  if (c == '\\' && (syntax & RE_BACKSLASH_ESCAPE_IN_LISTS)
      /* Build a tree for complex bracket.  */



	    }

#if 0


calc_eclosure_iter (re_node_set *new_set, re_dfa_t *dfa, int node, int root)
  volatile re_dfa_t *dfa = (re_dfa_t *) bufp->buffer;
	 a
      err = calc_eclosure_iter (&eclosure_elem, dfa, node_idx, 1);
#endif
  else if (strcmp (class_name, "graph") == 0)

			       reg_errcode_t (fn (void *, bin_tree_t *)),
      if (BE (mbc_tree != NULL, 1))
	  re_charset_t *cset = dfa->nodes[node].opr.mbcset;
	      {
   Contributed by Isamu Hasegawa <isamu@yamato.ibm.com>.
    end_wc = ((end_elem->type == SB_CHAR || end_elem->type == COLL_SYM)
	  || token->opr.ctx_type == NOT_WORD_DELIM)
	    goto parse_bracket_exp_espace;
static int

	      wchar_t wc;
	      token->opr.ctx_type = NOT_WORD_DELIM;
		{
  /* Equivalence Classes and Character Classes can't be a range start/end.  */
      if (BE (node->node_idx == -1, 0))
  int idx = (int) (intptr_t) extra;

    case OP_NOTSPACE:
	  node = node->parent;

	  || errcode >= (int) (sizeof (__re_error_msgid_idx)
    }
  for (i = start + 2; i <= end; ++i)
  if (cur_nsub <= '9' - '1')
    {

   different, incompatible syntaxes.
    {

  if (re_string_eoi (input))

static reg_errcode_t postorder (bin_tree_t *root,
  return REG_NOERROR;
      if (i == preg->re_nsub)

#else

	{
/* Duplicate the node whose index is ORG_IDX and set the constraint CONSTRAINT.
#define REG_EBRACE_IDX	(REG_EPAREN_IDX + sizeof "Unmatched ( or \\(")
	case 's':
	  *err = REG_BADPAT;
      assert (0);
  dfa->word_ops_used = 1;
	  re_node_set_empty (dfa->edests + clone_node);
   <reg_exp>  EOR
	  branch = parse_branch (regexp, preg, token, syntax, nest, err);
#ifdef RE_ENABLE_I18N
	assert (left > -1);
  if (BE (err != REG_NOERROR, 0))
  if (BE (preg->fastmap == NULL, 0))
#define REG_EBRACK_IDX	(REG_ESUBREG_IDX + sizeof "Invalid back reference")
}
	  && (token->type == OP_DUP_ASTERISK
  if (dfa->is_utf8 && !(syntax & RE_ICASE) && preg->translate == NULL)
	}
#endif /* not RE_ENABLE_I18N */
#ifdef RE_ENABLE_I18N
   Compile the regular expression PATTERN, whose length is LENGTH.
      if (!(syntax & RE_LIMITED_OPS) && !(syntax & RE_BK_PLUS_QM))
static int search_duplicated_node (const re_dfa_t *dfa, int org_node,
	      return NULL;
weak_alias (__re_compile_fastmap, re_compile_fastmap)
	has_period = 1;
  lookup_collation_sequence_value (br_elem)
  if (BE (*err != REG_NOERROR && tree == NULL, 0))
	    re_token_t *clexp_node;
parse_sub_exp (re_string_t *regexp, regex_t *preg, re_token_t *token,
	    token->type = OP_OPEN_DUP_NUM;
    {
	{
			 mbcset, &alloc,
    end_ch = ((end_elem->type == SB_CHAR ) ? end_elem->opr.ch
		    {
   Compile fastmap for the initial_state INIT_STATE.  */
	{
	}
  auto inline int32_t
	  dfa->sb_char = (re_bitset_ptr_t) utf8_sb_map;
  dfa->syntax = syntax;
					mbcset, &equiv_class_alloc,

  re_bitset_ptr_t sbcset;
    gettext_noop ("Trailing backslash") /* REG_EESCAPE */
  dfa->edests = re_malloc (re_node_set, dfa->nodes_alloc);
	     has a loop.   Then tie it to the destination of the root_node.  */
# ifndef _LIBC
   The result are written to MBCSET and SBCSET.

		{
    case OP_OPEN_DUP_NUM:
      if (nrules > 0 || dfa->mb_cur_max > 1)
	  dfa->nodes[node].mb_partial = 0;
}
#ifdef DEBUG
regcomp (regex_t *__restrict preg,
	      else
	  if (BE (dfa->sb_char == NULL, 0))
	goto parse_dup_op_espace;
    {
  /* This loop is actually executed only when end != -1,
#ifdef RE_ENABLE_I18N
  if (pat_len == SIZE_MAX)
    case '^':
      return 0;

	    {
static struct re_pattern_buffer re_comp_buf;
	{
    {
	return tree;
	      re_free (buf);
}

		*p++ = dfa->nodes[node].opr.c;
  switch (c)
/* Entry point for POSIX code.  */
parse (re_string_t *regexp, regex_t *preg, reg_syntax_t syntax,
	  /* In case of the node can epsilon-transit, and it has two
    }
# ifdef RE_ENABLE_I18N
static void optimize_utf8 (re_dfa_t *dfa);
	  /* In case of the node has another constraint, add it.  */
    for (i = 0; i < dfa->nodes_len; ++i)
    }

      free_token (dfa->nodes + i);
		goto parse_bracket_exp_free_return;
	  ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
  for (node = root; ; )
  mbcset->char_classes[mbcset->nchar_classes++] = __wctype (class_name);
	else if (dfa->nodes[node].type == OP_PERIOD)
  err = re_string_construct (&regexp, pattern, length, preg->translate,
     If REG_EXTENDED is set, we use POSIX extended syntax; otherwise, we
    }
	   / \
#endif
      token->type = CHARACTER;
  fastmap[ch] = 1;
      size_t len;

	}

	{
    case OP_ALT:
	case 'B':

  preg->used = 0;
      __regfree (&re_comp_buf);
  if (BE (dfa->init_state == NULL, 0))
  ret = re_compile_internal (&re_comp_buf, s, strlen (s), re_syntax_options);
   The argument SYNTAX is a bit mask comprised of the various bits
	  break;
     Return the index of the symbol in the SYMB_TABLE.  */
	{
    left->parent = tree;
	  return NULL;
  int idx;
static reg_errcode_t

					 int node, int root);
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
  auto inline reg_errcode_t
  if (BE (start > 0, 0))
static bin_tree_t *
#ifdef RE_ENABLE_I18N
					new_nranges);
  bin_tree_t *tree = NULL, *old_tree = NULL;
	{
      if (token->opr.ctx_type == WORD_DELIM
    {
   satisfies the constraint CONSTRAINT.  */

      int i;
	    }
     Also, regexec will try a match beginning after every newline.
     use POSIX basic syntax.
	    {
    return NULL;
	{
  for (node_cnt = 0; node_cnt < init_state->nodes.nelem; ++node_cnt)
  else
		     character.  */
	  if (!(syntax & RE_NO_BK_REFS))
   available.  */
#endif /* not RE_ENABLE_I18N */
	  /* Use realloc since the array is NULL if *alloc == 0.  */

      /* We must return here, since ANCHORs can't be followed
    /* Compute the fastmap now, since regexec cannot modify the pattern
{
	  if (BE (work_tree == NULL, 0))
  dfa->state_hash_mask = table_size - 1;
  first = dfa->str_tree->first->node_idx;
  re_free (cset->range_ends);
  /* Local function for parse_bracket_exp only used in case of NOT _LIBC.
      symb_table = (const int32_t *) _NL_CURRENT (LC_COLLATE,
      dfa->has_mb_node = 1;
    {
						   int32_t,
	case '`':
	      return NULL;
     OP_OPEN_SUBEXP, the contents, and an OP_CLOSE_SUBEXP.  */
			int *coll_sym_alloc, const unsigned char *name)
# ifdef RE_ENABLE_I18N
# endif
#define BUILD_CHARCLASS_LOOP(ctype_func)	\
	       reg_syntax_t syntax, int nest, reg_errcode_t *err)
#ifdef RE_ENABLE_I18N
  tree = create_token_tree (dfa, NULL, NULL, &br_token);
  re_bitset_ptr_t sbcset;
      /* Check start/end collation sequence values.  */
     update it.  */
      elem->type = CHAR_CLASS;
	 int *coll_sym_alloc;
	  re_node_set_free (&eclosure_elem);
	 start/end.  */
	    default:
}
		  if (BE (new_mbchars == NULL, 0))
      if (token->type == OP_CLOSE_BRACKET)
      for (ch = 0; ch < SBC_MAX; ch++)
	  if (!(syntax & RE_NO_GNU_OPS))
      start_collseq = lookup_collation_sequence_value (start_elem);
	      err = duplicate_node_closure (dfa, org_dest, clone_dest,
static reg_errcode_t
		  idx += sizeof (unsigned int) *
      idx1 = findidx (&cp);

		  && (__wcrtomb ((char *) buf, towlower (wc), &state)
	  if (!(syntax & RE_NO_GNU_OPS))
		 const char *class_name, reg_syntax_t syntax)
    case OP_OPEN_EQUIV_CLASS:
				 "_",
     Build the collating element which is represented by NAME.
	    bufp->can_be_null = 1;
  re_free (dfa->subexp_map);
	return REG_ECOLLATE;
	    }
    return REG_ECOLLATE;
	    break;
	    }
		  /* Compare the length of the name.  */
	  switch (start_elem.type)
   CFLAGS is a series of bits which affect compilation.
	  if (!(syntax & RE_NO_GNU_OPS))
  re_string_skip_bytes (regexp, token_len); /* Skip a token.  */
  return (int) ret;
	{
{
#endif /* not RE_ENABLE_I18N */
  if (node->token.type == CONCAT)
	return REG_ESPACE;
	  tree = create_tree (dfa, tree, elem, CONCAT);
    {
  tree->first = NULL;
      }
# endif /* _LIBC */
  preg->fastmap = re_malloc (char, SBC_MAX);
					    re_dfa_t *dfa,
	  if (BE (elem == NULL || tree == NULL, 0))
	   & (WORD_DELIM | NOT_WORD_DELIM | WORD_FIRST | WORD_LAST))
				       int non_match, reg_errcode_t *err);
   We must not use this function out of bracket expressions.  */
		re_set_fastmap (fastmap, 0, buf[0]);
optimize_utf8 (re_dfa_t *dfa)
    bitset_not (sbcset);
static reg_errcode_t calc_first (void *extra, bin_tree_t *node);
	      token->type = OP_BACK_REF;
      if (i >= BRACKET_NAME_BUF_SIZE)
	int edest = dfa->edests[node].elems[i];
      dup_node = *p_new;
      tree = create_tree (dfa, tree, elem, CONCAT);
#define REG_EEND_IDX	(REG_BADRPT_IDX + sizeof "Invalid preceding regular expression")
      }
	      if (BE (*err != REG_NOERROR, 0))
      int node = init_state->nodes.elems[node_cnt];
{
      /* Build a tree for complex bracket.  */
		  idx += sizeof (unsigned int);
	      : ((end_elem->type == COLL_SYM) ? end_elem->opr.name[0]
  preg->syntax = syntax;
  bin_tree_t *body = node->left;
	 const char *__restrict pattern,
	}
	 by repetition operators.
#ifdef RE_ENABLE_I18N
    re_node_set_init_empty (dfa->inveclosures + idx);
      int token_len;
  re_string_t regexp;
	  /* Set the bits corresponding to single byte chars.  */
    {
		     weights[(idx1 & 0xffffff) + 1 + cnt]
      break;

int
# endif /* _LIBC */
	 if that's the only child).  */

  re_free (preg->fastmap);
	{
	c2 = 0;
/* Duplicate the epsilon closure of the node ROOT_NODE.
#ifdef _LIBC
  return REG_NOERROR;
/* Lowering pass: Turn each SUBEXP node into the appropriate concatenation
	  if (!(syntax & RE_NO_GNU_OPS))
	default:
	  token->opr.c = c;
      /* Then join them by ALT node.  */
	  }
  {
static reg_errcode_t build_equiv_class (bitset_t sbcset,
      if (dfa->eclosures[node_idx].nelem != 0)
      return tree;
		}
  __attribute ((always_inline))
	  goto parse_bracket_exp_free_return;
  err = re_node_set_alloc (&eclosure, dfa->edests[node].nelem + 1);
      for (i = 0; i < preg->re_nsub; i++)
	  *err = build_range_exp (sbcset, mbcset, &range_alloc,
	  if (MB_CUR_MAX == 1)
	  ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
#else
  return msg_size;
					    re_token_t *token, int token_len,
#endif
	    return REG_ESPACE;
      if (BE (strlen ((const char *) name) != 1, 0))
    return ret;
	}
}
	  node = node->right;

	  break;
						  _NL_COLLATE_SYMB_TABLEMB);
	    /* There is not enough space, need realloc.  */
	  if (token->type == CHARACTER && token->opr.c == ',')
       Dump core so we can fix it.  */
	      bitset_word_t w = dfa->nodes[node].opr.sbcset[i];
  size_t name_len = strlen ((const char *) name);



      preg->allocated = 0;
  /* It must be the first time to invoke acquire_state.  */
	      /* Not enough, realloc it.  */
  if (node->token.type == SUBEXP && node->token.opr.idx == idx)
		  idx += 1 + extra[idx];
#ifdef RE_ENABLE_I18N
    }
      {
  if (nrules)
  unsigned char c;
	      token->opr.ctx_type = WORD_DELIM;
re_compile_fastmap (struct re_pattern_buffer *bufp)

      node->node_idx = re_dfa_add_node (dfa, node->token);
  const unsigned char *extra;
}
    start_wc = ((start_elem->type == SB_CHAR || start_elem->type == COLL_SYM)
	abort ();
	    |
		}
      && dfa->edests[node].nelem
    case '?':
	    /* Word anchors etc. cannot be handled.  It's okay to test
  /* And GNU code determines whether or not to get register information
     `re_nsub' to the number of subexpressions in PATTERN.
weak_alias (__re_compile_pattern, re_compile_pattern)
	  if (!(syntax & RE_NO_GNU_OPS))
/* Extended regular expression matching and search library.
/* This table gives an error message for each of the error codes listed
	  incomplete = 1;
  if (BE (ret != REG_NOERROR, 0))
   This function build the following tree, from regular expression <reg_exp>:
	  case BUF_LAST:
      if (BE (dfa->init_state_word == NULL || dfa->init_state_nl == NULL
static reg_errcode_t
					    mbchar_alloc);
	}
      return 1;
internal_function
  preg->translate = NULL;
{

	}

      token->opr.c = c2;
    }
	re_node_set_free (dfa->edests + i);
      token->opr.ctx_type = LINE_FIRST;
/* Free the work area which are only used while compiling.  */
	  if ((bufp->syntax & RE_ICASE) && dfa->mb_cur_max > 1)

   also be assigned to arbitrarily: each pattern buffer stores its own
	      token->type = ANCHOR;
   char tmp[2];
  bin_tree_t *dup_root;
		  idx = symb_table[2 * elem + 1];
     skip it if p_i_n will not run, as calc_inveclosure can be quadratic.  */
	  else
  /* If possible, do searching in single byte encoding to speed things up.  */

  uint32_t nrules = _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
      /* Otherwise exp == NULL, we don't need to create new tree.  */
      int32_t elem, idx;
  cur_nsub = preg->re_nsub++;
      if (node->left)
    return NULL;
  dfa->nexts = re_malloc (int, dfa->nodes_alloc);
	if (node->left)
	      *err = build_equiv_class (sbcset,
   we need more infrastructure to maintain two parallel trees --- so,
  preg->allocated = 0;
       code generates an invalid error code, then the program has a bug.
      reg_errcode_t err = fn (extra, node);
		return REG_ESPACE;
weak_alias (__regfree, regfree)
static void re_compile_fastmap_iter (regex_t *bufp,
    {
	     destination and store the original destination as the
    {
	      token->type = ANCHOR;
  tree = parse_branch (regexp, preg, token, syntax, nest, err);
    case END_OF_RE:
	      bitset_set (sbcset, name[0]);
	      break;
	  reg_errcode_t err = fn (extra, node);
      return NULL;
	  left = node->left->first->node_idx;
#endif /* RE_ENABLE_I18N */
	      mbc_remain = create_token_tree (dfa, NULL, NULL, token);
      /* If there are no bits set in sbcset, there is no point
  if (preg->no_sub
	    err = calc_eclosure_iter (&eclosure_elem, dfa, edest, 0);
  /* Avoid overflows.  */
  /* The back-references which are in initial states can epsilon transit,
	    }

	     sets, the SIMPLE_BRACKET again suffices.  */
				  &start_elem, &end_elem);
/* Functions for binary tree operation.  */
		    size_t length,
      && (codeset_name[1] == 'T' || codeset_name[1] == 't')
	      *coll_sym_alloc = new_coll_sym_alloc;
	}

	  int i;
      re_string_skip_bytes (input, 1);
#ifdef RE_ENABLE_I18N
      token->type = CHARACTER;
	}

#ifdef DEBUG
/* Initialize WORD_CHAR table, which indicate which character is
  for (idx = dfa->nodes_len - 1; dfa->nodes[idx].duplicated && idx > 0; --idx)
    bitset_mask (sbcset, dfa->sb_char);
   a worthwhile optimization.  */
  ret = calc_eclosure (dfa);
      int token_len2 = 0, is_range_exp = 0;

    return REG_ERANGE;
#ifdef _LIBC
	    case EQUIV_CLASS:

	    bitset_set (sbcset, ch);
	      return NULL;
      end = (token->type == OP_DUP_QUESTION) ? 1 : -1;

	re_free (entry->array);
      const unsigned char *weights, *extra, *cp;

	node = node->left;
    return REG_ESPACE;

    REG_EBRACK_IDX,
      /* Check whether the array has enough space.  */

	      else if (symb_table[2 * elem] == 0 && sym_name_len == 1)
  else if (strcmp (class_name, "upper") == 0)
	if (BE (*range_alloc == mbcset->nranges, 0))
    default:
    }
  int ret;
      assert (dfa->eclosures[node_idx].nelem != -1);
	  return elem;
      case SIMPLE_BRACKET:
    wchar_t cmp_buf[6] = {L'\0', L'\0', L'\0', L'\0', L'\0', L'\0'};
				  re_token_t *token, reg_syntax_t syntax,
	  && dfa->word_ops_used == 0)
	  if (BE (!(syntax & RE_INVALID_INTERVAL_ORD), 0))
	  if (BE (new_equiv_classes == NULL, 0))
      br_token.opr.mbcset = mbcset;
   POSIX doesn't require that we do anything for REG_NOERROR,
    cmp_buf[0] = start_wc;
		  if (__mbrtowc (NULL, (char *) &c, 1, &mbs) == (size_t) -2)
	{
	   / \
	  idx2 = table[ch];
    case OP_BACK_REF:

  char *codeset_name;
# else /* not RE_ENABLE_I18N */
#ifndef _LIBC
	  *err = REG_ESUBREG;
   it's easier to duplicate.  */
		 bracket_elem_t *end_elem)
duplicate_node (re_dfa_t *dfa, int org_idx, unsigned int constraint)
	    goto parse_bracket_exp_espace;

	     peek_token.  */
free_charset (re_charset_t *cset)
		  memset (&state, '\0', sizeof (state));
    REG_ECOLLATE_IDX,
  /* strcasecmp isn't a standard interface. brute force check */
      return 2;
     Build the range expression which starts from START_ELEM, and ends
   some hairy code in these two functions.  */
      assert (node->next == NULL);
		   const re_token_t *token)
	  br_token.opr.sbcset = sbcset;
static bin_tree_t *duplicate_tree (const bin_tree_t *src, re_dfa_t *dfa);
  else
		      re_token_t *token)
	case 'S':
      if ((syntax & RE_INTERVALS) && (syntax & RE_NO_BK_BRACES))
      node->token.opr.idx = dfa->subexp_map[idx];
	  *token = start_token;
static reg_errcode_t build_charclass (RE_TRANSLATE_TYPE trans,
	  if (tree == NULL)
  /* Local function for parse_bracket_exp used in _LIBC environment.
		goto parse_bracket_exp_free_return;
		  mbcset->mbchars = new_mbchars;
    {
      br_token.opr.mbcset = mbcset;
	      dup_node = dup_node->parent;
      return REG_NOERROR;
	  else
      for (ch = 0; ch < SBC_MAX; ++ch)
	    return REG_ESPACE;
	  || end_elem->type == EQUIV_CLASS || end_elem->type == CHAR_CLASS,
  if (non_match)
	    }
				      bin_tree_t *left, bin_tree_t *right,
		}
	if (dfa->subexp_map[i] != i)
   Returns 0 if the pattern was valid, otherwise an error string.
      dfa->used_bkref_map |= 1 << node->token.opr.idx;
  ret = re_compile_internal (preg, pattern, strlen (pattern), syntax);
  bufp->fastmap_accurate = 1;
    }
      /* If we have already calculated, skip it.  */
		if (wch != WEOF)

	if (wcscoll (cmp_buf, cmp_buf + 2) <= 0
      num = ((token->type != CHARACTER || c < '0' || '9' < c || num == -2)
/* Mark the tree SRC as an optional subexpression.
	      int cnt = 0;
  return ret;
     Return the value if succeeded, UINT_MAX otherwise.  */
	{
  return REG_NOERROR;
	  }
  };
static reg_errcode_t
	    {
  tree = create_tree (dfa, elem, NULL, (end == -1 ? OP_DUP_ASTERISK : OP_ALT));
	    }
     RANGE_ALLOC is the allocated size of mbcset->range_starts, and
  memset (fastmap, '\0', sizeof (char) * SBC_MAX);
		  /* No valid character.  Match it as a single byte
	      token->opr.ctx_type = WORD_FIRST;

  re_dfa_t *dfa;
  __attribute ((always_inline))

    }
	{
  err = re_node_set_init_copy (&init_nodes, dfa->eclosures + first);
      tree = parse_sub_exp (regexp, preg, token, syntax, nest + 1, err);
	    }

      token->mb_partial = 1;
	     ? -2 : ((num == -1) ? c - '0' : num * 10 + c - '0'));
  int idx = node->node_idx;
	      fetch_token (token, regexp, syntax);
	      assert (0);
	  re_string_cur_idx (input) + 1 != re_string_length (input))
  re_dfa_t *dfa = (re_dfa_t *) preg->buffer;
	      ? end_ch : end_elem->opr.wch);
		? start_ch : start_elem->opr.wch);
    _NL_CURRENT (LC_COLLATE, _NL_COLLATE_COLLSEQMB);
      else
  build_range_exp (sbcset, mbcset, range_alloc, start_elem, end_elem)
#ifdef _LIBC
     already created the start+1-th copy.  */
          : codeset_name[3] == '8' && codeset_name[4] == '\0'))
    case OP_DUP_ASTERISK:
		  const int32_t *table = (const int32_t *)
		{
	      new_array_end = re_realloc (mbcset->range_ends, uint32_t,
#define REG_ESPACE_IDX	(REG_ERANGE_IDX + sizeof "Invalid range end")
	      idx += 1 + extra[idx];
  bin_tree_t *tree;
	  return NULL;
		   reg_syntax_t syntax, reg_errcode_t *err)
	  if (BE (clone_dest == -1, 0))
      && (strcmp (class_name, "upper") == 0 || strcmp (class_name, "lower") == 0))
size_t
static reg_errcode_t

	  break;
    cmp_buf[4] = end_wc;
		return REG_NOERROR;
/* This function build the following tree, from regular expression
      free_dfa_content (dfa);
  tree->right = right;

	  if (node->parent == NULL)
       RE_SYNTAX_POSIX_BASIC;
    }
	  if (BE (tree == NULL, 0))
	err = re_node_set_init_2 (dfa->edests + idx, left, right);
  /* Then create the initial state of the dfa.  */
      break;
  reg_errcode_t ret;
		{
	    token->type = OP_DUP_PLUS;
	mbcset->range_ends[mbcset->nranges++] = end_wc;
  if (BE (dfa->nexts == NULL || dfa->org_indices == NULL || dfa->edests == NULL
	      if (BE (err != REG_NOERROR, 0))
static reg_errcode_t
	}
   but why not be nice?  */
	      if (__mbrtowc (&wc, (const char *) buf, p - buf,
      char_buf[1] = (unsigned char) '\0';
	      token->opr.idx = c2 - '1';
	}
	  mbcset->coll_syms[mbcset->ncoll_syms++] = idx;
   and its children. */

		}
	  && (nest == 0 || token->type != OP_CLOSE_SUBEXP))
    gettext_noop ("No match")	/* REG_NOMATCH */
#ifdef RE_ENABLE_I18N
	      token->opr.ctx_type = WORD_LAST;
	    {
      mbcset->non_match = 1;
   it the same all the time.  UTF-8 is the preferred encoding so this is
				       const char *class_name,
    case '-':
}
{
	  /* If the back reference epsilon-transit, its destination must
  if (dfa->init_state != dfa->init_state_begbuf)

   PATTERN is the address of the pattern string.
    {
      for (idx = 0; idx < dfa->eclosures[src].nelem; ++idx)
#ifdef RE_ENABLE_I18N
	      break;
      node->left = lower_subexp (&err, preg, node->left);
	case '{':
# include <locale/weight.h>
	    break;
  else if (strcmp (class_name, "cntrl") == 0)
#else
/* Specify the precise syntax of regexps for compilation.  This provides
	  *err = REG_BADRPT;
      else if (type == OP_PERIOD
	}
	  fetch_token (token, regexp, syntax);
  else
    "\0"
  if (BE (dup_idx != -1, 1))
	      ret = re_node_set_insert (dfa->edests + clone_node, clone_dest);
	  int i, ch;
				   syntax, first_round);

		  && memcmp (name, &extra[symb_table[2 * elem + 1] + 1],

		  char buf[256];
      if (sbc_idx < BITSET_WORDS)
      storage->next = dfa->str_tree_storage;
      assert (!IS_EPSILON_NODE (node->token.type));
	    }
      uint32_t start_collseq;
  for (table_size = 1; ; table_size <<= 1)
     If REG_NOSUB is set, then when PREG is passed to regexec, that
      return 1;


	  if (!(syntax & RE_LIMITED_OPS) && !(syntax & RE_NO_BK_VBAR))
	  case LINE_FIRST:
	      return NULL;
  /* Match anchors at newlines.  */
      if (BE (*err != REG_NOERROR, 0))
   CAT means concatenation.  */
	       are NULL if *range_alloc == 0.  */
   Return -2, if an error has occurred.  */
static reg_errcode_t

      dfa->str_tree_storage = storage;
  preg->used = 0;
static void free_charset (re_charset_t *cset);
      (*p_new)->parent = dup_node;
  bin_tree_t *tree;
	  if (BE (err != REG_NOERROR, 0))
	      }
	    /* This isn't a valid character.  */
	    }
		return REG_ESPACE;
      if (BE (mbc_tree == NULL, 0))
      collseqwc = _NL_CURRENT (LC_COLLATE, _NL_COLLATE_COLLSEQWC);
	    token->type = OP_CLOSE_DUP_NUM;
	break;
      int sbc_idx;
    "\0"
   in regex.h.  Obviously the order here has to be same as there.
    re_compile_fastmap_iter (bufp, dfa->init_state_nl, fastmap);
				 re_token_t *token, reg_syntax_t syntax,
	  break;
	       || type == OP_UTF8_PERIOD
    BUILD_CHARCLASS_LOOP (islower);
	     e.g. In da_DK, we want to catch 'a' since "aa" is a valid
	    {
	 const unsigned char *name;
  return tree;
#else
  if (node->type == COMPLEX_BRACKET && node->duplicated == 0)

	  if (BE (work_tree == NULL, 0))
    if (wcscoll (cmp_buf, cmp_buf + 4) > 0)
	break;
   License along with the GNU C Library; if not, see
	    break;

    }
static reg_errcode_t
     since in this case all of the subexpressions can be null.

	  memcpy (errbuf, msg, errbuf_size - 1);
	  {
 parse_bracket_exp_free_return:
	  while (node->right == prev || node->right == NULL)
	      token->opr.ctx_type = INSIDE_NOTWORD;
      token->type = OP_CHARSET_RANGE;
      break;
	  break;
	}
    case OP_CLOSE_DUP_NUM:
	    int dest_idx = dfa->edests[node_idx].elems[0];
	  token->type = CHARACTER;
	      tree_first = create_token_tree (dfa, NULL, NULL, token);

    token->word_char = IS_WORD_CHAR (token->opr.c);
	    {
	return NULL;
    {
{
	    continue;
  *err = REG_ESPACE;
static reg_errcode_t re_compile_internal (regex_t *preg, const char * pattern,
    for (wc = 0; wc < SBC_MAX; ++wc)
    REG_ERANGE_IDX,
#endif /* RE_ENABLE_I18N */
	{
  else

	    }

    }
	re_token_type_t type = dfa->nodes[node_idx].type;
   Return -1, if the number field is empty like "{,1}".
	    re_dfastate_t *state = entry->array[j];
  if (old_tree)
		  && name_len == extra[symb_table[2 * elem + 1]]
	  if (nrules != 0)

		 : ((token->type == CHARACTER && token->opr.c == ',')
	      /* First compare the hashing value.  */
    }
      extra = (const unsigned char *) _NL_CURRENT (LC_COLLATE,
					  new_nranges);

/* Pass 3: link all DFA nodes to their NEXT node (any order will do).  */
#endif
	    {
      /* Some error occurred while compiling the expression.  */
build_collating_symbol (bitset_t sbcset, const unsigned char *name)
      err = duplicate_node_closure (dfa, node, node, node,
	}
		return REG_ESPACE;
  if (input->mb_cur_max > 1)
  preg->allocated = 0;
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
  for (i = 0; i < dfa->nodes_len; ++i)
  /* If REG_NEWLINE is set, newlines are treated differently.  */
     */
      mbcset->equiv_classes[mbcset->nequiv_classes++] = idx1;
    }
#endif
	}
	    }
	case '\'':
		  return err;
  tree->left = left;
		if (err != REG_NOERROR)
   <http://www.gnu.org/licenses/>.  */
  return NULL;

    }
#endif
	int clexp_idx;
    "\0"
	      /* There is not enough space, need realloc.  */
    BUILD_CHARCLASS_LOOP (iscntrl);
	err = re_node_set_init_1 (dfa->edests + idx, dfa->nexts[idx]);
peek_token (re_token_t *token, re_string_t *input, reg_syntax_t syntax)
    {
  [0 ... 0x80 / BITSET_WORD_BITS - 1] = BITSET_WORD_MAX
				     const re_dfastate_t *init_state,
	return REG_EBRACK;
{
   License as published by the Free Software Foundation; either
	  if (nrules != 0)
      else
					start_elem.opr.name);
    {
      num = (num > RE_DUP_MAX) ? -2 : num;
      dfa->inveclosures = re_malloc (re_node_set, dfa->nodes_len);
  free_charset (mbcset);
	    return REG_NOERROR;
      if (BE (*err != REG_NOERROR && tree == NULL, 0))
	      return err;
   <branch1>|<branch2>:
     by passing null for the REGS argument to re_match, etc., not by
      for (sbc_idx = 0; sbc_idx < BITSET_WORDS; ++sbc_idx)

    BUILD_CHARCLASS_LOOP (isupper);
	  break;
	{
    default:
	}
  if (token->type == OP_OPEN_DUP_NUM)
#endif /* _LIBC */
    root = eor;
  ret = preorder (dfa->str_tree, link_nfa_nodes, dfa);
#endif
  preg->fastmap = NULL;
	 bracket_elem_t *br_elem;
#ifdef _LIBC
#endif /* RE_ENABLE_I18N */
  bin_tree_t *op, *cls, *tree1, *tree;
}
#endif /* not RE_ENABLE_I18N */
				     re_token_t *token, reg_syntax_t syntax,
  dfa->nodes = re_malloc (re_token_t, dfa->nodes_alloc);
	      mbcset->range_ends = new_array_end;
	  for (i = 0, ch = 0; i < BITSET_WORDS; ++i)
   visit similar to the one implemented by the generic visitor, but

  if ((!preg->no_sub && preg->re_nsub > 0 && dfa->has_plural_match)
  ret = build_charclass (trans, sbcset,

#ifdef RE_ENABLE_I18N
		  reg_syntax_t syntax, int nest, reg_errcode_t *err)
static reg_errcode_t preorder (bin_tree_t *root,


calc_eclosure (re_dfa_t *dfa)
  if (BE (token->type == END_OF_RE, 0))
  int org_node, clone_node, ret;
	    }
    free_charset (node->opr.mbcset);
      tree = create_tree (dfa, tree, mbc_tree, OP_ALT);
   We must not use this function inside bracket expressions.  */
	{
	  token->type = BACK_SLASH;
	  *err = build_range_exp (sbcset,
	      token->opr.ctx_type = WORD_LAST;
    {
      if (BE (err != REG_NOERROR, 0))
  if (non_match)
      /* A '-' must only appear as anything but a range indicator before
      !re_string_first_byte (input, re_string_cur_idx (input)))
      *err = REG_EESCAPE;
	  if (type == END_OF_RE)
      elem->type = COLL_SYM;
     at END_ELEM.  The result are written to MBCSET and SBCSET.
  /* Local function for parse_bracket_exp used in _LIBC environment.
	err = re_node_set_merge (&eclosure, &eclosure_elem);
init_word_char (re_dfa_t *dfa)
      if (BE ((end != -1 && start > end) || token->type != OP_CLOSE_DUP_NUM, 0))
						       CONTEXT_WORD);

    gettext_noop ("Unmatched [ or [^")	/* REG_EBRACK */
	  if (BE (clone_dest == -1, 0))
  else if (strcmp (class_name, "xdigit") == 0)
  if (input->mb_cur_max > 1 &&
	dfa->nodes[node->node_idx].constraint = node->token.opr.ctx_type;
	  else if (symb_table[2 * elem] == 0 && name_len == 1)
	token->type = OP_CLOSE_DUP_NUM;
	 eg. RE"^*" is invalid or "<ANCHOR(^)><CHAR(*)>",
  if (right != NULL)
/* Worker function for tree walking.  Free the allocated memory inside NODE
{
     support.  */
  /* \w match '_' also.  */
	      *range_alloc = new_nranges;
	{
  if (BE (name_len != 1, 0))
static void free_workarea_compile (regex_t *preg);

      break;
	  left = node->next->node_idx;
	    return REG_ESPACE;
	mbcset->range_starts[mbcset->nranges] = start_wc;
    "\0"
      /* Store the index of the original node.  */
      = dfa->init_state_begbuf = dfa->init_state;
  bin_tree_t *tree, *exp;
	  *err = REG_ERPAREN;
	  constraint |= dfa->nodes[org_node].constraint;
	return err;
      if (BE (new_char_classes == NULL, 0))
	  dfa->used_bkref_map &= ~((bitset_word_t) 1 << other_idx);
	    {
