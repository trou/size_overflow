/*
 * Copyright 2011-2015 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * https://github.com/ephox-gcc-plugins/size_overflow
 *
 * Documentation:
 * http://forums.grsecurity.net/viewtopic.php?f=7&t=3043
 *
 * This plugin recomputes expressions of function arguments marked by a size_overflow attribute
 * with double integer precision (DImode/TImode for 32/64 bit integer types).
 * The recomputed argument is checked against TYPE_MAX and an event is logged on overflow and the triggering process is killed.
 *
 * Usage:
 * $ make
 * $ make run
 */

#include "size_overflow.h"

static next_interesting_function_t walk_use_def_next_functions(gimple_set *visited, next_interesting_function_t next_cnodes_head, const_tree lhs);

next_interesting_function_t global_next_interesting_function[GLOBAL_NIFN_LEN];

static struct cgraph_node_hook_list *function_insertion_hook_holder;
static struct cgraph_2node_hook_list *node_duplication_hook_holder;

struct cgraph_node *get_cnode(const_tree fndecl)
{
	gcc_assert(TREE_CODE(fndecl) == FUNCTION_DECL);
#if BUILDING_GCC_VERSION <= 4005
	return cgraph_get_node((tree)fndecl);
#else
	return cgraph_get_node(fndecl);
#endif
}

static bool compare_next_interesting_functions(next_interesting_function_t cur_node, const char *decl_name, const char *context, unsigned int num)
{
	if (num != NONE_ARGNUM && cur_node->num != num)
		return false;
	if (strcmp(cur_node->context, context))
		return false;
	return !strcmp(cur_node->decl_name, decl_name);
}

// Return the type name for a function pointer (or "fielddecl" if the type has no name), otherwise either "vardecl" or "fndecl"
static const char* get_decl_context(const_tree decl)
{
	const char *context;

	if (TREE_CODE(decl) == VAR_DECL)
		return "vardecl";
	if (TREE_CODE(decl) == FUNCTION_DECL)
		return "fndecl";

	gcc_assert(TREE_CODE(decl) == FIELD_DECL);
	context = get_type_name_from_field(decl);

/* TODO: Ignore anonymous types for now
	if (!context)
		return "fielddecl"; */
	return context;
}

/* Find the function with the specified argument in the list
 *   * if marked is ASM_STMT_SO_MARK or YES_SO_MARK then filter accordingly
 *   * if num is CANNOT_FIND_ARG then ignore it
 */
next_interesting_function_t get_global_next_interesting_function_entry(struct fn_raw_data *raw_data)
{
	next_interesting_function_t cur_node, head;

	head = global_next_interesting_function[raw_data->hash];
	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if (compare_next_interesting_functions(cur_node, raw_data->decl_str, raw_data->context, raw_data->num))
			return cur_node;
	}
	return NULL;
}

next_interesting_function_t get_global_next_interesting_function_entry_with_hash(struct fn_raw_data *raw_data)
{
	raw_data->hash = get_decl_hash(raw_data->decl, raw_data->decl_str);
	if (raw_data->hash == NO_HASH)
		return NULL;

	raw_data->context = get_decl_context(raw_data->decl);
	if (!raw_data->context)
		return NULL;
	return get_global_next_interesting_function_entry(raw_data);
}

next_interesting_function_t create_new_next_interesting_entry(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node)
{
	next_interesting_function_t new_node;

	new_node = (next_interesting_function_t)xmalloc(sizeof(*new_node));
	new_node->decl_name = xstrdup(raw_data->decl_str);
	gcc_assert(raw_data->context);
	new_node->context = xstrdup(raw_data->context);
	new_node->hash = raw_data->hash;
	new_node->num = raw_data->num;
	new_node->next = NULL;
	new_node->children = NULL;
	new_node->marked = raw_data->marked;
	new_node->orig_next_node = orig_next_node;
	return new_node;
}

// Create the main data structure
next_interesting_function_t create_new_next_interesting_decl(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node)
{
	enum tree_code decl_code = TREE_CODE(raw_data->decl);

	gcc_assert(decl_code == FIELD_DECL || decl_code == FUNCTION_DECL || decl_code == VAR_DECL);

	if (is_vararg(raw_data->decl, raw_data->num))
		return NULL;

	raw_data->hash = get_decl_hash(raw_data->decl, raw_data->decl_str);
	if (raw_data->hash == NO_HASH)
		return NULL;

	gcc_assert(raw_data->num <= MAX_PARAM);
	// Clones must have an orig_next_node
	gcc_assert(!made_by_compiler(raw_data->decl) || orig_next_node);

	raw_data->context = get_decl_context(raw_data->decl);
	if (!raw_data->context)
		return NULL;
	return create_new_next_interesting_entry(raw_data, orig_next_node);
}

void add_to_global_next_interesting_function(next_interesting_function_t new_entry)
{
	next_interesting_function_t cur_global_head, cur_global, cur_global_end = NULL;

	// new_entry is appended to the end of a list
	new_entry->next = NULL;

	cur_global_head = global_next_interesting_function[new_entry->hash];
	if (!cur_global_head) {
		global_next_interesting_function[new_entry->hash] = new_entry;
		return;
	}


	for (cur_global = cur_global_head; cur_global; cur_global = cur_global->next) {
		if (!cur_global->next)
			cur_global_end = cur_global;

		if (compare_next_interesting_functions(cur_global, new_entry->decl_name, new_entry->context, new_entry->num))
			return;
	}

	gcc_assert(cur_global_end);
	cur_global_end->next = new_entry;
}

/* If the interesting function is a clone then find or create its original next_interesting_function_t node
 * and add it to global_next_interesting_function
 */
static next_interesting_function_t create_orig_next_node_for_a_clone(struct fn_raw_data *clone_raw_data)
{
	struct fn_raw_data orig_raw_data;
	next_interesting_function_t orig_next_node;
	enum tree_code decl_code;

	orig_raw_data.decl = get_orig_fndecl(clone_raw_data->decl);
	decl_code = TREE_CODE(orig_raw_data.decl);

	if (decl_code == FIELD_DECL || decl_code == VAR_DECL)
		orig_raw_data.num = clone_raw_data->num;
	else
		orig_raw_data.num = get_correct_argnum(clone_raw_data->decl, orig_raw_data.decl, clone_raw_data->num);

	// Skip over ISRA.162 parm decls
	if (orig_raw_data.num == CANNOT_FIND_ARG)
		return NULL;

	orig_raw_data.decl_str = get_orig_decl_name(orig_raw_data.decl);
	orig_raw_data.marked = NO_SO_MARK;
	orig_next_node = get_global_next_interesting_function_entry_with_hash(&orig_raw_data);
	if (orig_next_node)
		return orig_next_node;

	orig_raw_data.marked = clone_raw_data->marked;
	orig_next_node = create_new_next_interesting_decl(&orig_raw_data, NULL);
	gcc_assert(orig_next_node);

	add_to_global_next_interesting_function(orig_next_node);
	return orig_next_node;
}

// Find or create the next_interesting_function_t node for decl and num
next_interesting_function_t get_and_create_next_node_from_global_next_nodes(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node)
{
	next_interesting_function_t cur_next_cnode;

	if (DECL_NAME(raw_data->decl) == NULL_TREE)
		return NULL;
	raw_data->decl_str = DECL_NAME_POINTER(raw_data->decl);

	cur_next_cnode = get_global_next_interesting_function_entry_with_hash(raw_data);
	if (cur_next_cnode)
		goto out;

	if (!orig_next_node && made_by_compiler(raw_data->decl)) {
		orig_next_node = create_orig_next_node_for_a_clone(raw_data);
		if (!orig_next_node)
			return NULL;
	}

	cur_next_cnode = create_new_next_interesting_decl(raw_data, orig_next_node);
	if (!cur_next_cnode)
		return NULL;

	add_to_global_next_interesting_function(cur_next_cnode);
out:
	if (cur_next_cnode->marked != raw_data->marked && cur_next_cnode->marked != NO_SO_MARK)
		return cur_next_cnode;

	if (raw_data->marked != NO_SO_MARK && cur_next_cnode->marked == NO_SO_MARK)
		cur_next_cnode->marked = raw_data->marked;

	return cur_next_cnode;
}

static bool has_next_interesting_function_chain_node(next_interesting_function_t next_cnodes_head, struct fn_raw_data *raw_data)
{
	next_interesting_function_t cur_node;

	raw_data->decl_str = DECL_NAME_POINTER(raw_data->decl);
	raw_data->context = get_decl_context(raw_data->decl);
	if (!raw_data->context)
		return true;

	for (cur_node = next_cnodes_head; cur_node; cur_node = cur_node->next) {
		if (compare_next_interesting_functions(cur_node, raw_data->decl_str, raw_data->context, raw_data->num))
			return true;
	}
	return false;
}

static next_interesting_function_t handle_function(next_interesting_function_t next_cnodes_head, tree fndecl, const_tree arg)
{
	struct fn_raw_data raw_data;
	next_interesting_function_t orig_next_node, new_node;

	gcc_assert(fndecl != NULL_TREE);

	// ignore builtins to not explode coverage (e.g., memcpy)
	if (DECL_BUILT_IN(fndecl))
		return next_cnodes_head;

	raw_data.decl = fndecl;
	raw_data.decl_str = DECL_NAME_POINTER(fndecl);
	raw_data.marked = NO_SO_MARK;

	// convert arg into its position
	if (arg == NULL_TREE)
		raw_data.num = 0;
	else
		raw_data.num = find_arg_number_tree(arg, raw_data.decl);
	if (raw_data.num == CANNOT_FIND_ARG)
		return next_cnodes_head;

	if (has_next_interesting_function_chain_node(next_cnodes_head, &raw_data))
		return next_cnodes_head;

	if (made_by_compiler(raw_data.decl)) {
		orig_next_node = create_orig_next_node_for_a_clone(&raw_data);
		if (!orig_next_node)
			return next_cnodes_head;
	} else
		orig_next_node = NULL;

	new_node = create_new_next_interesting_decl(&raw_data, orig_next_node);
	if (!new_node)
		return next_cnodes_head;
	new_node->next = next_cnodes_head;
	return new_node;
}

static next_interesting_function_t walk_use_def_next_functions_phi(gimple_set *visited, next_interesting_function_t next_cnodes_head, const_tree result)
{
	gphi *phi = as_a_gphi(get_def_stmt(result));
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		next_cnodes_head = walk_use_def_next_functions(visited, next_cnodes_head, arg);
	}

	return next_cnodes_head;
}

static next_interesting_function_t walk_use_def_next_functions_binary(gimple_set *visited, next_interesting_function_t next_cnodes_head, const_tree lhs)
{
	gassign *def_stmt = as_a_gassign(get_def_stmt(lhs));
	tree rhs1, rhs2;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	next_cnodes_head = walk_use_def_next_functions(visited, next_cnodes_head, rhs1);
	return walk_use_def_next_functions(visited, next_cnodes_head, rhs2);
}

next_interesting_function_t __attribute__((weak)) handle_function_ptr_ret(gimple_set *visited __unused, next_interesting_function_t next_cnodes_head, const_tree fn_ptr __unused)
{
	return next_cnodes_head;
}

static next_interesting_function_t handle_struct_fields(next_interesting_function_t head, const_tree node)
{
	struct fn_raw_data raw_data;
	next_interesting_function_t new_node;

	switch (TREE_CODE(node)) {
	case ARRAY_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case INDIRECT_REF:
	case COMPONENT_REF:
		raw_data.decl = get_ref_field(node);
		break;
	// TODO
	case BIT_FIELD_REF:
	case VIEW_CONVERT_EXPR:
		return head;
	default:
		// XXX: keep this syncronized with size_overflow_transform.c:search_interesting_structs()
		debug_tree((tree)node);
		gcc_unreachable();
	}

	if (raw_data.decl == NULL_TREE)
		return head;

	if (DECL_NAME(raw_data.decl) == NULL_TREE)
		return head;

	raw_data.decl_str = DECL_NAME_POINTER(raw_data.decl);
	raw_data.num = 0;
	raw_data.marked = NO_SO_MARK;

	new_node = create_new_next_interesting_decl(&raw_data, NULL);
	if (!new_node)
		return head;
	new_node->next = head;
	return new_node;
}

/* Find all functions that influence lhs
 *
 * Encountered functions are added to the children vector (next_interesting_function_t).
 */
static next_interesting_function_t walk_use_def_next_functions(gimple_set *visited, next_interesting_function_t next_cnodes_head, const_tree lhs)
{
	enum tree_code code;
	const_gimple def_stmt;

	if (skip_types(lhs))
		return next_cnodes_head;

	code = TREE_CODE(lhs);
	if (code == PARM_DECL)
		return handle_function(next_cnodes_head, current_function_decl, lhs);

	if (TREE_CODE_CLASS(code) == tcc_reference)
		return handle_struct_fields(next_cnodes_head, lhs);

	if (code != SSA_NAME)
		return next_cnodes_head;

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return next_cnodes_head;

	if (pointer_set_insert(visited, def_stmt))
		return next_cnodes_head;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		return walk_use_def_next_functions(visited, next_cnodes_head, SSA_NAME_VAR(lhs));
	case GIMPLE_ASM:
		if (is_size_overflow_asm(def_stmt))
			return walk_use_def_next_functions(visited, next_cnodes_head, get_size_overflow_asm_input(as_a_const_gasm(def_stmt)));
		return next_cnodes_head;
	case GIMPLE_CALL: {
		tree fndecl = gimple_call_fndecl(def_stmt);

		if (fndecl != NULL_TREE)
			return handle_function(next_cnodes_head, fndecl, NULL_TREE);
		fndecl = gimple_call_fn(def_stmt);
		return handle_function_ptr_ret(visited, next_cnodes_head, fndecl);
	}
	case GIMPLE_PHI:
		return walk_use_def_next_functions_phi(visited, next_cnodes_head, lhs);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return walk_use_def_next_functions(visited, next_cnodes_head, gimple_assign_rhs1(def_stmt));
		case 3:
			return walk_use_def_next_functions_binary(visited, next_cnodes_head, lhs);
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Start the search for next_interesting_function_t children based on the (next_interesting_function_t) parent node
static next_interesting_function_t search_next_functions(const_tree node)
{
	gimple_set *visited;
	next_interesting_function_t next_cnodes_head;

	visited = pointer_set_create();
	next_cnodes_head = walk_use_def_next_functions(visited, NULL, node);
	pointer_set_destroy(visited);

	return next_cnodes_head;
}

// True if child already exists in the next_interesting_function_t children vector
bool has_next_interesting_function_vec(next_interesting_function_t target, next_interesting_function_t next_node)
{
	unsigned int i;
	next_interesting_function_t cur;

	gcc_assert(next_node);
	// handle recursion
	if (!strcmp(target->decl_name, next_node->decl_name) && target->num == next_node->num)
		return true;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, target->children))
		return false;
	FOR_EACH_VEC_ELT(next_interesting_function_t, target->children, i, cur) {
#else
	FOR_EACH_VEC_SAFE_ELT(target->children, i, cur) {
#endif
		if (compare_next_interesting_functions(cur, next_node->decl_name, next_node->context, next_node->num))
			return true;
	}
	return false;
}

void push_child(next_interesting_function_t parent, next_interesting_function_t child)
{
	if (!has_next_interesting_function_vec(parent, child)) {
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(next_interesting_function_t, heap, parent->children, child);
#else
		vec_safe_push(parent->children, child);
#endif
	}
}

void __attribute__((weak)) check_local_variables(next_interesting_function_t next_node __unused) {}

// Add children to parent and global_next_interesting_function
static void collect_data_for_execute(next_interesting_function_t parent, next_interesting_function_t children)
{
	next_interesting_function_t cur = children;

	gcc_assert(parent);

	while (cur) {
		struct fn_raw_data child_raw_data;
		next_interesting_function_t next, child;

		next = cur->next;

		child_raw_data.decl_str = cur->decl_name;
		child_raw_data.context = cur->context;
		child_raw_data.hash = cur->hash;
		child_raw_data.num = cur->num;
		child_raw_data.marked = NO_SO_MARK;
		child = get_global_next_interesting_function_entry(&child_raw_data);
		if (!child) {
			add_to_global_next_interesting_function(cur);
			child = cur;
		}

		check_local_variables(child);

		push_child(parent, child);

		cur = next;
	}

	check_local_variables(parent);
}

next_interesting_function_t __attribute__((weak)) get_and_create_next_node_from_global_next_nodes_fnptr(const_tree fn_ptr __unused, struct fn_raw_data *raw_data __unused)
{
	return NULL;
}

static next_interesting_function_t create_parent_next_cnode(const_gimple stmt, unsigned int num)
{
	struct fn_raw_data raw_data;

	raw_data.num = num;
	raw_data.marked = NO_SO_MARK;

	switch (gimple_code(stmt)) {
	case GIMPLE_ASM:
		raw_data.decl = current_function_decl;
		raw_data.marked = ASM_STMT_SO_MARK;
		return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
	case GIMPLE_CALL:
		raw_data.decl = gimple_call_fndecl(stmt);
		if (raw_data.decl != NULL_TREE)
			return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
		raw_data.decl = gimple_call_fn(stmt);
		return get_and_create_next_node_from_global_next_nodes_fnptr(raw_data.decl, &raw_data);
	case GIMPLE_RETURN:
		raw_data.decl = current_function_decl;
		return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
	case GIMPLE_ASSIGN:
		raw_data.decl = get_ref_field(gimple_assign_lhs(stmt));
		if (raw_data.decl == NULL_TREE)
			return NULL;
		return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
	default:
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}
}

// Handle potential next_interesting_function_t parent if its argument has an integer type
static void collect_all_possible_size_overflow_fns(const_gimple stmt, const_tree start_var, unsigned int num)
{
	next_interesting_function_t children_next_cnode, parent_next_cnode;

	// skip void return values
	if (start_var == NULL_TREE)
		return;

	if (skip_types(start_var))
		return;

	// handle intentional MARK_TURN_OFF
	if (check_intentional_size_overflow_asm_and_attribute(start_var) == MARK_TURN_OFF)
		return;

	parent_next_cnode = create_parent_next_cnode(stmt, num);
	if (!parent_next_cnode)
		return;

	children_next_cnode = search_next_functions(start_var);
	collect_data_for_execute(parent_next_cnode, children_next_cnode);
}

// Find potential next_interesting_function_t parents
static void handle_cgraph_node(struct cgraph_node *node)
{
	basic_block bb;
	tree cur_fndecl = NODE_DECL(node);

	set_current_function_decl(cur_fndecl);

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree start_var;
			gimple stmt = gsi_stmt(gsi);

			switch (gimple_code(stmt)) {
			case GIMPLE_RETURN: {
				const greturn *return_stmt = as_a_const_greturn(stmt);

				start_var = gimple_return_retval(return_stmt);
				collect_all_possible_size_overflow_fns(return_stmt, start_var, 0);
				break;
			}
			case GIMPLE_ASM: {
				const gasm *asm_stmt = as_a_const_gasm(stmt);

				if (!is_size_overflow_insert_check_asm(asm_stmt))
					break;
				start_var = get_size_overflow_asm_input(asm_stmt);
				collect_all_possible_size_overflow_fns(asm_stmt, start_var, 0);
				break;
			}
			case GIMPLE_CALL: {
				unsigned int i, len;
				const gcall *call = as_a_const_gcall(stmt);
				tree fndecl = gimple_call_fndecl(call);

				if (fndecl != NULL_TREE && DECL_BUILT_IN(fndecl))
					break;

				len = gimple_call_num_args(call);
				for (i = 0; i < len; i++) {
					start_var = gimple_call_arg(call, i);
					collect_all_possible_size_overflow_fns(call, start_var, i + 1);
				}
				break;
			}
			case GIMPLE_ASSIGN: {
				const gassign *assign = as_a_const_gassign(stmt);

				start_var = gimple_assign_rhs1(assign);
				collect_all_possible_size_overflow_fns(assign, start_var, 0);
				start_var = gimple_assign_rhs2(assign);
				collect_all_possible_size_overflow_fns(assign, start_var, 0);
#if BUILDING_GCC_VERSION >= 4006
				start_var = gimple_assign_rhs3(assign);
				collect_all_possible_size_overflow_fns(assign, start_var, 0);
#endif
				break;
			}
			default:
				break;
			}
		}
	}

	unset_current_function_decl();
}

/* Collect all potentially interesting function parameters and return values of integer types
 * and store their data flow dependencies
 */
static void size_overflow_generate_summary(void)
{
	struct cgraph_node *node;

	size_overflow_register_hooks();

	FOR_EACH_FUNCTION(node) {
		if (is_valid_cgraph_node(node))
			handle_cgraph_node(node);
	}
}

static void size_overflow_function_insertion_hook(struct cgraph_node *node __unused, void *data __unused)
{
	debug_cgraph_node(node);
	gcc_unreachable();
}

/* Handle dst if src is in the global_next_interesting_function list.
 * If src is a clone then dst inherits the orig_next_node of src otherwise
 * src will become the orig_next_node of dst.
 */
static void size_overflow_node_duplication_hook(struct cgraph_node *src, struct cgraph_node *dst, void *data __unused)
{
	next_interesting_function_t head, cur;
	struct fn_raw_data src_raw_data;

	src_raw_data.decl = NODE_DECL(src);
	src_raw_data.decl_str = DECL_NAME_POINTER(src_raw_data.decl);
	src_raw_data.context = get_decl_context(src_raw_data.decl);
	if (!src_raw_data.context)
		return;

	src_raw_data.num = NONE_ARGNUM;
	src_raw_data.marked = NO_SO_MARK;

	head = get_global_next_interesting_function_entry_with_hash(&src_raw_data);
	if (!head)
		return;

	for (cur = head; cur; cur = cur->next) {
		struct fn_raw_data dst_raw_data;
		next_interesting_function_t orig_next_node, next_node;

		if (!compare_next_interesting_functions(cur, src_raw_data.decl_str, src_raw_data.context, src_raw_data.num))
			continue;

		dst_raw_data.decl = NODE_DECL(dst);
		dst_raw_data.decl_str = cgraph_node_name(dst);
		dst_raw_data.marked = cur->marked;

		if (!made_by_compiler(dst_raw_data.decl))
			break;

		// For clones use the original node instead
		if (cur->orig_next_node)
			orig_next_node = cur->orig_next_node;
		else
			orig_next_node = cur;

		dst_raw_data.num = get_correct_argnum_fndecl(src_raw_data.decl, dst_raw_data.decl, cur->num);
		if (dst_raw_data.num == CANNOT_FIND_ARG)
			continue;

		next_node = create_new_next_interesting_decl(&dst_raw_data, orig_next_node);
		if (next_node)
			add_to_global_next_interesting_function(next_node);
	}
}

void size_overflow_register_hooks(void)
{
	static bool init_p = false;

	if (init_p)
		return;
	init_p = true;

	function_insertion_hook_holder = cgraph_add_function_insertion_hook(&size_overflow_function_insertion_hook, NULL);
	node_duplication_hook_holder = cgraph_add_node_duplication_hook(&size_overflow_node_duplication_hook, NULL);
}

static void set_yes_so_mark(next_interesting_function_t next_node)
{
	if (next_node->marked == NO_SO_MARK)
		next_node->marked = YES_SO_MARK;
	// Mark the orig decl as well if it's a clone
	if (next_node->orig_next_node && next_node->orig_next_node->marked == NO_SO_MARK)
		next_node->orig_next_node->marked = YES_SO_MARK;
}

// Determine whether node or orig node is part of a tracked data flow
static bool marked_fn(next_interesting_function_t next_node)
{
	bool is_marked_fn, is_marked_orig = false;

	is_marked_fn = next_node->marked != NO_SO_MARK;

	if (next_node->orig_next_node)
		is_marked_orig = next_node->orig_next_node->marked != NO_SO_MARK;

	return is_marked_fn || is_marked_orig;
}

// Determine whether node or orig node is in the hash table already
static bool already_in_the_hashtable(next_interesting_function_t next_node)
{
	if (next_node->orig_next_node)
		next_node = next_node->orig_next_node;
	return get_size_overflow_hash_entry(next_node->hash, next_node->decl_name, next_node->num) != NULL;
}

// Propagate the size_overflow marks up the use-def chains
static bool has_marked_child(next_interesting_function_t next_node)
{
	bool ret = false;
	unsigned int i;
	next_interesting_function_t child;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, next_node->children))
		return false;
	FOR_EACH_VEC_ELT(next_interesting_function_t, next_node->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(next_node->children, i, child) {
#endif
		if (!marked_fn(child) && !already_in_the_hashtable(child))
			continue;

		set_yes_so_mark(child);
		ret = true;
	}

	return ret;
}

/* Set YES_SO_MARK on the function, its orig node and children if:
 *      * the function or its orig node or one of its children is in the hash table already
 *      * the function's orig node is marked with YES_SO_MARK or ASM_STMT_SO_MARK
 *      * one of the children is marked with YES_SO_MARK or ASM_STMT_SO_MARK
 */
static void set_fn_mark(next_interesting_function_t next_node)
{
	bool so_fn, so_hashtable, so_child;

	so_hashtable = already_in_the_hashtable(next_node);
	so_fn = marked_fn(next_node);
	so_child = has_marked_child(next_node);

	if (so_fn || so_hashtable || so_child)
		set_yes_so_mark(next_node);
}

// Determine if any of the function pointer targets have data flow between the return value and one of the arguments
static next_interesting_function_t get_same_not_ret_child(next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return NULL;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		if (child->num == 0)
			continue;
		if (strcmp(parent->decl_name, child->decl_name))
			continue;
		if (!strcmp(child->context, "fndecl"))
			return child;
	}
	return NULL;
}

/* Trace a return value of function pointer type back to an argument via a concrete function
   fnptr 0 && fn 0 && (fn 0 -> fn 2) => fnptr 2 */
static void search_missing_fptr_arg(next_interesting_function_t parent)
{
	next_interesting_function_t child;
	unsigned int i;
#if BUILDING_GCC_VERSION <= 4007
	VEC(next_interesting_function_t, heap) *new_children = NULL;
#else
	vec<next_interesting_function_t, va_heap, vl_embed> *new_children = NULL;
#endif

	if (parent->num != 0)
		return;
	if (!strcmp(parent->context, "fndecl"))
		return;
	if (!strcmp(parent->context, "vardecl"))
		return;

	// fnptr 0 && fn 0
#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		next_interesting_function_t cur_next_node, tracked_fn;

		if (child->num != 0)
			continue;
		// (fn 0 -> fn 2)
		tracked_fn = get_same_not_ret_child(child);
		if (!tracked_fn)
			continue;

		// fn 2 => fnptr 2
		for (cur_next_node = global_next_interesting_function[parent->hash]; cur_next_node; cur_next_node = cur_next_node->next) {
			if (cur_next_node->num != tracked_fn->num)
				continue;

			if (strcmp(parent->decl_name, cur_next_node->decl_name))
				continue;

			if (!has_next_interesting_function_vec(parent, cur_next_node)) {
#if BUILDING_GCC_VERSION <= 4007
				VEC_safe_push(next_interesting_function_t, heap, new_children, cur_next_node);
#else
				vec_safe_push(new_children, cur_next_node);
#endif
			}
		}
	}

#if BUILDING_GCC_VERSION == 4005
	if (VEC_empty(next_interesting_function_t, new_children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, new_children, i, child)
		VEC_safe_push(next_interesting_function_t, heap, parent->children, child);
#elif BUILDING_GCC_VERSION <= 4007
	VEC_safe_splice(next_interesting_function_t, heap, parent->children, new_children);
#else
	vec_safe_splice(parent->children, new_children);
#endif
}

static void set_so_mark(next_interesting_function_set *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

	gcc_assert(parent);
	set_fn_mark(parent);

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		if (parent->marked != NO_SO_MARK)
			set_yes_so_mark(child);
		set_fn_mark(child);
		if (!pointer_set_insert(visited, child))
			set_so_mark(visited, child);
	}
}

// Do a depth-first recursive dump of the next_interesting_function_t children vector
static void print_missing_functions(next_interesting_function_set *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

	gcc_assert(parent);
	gcc_assert(parent->marked != NO_SO_MARK);
	print_missing_function(parent);

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		gcc_assert(child->marked != NO_SO_MARK);
		if (!pointer_set_insert(visited, child))
			print_missing_functions(visited, child);
	}
}

void __attribute__((weak)) check_global_variables(next_interesting_function_t cur_global __unused) {}

// Print all missing interesting functions
static unsigned int size_overflow_execute(void)
{
	unsigned int i;
	next_interesting_function_set *visited;
	next_interesting_function_t cur_global;

	// Collect vardecls and funtions reachable by function pointers
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			check_global_variables(cur_global);
			search_missing_fptr_arg(cur_global);
		}
	}

	// Set YES_SO_MARK on functions that will be emitted into the hash table
	visited = next_interesting_function_pointer_set_create();
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			if (cur_global->marked == ASM_STMT_SO_MARK)
				set_so_mark(visited, cur_global);
		}
	}
	pointer_set_destroy(visited);

	// Print functions missing from the hash table
	visited = next_interesting_function_pointer_set_create();
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			if (cur_global->marked == ASM_STMT_SO_MARK)
				print_missing_functions(visited, cur_global);
		}
	}
	pointer_set_destroy(visited);

	if (in_lto_p) {
		fprintf(stderr, "%s: SIZE_OVERFLOW EXECUTE\n", __func__);
		print_global_next_interesting_functions();
	}

	return 0;
}

// Omit the IPA/LTO callbacks until https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61311 gets fixed (license concerns)
#if BUILDING_GCC_VERSION >= 4008
void __attribute__((weak)) size_overflow_write_summary_lto(void) {}
#elif BUILDING_GCC_VERSION >= 4006
void __attribute__((weak)) size_overflow_write_summary_lto(cgraph_node_set set __unused, varpool_node_set vset __unused) {}
#else
void __attribute__((weak)) size_overflow_write_summary_lto(cgraph_node_set set __unused) {}
#endif

void __attribute__((weak)) size_overflow_read_summary_lto(void) {}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data size_overflow_functions_pass_data = {
#else
static struct ipa_opt_pass_d size_overflow_functions_pass = {
	.pass = {
#endif
		.type			= IPA_PASS,
		.name			= "size_overflow_functions",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 5000
#elif BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= size_overflow_execute,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= 0,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= 0,
#if BUILDING_GCC_VERSION < 4009
	},
	.generate_summary		= size_overflow_generate_summary,
	.write_summary			= size_overflow_write_summary_lto,
	.read_summary			= size_overflow_read_summary_lto,
#if BUILDING_GCC_VERSION >= 4006
	.write_optimization_summary	= size_overflow_write_summary_lto,
	.read_optimization_summary	= size_overflow_read_summary_lto,
#endif
	.stmt_fixup			= NULL,
	.function_transform_todo_flags_start		= 0,
	.function_transform		= size_overflow_transform,
	.variable_transform		= NULL,
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class size_overflow_functions_pass : public ipa_opt_pass_d {
public:
	size_overflow_functions_pass() : ipa_opt_pass_d(size_overflow_functions_pass_data,
			 g,
			 size_overflow_generate_summary,
			 size_overflow_write_summary_lto,
			 size_overflow_read_summary_lto,
			 size_overflow_write_summary_lto,
			 size_overflow_read_summary_lto,
			 NULL,
			 0,
			 size_overflow_transform,
			 NULL) {}
#if BUILDING_GCC_VERSION >= 5000
	virtual unsigned int execute(function *) { return size_overflow_execute(); }
#else
	unsigned int execute() { return size_overflow_execute(); }
#endif
};
}

opt_pass *make_size_overflow_functions_pass(void)
{
	return new size_overflow_functions_pass();
}
#else
struct opt_pass *make_size_overflow_functions_pass(void)
{
	return &size_overflow_functions_pass.pass;
}
#endif
