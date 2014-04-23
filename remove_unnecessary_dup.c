/*
 * Copyright 2011-2014 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * Homepage:
 * http://www.grsecurity.net/~ephox/overflow_plugin/
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

#include "gcc-common.h"
#include "size_overflow.h"

static void insert_cast_all_op(struct pointer_set_t *visited, gimple stmt, tree orig_type);
static bool search_cond(struct pointer_set_t *visited, tree node, bool res);

static bool is_size_overflow_type(const_tree var)
{
	const char *name;
	const_tree type_name, type = TREE_TYPE(var);

	type_name = TYPE_NAME(type);
	if (type_name == NULL_TREE)
		return false;

	if (DECL_P(type_name))
		name = DECL_NAME_POINTER(type_name);
	else
		name = IDENTIFIER_POINTER(type_name);

	if (!strncmp(name, "size_overflow_type", 18))
		return true;
	return false;
}

static bool search_size_overflow_type(void)
{
	tree var;
	unsigned int i;

	FOR_EACH_LOCAL_DECL(cfun, i, var)
		if (is_size_overflow_type(var))
			return true;

	return false;
}

static void create_up_and_down_cast(struct pointer_set_t *visited, gimple use_stmt, tree orig_type, tree rhs)
{
	const_tree orig_rhs1;
	tree down_lhs, new_lhs, dup_type = TREE_TYPE(rhs);
	const_gimple down_cast, up_cast;
	gimple_stmt_iterator gsi = gsi_for_stmt(use_stmt);

	down_cast = build_cast_stmt(orig_type, rhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	down_lhs = gimple_assign_lhs(down_cast);

	gsi = gsi_for_stmt(use_stmt);
	up_cast = build_cast_stmt(dup_type, down_lhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	new_lhs = gimple_assign_lhs(up_cast);

	orig_rhs1 = gimple_assign_rhs1(use_stmt);
	if (operand_equal_p(orig_rhs1, rhs, 0))
		gimple_assign_set_rhs1(use_stmt, new_lhs);
	else
		gimple_assign_set_rhs2(use_stmt, new_lhs);
	update_stmt(use_stmt);

	pointer_set_insert(visited, up_cast);
	pointer_set_insert(visited, down_cast);
}

static void walk_use_def_search_ops(struct pointer_set_t *visited, tree lhs, tree orig_type)
{
	gimple def_stmt = get_def_stmt(lhs);

	if (!def_stmt)
		return;
	if (pointer_set_insert(visited, lhs))
		return;
	if (!is_size_overflow_type(lhs))
		return;

	insert_cast_all_op(visited, def_stmt, orig_type);

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
	case GIMPLE_ASM:
	case GIMPLE_CALL:
		break;
	case GIMPLE_PHI: {
		unsigned int i, n = gimple_phi_num_args(def_stmt);

		for (i = 0; i < n; i++)
			walk_use_def_search_ops(visited, gimple_phi_arg_def(def_stmt, i), orig_type);
		break;
	}
	case GIMPLE_ASSIGN:
		if (gimple_num_ops(def_stmt) == 2)
			walk_use_def_search_ops(visited, gimple_assign_rhs1(def_stmt), orig_type);
		else {
			walk_use_def_search_ops(visited, gimple_assign_rhs1(def_stmt), orig_type);
			walk_use_def_search_ops(visited, gimple_assign_rhs2(def_stmt), orig_type);
		}
		break;
	default:
		gcc_unreachable();
	}
}

static void insert_cast_all_op(struct pointer_set_t *visited, gimple stmt, tree orig_type)
{
	imm_use_iterator imm_iter;
	tree lhs;
	gimple use_stmt;

	if (gimple_code(stmt) == GIMPLE_ASSIGN)
		lhs = gimple_assign_lhs(stmt);
	else if (gimple_code(stmt) == GIMPLE_PHI) {
		unsigned int i, n = gimple_phi_num_args(stmt);

		for (i = 0; i < n; i++)
			walk_use_def_search_ops(visited, gimple_phi_arg_def(stmt, i), orig_type);
		lhs = gimple_phi_result(stmt);
	} else
		lhs = NULL_TREE;

	if (lhs == NULL_TREE || TREE_CODE(lhs) != SSA_NAME)
		return;
	if (pointer_set_insert(visited, stmt))
		return;

	if (is_gimple_assign(stmt) && gimple_assign_cast_p(stmt) && !is_size_overflow_type(lhs))
		return;

	FOR_EACH_IMM_USE_STMT(use_stmt, imm_iter, lhs) {
		if (use_stmt == NULL)
			break;
		if (is_gimple_debug(use_stmt))
			continue;

		if (is_gimple_assign(use_stmt) && gimple_num_ops(use_stmt) == 3)
			create_up_and_down_cast(visited, use_stmt, orig_type, lhs);
		insert_cast_all_op(visited, use_stmt, orig_type);
	}
}

static bool walk_use_def_search_cond(struct pointer_set_t *visited, tree lhs, bool res)
{
	gimple def_stmt = get_def_stmt(lhs);

	if (!def_stmt)
		return res;
	if (pointer_set_insert(visited, lhs))
		return res;
	if (!is_size_overflow_type(lhs))
		return res;

	res = search_cond(visited, lhs, res);
	if (res)
		return res;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
	case GIMPLE_ASM:
	case GIMPLE_CALL:
		break;
	case GIMPLE_PHI: {
		unsigned int i, n = gimple_phi_num_args(def_stmt);

		for (i = 0; i < n; i++)
			res = walk_use_def_search_cond(visited, gimple_phi_arg_def(def_stmt, i), res);
		break;
	}
	case GIMPLE_ASSIGN:
		if (gimple_num_ops(def_stmt) == 2)
			res = walk_use_def_search_cond(visited, gimple_assign_rhs1(def_stmt), res);
		else {
			res = walk_use_def_search_cond(visited, gimple_assign_rhs1(def_stmt), res);
			res = walk_use_def_search_cond(visited, gimple_assign_rhs2(def_stmt), res);
		}
		break;
	default:
		gcc_unreachable();
	}

	return res;
}

static bool search_cond(struct pointer_set_t *visited, tree node, bool res)
{
	use_operand_p use_p;
	imm_use_iterator imm_iter;

	if (node == NULL_TREE || TREE_CODE(node) != SSA_NAME)
		return res;

	if (pointer_set_insert(visited, node))
		return res;
	if (!is_size_overflow_type(node))
		return res;

	FOR_EACH_IMM_USE_FAST(use_p, imm_iter, node) {
		tree lhs;
		gimple stmt = USE_STMT(use_p);

		if (stmt == NULL)
			return res;
		if (is_gimple_debug(stmt))
			continue;

		switch (gimple_code(stmt)) {
		case GIMPLE_CALL:
		case GIMPLE_RETURN:
		case GIMPLE_ASM:
		case GIMPLE_SWITCH:
			break;
		case GIMPLE_ASSIGN:
			lhs = gimple_assign_lhs(stmt);
			res = search_cond(visited, lhs, res);
			break;
		case GIMPLE_PHI: {
			unsigned int i, n = gimple_phi_num_args(stmt);

			for (i = 0; i < n; i++)
				res = walk_use_def_search_cond(visited, gimple_phi_arg_def(stmt, i), res);
			if (res)
				return res;

			lhs = gimple_phi_result(stmt);
			res = search_cond(visited, lhs, res);
			break;
		}
		case GIMPLE_COND:
			return true;
		default:
			debug_gimple_stmt((gimple)stmt);
			gcc_unreachable();
			break;
		}
	}
	return res;
}

static tree get_proper_unsigned_type(const_tree node)
{
	tree new_type, type = TREE_TYPE(node);

	if (TYPE_UNSIGNED(type))
		return type;

	switch (TYPE_MODE(type)) {
	case QImode:
		new_type = unsigned_intQI_type_node;
		break;
	case HImode:
		new_type = unsigned_intHI_type_node;
		break;
	case SImode:
		new_type = unsigned_intSI_type_node;
		break;
	case DImode:
		new_type = unsigned_intDI_type_node;
		break;
	case TImode:
		new_type = unsigned_intTI_type_node;
		break;
	default:
		gcc_unreachable();
	}

	if (TYPE_QUALS(type) != 0)
		return build_qualified_type(new_type, TYPE_QUALS(type));
	return new_type;
}

static unsigned int check_functions(void)
{
	bool ret;
	struct pointer_set_t *visited, *visited_in_fn;
	basic_block bb;

	if (!search_size_overflow_type())
		return 0;

	visited_in_fn = pointer_set_create();
	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree lhs, orig_type;
			const_tree orig_rhs;
			gimple stmt = gsi_stmt(gsi);

			if (!gimple_assign_cast_p(stmt))
				continue;
			if (pointer_set_contains(visited_in_fn, stmt))
				continue;
			lhs = gimple_assign_lhs(stmt);
			if (!is_size_overflow_type(lhs))
				continue;

			visited = pointer_set_create();
			ret = search_cond(visited, lhs, false);
			pointer_set_destroy(visited);

			if (ret)
				continue;

			orig_rhs = gimple_assign_rhs1(stmt);
			orig_type = get_proper_unsigned_type(orig_rhs);
			insert_cast_all_op(visited_in_fn, stmt, orig_type);
//			inform(gimple_location(stmt), "HERE");
		}
	}
	pointer_set_destroy(visited_in_fn);

	return 0;
}

#if BUILDING_GCC_VERSION >= 4009
static const struct pass_data remove_unnecessary_dup_pass_data = {
#else
static struct gimple_opt_pass remove_unnecessary_dup_pass = {
	.pass = {
#endif
		.type			= GIMPLE_PASS,
		.name			= "remove_unnecessary_dup",
#if BUILDING_GCC_VERSION >= 4008
		.optinfo_flags		= OPTGROUP_NONE,
#endif
#if BUILDING_GCC_VERSION >= 4009
		.has_gate		= false,
		.has_execute		= true,
#else
		.gate			= NULL,
		.execute		= check_functions,
		.sub			= NULL,
		.next			= NULL,
		.static_pass_number	= 0,
#endif
		.tv_id			= TV_NONE,
		.properties_required	= PROP_cfg,
		.properties_provided	= 0,
		.properties_destroyed	= 0,
		.todo_flags_start	= 0,
		.todo_flags_finish	= TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_ggc_collect | TODO_verify_flow | TODO_dump_func | TODO_update_ssa_no_phi,
#if BUILDING_GCC_VERSION < 4009
	}
#endif
};

#if BUILDING_GCC_VERSION >= 4009
namespace {
class remove_unnecessary_dup_pass : public gimple_opt_pass {
public:
	remove_unnecessary_dup_pass() : gimple_opt_pass(remove_unnecessary_dup_pass_data, g) {}
	unsigned int execute() { return check_functions(); }
};
}
#endif

struct opt_pass *make_remove_unnecessary_dup_pass(void)
{
#if BUILDING_GCC_VERSION >= 4009
	return new remove_unnecessary_dup_pass();
#else
	return &remove_unnecessary_dup_pass.pass;
#endif
}

