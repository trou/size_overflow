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

static bool search_size_overflow_type(void)
{
	tree var;
	unsigned int i;

	FOR_EACH_LOCAL_DECL(cfun, i, var)
		if (TYPE_MODE(TREE_TYPE(var)) == TImode)
			return true;

	return false;
}

static void restore_orig_data_flow(gimple stmt, tree orig_type)
{
	imm_use_iterator imm_iter;
	tree lhs, new_lhs;
	gimple use_stmt;

	lhs = gimple_assign_lhs(stmt);
	gcc_assert(lhs != NULL_TREE && TREE_CODE(lhs) == SSA_NAME);

	new_lhs = create_new_var(orig_type);
	gimple_assign_set_lhs(stmt, make_ssa_name(new_lhs, stmt));
	update_stmt(stmt);
	new_lhs = gimple_assign_lhs(stmt);

	FOR_EACH_IMM_USE_STMT(use_stmt, imm_iter, lhs) {
		const_tree orig_rhs1;

		gcc_assert(is_gimple_assign(use_stmt));

		orig_rhs1 = gimple_assign_rhs1(use_stmt);
		if (operand_equal_p(orig_rhs1, lhs, 0))
			gimple_assign_set_rhs1(use_stmt, new_lhs);
		else
			gimple_assign_set_rhs2(use_stmt, new_lhs);
		update_stmt(use_stmt);

		if (!gimple_assign_cast_p(use_stmt) || TYPE_MODE(TREE_TYPE(orig_rhs1)) != TImode)
			restore_orig_data_flow(use_stmt, orig_type);
	}
}

static bool search_cond(struct pointer_set_t *visited, tree node, bool res)
{
	use_operand_p use_p;
	imm_use_iterator imm_iter;

	if (node == NULL_TREE || TREE_CODE(node) != SSA_NAME)
		return res;

	if (pointer_set_insert(visited, node))
		return res;

	FOR_EACH_IMM_USE_FAST(use_p, imm_iter, node) {
		tree lhs;
		const_gimple stmt = USE_STMT(use_p);

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
		case GIMPLE_PHI:
			lhs = gimple_phi_result(stmt);
			res = search_cond(visited, lhs, res);
			break;
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

static unsigned int check_functions(void)
{
	bool ret;
	struct pointer_set_t *visited;
	basic_block bb;

	if (!search_size_overflow_type())
		return 0;

	FOR_ALL_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree lhs, orig_type;
			gimple stmt = gsi_stmt(gsi);

			if (!gimple_assign_cast_p(stmt))
				continue;

			lhs = gimple_assign_lhs(stmt);
			if (TYPE_MODE(TREE_TYPE(lhs)) != TImode)
				continue;
			visited = pointer_set_create();
			ret = search_cond(visited, lhs, false);
			pointer_set_destroy(visited);

			if (ret)
				continue;

			orig_type = TREE_TYPE(gimple_assign_rhs1(stmt));
			restore_orig_data_flow(stmt, orig_type);
//			inform(gimple_location(stmt), "HERE");
		}
	}

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

