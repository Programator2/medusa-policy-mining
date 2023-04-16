from mpm.test_cases.helpers import TestCaseContext


def test_core(ctx: TestCaseContext) -> None:
    ctx.tree.generalize_by_owner(ctx.db, verbose=True)
    ctx.tree.move_generalized_to_regexp()
