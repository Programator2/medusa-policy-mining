from mpm.test_cases.helpers import TestCaseContext


def test_core(ctx: TestCaseContext) -> None:
    ctx.tree.generalize(ctx.tree.get_node(ctx.tree.root), verbose=False)
    ctx.tree.move_generalized_to_regexp()
