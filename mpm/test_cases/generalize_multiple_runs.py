from mpm.tree import NpmTree
from mpm.generalize.runs import generalize_mupltiple_runs, merge_tree
from mpm.test_cases.helpers import TestCaseContext


def test_core(ctx: TestCaseContext) -> None:
    trees = [NpmTree(tree=tree, deep=True) for tree in ctx.trees]
    regex_tree = generalize_mupltiple_runs(ctx.db, *trees)
    tree = merge_tree(*trees, regex_tree)
    tree.move_generalized_to_regexp()
    ctx.tree = tree
