from mpm.tree import NpmTree
from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.generalize.runs import generalize_mupltiple_runs, merge_tree
from mpm.test_cases.helpers import evaluate


def test(
    trees: Iterable[NpmTree],
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseWriter,
    fhs_path: str,
):
    trees = [NpmTree(tree=tree, deep=True) for tree in trees]
    regex_tree = generalize_mupltiple_runs(db, *trees)
    tree = merge_tree(*trees, regex_tree)
    tree.move_generalized_to_regexp()
    return evaluate(
        tree,
        case_name,
        eval_case,
        subject_contexts,
        object_types,
        medusa_domains,
        db,
        fhs_path
    )
