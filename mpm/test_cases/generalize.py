from mpm.tree import NpmTree
from fs2json.db import DatabaseRead
from collections.abc import Iterable
from mpm.test_cases.helpers import populate_accesses, export_results
from mpm.generalize.generalize import generalize_from_fhs_rules


def test(
    tree: NpmTree,
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseRead,
):
    tree = NpmTree(tree=tree, deep=True)
    # Do necessary generalizations here
    tree.generalize(tree.get_node(tree.root), verbose=False)
    tree.move_generalized_to_regexp()
    generalize_from_fhs_rules('fhs_rules.txt', tree, medusa_domains)
    populate_accesses(
        tree,
        db,
        case_name,
        eval_case,
        subject_contexts,
        object_types,
        medusa_domains,
    )
    export_results(case_name, eval_case, subject_contexts, db, tree)
    return db.get_permission_confusion(case_name, subject_contexts, eval_case)
