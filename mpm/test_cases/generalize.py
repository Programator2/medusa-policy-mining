from mpm.tree import NpmTree
from fs2json.db import DatabaseRead
from collections.abc import Iterable
from mpm.test_cases.helpers import populate_accesses


def test(
    tree: NpmTree,
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseRead,
):
    # tree.show()
    # print('-'*80)
    tree = NpmTree(tree=tree, deep=True)
    # Do necessary generalizations here
    tree.generalize(tree.get_node(tree.root), verbose=False)
    tree.move_generalized_to_regexp()
    # tree.show()
    populate_accesses(
        tree,
        db,
        case_name,
        eval_case,
        subject_contexts,
        object_types,
        medusa_domains,
    )
    return db.get_permission_confusion(case_name, subject_contexts, eval_case)
