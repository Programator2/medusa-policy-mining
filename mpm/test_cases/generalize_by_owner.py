from mpm.tree import NpmTree
from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.test_cases.helpers import populate_accesses


def test(
    tree: NpmTree,
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseWriter
):
    tree = NpmTree(tree=tree, deep=True)
    tree.generalize_by_owner(db, verbose=True)
    tree.move_generalized_to_regexp()
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