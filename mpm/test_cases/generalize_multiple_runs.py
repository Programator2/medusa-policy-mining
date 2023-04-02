from mpm.tree import NpmTree
from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.generalize.runs import generalize_mupltiple_runs, merge_tree
from mpm.test_cases.helpers import populate_accesses


def test(
    trees: Iterable[NpmTree],
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseWriter
):
    regex_tree = generalize_mupltiple_runs(db, *trees)
    new_tree = merge_tree(*trees, regex_tree)
    new_tree.move_generalized_to_regexp()
    populate_accesses(
        new_tree,
        db,
        case_name,
        eval_case,
        subject_contexts,
        object_types,
        medusa_domains,
    )
    return db.get_permission_confusion(case_name, subject_contexts, eval_case)