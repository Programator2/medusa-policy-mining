from mpm.tree import NpmTree
from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.test_cases.helpers import populate_accesses, export_results
from mpm.domain import get_current_euid
from mpm.generalize.generalize import generalize_from_fhs_rules


def test(
    tree: NpmTree,
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseWriter,
    uids: Iterable[int] = [],
    gids: Iterable[int] = [],
):
    tree = NpmTree(tree=tree, deep=True)
    domains = list(filter(lambda x: get_current_euid(x) in uids,
                          medusa_domains))
    tree.generalize_by_owner_directory(db, domains, uids, gids, verbose=True)
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
