from mpm.tree import NpmTree
from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.domain import get_current_euid
from mpm.test_cases.helpers import evaluate


def test(
    tree: NpmTree,
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseWriter,
    fhs_path: str,
    uids: Iterable[int] = [],
    gids: Iterable[int] = [],
):
    tree = NpmTree(tree=tree, deep=True)
    domains = list(
        filter(lambda x: get_current_euid(x) in uids, medusa_domains)
    )
    tree.generalize_by_owner_directory(db, domains, uids, gids, verbose=True)

    # TODO: This probably doesn't have to be used here.
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
