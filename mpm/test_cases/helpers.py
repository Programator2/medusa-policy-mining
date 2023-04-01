"""Helper functions for test cases."""

from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.tree import NpmTree


def populate_accesses(
    tree: NpmTree,
    db: DatabaseWriter,
    case: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: set[tuple[tuple]],
) -> None:
    tree.insert_medusa_accesses(
        db,
        case,
        eval_case,
        subject_contexts,
        medusa_domains,
    )

    # TODO: This needs to be done just once --- refactor it out
    db.insert_selinux_accesses(
        case,
        subject_contexts,
        object_types,
        verbose=False,
    )

    db.fill_missing_selinux_accesses(
        case,
        verbose=False,
    )
    tree.fill_missing_medusa_accesses(
        db,
        case,
        eval_case,
        subject_contexts,
        medusa_domains,
    )
