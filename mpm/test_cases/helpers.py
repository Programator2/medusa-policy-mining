"""Helper functions for test cases."""

from fs2json.db import DatabaseWriter
from collections.abc import Iterable
from mpm.tree import NpmTree
from pathlib import Path


def prepare_selinux_accesses(
    db: DatabaseWriter,
    case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
):
    """Insert SELinux accesses into the database.

    Accesses are selected according to `object_types`. This function should be
    called just once before the generalization tests.
    """
    db.insert_selinux_accesses(
        case,
        subject_contexts,
        object_types,
        verbose=False,
    )


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


def export_results(
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    db: DatabaseWriter,
    tree: NpmTree = None,
):
    result_dir = Path(f'results/{case_name}/{eval_case}')
    result_dir.mkdir(parents=True, exist_ok=True)
    with open(result_dir / 'hit.txt', 'w') as f:
        db.print_confusion(
            case_name, subject_contexts, eval_case, 'hit', f
        )
    with open(result_dir / 'correct_denial.txt', 'w') as f:
        db.print_confusion(
            case_name, subject_contexts, eval_case, 'correct denial', f
        )
    with open(result_dir / 'undepermission.txt', 'w') as f:
        db.print_confusion(
            case_name, subject_contexts, eval_case, 'underpermission', f
        )
    with open(result_dir / 'overpermission.txt', 'w') as f:
        db.print_confusion(
            case_name, subject_contexts, eval_case, 'overpermission', f
        )
    if tree is not None:
        with open(result_dir / 'tree.txt', 'w') as f:
            f.write(tree.show(stdout=False))
