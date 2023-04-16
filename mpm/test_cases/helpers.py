"""Helper functions for test cases."""

from fs2json.db import DatabaseWriter, DatabaseRead
from fs2json.evaluation import Result
from collections.abc import Iterable
from mpm.tree import NpmTree
from pathlib import Path
from mpm.generalize.generalize import generalize_from_fhs_rules
from dataclasses import dataclass, field


@dataclass
class TestCaseContext:
    tree: NpmTree
    case_name: str
    eval_case: str
    subject_contexts: Iterable[str]
    object_types: Iterable[str]
    medusa_domains: Iterable[tuple[tuple]]
    db: DatabaseRead
    fhs_path: str
    uids: Iterable[int] = field(default_factory=list)
    gids: Iterable[int] = field(default_factory=list)
    trees: Iterable[NpmTree] = field(default_factory=list)


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
    confusion: Result,
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
    with open(result_dir / 'underpermission.txt', 'w') as f:
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
    with open(result_dir / 'confusion.txt', 'w') as f:
        f.write(confusion. summary())


def evaluate(
    tree: NpmTree,
    case_name: str,
    eval_case: str,
    subject_contexts: Iterable[str],
    object_types: Iterable[str],
    medusa_domains: Iterable[tuple[tuple]],
    db: DatabaseRead,
    fhs_path: str,
) -> Result:
    generalize_from_fhs_rules(fhs_path, tree, medusa_domains)
    populate_accesses(
        tree,
        db,
        case_name,
        eval_case,
        subject_contexts,
        object_types,
        medusa_domains,
    )
    confusion = db.get_permission_confusion(
        case_name, subject_contexts, eval_case
    )
    export_results(case_name, eval_case, subject_contexts, db, confusion, tree)
    return confusion


def prologue(ctx: TestCaseContext) -> None:
    """Prepare test case."""
    ctx.tree = NpmTree(tree=ctx.tree, deep=True)


def epilogoue(ctx: TestCaseContext) -> Result:
    """Compute evaluation."""
    return evaluate(
        ctx.tree,
        ctx.case_name,
        ctx.eval_case,
        ctx.subject_contexts,
        ctx.object_types,
        ctx.medusa_domains,
        ctx.db,
        ctx.fhs_path
    )
