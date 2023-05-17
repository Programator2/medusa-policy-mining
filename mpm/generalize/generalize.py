from __future__ import annotations
import re
from pathlib import PurePosixPath
from fs2json.db import DatabaseRead
from mpm.config import GENERALIZE_PROC
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mpm.tree import NpmTree
from collections.abc import Iterable


def generalize_proc(path: str) -> str:
    """Generalize accesses to /proc filesystem. Generalizes accesses to PIDs.

    This function should be used on final paths in the Constable policy.

    :returns: Original path with number regex or the same path if it's not a
    path in the `/proc` filesystem.
    """
    if not GENERALIZE_PROC:
        return path
    return re.sub(r'^/proc/[0-9]+/', r'/proc/[0-9]+/', path, 1)


def generalize_nonexistent(path: str, db: DatabaseRead):
    """Generalize non-existent files.

    Rationale: The file had to be deleted if the database of the filesystem was
    generated after the log. If a process can create files in a directory, then
    it should have at least access to the files in the directory and write
    access to the directory itself. Note that as all generalizations, this can
    cause overpermission.

    :returns: Generalized path containing regex.
    """
    # TODO: Rename this function or remove it altogether --- it doesn't serve
    # the intended (based on its name) purpose where it's used.
    found = db.search_path(path)
    if found:
        # Path exists, no need to generalize
        return ''
    # Path doesn't exist, generalize up to last component
    return str(PurePosixPath(path) / '.*')


def generalize_from_fhs_rules(
    rules_path: str,
    tree: NpmTree,
    medusa_domain_groups: Iterable[Iterable[tuple[tuple]]],
) -> None:
    """Generalize using rules from a file.

    Rules should use general knowledge about the Linux operating system. Name
    FHS comes from the Filesystem Hierarchy Standard that describes standard
    hierarchy of folders and their contents. The rules should ideally include
    permissions that are applicable to all subjects on the system (ambient
    rules).

    The main purpose of this function is to clean up undepermissions that are
    created by the `fill_missing_selinux_accesses` method. Underpermission
    entries that are created by that function may not be necessary for the
    correct function of the application and they taint and shew the results of
    the evaluation (higher false negatives).

    `generalize_from_fhs_rules` can use different rules for every
    generalization, but ideally, one rule list should be used.

    :param rules_path: path to the rules file.
    :param tree: tree that the generalization will be applied to.
    :param medusa_domains: domains that will be used as subjects for the newly
    created rules.
    """
    access_info = []
    for medusa_domains in medusa_domain_groups:
        for d in medusa_domains:
            access_info.append((d[-1][1], d))

    with open(rules_path) as f:
        rules = tree.load_fhs_config(f)
    for rule in rules:
        tree.generalize_fhs_rule(rule, access_info)
