import re
from utils import path_components
from pathlib import PurePosixPath
from fs2json.db import DatabaseRead
from config import GENERALIZE_PROC


def generalize_proc(path: str) -> str:
    """Generalize accesses to /proc filesystem. Generalizes accesses to PIDs.

    This function should be used on final paths in the Constable policy.

    :returns: Original path with number regex or the same path if it's not a
    path in the `/proc` filesystem.
    """
    if not GENERALIZE_PROC:
        return path
    return re.sub(r'^/proc/[0-9]+/', r'/proc/[0-9]+/', path, 1)


# TODO: Based on the real contents of the folder (normal algorithm, but with
# information from the database applied)
def generalize_full_fs(path: str, db):
    pass


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


# TODO: Compare multiple runs
def generalize_mupltiple_runs():
    pass
