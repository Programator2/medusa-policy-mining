from enum import Flag, auto, Enum


class OwnerGeneralizationStrategy(Flag):
    """1) If the current user owns the directory, it will be automatically
    generalized
    2) If the current user owns all the files in the directory, it will be
    automatically generalized
    3) If the current user has read access to all the files in the directory, it
    will be automatically generalized read star access to contents of this
    directory
    4) If the current user has write access to all the files in the directory,
    it will be automatically generalized write star access to contents of this
    directory
    """

    OWN_DIR = auto()
    OWN_FILES = auto()
    READ_FILES = auto()
    WRITE_FILES = auto()


class MultipleRunsSingleton(Enum):
    """To configure multiple runs generalization."""
    NO_ACTION = auto()
    """No generalization will be created."""
    NUMERICAL_GENERALIZATION = auto()
    """Numerical part will be regexped."""
    FULL_GENERALIZATION = auto()
    """All siblings of the file will be generalized (the same as .* under parent
    directory)."""


GENERALIZE_THRESHOLD = 1.0
"""Fraction of how many items need to have the same domain and permission from
the directory for the directory to be generalized (globbed).

Total number of items in a directory is derived *just* from the logs.
"""

GENERALIZE_FS_THRESHOLD = 1.0
"""Fraction of how many items need to have the same domain and permission from
the directory for the directory to be generalized (globbed).

Total number of items in a directory is derived from the filesystem snapshot
(database).
"""

GENERALIZE_PROC = True
"""`True` if accesses to /proc/.*/ should be generalized"""

OWNER_GENERALIZATION_STRATEGY = (
    OwnerGeneralizationStrategy.OWN_DIR
    | OwnerGeneralizationStrategy.OWN_FILES
    | OwnerGeneralizationStrategy.READ_FILES
    | OwnerGeneralizationStrategy.WRITE_FILES
)
"""Which generalization strategies will be used for UGO generalization."""

MULTIPLE_RUNS_STRATEGY = MultipleRunsSingleton.NUMERICAL_GENERALIZATION
