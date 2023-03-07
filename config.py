from enum import Flag, auto


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


GENERALIZE_PROC = True
OWNER_GENERALIZATION_STRATEGY = (
    OwnerGeneralizationStrategy.OWN_DIR
    | OwnerGeneralizationStrategy.OWN_FILES
    | OwnerGeneralizationStrategy.READ_FILES
    | OwnerGeneralizationStrategy.WRITE_FILES
)
