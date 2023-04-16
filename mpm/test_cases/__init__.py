from . import (
    generalize,
    generalize_by_owner,
    generalize_multiple_runs,
    generalize_nonexistent,
    generalize_by_owner_directory,
)
from enum import Enum, auto
from collections.abc import Iterable
from .helpers import prologue, epilogoue, TestCaseContext
from fs2json.evaluation import Result


test_case_funcs = {}


class TestCase(Enum):
    NO_GENERALIZATION = auto()
    STANDARD = auto()
    OWNER = auto()
    OWNER_DIRECTORY = auto()
    MULTIPLE_RUNS = auto()
    NONEXISTENT = auto()


test_case_funcs[TestCase.NO_GENERALIZATION] = lambda x: None
test_case_funcs[TestCase.STANDARD] = generalize.test_core
test_case_funcs[TestCase.OWNER] = generalize_by_owner.test_core
test_case_funcs[
    TestCase.OWNER_DIRECTORY
] = generalize_by_owner_directory.test_core
test_case_funcs[TestCase.MULTIPLE_RUNS] = generalize_multiple_runs.test_core
test_case_funcs[TestCase.NONEXISTENT] = generalize_nonexistent.test_core


def execute_tests(
    test_cases: Iterable[TestCase], ctx: TestCaseContext
) -> Result:
    prologue(ctx)
    for test in test_cases:
        test_case_funcs[test](ctx)
    return epilogoue(ctx)
