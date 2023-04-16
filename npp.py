#!/usr/bin/env python3
from mpm.tree import NpmTree, DomainTree
from sys import argv, stderr, exit
from mpm.policy import create_constable_policy
from mpm.parser import parse_log
from pprint import pprint
from fs2json.db import DatabaseWriter
from more_itertools import split_at
from mpm.contexts.objects import get_object_types_by_name
from mpm.contexts.subjects import get_subject_context_by_name
import mpm.test_cases
from fs2json.evaluation import Result
from getopt import getopt, GetoptError
from typing import Any
import sys
import io
from pathlib import Path
from mpm.test_cases.helpers import TestCaseContext
from mpm.test_cases import TestCase
from copy import copy


def usage():
    print(
        f"""Usage: {argv[0]} [OPTION]... CASE_NAME SERVICE1_LOG1... [-- SERVICE2_LOG1... ]...

Logs from different services should be split using '--'. Multiple runs of the
same service can be specified without the splitter.

Options:

      --user=USER_NAME     Name of a user that should be used for the owner
                           directory generalizer. Multiple names may be
                           specified.
      --group=GROUP_NAME   Name of a group that should be used for the owner
                           directory generalizer. Multiple names may be
                           specified.
      --subject=CONTEXT    Name of the subject context as defined in
                           subjects.py
      --object=CONTEXT     Name of the object context as defined in objects.py
 """,
        file=stderr,
    )
    return -1


def main():
    if len(argv) < 3:
        return usage()
    try:
        optlist, args = getopt(
            argv[1:], '', ['user=', 'group=', 'subject=', 'object=', 'help']
        )
    except GetoptError as e:
        print(e, file=sys.stderr)
        return usage()

    uid_names: list[str] = []
    gid_names: list[str] = []

    subject_contexts: tuple[str, ...] = None
    object_types: tuple[str, ...] = None

    for opt, value in optlist:
        match opt:
            case '--user':
                uid_names.append(value)
            case '--group':
                gid_names.append(value)
            case '--object':
                object_types = get_object_types_by_name(value)
            case '--subject':
                subject_contexts = get_subject_context_by_name(value)
            case '--help':
                return usage()
            case _:
                return usage()

    case = args[0]
    args = args[1:]
    runs = list(split_at(args, lambda x: x == '--'))
    max_runs = max(len(run) for run in runs)
    trees: list[NpmTree] = []
    domain_trees: list[DomainTree] = []
    domain_transitions: list[dict[tuple[tuple, str, Any], tuple]] = []

    for i in range(max_runs):
        trees.append(NpmTree())
        domain_trees.append(DomainTree())
        domain_transitions.append({})

    for logs in runs:
        for i, log_path in enumerate(logs):
            log = parse_log(log_path, domain_trees[i], domain_transitions[i])
            trees[i].load_log(log)

    db = DatabaseWriter('fs.db')

    results: dict[Result] = {}

    mpm.test_cases.helpers.prepare_selinux_accesses(
        db, case, subject_contexts, object_types
    )

    fhs_path = 'fhs_rules.txt'

    ctx = TestCaseContext(
        trees[0],
        case,
        '',
        subject_contexts,
        object_types,
        domain_transitions[0].values(),
        db,
        fhs_path,
    )
    ctx.trees = trees
    ctx.uids = [db.get_uid_from_name(name) for name in uid_names]
    ctx.gids = [db.get_gid_from_name(name) for name in gid_names]

    # Double pass because reference items may be added to the database through
    # generalization
    for _ in range(2):
        ctx.eval_case = 'no generalization'
        test_cases = (TestCase.NO_GENERALIZATION,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'standard generalization'
        test_cases = (TestCase.STANDARD,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'by owner'
        test_cases = (TestCase.OWNER,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'by owner directory'
        test_cases = (TestCase.OWNER_DIRECTORY,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'nonexistent'
        test_cases = (TestCase.NONEXISTENT,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'multiple'
        test_cases = (TestCase.MULTIPLE_RUNS,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'multiple+generalize'
        test_cases = (TestCase.MULTIPLE_RUNS, TestCase.STANDARD)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'nonexistent+generalize'
        test_cases = (TestCase.NONEXISTENT, TestCase.STANDARD)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

    db.close()

    summary_buf = io.StringIO()

    for name, result in results.items():
        print(name, file=summary_buf)
        print('-' * len(name), file=summary_buf)
        print(result.summary(), end='\n\n', file=summary_buf)

    summary_str = summary_buf.getvalue()

    print(summary_str, end='')
    result_dir = Path(f'results/{case}')
    with open(result_dir / 'summary.txt', 'w') as f:
        f.write(summary_str)

    summary_buf.close()

    return 0


if __name__ == '__main__':
    exit(main())
