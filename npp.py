#!/usr/bin/env python3
#  Copyright (C) 2023 Roderik Ploszek
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
from itertools import chain


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

    uid_name_groups: list[list[str]] = []
    gid_name_groups: list[list[str]] = []

    subject_context_groups: list[list[str, ...]] = []
    object_type_groups: list[list[str, ...]] = []

    for opt, value in optlist:
        match opt:
            case '--user':
                uid_name_groups.append(value.split(','))
            case '--group':
                gid_name_groups.append(value.split(','))
            case '--object':
                object_type_groups.append(
                    list(
                        chain.from_iterable(
                            get_object_types_by_name(v)
                            for v in value.split(',')
                        )
                    )
                )
            case '--subject':
                subject_context_groups.append(
                    list(
                        chain.from_iterable(
                            get_subject_context_by_name(v)
                            for v in value.split(',')
                        )
                    )
                )
            case '--help':
                return usage()
            case _:
                return usage()

    # Clean up gids
    # This is a hack and it should be handled better.
    # But there's no time, so I'm doing it like this.
    #
    # Basically, the number of items in these lists has to be the same, because
    # later I'm zipping theme together.
    if len(uid_name_groups) > len(gid_name_groups):
        for i in range(len(uid_name_groups) - len(gid_name_groups)):
            gid_name_groups.append([])
    if len(gid_name_groups) > len(uid_name_groups):
        for i in range(len(gid_name_groups) - len(uid_name_groups)):
            uid_name_groups.append([])

    case = args[0]
    args = args[1:]
    # runs contains individual services: [[service1 log1, service1 log2],
    # [service2 log1, service2 log2]]
    runs = list(split_at(args, lambda x: x == '--'))
    max_runs = max(len(run) for run in runs)
    # One tree for each "run", but multiple services
    trees: list[NpmTree] = []
    # domain_trees: list[DomainTree] = []
    # `domain_transition_groups`: [[{s1 run1}, {s1 run2}], [{s2 run1}, {s2 run2}]]
    domain_transition_groups: list[
        list[dict[tuple[tuple, str, Any], tuple]]
    ] = []

    # Create one tree for each run. A tree can contain multiple services.
    for i in range(max_runs):
        trees.append(NpmTree())

    # Create dicts for domain transitions. Each service gets private domain
    # transition sets for each run.
    for _ in runs:
        l = []
        domain_transition_groups.append(l)
        for i in range(max_runs):
            # domain_trees.append(DomainTree())
            l.append({})

    for j, logs in enumerate(runs):
        # `logs` are log files from one service
        for i, log_path in enumerate(logs):
            # TODO: Remove second argument altogether
            # These are different runs for *one* service
            log = parse_log(log_path, None, domain_transition_groups[j][i])
            trees[i].load_log(log)

    db = DatabaseWriter('fs.db')

    results: dict[str, Result] = {}

    mpm.test_cases.helpers.prepare_selinux_accesses(
        db, case, subject_context_groups, object_type_groups
    )

    fhs_path = 'fhs_rules.txt'

    ctx = TestCaseContext(
        trees[0],
        case,
        '',
        subject_context_groups,
        object_type_groups,
        [
            domain_transitions[0].values()
            for domain_transitions in domain_transition_groups
        ],
        db,
        fhs_path,
    )
    ctx.trees = trees
    ctx.uids = [
        [db.get_uid_from_name(name) for name in uid_names]
        for uid_names in uid_name_groups
    ]
    ctx.gids = [
        [db.get_gid_from_name(name) for name in gid_names]
        for gid_names in gid_name_groups
    ]

    # Double pass because reference items may be added to the database through
    # generalization
    for _ in range(2):
        ctx.eval_case = 'no generalization'
        test_cases = (TestCase.NO_GENERALIZATION,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'T'
        test_cases = (TestCase.STANDARD,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'O'
        test_cases = (TestCase.OWNER,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'OD'
        test_cases = (TestCase.OWNER_DIRECTORY,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'N'
        test_cases = (TestCase.NONEXISTENT,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        ctx.eval_case = 'M'
        test_cases = (TestCase.MULTIPLE_RUNS,)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )

        # pairs
        ctx.eval_case = 'M+T'
        test_cases = (TestCase.MULTIPLE_RUNS, TestCase.STANDARD)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'N+T'
        test_cases = (TestCase.NONEXISTENT, TestCase.STANDARD)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'O+T'
        test_cases = (TestCase.OWNER, TestCase.STANDARD)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'OD+T'
        test_cases = (TestCase.OWNER_DIRECTORY, TestCase.STANDARD)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'OD+O'
        test_cases = (TestCase.OWNER_DIRECTORY, TestCase.OWNER)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'O+N'
        test_cases = (TestCase.OWNER, TestCase.NONEXISTENT)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'M+O'
        test_cases = (TestCase.MULTIPLE_RUNS, TestCase.OWNER)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'OD+N'
        test_cases = (TestCase.OWNER_DIRECTORY, TestCase.NONEXISTENT)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'M+OD'
        test_cases = (TestCase.MULTIPLE_RUNS, TestCase.OWNER_DIRECTORY)
        results[ctx.eval_case] = mpm.test_cases.execute_tests(
            test_cases, copy(ctx)
        )
        ctx.eval_case = 'M+N'
        test_cases = (TestCase.MULTIPLE_RUNS, TestCase.NONEXISTENT)
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

    with open(result_dir / 'summary.csv', 'w') as f:
        f.write(result.summary_csv_header())
        for name, result in results.items():
            f.write(result.summary_csv_line(name))

    with open(result_dir / 'short_summary.tex', 'w') as f:
        f.write(result.summary_tabular_short_header())
        for name, result in results.items():
            f.write(result.summary_tabular_short_line(name))
        f.write(result.summary_tabular_footer())

    with open(result_dir / 'full_summary.tex', 'w') as f:
        f.write(result.summary_csv_header())
        for name, result in results.items():
            f.write(result.summary_tabular_full_line(name))
        f.write(result.summary_tabular_footer())

    summary_buf.close()

    return 0


if __name__ == '__main__':
    exit(main())
