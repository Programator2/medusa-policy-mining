#!/usr/bin/env python3
from mpm.tree import NpmTree, DomainTree
from sys import argv, stderr, exit
from mpm.policy import create_constable_policy
from mpm.parser import parse_log
from pprint import pprint
from fs2json.db import DatabaseWriter
from more_itertools import split_at
import mpm.contexts
import mpm.test_cases


def main():
    if len(argv) < 2:
        print(
            f"""Usage: {argv[0]} <service1-log1> ... [--] <service2-log1> ...

Logs from different services should be split using `--`. Multiple runs of the
same service can be specified without the splitter.""",
            file=stderr,
        )
        return -1
    args = argv[1:]
    runs = list(split_at(args, lambda x: x == '--'))
    max_runs = max(len(run) for run in runs)
    trees: list[NpmTree] = []
    domain_trees: list[DomainTree] = []
    domain_transitions: list[dict[tuple[tuple, str, Any], tuple]] = []
    for i in range(max_runs):
        trees.append(NpmTree())
        domain_trees.append(DomainTree())
        domain_transitions.append({})

    tree = trees[0]
    domain_transition: dict[tuple[tuple, str, Any], tuple] = domain_transitions[
        0
    ]

    for logs in runs:
        for i, log_path in enumerate(logs):
            log = parse_log(log_path, domain_trees[i], domain_transitions[i])
            trees[i].load_log(log)

    trees[0].move_generalized_to_regexp()

    db = DatabaseWriter('fs.db')

    case = 'postgresql1'
    results = {}

    subject_contexts = mpm.contexts.subjects.POSTGRESQL
    object_types = mpm.contexts.objects.POSTGRESQL

    mpm.test_cases.helpers.prepare_selinux_accesses(
        db, case, subject_contexts, object_types
    )

    # Double pass because reference items may be added to the database through
    # generalization
    for _ in range(2):
        eval_case = 'standard generalization'
        results[eval_case] = mpm.test_cases.generalize.test(
            trees[0],
            case,
            eval_case,
            subject_contexts,
            object_types,
            domain_transitions[0].values(),
            db,
        )
        eval_case = 'by owner'
        results[eval_case] = mpm.test_cases.generalize_by_owner.test(
            trees[0],
            case,
            eval_case,
            subject_contexts,
            object_types,
            domain_transitions[0].values(),
            db,
        )
        eval_case = 'by owner directory'
        results[eval_case] = mpm.test_cases.generalize_by_owner_directory.test(
            trees[0],
            case,
            eval_case,
            subject_contexts,
            object_types,
            domain_transitions[0].values(),
            db,
            [db.get_uid_from_name('postgres')],
            [],
        )
        eval_case = 'nonexistent'
        results[eval_case] = mpm.test_cases.generalize_nonexistent.test(
            trees[0],
            case,
            eval_case,
            subject_contexts,
            object_types,
            domain_transitions[0].values(),
            db,
        )
        eval_case = 'multiple'
        results[eval_case] = mpm.test_cases.generalize_multiple_runs.test(
            trees,
            case,
            eval_case,
            subject_contexts,
            object_types,
            domain_transitions[0].values(),
            db,
        )

    db.close()

    pprint(results)

    return 0


if __name__ == '__main__':
    exit(main())
