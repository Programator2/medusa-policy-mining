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

    results['standard generalization'] = (
        mpm.test_cases.generalize.test(
            trees[0],
            'postgresql1',
            'standard generalization',
            mpm.contexts.subjects.POSTGRESQL,
            mpm.contexts.objects.POSTGRESQL,
            domain_transitions[0].values(),
            db,
        )
    )
    results['by owner'] = (
        mpm.test_cases.generalize_by_owner.test(
            trees[0],
            'postgresql1',
            'by owner',
            mpm.contexts.subjects.POSTGRESQL,
            mpm.contexts.objects.POSTGRESQL,
            domain_transitions[0].values(),
            db,
        )
    )
    results['nonexistent'] = (
        mpm.test_cases.generalize_nonexistent.test(
            trees[0],
            'postgresql1',
            'nonexistent',
            mpm.contexts.subjects.POSTGRESQL,
            mpm.contexts.objects.POSTGRESQL,
            domain_transitions[0].values(),
            db,
        )
    )
    results['multiple'] = (
        mpm.test_cases.generalize_multiple_runs.test(
            trees,
            'postgresql1',
            'multiple',
            mpm.contexts.subjects.POSTGRESQL,
            mpm.contexts.objects.POSTGRESQL,
            domain_transitions[0].values(),
            db,
        )
    )

    db.close()

    pprint(results)

    return 0


if __name__ == '__main__':
    exit(main())
