#!/usr/bin/env python3
from tree import NpmTree
from sys import argv, stderr, exit
from policy import create_constable_policy
from parser import parse_log
from tree import DomainTree
from pprint import pprint
from fs2json.db import DatabaseRead
from generalize.runs import generalize_mupltiple_runs, merge_tree
from more_itertools import split_at


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

    db = DatabaseRead('fs.db')

    for logs in runs:
        for i, log_path in enumerate(logs):
            log = parse_log(log_path, domain_trees[i], domain_transitions[i])
            trees[i].load_log(log)


    # tree.generalize(trees[0].get_node(tree.root), verbose=True)
    tree.generalize_nonexistent(db, verbose=True)
    tree.show()
    # tree.generalize_by_owner(db, verbose=True)

    regex_tree = generalize_mupltiple_runs(db, *trees)
    new_tree = merge_tree(*trees)
    # policy = create_constable_policy(tree, domain_transition)
    # print(policy)
    new_tree.show()
    db.close()
    return 0


if __name__ == '__main__':
    exit(main())
