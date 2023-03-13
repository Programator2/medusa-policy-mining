from load import load_policy
from tree import NpmTree
from sys import argv
from policy import create_constable_policy
from parser import parse_log
from tree import DomainTree
from pprint import pprint
from blessed import BlessedList
from fs2json.db import DatabaseRead
from generalize.runs import generalize_mupltiple_runs


def main():
    trees: BlessedList[NpmTree] = BlessedList(NpmTree)
    domain_trees: BlessedList[DomainTree] = BlessedList(DomainTree)
    domain_transitions: BlessedList[
        dict[tuple[tuple, str, Any], tuple]
    ] = BlessedList(dict)

    tree = trees[0]
    domain_tree = domain_trees[0]
    domain_transition: dict[tuple[tuple, str, Any], tuple] = domain_transitions[
        0
    ]

    db = DatabaseRead('fs.db')

    for i, arg in enumerate(argv[1:]):
        log = parse_log(arg, domain_trees[i], domain_transitions[i])
        trees[i].load_log(log)

    regex_tree = generalize_mupltiple_runs(db, *trees)

    # tree.generalize(tree.get_node(tree.root), verbose=True)
    # tree.show()
    # tree.generalize_nonexistent(db, verbose=True)
    # tree.generalize_by_owner(db, verbose=True)
    # policy = create_constable_policy(tree, domain_transition)
    # print(policy)
    db.close()


if __name__ == '__main__':
    main()
