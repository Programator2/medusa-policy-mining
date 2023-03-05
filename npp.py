from load import load_policy
from tree import NpmTree
from sys import argv
from policy import create_constable_policy
from parser import parse_log
from tree import DomainTree


def main():
    tree = NpmTree(db='fs.db')
    domain_tree = DomainTree()
    domain_transition: dict[tuple[tuple, str, Any], tuple] = {}
    for arg in argv[1:]:
        log = parse_log(arg, domain_tree, domain_transition)
        tree.load_log(log)

    tree.generalize(tree.get_node(tree.root), True)
    tree.generalize_nonexistent(True)
    policy = create_constable_policy(tree, domain_transition)
    print(policy)


if __name__ == '__main__':
    main()
