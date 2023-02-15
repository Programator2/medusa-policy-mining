from load import load_policy
from tree import NpmTree
from sys import argv
from policy import create_constable_policy
from parser import parse_log
from tree import DomainTree


def main():
    tree = NpmTree()
    domain_tree = DomainTree()
    for arg in argv[1:]:
        tree.load_log(parse_log(arg, domain_tree))
    domain_tree.show()
    tree.generalize(tree.get_node(tree.root))
    print('Po generalizacii')
    tree.show()
    print(create_constable_policy(tree))


if __name__ == '__main__':
    main()
