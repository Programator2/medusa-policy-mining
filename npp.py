from load import load_policy
from tree import NpmTree
from sys import argv
from policy import create_constable_policy
from parser import parse_log


def main():
    tree = NpmTree()
    for arg in argv[1:]:
        tree.load_log(parse_log(arg))
    # tree._create_path('/this/is/a/path')
    # tree._create_path('/this/is/another/path')
    tree.show()
    # tree.print_access('/var/lib/mysql')
    # tree.print_access('/')
    tree.generalize(tree.get_node(tree.root))
    print('Po generalizacii')
    tree.show()
    print(create_constable_policy(tree))


if __name__ == '__main__':
    main()
