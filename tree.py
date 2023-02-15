"""Tree data structure for the Medusa Policy Miner"""
from treelib import Tree
from treelib.exceptions import NodeIDAbsentError
from treelib.node import Node
from typing import Callable
from collections import UserList, Counter
from pprint import pprint
from collections.abc import Iterable
from more_itertools import first
from permission import Permission


class Access:
    """Represents an access by some proces. Stored inside NpmNode"""

    def __init__(self, permissions: Permission):
        self.permissions = permissions
        self.uid = None
        self.comm = None

    def __repr__(self):
        return f'<{self.comm} ({self.uid}): {self.permissions}>'

    def __eq__(self, other):
        return (
            self.permissions == other.permissions
            and self.uid == other.uid
            and self.comm == other.comm
        )

    def __hash__(self):
        return hash((self.permissions, self.uid, self.comm))


class NpmNode(set):
    """Represents internal data of the node (especially permissions)."""

    def __init__(self, *args):
        # Contains set of `Access` objects that were generalized (globbed) for
        # this node. This access should be used for node/* rule. This set should
        # contain just one object, but I'm keeping it as a set just in case.
        self.generalized : set[Access] = set()
        super().__init__(self, *args)

    def add_item(self, access: Access):
        """Add access to this list, if it doesn't already exist. If there is an
        access with the same uid and comm but different permissions, adjust
        permissions of the existing access accordingly. This can only add
        permissions, not remove them.

        For example, if there is an access for reading lready in the list and
        add is called with another access with the same uid and comm, but with
        write permission, the new permissions will be set to read and write.
        """
        for a in self:
            if access.uid == a.uid and access.comm == a.comm:
                self.remove(a)
                a.permissions = access.permissions | a.permissions
                self.add(a)
                return
        self.add(access)


class GenericTree(Tree):
    def __init__(self, *args, **kwargs):
        super().__init__(self, args, kwargs)

    def _create_path(self, entries: Iterable):
        """Create necessary nodes in the tree to represent a path.

        :param path: tuple of strings representing names of nodes in the path
        """
        parent = self.npm_root
        for e in entries:
            exists = next(
                filter(
                    lambda x: x.tag == e,
                    (self[y] for y in parent.successors(self.identifier)),
                ),
                None,
            )
            if exists is not None:
                parent = exists
            else:
                parent = self.create_node(e, parent=parent.identifier)
        return parent


class DomainTree(GenericTree):
    def __init__(self, *args, **kwargs):
        super().__init__(self, args, kwargs)
        self.npm_root = self.create_node('/', '/')
        self.root = self.npm_root.identifier

    def _create_path(self, path: tuple[str]):
        """Create necessary nodes in the tree to represent an execution path.

        :param path: tuple of strings representing paths of executables
        executed in a thread
        """
        return GenericTree._create_path(self, path)


class NpmTree(GenericTree):
    def __init__(self, *args, **kwargs):
        super().__init__(self, args, kwargs)
        self.npm_root = self.create_node('/', '/')
        self.root = self.npm_root.identifier

    def _create_path(self, path: str):
        """Create necessary nodes in the tree to represent a path.

        :param path: string in the form of `/this/is/a/path`. It has to start
        with a `/` and optionally end with a `/`
        """
        entries = filter(lambda x: bool(x), path.split('/'))
        return GenericTree._create_path(self, entries)

    def _create_path_with_permission(self, path: str):
        node = self._create_path(path)
        return node

    def load_log(self, log: Iterable):
        def normalize_comm(comm: str) -> str:
            """Return a normalized version of the comm name. E.g. `(mariadbd)`
            will become `mariadb`"""
            comms = ('sshd', 'mariadbd')
            for c in comms:
                if c in comm:
                    return c
            return comm

        # TODO: Also normalize accesses. If someone requests write, it should
        # get the highest priority.

        # TODO: Also de-duplicate after normalizing comm
        for d in log:
            node = self._create_path_with_permission(
                d.path.removesuffix(' (deleted)')
            )

            perm = Permission(int(d.permission))

            if node.data == None:
                node.data = NpmNode()
            access = Access(perm)
            access.uid = int(d.uid)
            access.comm = normalize_comm(d.proctitle)

            node.data.add_item(access)

    def get_parent(self, node: Node) -> Node:
        """Return parent Node object for node"""
        return self.get_node(node.predecessor(self.identifier))

    def print_access(self, path: str):
        """Prints access information for a given path.

        :param path: Absolute path in a form of /etc/a/b"""
        entries = filter(lambda x: bool(x), path.split('/'))
        parent = self.npm_root
        for e in entries:
            exists = next(
                filter(
                    lambda x: x.tag == e,
                    (self[y] for y in parent.successors(self.identifier)),
                ),
                None,
            )
            if exists is not None:
                parent = exists
            else:
                print(f'Path {path} does not exist.')
                return
        pprint(parent.data)

    def get_path(self, node: Node) -> str:
        """Print full path for a given node"""
        path = ''
        while node != self.npm_root:
            # print('at', node.tag)
            path = '/' + node.tag + path
            node = self.get_parent(node)
        return path

    def generalize(self, node: Node):
        """Do a recursive depth-first search and on the way up TODO:
        finish"""
        if not (children := node.successors(self.identifier)):
            return
        for n in children:
            self.generalize(self.get_node(n))
        # TODO Maybe all nodes should include NpmNode as their data, because now
        # we have to checke everywhere if data is not None
        access_sets = filter(
            lambda x: x is not None, (self.get_node(n).data for n in children)
        )
        # access_sets_list = list(access_sets)
        # breakpoint()
        # number_of_items = len(access_sets_list)
        c = Counter()
        items_count = 0
        for access in access_sets:
            items_count += 1
            for perm in access:
                c[perm] += 1
        # access_set = set().union(*access_sets)
        # TODO: If you want to include threshold parameter, you need to compute
        # the ratio here
        for perm, number in c.items():
            # This just checks for the complete number of items not considering
            # the type (directory/file)
            if number == items_count:
                # This means that all child items have the same accesses
                if node.data == None:
                    node.data = NpmNode()
                node.data.generalized.add(ac := perm)
                print(f'Generalized {ac} for {self.get_path(node)}')

        # if len(access_set) == 1:
        #     # This means that all child items have the same accesses
        #     if node.data == None:
        #         node.data = NpmNode()
        #     node.data.generalized.add(ac := first(access_set))
        #     print(f'Generalized {ac} for {self.get_path(node)}')
        # print('Access set ma', len(access_set), 'poloziek')

    # TODO: override this function without copying so much stuff from the
    # library
    def show(
        self,
        nid=None,
        level=Tree.ROOT,
        idhidden=True,
        filter=None,
        key=None,
        reverse=False,
        line_type='ascii-ex',
        data_property=None,
        stdout=True,
    ):
        """
        Print the tree structure in hierarchy style.

        You have three ways to output your tree data, i.e., stdout with ``show()``,
        plain text file with ``save2file()``, and json string with ``to_json()``. The
        former two use the same backend to generate a string of tree structure in a
        text graph.

        * Version >= 1.2.7a*: you can also specify the ``line_type`` parameter, such as 'ascii' (default), 'ascii-ex', 'ascii-exr', 'ascii-em', 'ascii-emv', 'ascii-emh') to the change graphical form.

        :param nid: the reference node to start expanding.
        :param level: the node level in the tree (root as level 0).
        :param idhidden: whether hiding the node ID when printing.
        :param filter: the function of one variable to act on the :class:`Node` object.
            When this parameter is specified, the traversing will not continue to following
            children of node whose condition does not pass the filter.
        :param key: the ``key`` param for sorting :class:`Node` objects in the same level.
        :param reverse: the ``reverse`` param for sorting :class:`Node` objects in the same level.
        :param line_type:
        :param data_property: the property on the node data object to be printed.
        :return: None
        """
        self._reader = ""

        def write(line):
            self._reader += line.decode('utf-8') + "\n"

        def print_callback(node):
            return (
                '[' + ', '.join(str(i) for i in node.data) + ']' + (f' glob:{node.data.generalized}' if node.data.generalized else '')
                if node.data is not None
                else ""
            )

        try:
            self.print_backend(
                nid,
                level,
                idhidden,
                filter,
                key,
                reverse,
                line_type,
                data_property,
                func=write,
                print_callback=print_callback,
            )
        except NodeIDAbsentError:
            print('Tree is empty')

        if stdout:
            print(self._reader)
        else:
            return self._reader

    def print_backend(
        self,
        nid=None,
        level=Tree.ROOT,
        idhidden=True,
        filter=None,
        key=None,
        reverse=False,
        line_type='ascii-ex',
        data_property=None,
        func=print,
        print_callback: Callable[[Node], str] = None,
    ):
        """Another implementation of printing tree using Stack
        Print tree structure in hierarchy style.

        For example:

        .. code-block:: bash

            Root
            |___ C01
            |    |___ C11
            |         |___ C111
            |         |___ C112
            |___ C02
            |___ C03
            |    |___ C31

        A more elegant way to achieve this function using Stack
        structure, for constructing the Nodes Stack push and pop nodes
        with additional level info.

        UPDATE: the @key @reverse is present to sort node at each
        level.

        :param print_callback: Callback that gets the node and should return
        string that will be printed after the node label.

        """

        def call_callback(func):
            def wrapper(node):
                return func(node) + (
                    " " + print_callback(node)
                    if print_callback is not None
                    else ""
                )

            return wrapper

        # Factory for proper get_label() function
        if data_property:
            if idhidden:

                @call_callback
                def get_label(node):
                    return getattr(node.data, data_property)

            else:

                @call_callback
                def get_label(node):
                    return "%s[%s]" % (
                        getattr(node.data, data_property),
                        node.identifier,
                    )

        else:
            if idhidden:

                @call_callback
                def get_label(node):
                    return node.tag

            else:

                @call_callback
                def get_label(node):
                    return "%s[%s]" % (node.tag, node.identifier)

        # legacy ordering
        if key is None:

            def key(node):
                return node

        # iter with func
        for pre, node in self._get(nid, level, filter, key, reverse, line_type):
            label = get_label(node)
            func('{0}{1}'.format(pre, label).encode('utf-8'))

    def _get(self, nid, level, filter_, key, reverse, line_type):
        # default filter
        if filter_ is None:

            def filter_(node):
                return True

        # render characters
        dt = {
            'ascii': ('|', '|-- ', '+-- '),
            'ascii-ex': (
                '\u2502',
                '\u251c\u2500\u2500 ',
                '\u2514\u2500\u2500 ',
            ),
            'ascii-exr': (
                '\u2502',
                '\u251c\u2500\u2500 ',
                '\u2570\u2500\u2500 ',
            ),
            'ascii-em': (
                '\u2551',
                '\u2560\u2550\u2550 ',
                '\u255a\u2550\u2550 ',
            ),
            'ascii-emv': (
                '\u2551',
                '\u255f\u2500\u2500 ',
                '\u2559\u2500\u2500 ',
            ),
            'ascii-emh': (
                '\u2502',
                '\u255e\u2550\u2550 ',
                '\u2558\u2550\u2550 ',
            ),
        }[line_type]

        return self.__get_iter(nid, level, filter_, key, reverse, dt, [])

    def __get_iter(self, nid, level, filter_, key, reverse, dt, is_last):
        dt_vline, dt_line_box, dt_line_cor = dt

        nid = self.root if (nid is None) else nid
        if not self.contains(nid):
            raise NodeIDAbsentError("Node '%s' is not in the tree" % nid)

        node = self[nid]

        if level == self.ROOT:
            yield "", node
        else:
            leading = ''.join(
                map(
                    lambda x: dt_vline + ' ' * 3 if not x else ' ' * 4,
                    is_last[0:-1],
                )
            )
            lasting = dt_line_cor if is_last[-1] else dt_line_box
            yield leading + lasting, node

        if filter_(node) and node.expanded:
            children = [
                self[i]
                for i in node.successors(self._identifier)
                if filter_(self[i])
            ]
            idxlast = len(children) - 1
            if key:
                children.sort(key=key, reverse=reverse)
            elif reverse:
                children = reversed(children)
            level += 1
            for idx, child in enumerate(children):
                is_last.append(idx == idxlast)
                for item in self.__get_iter(
                    child.identifier, level, filter_, key, reverse, dt, is_last
                ):
                    yield item
                is_last.pop()
