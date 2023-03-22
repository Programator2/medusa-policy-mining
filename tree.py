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
from mpm_types import AuditEntry
from generalize.generalize import generalize_nonexistent
from fs2json.db import DatabaseRead
from config import (
    OwnerGeneralizationStrategy,
    OWNER_GENERALIZATION_STRATEGY,
    GENERALIZE_THRESHOLD,
    GENERALIZE_FS_THRESHOLD
)
import sys
from copy import copy
from re import search


class Access:
    """Represents an access by some proces. Stored inside NpmNode"""

    def __init__(self, permissions: Permission):
        self.permissions = permissions
        self._uid = None
        # comm is being deprecated as it doesn't accurate represent the current
        # domain of the process (it may be changed by the running process and
        # Medusa doesn't keep it updated one set in the kobject)
        self._comm = None
        self._domain = None

    @property
    def uid(self):
        return self._uid

    @uid.setter
    def uid(self, uid):
        if self._uid is not None:
            raise Exception("attribute can't be modified")
        self._uid = uid

    @property
    def comm(self):
        return self._comm

    @comm.setter
    def comm(self, comm):
        if self._comm is not None:
            raise Exception("attribute can't be modified")
        self._comm = comm

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, domain):
        if self._domain is not None:
            raise Exception("attribute can't be modified")
        self._domain = domain

    def __repr__(self):
        # This is a shortened version, for the full version see `full_repr`
        return f'<{str(hash(self.domain))[:2]} {self.domain[-1][0]}({self.domain[-1][1]}): {self.permissions}>'

    def full_repr(self) -> str:
        return f'<{self.domain} {self.comm} ({self.uid}): {self.permissions}>'

    def __eq__(self, other):
        return (
            self.permissions == other.permissions
            and self.uid == other.uid
            and self.domain == other.domain
        )

    def __hash__(self):
        return hash((self.permissions, self.uid, self.domain))


class NpmNode(set):
    """Represents internal data of the node (especially permissions)."""

    def __init__(self, args: Iterable = None):
        # Contains set of `Access` objects that were generalized (globbed) for
        # this node. This access should be used for node/* rule. This set should
        # contain just one object, but I'm keeping it as a set just in case.
        self.generalized: set[Access] = set()

        # Used by multiple runs generalizator
        self.visited = False

        # Nodes represented by a regexp set this to `True`
        self.is_regexp = False

        if args is not None:
            self.update(args)

    @staticmethod
    def generic_add_access(s: set, access: Access) -> None:
        """Add `access` to `s`, if it isn't already present in the set. If there
        is an access with the same uid and domain but different permissions,
        adjust permissions of the existing access accordingly. This can only add
        permissions, not remove them.

        For example, if there is an access READ already in the list and
        `add_access` is called with another access with the same uid and domain,
        but with WRITE permission, the new permissions will be set to
        `READ|WRITE`.
        """
        for a in s:
            if access.uid == a.uid and access.domain == a.domain:
                try:
                    s.remove(a)
                except KeyError:
                    print("Pridavany:")
                    pprint(access)
                    print("Porovnavany:")
                    pprint(a)
                    print("Obsah:")
                    pprint(s)
                    sys.exit(-1)
                a.permissions = access.permissions | a.permissions
                s.add(a)
                return
        s.add(access)

    def add_access(self, access: Access):
        """Add `access` to `self`, if it isn't already present in the set. If
        there is an access with the same uid and domain but different
        permissions, adjust permissions of the existing access accordingly. This
        can only add permissions, not remove them.

        For example, if there is an access READ already in the list and
        `add_item` is called with another access with the same uid and domain,
        but with WRITE permission, the new permissions will be set to
        `READ|WRITE`.
        """
        self.generic_add_access(self, access)


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

    def _create_path(self, path: str) -> Node:
        """Create necessary nodes in the tree to represent a path.

        :param path: string in the form of `/this/is/a/path`. It has to start
        with a `/` and optionally end with a `/`
        """
        entries = filter(lambda x: bool(x), path.split('/'))
        return GenericTree._create_path(self, entries)

    def load_log(self, log: Iterable[AuditEntry]):
        # TODO: Also normalize accesses. If someone requests write, it should
        # get the highest priority.

        for d in log:
            # Create path in the tree
            node = self._create_path(d.path.removesuffix(' (deleted)'))

            perm = Permission(int(d.permission))

            if node.data == None:
                node.data = NpmNode()

            access = Access(perm)
            access.uid = int(d.uid)
            access.comm = d.proctitle
            access.domain = d.domain

            node.data.add_access(access)

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
            path = '/' + node.tag + path
            node = self.get_parent(node)
        return path

    def get_accessed_paths(self) -> dict[str, Node]:
        ret = {}
        for node in self.all_nodes_itr():
            if (data := node.data) is None:
                continue
            ret[self.get_path(node)] = node
        return ret

    def add_path_generalization(self, path: str) -> Node:
        """Add regexp generalization to the tree.

        :param path: String starting with `/` and ending with last component
        (not `/`). Path components that contain regexps will be inserted into
        node's generalization set.
        """
        entries = filter(lambda x: bool(x), path.split('/'))
        parent = self.npm_root
        for e in entries:
            # Check if this is a regular expression (currently checking just for
            # the dot)
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
                pattern = r'[^\\]\.'
                if search(pattern, e) is not None:
                    is_regexp = True
                else:
                    is_regexp = False
                data = NpmNode()
                data.is_regexp = is_regexp
                parent = self.create_node(e, parent=parent.identifier, data=data)
        # Transfer permission from regexed paths, maybe return and do it in the
        # caller
        return parent

    def generalize(self, node: Node, verbose=False) -> None:
        """Do a recursive depth-first search and on the way up TODO:
        finish

        Here we work with the assumption that if all files in a folder have the
        same access permission, we can generalize this access permission for the
        entire contents of the folder.
        """
        if not (children := node.successors(self.identifier)):
            # Skip leaves
            return
        for n in children:
            # Depth-first search
            self.generalize(self.get_node(n), verbose)

        # TODO Maybe all nodes should include NpmNode as their data, because now
        # we have to check everywhere if data is not None

        # Get accesses from child items. Not accessed nodes have `None` `data`
        # attribute.
        access_sets = filter(
            lambda x: x is not None, (self.get_node(n).data for n in children)
        )

        c = Counter()
        total_count = 0
        for access_set in access_sets:
            total_count += 1
            for access in access_set:
                # access is `Access`
                for permission in access.permissions:
                    new_access = copy(access)
                    new_access.permissions = permission
                    c[new_access] += 1

        generalized = set()
        for access, number in c.items():
            # This just checks for the complete number of items not considering
            # the type (directory/file)
            if number / total_count >= GENERALIZE_THRESHOLD:
                # This means that all child items have the same accesses
                if node.data == None:
                    node.data = NpmNode()
                NpmNode.generic_add_access(node.data.generalized, ac := access)
                if verbose:
                    print(f'Generalized (from logs) {ac} for {self.get_path(node)}')

    def generalize_fs(self, db: DatabaseRead, verbose=False):
        """Same as `generalize`, but with fs database."""
        if not (children := node.successors(self.identifier)):
            # Skip leaves
            return
        for n in children:
            # Depth-first search
            self.generalize_fs(self.get_node(n), db, verbose)

        # TODO Maybe all nodes should include NpmNode as their data, because now
        # we have to check everywhere if data is not None

        # Get accesses from child items. Not accessed nodes have `None` `data`
        # attribute.
        access_sets = filter(
            lambda x: x is not None, (self.get_node(n).data for n in children)
        )

        path = self.get_path(node)
        c = Counter()
        total_count = db.get_num_children(path)
        for access_set in access_sets:
            for access in access_set:
                # access is `Access`
                for permission in access.permissions:
                    new_access = copy(access)
                    new_access.permissions = permission
                    c[new_access] += 1

        generalized = set()
        for access, number in c.items():
            # This just checks for the complete number of items not considering
            # the type (directory/file)
            if number / total_count >= GENERALIZE_FS_THRESHOLD:
                # This means that all child items have the same accesses
                if node.data == None:
                    node.data = NpmNode()
                NpmNode.generic_add_access(node.data.generalized, ac := access)
                if verbose:
                    print(f'Generalized (with fs) {ac} for {path}')

    def generalize_nonexistent(self, db: DatabaseRead, verbose=False):
        # TODO: Take order of generalization into consideration. For example,
        # after `/proc/.*/` generalization, these folders shouldn't be used in
        # following generalizations, such as this one.

        # TODO: Not just leaves but every accessed node
        for node in self.all_nodes_itr():
            if (data := node.data) is None:
                continue
            path = self.get_path(node)
            generalized_path = generalize_nonexistent(path, db)
            if generalized_path:
                parent = self.get_parent(node)
                if parent.data == None:
                    parent.data = NpmNode()
                # TODO: Also update generalizations?
                parent.data.generalized.update(node.data)
                if verbose:
                    print(f'Generalized parent for nonexistent {path}.')

    @staticmethod
    def all_if_any(it: Iterable) -> bool:
        """Return `True` if all elements of `it` are true and there is at least
        one element."""
        try:
            item = next(it)
        except StopIteration:
            return False
        return all(it) if item else False

    def generalize_by_owner(self, db: DatabaseRead, verbose: bool = False):
        """See `OwnerGeneralizationStrategy` for explanation of used
        strategies."""
        for node in self.all_nodes_itr():
            if (data := node.data) is None:
                continue
            for access in data:
                if (
                    OWNER_GENERALIZATION_STRATEGY
                    & OwnerGeneralizationStrategy.OWN_DIR
                ):
                    path = self.get_path(node)
                    if db.is_directory(
                        path
                    ) and access.uid == db.get_owner(path):
                        data.generalized.add(access)
                        if verbose:
                            print(
                                f"Generalized by owner of '{path}' for {access}."
                            )
                elif (
                    OWNER_GENERALIZATION_STRATEGY
                    & OwnerGeneralizationStrategy.OWN_FILES
                ):
                    if self.all_if_any(
                        access.uid == inode.uid
                        for inode in db.get_children(self.get_path(node))
                    ):
                        data.generalized.add(access)
                        if verbose:
                            print(
                                f"Generalized by owner of files in '{path}' for {access}."
                            )
                elif (
                    OWNER_GENERALIZATION_STRATEGY
                    & OwnerGeneralizationStrategy.READ_FILES
                ):
                    if self.all_if_any(
                        db.can_read(ino, access.uid)
                        for ino in db.get_children(self.get_path(node))
                    ):
                        data.generalized.add(access)
                        if verbose:
                            print(
                                f"Generalized by read access of files in '{path}' for {access}."
                            )
                elif (
                    OWNER_GENERALIZATION_STRATEGY
                    & OwnerGeneralizationStrategy.WRITE_FILES
                ):
                    if self.all_if_any(
                        db.can_write(ino, access.uid)
                        for ino in db.get_children(self.get_path(node))
                    ):
                        data.generalized.add(access)
                        if verbose:
                            print(
                                f"Generalized by write access of files in '{path}' for {access}."
                            )

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
                '['
                + ', '.join(str(i) for i in node.data)
                + ']'
                + (
                    f' glob:{node.data.generalized}'
                    if node.data.generalized
                    else ''
                )
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
        """Another implementation of printing tree using Stack.
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
