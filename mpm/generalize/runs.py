from fs2json.db import DatabaseRead
from mpm.tree import NpmTree
from treelib import Node
from itertools import groupby, chain
from functools import reduce
from operator import xor
from string_grouper import group_similar_strings
from pandas import DataFrame
from diff_match_patch import diff_match_patch as DiffMatchPatch
from collections.abc import Iterable
from re import escape, fullmatch
from collections import Counter
from copy import deepcopy, copy
from mpm.config import MULTIPLE_RUNS_STRATEGY, MultipleRunsSingleton
import sys
from mpm.generalize.lcs import prefix_postfix_regexp


def regex_from_diff(diff: Iterable[tuple[int, str]]) -> str:
    """Convert diff provided by diff_match_patch into regexp."""
    regex = ''
    modifications = []
    for op, change in diff:
        match op:
            case DiffMatchPatch.DIFF_EQUAL:
                if modifications:
                    # TODO: Regexp can be improved by including character types,
                    # string lengths, but make sure to take into account the law
                    # of dominishing returns
                    regex += r'.*?'
                    modifications.clear()
                regex += escape(change)
            case DiffMatchPatch.DIFF_INSERT:
                modifications.append((op, change))
            case DiffMatchPatch.DIFF_DELETE:
                modifications.append((op, change))
    if modifications:
        # TODO: Regexp can be improved by including character types,
        # string lengths, but make sure to take into account the law
        # of dominishing returns
        regex += r'.*?'
        # Not needed as returning from the function anyway
        # modifications.clear()
    return regex


def _get_numeric_regexp(name: str) -> str:
    """Replace strings of numeric characters by regexp.

    Replace strings of numeric characters in `name` by unlimited number of
    decimal regexp characters.
    """
    # First escape all regexp characters:
    name = escape(name)
    ret = ''
    in_number = False
    try:
        for l in name:
            if l.isnumeric():
                in_number = True
                continue
            if in_number:
                ret += r'\d*'
                in_number = False
            ret += l
    except AttributeError:
        breakpoint()
    if in_number:
        ret += r'\d*'
    return ret


def construct_regex_and_delete_originals(
    all_paths, paths, regex_tree, reg, verbose=False
):
    # 1. Get original accesses and delete them from original tree
    accesses: set[Access] = set()
    for row in all_paths:
        node = None
        for tree in paths:
            try:
                node = tree[row.path]
            except KeyError:
                print(f"couldn't find {row.path}")
                continue
            if node is None:
                raise RuntimeError(f'Unexpected: {row.path} not in the tree.')
            accesses.update(node.data)

            # Clearing original accesses without additional processing is not a
            # good idea. This leaves a node without any permissions, causing the
            # decision algorithm to deny any access to that node. Correct
            # solution would be to remove the whole node altogether, but also
            # remove that same node from other trees.
            #
            # As this would be more complicated to implement, an easier solution
            # is here: just don't remove the original accesses. When accessing
            # this file, the original access will be used and for any other
            # access, the regexp will be used. So ot removing the access won't
            # break anything.
            # node.data.clear()
            break

    # print(f'{accesses=} for {control.path}')
    if verbose:
        print('Generated multiple runs regexp:', reg)

    # 2. Construct a new path with regex
    node = regex_tree.add_path_generalization(reg)

    # 3. Add access to the new node
    for access in accesses:
        node.data.add_access(access)


def generalize_mupltiple_runs(db: DatabaseRead, *trees: NpmTree) -> NpmTree:

    """Identify unique accesses in multiple runs and try to generalize them
    based on similarity. Permissions that were generalized are removed from the
    input trees and moved into a new regex-only tree.

    :returns: `Tree` with generalized accesses (containing regexed paths).
    """
    paths: list[dict[str, Node]] = []
    uniq_paths: list[set[str]] = []
    dmp = DiffMatchPatch()

    # Get list of paths that were accessed
    for tree in trees:
        paths.append(p := tree.get_accessed_paths())

    # Construct a list of paths that are unique across all trees
    # see https://stackoverflow.com/questions/48674775/how-to-add-multiple-sets-in-python-but-only-if-items-are-unique
    uniq_paths_ = [
        k
        for k, count in Counter(chain.from_iterable(paths)).items()
        if count == 1
    ]
    uniq_paths_ = list(reduce(xor, (p.keys() for p in paths)))

    regex_tree = NpmTree()

    # Create preliminary groups based on number of path components
    uniq_paths_.sort(key=lambda x: x.count('/'))
    for key, group in groupby(uniq_paths_, lambda x: x.count('/')):
        uniq_paths_series = DataFrame(group, columns=['path'])

        # Similarity was experimentally deduced:
        # 0.5 was too high
        # 0.45 was too high
        # 0.425 was all right

        # Analyse similar paths
        uniq_paths_series[["group-id", "name_deduped"]] = group_similar_strings(
            uniq_paths_series['path'],
            ignore_case=False,
            min_similarity=0.425,
        )
        uniq_paths_series.sort_values(
            by=[
                'group-id',
            ],
            inplace=True,
        )

        # print(uniq_paths_series)

        groups = uniq_paths_series.groupby('group-id')

        for name, group in groups:
            # `control` is the "group leader" row of a DataFrame and `others`
            # are rows that belong to this group
            all_paths = list(group.itertuples())
            if len(all_paths) == 1:
                # We can't search for difference with just one string
                match MULTIPLE_RUNS_STRATEGY:
                    case MultipleRunsSingleton.NUMERICAL_GENERALIZATION:
                        reg = _get_numeric_regexp(all_paths[0].path)
                        construct_regex_and_delete_originals(
                            all_paths, paths, regex_tree, reg, True
                        )
                    case MultipleRunsSingleton.FULL_GENERALIZATION:
                        reg = '.*'
                        construct_regex_and_delete_originals(
                            all_paths, paths, regex_tree, reg, True
                        )
                continue
            # TODO: mY recommends to construct diff for all pairs, not just
            # `control` with paths from `others`.
            control, *others = all_paths
            # TOOD: make `regexps` a set
            regexps = []
            # print(f'{control.path=}')
            for row in others:
                diff = dmp.diff_main(control.path, row.path)
                dmp.diff_cleanupSemantic(diff)
                regexp = regex_from_diff(diff)
                # print(row.path, ':', regexp)
                regexps.append(regexp)
            # print('-' * 80)

            # Choose the best one (the one that matches all paths from the
            # group)
            # TODO: with the least number of stars
            if len(others) > 1:
                for reg in regexps:
                    # Don't need to check `control` as it was used to construct
                    # the regex
                    if all(fullmatch(reg, row.path) for row in others):
                        break
                else:
                    print(
                        "Regexp that covers all paths doesn't exist. Using alternative regexp generator.",
                        file=sys.stderr,
                    )
                    reg = prefix_postfix_regexp([row.path for row in all_paths])
                    # This is just sanity check, but who knows.
                    if not all(fullmatch(reg, row.path) for row in all_paths):
                        raise RuntimeError(
                            "Regexp that covers all paths doesn't exist."
                        )
            else:
                try:
                    reg = regexps[0]
                except IndexError:
                    breakpoint()

            construct_regex_and_delete_originals(
                all_paths, paths, regex_tree, reg, True
            )

        # print('=' * 80)
    # regex_tree.show()
    return regex_tree


def _check_tree(new_tree: NpmTree, new_node: Node, tree: NpmTree, node: Node):
    """Merge `tree` into `new_tree`."""
    children_nids = node.successors(tree.identifier)
    new_children_nids = new_node.successors(new_tree.identifier)
    new_children_tag_to_node = {
        new_tree.get_node(n).tag: new_tree.get_node(n)
        for n in new_children_nids
    }
    for child_nid in children_nids:
        child = tree.get_node(child_nid)
        if child.tag in new_children_tag_to_node:
            # This directory is already present in the new tree, no need to move
            # anything
            #
            # Move permissions from child to new_child_node.
            new_child_node = new_children_tag_to_node[child.tag]
            if new_child_node.data is None and child.data is not None:
                # Original node was empty, just copy the `NpmNode`.
                new_child_node.data = copy(child.data)
            elif new_child_node.data is not None and child.data is not None:
                # Original node has some accesses, merge the new one into it.
                assert new_child_node.data.is_regexp == child.data.is_regexp
                new_child_node.data.merge(child.data)
        else:
            # Copy `child` to the `new_tree` at the same position
            new_child_node = deepcopy(child)
            new_tree.add_node(new_child_node, new_node)
        _check_tree(new_tree, new_child_node, tree, child)


def merge_tree(*trees: NpmTree) -> NpmTree:
    # TODO: Implement cleaning function that removes excess nodes that are
    # covered by regexes
    new_tree = NpmTree()
    for tree in trees:
        _check_tree(new_tree, new_tree.npm_root, tree, tree.npm_root)
    return new_tree
