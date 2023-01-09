from tree import NpmTree, Access, Permission
from collections import UserDict, defaultdict
from itertools import count


class Domain(UserDict):
    def __init__(self):
        UserDict.__init__(self)
        self.data[Permission.READ] = []
        self.data[Permission.WRITE] = []
        self.data[Permission.SEE] = []


def make_unique(name: str, s: dict) -> str:
    """If name is in s, returns a slightly modified version of name that is not
    in s. Otherwise returns name."""
    original_name = name
    c = count()
    while name in s:
        name = original_name + str(next(c))
    return name


def get_access_name(access: Access) -> str:
    """Create a descriptive name for access."""
    return f'{access.comm.replace(" ", "")}{access.uid}_{access.permissions}'


def get_uniq_acess_name(access: Access, s: dict) -> str:
    return make_unique(get_access_name(access), s)


def create_constable_policy(t: NpmTree) -> str:
    # This dictionary contains all paths accessed (values) for a given Access
    # type (this will be used to create virtual spaces)
    spaces = defaultdict(list)
    for n in t.all_nodes_itr():
        if n.data is None:
            continue
        path = t.get_path(n)
        # if n,pare
        for access in n.data:
            spaces[access].append(path)
        # TODO: direct child nodes of generalized nodes should not be included
        # in the final output policy
        if n.data.generalized:
            for access in n.data.generalized:
                spaces[access].append(path + '/*')

    config = ''

    # Assign paths to virtual spaces
    spaces_names: dict[str, Access] = {}  # name to Access
    for s, v in spaces.items():
        name = get_uniq_acess_name(s, spaces_names)
        spaces_names[name] = s

        config += f'space {name} = '
        for i, path in enumerate(v):
            if i != 0:
                config += ' +\n    '
            config += path
        config += ';\n'

    # Create domains and set permissions
    # Group accesses based on name and uid with tuple (comm, uid)
    domains = defaultdict(Domain)
    for space, access in spaces_names.items():
        domain_tuple = (access.comm, access.uid)
        for permission in access.permissions:
            domains[domain_tuple][permission].append(space)

    for (comm, uid), domain in domains.items():
        domain_name = f'{comm.replace(" ", "")}{uid}'
        config += f'space {domain_name} = "domain/{domain_name}";\n'
        config += f'{domain_name}    '
        ending_comma = ''       # On the first row we don't need a comma
        for i, permission in enumerate(Permission):
            if not (permission_list := domain[permission]):
                continue
            config += ending_comma + permission.name + ' '
            config += ', '.join(permission_list)
            ending_comma = ',\n        '
        # Finish the domain permission block here
        config += ';\n'

    return config
