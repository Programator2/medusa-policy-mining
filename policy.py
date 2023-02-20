from tree import NpmTree, Access, Permission
from collections import UserDict, defaultdict
from itertools import count
from pprint import pprint
from typing import DefaultDict, Any

STANDARD_TREES = """tree "fs" clone of file by getfile getfile.filename;
primary tree "fs";
tree "domain" of process;
"""

STANDARD_SPACES = """space all_domains = recursive "domain";
primary space init = "domain/init";
space all_files = recursive "/";
"""

GETPROCESS = """* getprocess * {
  enter(process, @"domain/init");
  return ALLOW;
}
"""


def fexec_handler(subject: str, _object: str, target_domain: str) -> str:
    return f"""{subject} fexec "{_object}" {{
  enter(process, @"domain/{target_domain}");
  return ALLOW;
}}
"""


def setresuid_handler(subject: str, condition: str, target_domain: str) -> str:
    return f"""{subject} setresuid {{
  if ({condition}) {{
    enter(process, @"domain/{target_domain}");
    return ALLOW;
  }}
  return DENY;
}}
"""


class Domain(UserDict):
    def __init__(self):
        UserDict.__init__(self)
        self.data[Permission.READ] = []
        self.data[Permission.WRITE] = []
        self.data[Permission.SEE] = []


def make_unique(name: str, s: dict) -> str:
    """If `name` is in `s`, return a slightly modified version of `name` that is
    not in `s`. Otherwise return `name`.
    """
    original_name = name
    c = count()
    while name in s:
        name = original_name + str(next(c))
    return name


def get_access_name(access: Access) -> str:
    """Create a descriptive name for access."""
    # TODO: replace in one pass
    domain = access.comm.replace(" ", "").replace('/', '_')
    return f'{domain}{access.uid}_{access.permissions.short_repr()}'


def get_uniq_acess_name(access: Access, s: dict) -> str:
    return make_unique(get_access_name(access), s)


def space_name_from_exec_history(exec_history: tuple[str, ...]) -> str:
    return ''.join(exec_history).replace(" ", "").replace('/', '_')


def domain_transition_handlers(
    domain_transition: dict[tuple[tuple, str, Any], tuple]
) -> str:
    config = ''

    for k, v in domain_transition.items():
        match k:
            case ((old_exec_his, euid), 'exec', exec_file):
                config += fexec_handler(
                    f'{space_name_from_exec_history(old_exec_his)}{euid}',
                    exec_file,
                    f'{space_name_from_exec_history(v[0])}{euid}',
                )
            case ((exec_his, euid), 'setresuid', new_euid):
                config += setresuid_handler(
                    f'{space_name_from_exec_history(exec_his)}{euid}',
                    f'setresuid.euid == {new_euid}',
                    f'{space_name_from_exec_history(exec_his)}{new_euid}')

    return config


def create_constable_policy(
    t: NpmTree, domain_transition: dict[tuple[tuple, str, Any], tuple]
) -> str:
    # This dictionary contains all paths accessed (values) for a given Access
    # type (this will be used to create virtual spaces)
    spaces: DefaultDict[Access, list[str]] = defaultdict(list)
    for n in t.all_nodes_itr():
        if n.data is None:
            continue
        path = t.get_path(n)
        # Create a list of paths or each `Access`. Note that `Access` is grouped
        # (hashed) by permissions, uid and domain
        for access in n.data:
            spaces[access].append(path)
        # TODO: direct child nodes of generalized nodes should not be included
        # in the final output policy
        if n.data.generalized:
            for access in n.data.generalized:
                spaces[access].append(path + '/*')

    config = STANDARD_TREES + STANDARD_SPACES

    # pprint(spaces)

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
    domains: DefaultDict[tuple[tuple[str], int], Domain()] = defaultdict(Domain)
    for space, access in spaces_names.items():
        domain_tuple = (access.domain, access.uid)
        for permission in access.permissions:
            domains[domain_tuple][permission].append(space)

    for (exec_history, uid), domain in domains.items():
        concatenated_exec_history = space_name_from_exec_history(exec_history)
        domain_name = f'{concatenated_exec_history}{uid}'
        config += f'space {domain_name} = "domain/{domain_name}";\n'
        config += f'{domain_name} '
        ending_comma = ''  # On the first row we don't need a comma
        for i, permission in enumerate(Permission):
            if not (permission_list := domain[permission]):
                continue
            config += ending_comma + permission.name + ' '
            config += ', '.join(permission_list)
            ending_comma = ',\n        '
        # Finish the domain permission block here
        config += ';\n'

    # Create domain transition handlers

    config += domain_transition_handlers(domain_transition)

    return config
