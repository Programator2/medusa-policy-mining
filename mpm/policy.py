from mpm.tree import NpmTree, Access, Permission
from collections import UserDict, defaultdict
from itertools import count
from pprint import pprint
from typing import DefaultDict, Any
from mpm.generalize.generalize import generalize_proc

STANDARD_TREES = """tree "fs" clone of file by getfile getfile.filename;
primary tree "fs";
tree "domain" of process;
"""

DEFAULT_DOMAIN = "domain/init"

STANDARD_SPACES = f"""space all_domains = recursive "domain";
primary space init = "{DEFAULT_DOMAIN}";
space all_files = recursive "/";
"""

STANDARD_ACCESSES = """all_domains READ all_files, all_domains,
            WRITE all_files, all_domains,
            SEE all_files, all_domains;
"""

PEXEC_DEBUG = """all_domains pexec * {
  log(spaces(process.vs) + " pexec " + pexec.filename);
  return ALLOW;
}
"""

GETPROCESS = f"""* getprocess * {{
  enter(process, @"{DEFAULT_DOMAIN}");
  process.med_sact = 0x3fffffff;
  return ALLOW;
}}
"""

LOG_FUNCTION = """function log
{
  local printk buf.message=$1 + "\\n";
  update buf;
}
"""

INIT_FUNCTION = """function _init
{
}
"""


def fexec_handler(subject: str, _object: str, target_domain: str) -> str:
    return f"""{subject} fexec "{_object}" {{
  log("fexec {subject}->{_object}");
  enter(process, @"domain/{target_domain}");
  return ALLOW;
}}
"""


def setresuid_handler(subject: str, condition: str, target_domain: str) -> str:
    return f"""{subject} setresuid {{
  if ({condition}) {{
    log("setresuid {subject} flags=" + setresuid.flags + " ruid=" +
        setresuid.old_ruid + "->" + setresuid.ruid + " euid=" +
        setresuid.old_euid + "->" + setresuid.euid + " suid=" +
        setresuid.old_suid + "->" + setresuid.suid +
        " entering {target_domain}");
    enter(process, @"domain/{target_domain}");
    return ALLOW;
  }}
  log("setresuid {subject} flags=" + setresuid.flags + " ruid=" +
    setresuid.old_ruid + "->" + setresuid.ruid + " euid=" +
    setresuid.old_euid + "->" + setresuid.euid + " suid=" +
    setresuid.old_suid + "->" + setresuid.suid +
    " DOMAIN UNCHANGED");
  return ALLOW;
}}
"""


class Domain(UserDict):
    def __init__(self):
        UserDict.__init__(self)
        self.data[Permission.READ] = set()
        self.data[Permission.WRITE] = set()
        self.data[Permission.SEE] = set()


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
    domain = access.domain[-1][0].replace(" ", "").replace('/', '_')
    return f'{domain}{access.uid}_{access.permissions.short_repr()}'


def get_uniq_acess_name(access: Access, s: dict) -> str:
    return make_unique(get_access_name(access), s)


def space_name_from_exec_history(exec_history: tuple[str, ...]) -> str:
    if not exec_history:
        # `exec_history` is an empty tuple. This means that this exec was
        # executed by the init process or some other proces for which we don't
        # have more information. Use the default domain for this subject.
        return f'"{DEFAULT_DOMAIN}"'
    return ''.join(exec_history).replace(" ", "").replace('/', '_')


def space_name_from_domain(domain: tuple[tuple, ...]) -> str:
    if not domain:
        # `domain` is an empty tuple. This means that this exec was executed by
        # the init process or some other proces for which we don't have more
        # information. Use the default domain for this subject.
        return f'"{DEFAULT_DOMAIN}"'
    return (
        ''.join((f'{filename}{euid}' for filename, euid in domain))
        .replace(" ", "")
        .replace('/', '_')
    )


def domain_transition_handlers(
    domain_transition: dict[tuple[tuple, str, Any], tuple]
) -> str:
    config = ''

    # pprint(domain_transition)

    for k, new_domain in domain_transition.items():
        match k:
            case (old_domain, 'exec', exec_file):
                domain = space_name_from_domain(old_domain)
                config += fexec_handler(
                    domain, exec_file, space_name_from_domain(new_domain)
                )
            case (old_domain, 'setresuid', new_euid):
                domain = space_name_from_domain(old_domain)
                config += setresuid_handler(
                    domain,
                    f'setresuid.euid == {new_euid}',
                    space_name_from_domain(new_domain),
                )

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
                spaces[access].append(path + '/.*')

    config = (
        STANDARD_TREES
        + STANDARD_SPACES
        + STANDARD_ACCESSES
        + LOG_FUNCTION
        + GETPROCESS
        + PEXEC_DEBUG
        + INIT_FUNCTION
    )

    # pprint(spaces)

    # Assign file paths to virtual spaces.
    spaces_names: dict[str, Access] = {}  # name to Access
    for s, v in spaces.items():
        name = get_uniq_acess_name(s, spaces_names)
        spaces_names[name] = s

        config += f'space {name} = '
        for i, path in enumerate(v):
            if i != 0:
                config += ' +\n    '
            # Generalize common paths
            path = generalize_proc(path)
            config += f'"{path}"'
        config += ';\n'

    config += '\n'

    # Create domains and set permissions
    # Group accesses based on name and uid with tuple (comm, uid)
    domains: DefaultDict[tuple, Domain] = defaultdict(Domain)
    for space, access in spaces_names.items():
        domain = access.domain
        for permission in access.permissions:
            domains[domain][permission].add(space)
            # HACK: Since we "ignore" the SEE permission, we need to add
            # everything from READ and WRITE to this set.
            domains[domain][Permission.SEE].add(space)

    for domain_history, domain in domains.items():
        domain_name = space_name_from_domain(domain_history)
        config += f'primary space {domain_name} = "domain/{domain_name}";\n'
        space_name_in_config = f'{domain_name} '
        config += space_name_in_config
        # On the first row we don't need a comma
        ending_comma = ''
        for i, permission in enumerate(Permission):
            if not (permission_set := domain[permission]):
                # This permission type is empty, nothing to include
                continue
            config += ending_comma + permission.name + ' '
            config += ', '.join(permission_set)
            ending_comma = ',\n' + ' ' * len(space_name_in_config)
        # Finish the domain permission block here
        config += ';\n'

    # Create domain transition handlers
    config += '\n' + domain_transition_handlers(domain_transition)

    return config
