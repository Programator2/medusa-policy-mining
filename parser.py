""" Parser for audit.log format """


from collections import defaultdict
from itertools import takewhile, groupby
from permission import Permission
from pprint import pprint
from treelib import Tree
from tree import DomainTree
from mpm_types import PathAccess, AuditLogRaw, AuditEntry


def search_field(l: list[dict], key: str):
    """Given a list of dictionaries search for a given key. The first matching
    value is returned."""
    for msg in l:
        if key in msg:
            return msg[key]


def create_log_entries(l: list[AuditLogRaw]) -> list[AuditEntry]:
    entries = []
    for a in l:
        for permission in a.path:
            entry = AuditEntry(
                proctitle=a.proctitle,
                path=permission.path,
                permission=permission.permissions,
                uid=a.uid,
                pid=a.pid,
                ppid=a.ppid,
                operation=a.operation,
            )
            entries.append(entry)
    return entries


def initialize_domain(message: dict, messages: list, domains: defaultdict):
    """If current process (message['pid']) doesn't have a domain, try to get it
    from the parent. If it's not available, do nothing.

    :returns: domain tuple, if found"""
    if (pid := message['pid']) not in domains:
        if (ppid := search_field(messages, 'ppid')) in domains:
            domains[pid] = domains[ppid]
            return domains[pid]


def assign_permissions(entries: list[dict], domain_tree: DomainTree) -> list[AuditLogRaw]:
    """Assign permissions based on operation type and create a new list of
    accesses with compressed information (leave out everything that's not
    needed).

    :param serials: dictionary that contains integer serial values as keys and
    list of dictionaries as values. Every inner dictionary represents one line
    of audit (one message).

    """
    # TODO: Isn't this already sorted?
    # Sort it just to be sure, it should be the best case anyway.
    entries.sort(key=lambda x: x['serial'])
    serials = groupby(entries, lambda x: x['serial'])

    abbreviated_messages = []
    # Assign pid to a domain. Changes as log entries are iterated. Domain is
    # a tuple containing filenames of executed binaries. In the future this
    # might also contain UID at the time of exec.
    domains = defaultdict(tuple)

    for key, msg_iter in serials:
        messages = list(msg_iter)
        # `messages` contains multiple messages from audit with the same serial.
        # This means it's the same operation, but the type of the message is
        # different (e.g. one describing the decision of a security module,
        # another one describing the current system call)
        for m in messages:
            # This works only on messages from Medusa. They have AVC type.
            if m['type'] != 'AVC':
                break
            MAY_WRITE = 0x2
            MAY_READ = 0x4
            match m['op']:
                case 'unlink' | 'rmdir':
                    access = (
                        PathAccess(
                            m['dir'] + '/' + m['name'],
                            Permission.READ | Permission.WRITE,
                        ),
                    )
                case 'mkdir' | 'mknod' | 'truncate' | 'symlink' | 'chmod' | 'dir':
                    access = (
                        PathAccess(
                            m['dir'], Permission.READ | Permission.WRITE
                        ),
                    )
                case 'link':
                    access = (
                        PathAccess(
                            m['dir'], Permission.READ | Permission.WRITE
                        ),
                        PathAccess(
                            m['old_dir'], Permission.READ | Permission.WRITE
                        ),
                    )
                case 'rename':
                    access = (
                        PathAccess(
                            m['old_dir'] + '/' + m['old_name'],
                            Permission.READ | Permission.WRITE,
                        ),
                        PathAccess(
                            m['new_dir'], Permission.READ | Permission.WRITE
                        ),
                    )
                case 'chown' | 'path':
                    access = (
                        PathAccess(
                            m['path'], Permission.READ | Permission.WRITE
                        ),
                    )
                case 'exec':
                    access = (PathAccess(m['filename'], Permission.READ),)
                    # TODO: Some time in the future we will remove pid from AVC
                    # entry, so this should be replaced by `search_field`
                    initialize_domain(m, messages, domains)
                    domains[m['pid']] += (m['filename'],)
                    # A new domain has been created, add it to the tree
                    domain_tree._create_path(domains[m['pid']])
                case 'open':
                    access = (
                        PathAccess(
                            m['dir'],
                            Permission.READ
                            | (
                                Permission.WRITE if m['mode'] & MAY_WRITE else 0
                            ),
                        ),
                    )

            # Determine domain:
            initialize_domain(m, messages, domains)

            # We know that some of these field are straight in the AVC message.
            # Others have to be found in other messages with the same serial
            # number using `search_field`.
            log = AuditLogRaw(
                serial=m['serial'],
                proctitle=search_field(messages, 'proctitle'),
                mode=m.get('mode', None),
                uid=search_field(messages, 'uid'),
                pid=m['pid'],
                ppid=search_field(messages, 'ppid'),
                path=access,
                syscall=search_field(messages, 'syscall'),
                operation=m['op'],
                domain=domains[m['pid']]
            )
            # pprint(log)

            abbreviated_messages.append(log)

    return abbreviated_messages


def parse_msg(v: str) -> (int, int, int):
    """Parse audit timestamp.

    :param v: timestamp value without the key, i.e. starting with
    audit(
    :returns: Tuple in the form of (seconds, milliseconds, serial).
    """
    assert v.startswith('audit(')
    # Remove 'audit(' and '):'
    v = v[6:-2]
    timestamp, _, serial = v.partition(':')

    seconds, _, miliseconds = timestamp.partition('.')

    seconds, miliseconds, serial = map(int, (seconds, miliseconds, serial))

    return seconds, miliseconds, serial


def take_type(l: str) -> (str, str):
    """Return type of the audit message `l` and rest of the message as
    a tuple"""
    assert l.startswith('type=')
    space_i = l.find(' ')
    return l[5:space_i], l[space_i + 1 :]


def chunked_string(s: str, n: int):
    """Chunk a string similar to `more_itertools.chunked`, but the generator
    returns strings.
    """
    return (s[i : i + n] for i in range(0, len(s), n))


def hex_decode(v: str):
    """Convert ascii hexadecimal representation of a string to a unicode string.
    If there is a null byte, cut the string at its position.

    """
    assert len(v) % 2 == 0

    return ''.join(
        chr(int(x, 16))
        for x in takewhile(lambda x: x != '00', chunked_string(v, 2))
    )


def get_fields(l: str) -> dict:
    """Return dictionary of fields in the audit message"""
    ret = {}
    fields = l.split()

    for f in fields:
        field, _, value = f.partition('=')
        if not value:
            # Equal sign was not contained in `f`. For example:
            # "Medusa:"
            continue

        # Special parsing of msg containing the timestamp. We can do
        # this also earlier, thus speeding up the process. Maybe move it
        # to the calling function.
        if field == 'msg':
            seconds, miliseconds, serial = parse_msg(value)
            ret['secs'] = seconds
            ret['mils'] = miliseconds
            ret['serial'] = serial
            # We are done with this field, no need to parse longer
            continue

        # field parser is not needed for the time being
        # value = field_parser.get(field, lambda x: value)(value)

        may_be_escaped = {'dir', 'path', 'proctitle'}

        # Process escaped strings (hexadecimal ascii)
        if field in may_be_escaped and value[0] != '"':
            value = hex_decode(value)
        else:
            # Process numbers
            try:
                value = int(value)
            except ValueError:
                # It's not a number, but a string
                value = value.strip('"')

        ret[field] = value

    return ret


def parse(path: str) -> list[dict]:
    """Return parsed audit entries as a key-value directory. Entries have the
    same order as in the audit log.

    :param path: Path to the audit log (raw audit.log with no processing)."""
    field_parser = {}
    with open(path) as f:
        entries = []
        for l in f.readlines():
            msg_type, l = take_type(l)

            if msg_type not in {'AVC', 'SYSCALL', 'PROCTITLE'}:
                # For the time being, we are only interested in AVC messages
                continue

            fields = {'type': msg_type}

            # `left` contains raw keys (numerical values), `computed`
            # contains computed names (eg. user name instead of number)
            left, _, computed = l.partition('')
            # TODO: handle special msg='' payloads in `left`

            fields.update(get_fields(left))
            fields.update(get_fields(computed))

            entries.append(fields)

    return entries


def parse_log(path: str, domain_tree: Tree) -> list[AuditEntry]:
    """Parse the log, process AVC entries and create domain transfer
    tree.

    :param path: path to the audit.log log
    :param domain_tree: `Tree` object that will be used to create
    domain transfer tree
    """
    serials = parse(path)
    out = assign_permissions(serials, domain_tree)
    out = create_log_entries(out)
    return out
