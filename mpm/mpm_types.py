"""Types used in the project"""
from collections import namedtuple


PathAccess = namedtuple('PathAccess', ['path', 'permissions'])

# `AuditLogRaw` is used internally to store important information from the audit
# log that will be later processed
AuditLogRaw = namedtuple(
    'AuditLogRaw',
    [
        'serial',
        'proctitle',
        'mode',
        'uid',
        'pid',
        'ppid',
        'path',
        'syscall',
        'operation',
        'domain',
    ],
)

# Final output of this module is a list of `AuditEntry` tuples
AuditEntry = namedtuple(
    'AuditEntry',
    [
        'proctitle',
        'path',
        'permission',
        'uid',
        'pid',
        'ppid',
        'operation',
        'domain',
    ],
)
