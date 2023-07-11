#  Copyright (C) 2023 Roderik Ploszek
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

FHSConfigRule = namedtuple(
    'FHSConfgRule',
    [
        'path',
        'permissions',
        'recursive',
        'regexp',
    ],
)
