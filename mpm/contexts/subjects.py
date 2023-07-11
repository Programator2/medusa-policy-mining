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

"""SElinux subject contexts"""

POSTGRESQL = ('system_u:system_r:postgresql_t:s0',)
SSHD = ('system_u:system_r:sshd_t:s0-s0:c0.c1023',)
POSTFIX = (
    'system_u:system_r:postfix_master_t:s0',
    'system_u:system_r:postfix_pickup_t:s0',
    'system_u:system_r:postfix_qmgr_t:s0',
)
APACHE = ('system_u:system_r:httpd_t:s0',)


def get_subject_context_by_name(name: str) -> tuple[str, ...]:
    """Get a tuple of object contexts for the given service."""
    return {
        'postgres': POSTGRESQL,
        'sshd': SSHD,
        'postfix': POSTFIX,
        'apache': APACHE,
    }[name]
