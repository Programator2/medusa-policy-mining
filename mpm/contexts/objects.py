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

"""SElinux object types"""

POSTGRESQL = (
    'postgresql_etc_t',
    'postgresql_initrc_exec_t',
    'postgresql_exec_t',
    'postgresql_db_t',
    'postgresql_unit_file_t',
    'postgresql_log_t',
    'postgresql_var_run_t',
)


SSHD = (
    'sshd_exec_t',
    'sshd_key_t',
    'sshd_keygen_exec_t',
    'sshd_keygen_unit_file_t',
    'sshd_unit_file_t'
)


POSTFIX = (
    'postfix_bounce_exec_t',
    'postfix_cleanup_exec_t',
    'postfix_data_t',
    'postfix_etc_t',
    'postfix_exec_t',
    'postfix_local_exec_t',
    'postfix_map_exec_t',
    'postfix_master_exec_t',
    'postfix_pickup_exec_t',
    'postfix_pipe_exec_t',
    'postfix_postdrop_exec_t',
    'postfix_postqueue_exec_t',
    'postfix_private_t',
    'postfix_public_t',
    'postfix_qmgr_exec_t',
    'postfix_showq_exec_t',
    'postfix_smtp_exec_t',
    'postfix_smtpd_exec_t',
    'postfix_spool_bounce_t',
    'postfix_spool_t',
    'postfix_virtual_exec_t'
)

APACHE = (
    'httpd_cache_t',
    'httpd_config_t',
    'httpd_exec_t',
    'httpd_log',
    'httpd_modules_t',
    'httpd_rotatelogs_exec',
    'httpd_suexec_exec_t',
    'httpd_sys_content_',
    'httpd_sys_script_exec_t',
    'httpd_unit_file_t',
    'httpd_var_lib_t',
    'httpd_var_run_t',
)


def get_object_types_by_name(name: str) -> tuple[str, ...]:
    """Get a tuple of object contexts for the given service."""
    return {
        'postgres': POSTGRESQL,
        'sshd': SSHD,
        'postfix': POSTFIX,
        'apache': APACHE,
    }[name]
