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


def get_object_types_by_name(name: str) -> tuple[str, ...]:
    """Get a tuple of object contexts for the given service."""
    return {
        'postgres': POSTGRESQL,
        'sshd': SSHD,
    }[name]
