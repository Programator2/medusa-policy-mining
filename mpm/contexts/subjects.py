"""SElinux subject contexts"""

POSTGRESQL = ('system_u:system_r:postgresql_t:s0',)
SSHD = ('system_u:system_r:sshd_t:s0-s0:c0.c1023',)
POSTFIX = (
    'system_u:system_r:postfix_master_t:s0',
    'system_u:system_r:postfix_pickup_t:s0',
    'system_u:system_r:postfix_qmgr_t:s0',
)


def get_subject_context_by_name(name: str) -> tuple[str, ...]:
    """Get a tuple of object contexts for the given service."""
    return {
        'postgres': POSTGRESQL,
        'sshd': SSHD,
        'postfix': POSTFIX,
    }[name]
