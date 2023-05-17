from mpm.domain import get_current_euid
from mpm.test_cases.helpers import TestCaseContext


def test_core(ctx: TestCaseContext) -> None:
    for uids, gids, domains_ in zip(ctx.uids, ctx.gids, ctx.medusa_domains):
        domains = list(
            filter(lambda x: get_current_euid(x) in uids, domains_)
        )
        ctx.tree.generalize_by_owner_directory(
            ctx.db, domains, uids, gids, verbose=True
        )

    # TODO: This probably doesn't have to be used here.
    # ctx.tree.move_generalized_to_regexp()
