from mpm.domain import get_current_euid
from mpm.test_cases.helpers import TestCaseContext


def test_core(ctx: TestCaseContext) -> None:
    domains = list(
        filter(lambda x: get_current_euid(x) in ctx.uids, ctx.medusa_domains)
    )
    ctx.tree.generalize_by_owner_directory(
        ctx.db, domains, ctx.uids, ctx.gids, verbose=True
    )

    # TODO: This probably doesn't have to be used here.
    ctx.tree.move_generalized_to_regexp()
