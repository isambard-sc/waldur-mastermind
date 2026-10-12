from . import views


def register_in(router):
    router.register(
        r"proposal-archive-calls",
        views.ArchivedCallViewSet,
        basename="proposal-archive-call",
    )
    router.register(
        r"proposal-archive-rounds",
        views.ArchivedRoundViewSet,
        basename="proposal-archive-round",
    )
    router.register(
        r"proposal-archive-proposals",
        views.ArchivedProposalViewSet,
        basename="proposal-archive-proposal",
    )
    router.register(
        r"proposal-archive-reviews",
        views.ArchivedReviewViewSet,
        basename="proposal-archive-review",
    )
    router.register(
        r"proposal-archive-memberships",
        views.ArchivedMembershipViewSet,
        basename="proposal-archive-membership",
    )
    router.register(
        r"proposal-archive-resolve",
        views.ArchiveResolveViewSet,
        basename="proposal-archive-resolve",
    )
