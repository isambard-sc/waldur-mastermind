"""Mint API tokens on a sanitised copy so impersonation works.

Impersonating a user fails on a sanitised copy with

    403: Unable to impersonate user that does not have an active session.

The message is misleading: core/authentication.py set_user_context() tests
``Token.objects.filter(user=user).exists()`` - a DRF authtoken row, not a
session. Waldur creates one per user at creation (core/handlers.py), so on a
real deployment everyone has one; the sanitiser wipes `authtoken_token` and
`core_personalaccesstoken`, and the verifier FAILS the run unless both are
empty. That is deliberate - a token is a live credential, and a dump carrying
production's tokens would let anyone authenticate as those users.

So the dump must not contain tokens, and this mints FRESH random ones locally
after the restore. They are new values that never existed in production and
grant access only to this copy.

    # how many users lack one
    docker compose exec -T waldur-mastermind-api waldur shell \
        -c "$(cat scripts/restore_impersonation_tokens.py)"

    # mint for everyone
    docker compose exec -T -e TOKENS_APPLY=1 waldur-mastermind-api waldur shell \
        -c "$(cat scripts/restore_impersonation_tokens.py)"

    # or just the ones you want to impersonate
    docker compose exec -T -e TOKENS_APPLY=1 -e TOKENS_USERS=person12,person34 \
        waldur-mastermind-api waldur shell \
        -c "$(cat scripts/restore_impersonation_tokens.py)"

Do NOT run this against production: every user there already has a token, and
minting more is at best noise.
"""

import os

from rest_framework.authtoken.models import Token

from waldur_core.core.models import User

APPLY = os.environ.get("TOKENS_APPLY") == "1"
WANTED = [u.strip() for u in os.environ.get("TOKENS_USERS", "").split(",") if u.strip()]

users = User.objects.filter(username__in=WANTED) if WANTED else User.objects.all()

if WANTED:
    found = set(users.values_list("username", flat=True))
    for missing in sorted(set(WANTED) - found):
        print(f"  no such user: {missing!r}")

has_token = set(Token.objects.values_list("user_id", flat=True))
without = [u for u in users if u.id not in has_token]

print(f"{users.count()} users selected, {len(without)} without a token")

if not without:
    print("Nothing to do: every selected user can already be impersonated.")
elif not APPLY:
    for user in without[:20]:
        print(f"  would mint: {user.username}")
    if len(without) > 20:
        print(f"  ... and {len(without) - 20} more")
    print("\nDry run. Re-run with TOKENS_APPLY=1 to create them.")
else:
    # get_or_create rather than create: concurrent runs, or a user who gained
    # a token between the read above and here, must not raise.
    created = 0
    for user in without:
        _token, was_created = Token.objects.get_or_create(user=user)
        created += bool(was_created)
    print(f"{created} tokens minted. Impersonation will now work for them.")
