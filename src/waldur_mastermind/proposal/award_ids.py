"""Award identifiers: the format, and when to issue them.

An award ID looks like ``0261-4064-4676-1``::

    026 1 - 4064-467 6 - 1
    ─┬─ ┬   ────┬─── ┬   ┬
     │  │       │    │   └ version: 1 for a new award; a follow-on is 2, 3...
     │  │       │    └──── Luhn check digit over everything to its left
     │  │       └───────── the year's sequence number, scrambled
     │  └───────────────── scheme version, always 1
     └──────────────────── last three digits of the year

The sequence is scrambled so that consecutive awards do not read as
consecutive: ``0``, ``1``, ``2`` become ``4788887``, ``7531906``, ``274925``.
The scramble is a bijection on 0..9,999,999, so decoding is exact and no two
sequences can ever produce the same ID.

**The constants below are load-bearing.** They defined every award ID the
awards portal issued before the resync, which people already hold -- on
projects, in emails, in funders' records. Change any of them and newly issued
IDs stop being comparable with, and can collide with, the old ones.

Issuing is gated by ``proposal.auto_assign_award_id``, and only takes effect
alongside ``deployment.application_portal_only``: without that one,
``ProjectInfo.set_shortname()`` copies the OpenPortal shortname over
``Project.slug``, and an award ID set correctly at creation would later be
silently replaced.
"""

from __future__ import annotations

import logging
import re

from waldur_core.core.models import APPLICATION_PORTAL_FEATURE, is_feature_enabled

logger = logging.getLogger(__name__)

AWARD_ID_FEATURE = "proposal.auto_assign_award_id"

SCHEME_VERSION = 1
MAX_SEQUENCE = 9_999_999

# The linear congruential scramble. Used as a single step, n -> (a*n + c) % m,
# never iterated, so it needs only ``a`` coprime with ``m`` to be a bijection --
# which it is: 2743019 is odd and does not end in 5. (The fork's original
# comment claimed "full period", which is a property of iterating an LCG and
# does not hold for these parameters; it was never needed.)
_MODULUS = 10_000_000
_MULTIPLIER = 2_743_019
_INCREMENT = 4_788_887
_INVERSE = pow(_MULTIPLIER, -1, _MODULUS)

_AWARD_ID = re.compile(r"^(\d{3})(\d)-(\d{4})-(\d{3})(\d)-([1-9]\d*)$")


def _scramble(sequence: int) -> int:
    return (_MULTIPLIER * sequence + _INCREMENT) % _MODULUS


def _unscramble(scrambled: int) -> int:
    return (_INVERSE * (scrambled - _INCREMENT)) % _MODULUS


def _luhn(digits: str) -> int:
    total = 0
    for position, digit in enumerate(reversed(digits)):
        value = int(digit)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return (10 - total % 10) % 10


def format_award_id(sequence: int, year: int, version: int = 1) -> str:
    """The award ID for ``sequence`` in ``year``."""
    if not 0 <= sequence <= MAX_SEQUENCE:
        raise ValueError(f"sequence must be 0..{MAX_SEQUENCE}, not {sequence}")
    if version < 1:
        raise ValueError(f"version must be at least 1, not {version}")
    year_part = f"{year % 1000:03d}"
    scrambled = f"{_scramble(sequence):07d}"
    check = _luhn(f"{year_part}{SCHEME_VERSION}{scrambled}")
    return (
        f"{year_part}{SCHEME_VERSION}-{scrambled[:4]}-{scrambled[4:]}{check}-{version}"
    )


def parse_award_id(value: str) -> tuple[int, int, int]:
    """``(year, sequence, version)`` for an award ID; ValueError otherwise.

    Validates the check digit, so an arbitrary slug that merely has the right
    shape -- ``1234-5678-9012-3`` -- is rejected rather than decoded into a
    nonsense sequence number. ``year`` is returned as a full year in the
    2000s, which is the only century this scheme has been used in.
    """
    match = _AWARD_ID.match(value or "")
    if not match:
        raise ValueError(f"{value!r} is not an award ID")
    year_part, scheme, head, tail, check, version = match.groups()
    if int(scheme) != SCHEME_VERSION:
        raise ValueError(f"{value!r} uses unknown scheme {scheme}")
    scrambled = head + tail
    if _luhn(f"{year_part}{scheme}{scrambled}") != int(check):
        raise ValueError(f"{value!r} fails its check digit")
    return 2000 + int(year_part), _unscramble(int(scrambled)), int(version)


def is_award_id(value: str | None) -> bool:
    try:
        parse_award_id(value or "")
    except ValueError:
        return False
    return True


def is_enabled() -> bool:
    """Whether new proposals should be given award IDs.

    Both flags, not one. ``auto_assign_award_id`` alone would issue an ID the
    OpenPortal shortname sync is free to overwrite on the project, which is
    worse than issuing none: the award would carry one identifier in the
    proposal and a different one on its project. When only the first flag is
    on, this says so in the log, since otherwise the flag appears to do
    nothing at all.
    """
    if not is_feature_enabled(AWARD_ID_FEATURE):
        return False
    if not is_feature_enabled(APPLICATION_PORTAL_FEATURE):
        logger.warning(
            "%s is on but %s is off, so no award ID is being assigned: "
            "without it the OpenPortal shortname would overwrite the "
            "project slug the award ID is written to.",
            AWARD_ID_FEATURE,
            APPLICATION_PORTAL_FEATURE,
        )
        return False
    return True
