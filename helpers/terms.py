"""The version number of the signup terms, in one place both sides can read.

WHY A NUMBER AT ALL. "I agree to the terms" is worth nothing as a record if
nobody can say WHICH terms. The web app renders `TermsView.vue`, publishes the
version it rendered, and sends it back with the registration; the backend
refuses a registration that names a version it does not recognise. So an
account created today is tied to the text that was on screen today, and terms
edited next month do not retroactively become the thing somebody agreed to.

WHAT THIS IS NOT. It is an assertion by the client, logged at registration —
not a signature, and not proof. A caller posting straight at the API can send
whatever it likes, exactly as it can skip the checkbox. That is the honest
limit of a tick-box on a form, and the reason the number exists is
record-keeping rather than enforcement.

BUMP IT WHEN THE TERMS CHANGE in any way that matters to somebody who already
agreed. `TermsView.vue` renders this same number and the date beside it, and
`check:terms` fails if the two files disagree — a version bumped on one side
only is worse than no version, because it reads as precision.
"""

from __future__ import annotations

# Bump together with the "Version" line in thrilla's src/views/TermsView.vue.
TERMS_VERSION = 1

# The date that version was published, for the page and for anyone reading a
# log line. ISO, because a log is read by whoever is awake.
TERMS_EFFECTIVE = "2026-10-21"


def terms_version_ok(claimed) -> bool:
    """Whether a registration's claimed terms version is one we know.

    Only the CURRENT version is accepted. An older one means the client is
    running a stale bundle and is showing text that is no longer the offer —
    the fix is a reload, which is what the client is told. Accepting it
    quietly would record agreement to terms this instance has stopped
    publishing, which is the one thing the number is here to prevent.
    """
    try:
        return int(claimed) == TERMS_VERSION
    except (TypeError, ValueError):
        return False
