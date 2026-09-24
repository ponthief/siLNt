"""What to say when a connection request has nowhere to go.

create_payjoin_contact returns the existing row when one already exists between
two users — in either direction and in any status — and the endpoint used to
answer "sent" regardless. So asking again someone who had declined you, or
someone who had asked YOU, or someone you were already connected to, all
reported success and did nothing. Two requests, one new pending row, and no way
to tell which had landed.

The state between two people is not the same question as whether the username
exists or whether they are on your network, so it gets its own answer. Kept
here as a pure function because the wording is the whole of it and the branches
are what went untested.
"""

from __future__ import annotations

from typing import Optional

PENDING = "PENDING"
ACCEPTED = "ACCEPTED"
DECLINED = "DECLINED"


def refusal_for_existing(
    status: Optional[str],
    i_am_the_requester: bool,
    username: str,
) -> Optional[str]:
    """Why this request cannot be made, or None when there is nothing in the way.

    None is returned for an absent row and for any status this does not know
    about: a state nobody anticipated should not silently block a connection,
    and the insert's own guard against duplicates still holds.

    A DECLINED row is refused when the caller is the one who WAS declined:
    letting a fresh request overwrite it would make "no" mean "ask again",
    which is not what the other person chose. The caller can clear it
    themselves — their own declined requests are listed for them — so the
    message points there.

    When the caller is the one who DID the declining, see may_reopen: there is
    nothing to refuse, because the only person the refusal protected is the one
    now asking.
    """
    if not status:
        return None
    state = status.strip().upper()

    if state == ACCEPTED:
        return f"You are already connected with '{username}'."

    if state == PENDING:
        if i_am_the_requester:
            return (
                f"You have already asked '{username}'. It is still waiting on "
                f"them — you can withdraw it under Connections."
            )
        return (
            f"'{username}' has already asked to connect with YOU. Approve "
            f"their request under Connections instead."
        )

    if state == DECLINED:
        if i_am_the_requester:
            return (
                f"'{username}' declined your request. Clear it under "
                f"Connections → Declined, then you can ask again."
            )
        # The caller declined THEM, and is now asking. Reopened, not refused.
        return None

    return None


def may_reopen(status: Optional[str], i_am_the_requester: bool) -> bool:
    """Whether this request should revive the existing row instead of being
    refused.

    ONE CASE: the caller declined this person, and has now asked to connect
    with them. That is a change of mind about the caller's own refusal, and
    nobody else's wishes are being overridden — the reason not to reopen a
    decline is to stop the person who was told no from asking again, and here
    the person asking is the one who said it.

    It also has to work this way because of where the row lives. A DECLINED row
    is listed only for the requester, so the decliner cannot see it: told to
    dismiss it first, they would be hunting for a row their own screen does not
    show. The fix is not to make them clear it — it is not to need them to.
    """
    if not status:
        return False
    return status.strip().upper() == DECLINED and not i_am_the_requester
