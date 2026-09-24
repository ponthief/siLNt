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

    A DECLINED row is refused rather than reopened. Letting a fresh request
    overwrite it would make "no" mean "ask again", which is not what the person
    who declined chose — so it has to be dismissed first, and dismissing is
    theirs or the asker's own act.
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
                f"'{username}' declined your request. Dismiss it under "
                f"Connections, then you can ask again."
            )
        return (
            f"You declined a request from '{username}'. Dismiss it under "
            f"Connections, then you can ask again."
        )

    return None
