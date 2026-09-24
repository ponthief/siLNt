async def m001_initial(db):
    """
    Initial wallet table.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.wallets (
            id TEXT NOT NULL PRIMARY KEY,
            "user" TEXT,
            network TEXT DEFAULT 'mainnet',
            title TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT {db.timestamp_now},
            updated_at TIMESTAMPTZ NOT NULL DEFAULT {db.timestamp_now},            
            sp_address TEXT NOT NULL,
            hr_address TEXT NOT NULL,
            last_height INTEGER,
            last_scan_height INTEGER NOT NULL DEFAULT 0,
            balance {db.big_int}
        );
    """
    )

    await db.execute(
        f"""
        CREATE TABLE silnt.utxos (
            txid TEXT NOT NULL PRIMARY KEY,
            vout SMALLINT NOT NULL,            
            amount {db.big_int} NOT NULL,
            priv_key_tweak TEXT NOT NULL,
            pub_key TEXT NOT NULL,            
            utxo_state TEXT NOT NULL,
            timestamp INTEGER NOT NULL DEFAULT 0,           
            wallet_id TEXT NOT NULL,
            label TEXT DEFAULT NULL,
            frozen BOOLEAN DEFAULT FALSE,
            freeze_reason TEXT DEFAULT NULL,
            suspected_dust BOOLEAN DEFAULT FALSE,
            spent_in_txid TEXT DEFAULT NULL,
            label_index INTEGER
        );
    """
    )
    await db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_silnt_utxos_vout_wallet_id ON silnt.utxos (txid, vout, wallet_id);
        """
    )


async def m002_subaccounts(db):
    await db.execute("""
    CREATE TABLE IF NOT EXISTS silnt.wallet_addresses (
        sp_address TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        label TEXT DEFAULT NULL,       
        label_index INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT 0        
    )
    """)


async def m003_add_spent_in_txid(db):    
    await db.execute(
        "CREATE INDEX IF NOT EXISTS utxos_spent_in_txid ON silnt.utxos(spent_in_txid)"
    )

async def m004_add_spent_at(db):
    await db.execute(
        "ALTER TABLE silnt.utxos ADD COLUMN IF NOT EXISTS spent_at INTEGER DEFAULT NULL"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS utxos_spent_at ON silnt.utxos(spent_at)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS utxos_wallet_timestamp ON silnt.utxos(wallet_id, timestamp)"
    )

async def m005_trusted_devices(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.trusted_devices (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            user_agent      TEXT,
            ip              TEXT,
            label           TEXT,
            confirmed_at    INTEGER NOT NULL,
            last_seen_at    INTEGER NOT NULL,
            UNIQUE(user_id, device_id)
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS trusted_devices_user ON silnt.trusted_devices(user_id)"
    )

async def m006_user_prefs(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.user_prefs (
            user_id              TEXT PRIMARY KEY,
            dust_threshold_sats  INTEGER DEFAULT NULL,
            updated_at           INTEGER NOT NULL
        )
        """
    )

async def m007_bip353_requests(db):
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.bip353_requests (
            id                  TEXT PRIMARY KEY,
            user_id             TEXT NOT NULL,
            wallet_id           TEXT NOT NULL,
            sp_address          TEXT NOT NULL,
            requested_username  TEXT NOT NULL,
            final_username      TEXT,
            message             TEXT,
            status              TEXT NOT NULL DEFAULT 'pending',
            reject_reason       TEXT,
            created_at          INTEGER NOT NULL,
            processed_at        INTEGER,
            processed_by        TEXT
        )
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS bip353_requests_user ON silnt.bip353_requests(user_id, status)"
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS bip353_requests_status ON silnt.bip353_requests(status, created_at)"
    )

async def m008_boltz_swaps(db):
    await db.execute(
        f"""
        CREATE TABLE silnt.boltz_swaps (
            id                   TEXT PRIMARY KEY,          -- Boltz swap id
            wallet_id            TEXT NOT NULL,             -- LNbits wallet (LN side)
            silnt_wallet_id      TEXT,                      -- SP wallet that funded it
            status               TEXT NOT NULL,             -- created/funded/failed/refunded/completed
            timeout_block_height INTEGER,                   -- refund nLockTime floor
            created_at           TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at           TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            json_data            TEXT NOT NULL              -- the rest (see SwapRecord)
        );
        """
    )
    # index for finding swaps that may need refunding
    await db.execute(
        "CREATE INDEX idx_boltz_swaps_status ON silnt.boltz_swaps (status);"
    )

async def m009_fix_utxos_primary_key(db):
    """
    The original PK was on txid alone, making a txid globally unique across ALL
    wallets. That's wrong: two different wallets can receive outputs in the same
    transaction, and one tx can pay multiple vouts to one wallet. The txid-only PK
    fired before the ON CONFLICT (txid,vout,wallet_id) upsert could absorb the
    re-insert, causing a duplicate-key crash when a 2nd wallet saw the same txid.
    Drop it and use the full outpoint-per-wallet as the PK (the unique index
    idx_silnt_utxos_vout_wallet_id already enforces this combination).
    """
    await db.execute("ALTER TABLE silnt.utxos DROP CONSTRAINT IF EXISTS utxos_pkey")
    await db.execute(
        "ALTER TABLE silnt.utxos "
        "ADD CONSTRAINT utxos_pkey PRIMARY KEY (txid, vout, wallet_id)"
    )

async def m010_bitmail_per_address(db):
    """
    Per-address BitMail (BIP-353): each SP address — the wallet's base address
    OR a labeled address — may have at most one BitMail, assigned once.

    1. wallet_addresses.hr_address: the BitMail bound to a labeled address.
       (The wallet's BASE address continues to use wallets.hr_address.)
    2. bip353_requests.address_id: which labeled address the request targets.
       NULL = the wallet's base SP address (back-compat: all existing rows are
       base-address requests, so NULL is the correct default for them).
    """
    await db.execute(
        "ALTER TABLE silnt.wallet_addresses "
        "ADD COLUMN IF NOT EXISTS hr_address TEXT DEFAULT NULL"
    )
    await db.execute(
        "ALTER TABLE silnt.bip353_requests "
        "ADD COLUMN IF NOT EXISTS address_id TEXT DEFAULT NULL"
    )
    # Helps the per-address "already has an approved BitMail?" lifetime check.
    await db.execute(
        "CREATE INDEX IF NOT EXISTS bip353_requests_addr "
        "ON silnt.bip353_requests(wallet_id, address_id, status)"
    )

async def m011_payjoin_requests(db):
    """
    PayJoin (BIP-84, watch-only, external Sparrow signing) coordination.

    Two users of this instance PayJoin each other. siLNt holds ONLY xpubs + PSBTs
    — never seeds/keys. This table carries one PayJoin attempt through its state
    machine and stores the in-progress PSBT (base64).

    State machine:
      PROPOSED    sender proposed; siLNt built the sender-only draft PSBT
      CONTRIBUTED receiver accepted; siLNt added receiver input + bumped payment
                  output; receiver signed their input. Final unsigned PSBT exists.
      FINALIZING  sender signed the final PSBT; siLNt combining + finalizing
      BROADCAST   network tx broadcast; confirmation tracked by send-watch
      CANCELLED   declined / cancelled / expired (terminal)
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_requests (
            id                  TEXT PRIMARY KEY,
            status              TEXT NOT NULL DEFAULT 'PROPOSED',

            -- parties (on-instance, addressed by username per decision)
            sender_user_id      TEXT NOT NULL,
            sender_username     TEXT NOT NULL,
            receiver_user_id    TEXT,
            receiver_username   TEXT NOT NULL,

            -- which imported BIP-84 wallets are involved (refs payjoin_descriptors)
            sender_descriptor_id   TEXT NOT NULL,
            receiver_descriptor_id TEXT,

            -- economics (sender pays fee per decision)
            amount_sats         {db.big_int} NOT NULL,
            fee_rate            REAL NOT NULL,
            payment_address     TEXT NOT NULL,      -- receiver's payment address
            receiver_input_sats {db.big_int},       -- R, once contributed
            fee_sats            {db.big_int},        -- computed at contribute time

            -- the in-progress artifact (base64). One column, overwritten as the
            -- PSBT advances: draft -> final-unsigned -> partially-signed -> final
            psbt                TEXT,
            -- the two parties' signed copies are merged by siLNt; we keep the
            -- latest combined PSBT in `psbt` and the broadcast tx hex here:
            unsigned_psbt       TEXT,
            -- receiver's signed copy (their partial_sig) stored at /contribute;
            -- sender's signed copy arrives at /finalize and is combined with it.
            receiver_signed_psbt TEXT,
            tx_hex              TEXT,
            txid                TEXT,

            -- selected inputs (JSON): sender inputs at propose, receiver input at
            -- contribute. Outpoints + (chain,index) for derivation/validation.
            sender_inputs       TEXT,               -- JSON array
            receiver_input      TEXT,               -- JSON object

            reject_reason       TEXT,
            created_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            -- expiry stored as Unix seconds (BIGINT) rather than TIMESTAMP: the
            -- codebase only ever uses db.timestamp_now for defaults and never
            -- writes computed timestamps, so an int avoids datetime-serialization
            -- ambiguity across Postgres/SQLite.
            expires_at          {db.big_int}
        );
        """
    )
    # Lookups: receiver's incoming queue, sender's outgoing, expiry sweep.
    await db.execute(
        "CREATE INDEX idx_payjoin_receiver ON silnt.payjoin_requests (receiver_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sender ON silnt.payjoin_requests (sender_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_status ON silnt.payjoin_requests (status, expires_at);"
    )


# Companion table: a user's imported watch-only BIP-84 wallet, imported as an
# OUTPUT DESCRIPTOR (single copy-paste from Sparrow). embit parses it, so siLNt
# extracts fingerprint + path + xpub from the descriptor itself — no separate
# fingerprint field for the user to find, and the key-origin used in PSBTs
# matches exactly what the wallet declared (avoids Sparrow-recognition issues).
async def m012_payjoin_descriptors(db):
    """
    Imported watch-only BIP-84 accounts for PayJoin, as output descriptors.
    User pastes e.g.  wpkh([bc7a6fe7/84h/1h/0h]tpub.../<0;1>/*)
    siLNt stores the raw descriptor plus the fields embit parses out of it.
    siLNt stores ONLY public data (descriptor/xpub/fingerprint). No keys/seeds.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_descriptors (
            id              TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL,
            label           TEXT,
            descriptor      TEXT NOT NULL,          -- raw output descriptor (as pasted)
            -- parsed from the descriptor by embit at import (cached for queries):
            xpub            TEXT NOT NULL,          -- account xpub (tpub/xpub)
            master_fp       TEXT NOT NULL,          -- 8 hex chars, from [origin]
            account_path    TEXT NOT NULL,          -- e.g. "84h/1h/0h"
            script_type     TEXT NOT NULL DEFAULT 'wpkh',  -- validated == wpkh
            network         TEXT NOT NULL,          -- mainnet/signet/regtest
            last_sync_at    TIMESTAMP,
            created_at      TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )

    await db.execute(
        "CREATE INDEX idx_payjoin_descriptors_user ON silnt.payjoin_descriptors (user_id);"
    )

async def m013_payjoin_invoice_fields(db):
    """
    Invoice model (payee-initiated, directed PayJoin): add a memo and a second
    order-independent signature slot to payjoin_requests.
      receiver_* = payee A (set at invoice creation, incl. A's contributed input)
      sender_*   = payer B (B's inputs set when B pays)
    Runtime statuses: 'OPEN' (A posted invoice) -> 'CLAIMED' (B paid, PSBT built,
    awaiting both signatures) -> 'BROADCAST' / 'CANCELLED'. status is TEXT, so no
    enum to alter. Fulcrum config needs NO migration (BackendConfig is stored as
    JSON in blindbit_config.json_data).
    """
    await db.execute("ALTER TABLE silnt.payjoin_requests ADD COLUMN memo TEXT;")
    await db.execute("ALTER TABLE silnt.payjoin_requests ADD COLUMN sender_signed_psbt TEXT;")


async def m014_payjoin_contacts(db):
    """
    Consent-based connections between two users on this instance, so a payee can
    keep a private, curated list of payers (and vice-versa) WITHOUT exposing the
    global user base. One row per connection:
      status PENDING  -> requester asked target; awaiting target's approval
      status ACCEPTED -> mutual connection; each may invoice/pay the other and
                         sees the other in their invoice payer-picker
    Either party can delete the row (sever the connection). No enumeration: a
    request is only created by exact known username (resolve-payer check).
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_contacts (
            id                 TEXT PRIMARY KEY,
            status             TEXT NOT NULL DEFAULT 'PENDING',
            requester_user_id  TEXT NOT NULL,
            target_user_id     TEXT NOT NULL,
            created_at         TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at         TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_contacts_req ON silnt.payjoin_contacts (requester_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_contacts_tgt ON silnt.payjoin_contacts (target_user_id, status);"
    )


async def m015_payjoin_contact_labels(db):
    """
    Per-side private labels for connections. Each user can label a connection
    independently; the label is visible only to the labeler (not shared with the
    counterparty). Keyed by (contact_id, labeler_user_id). Separate table because
    the connection row itself is shared by both parties.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_contact_labels (
            contact_id      TEXT NOT NULL,
            labeler_user_id TEXT NOT NULL,
            label           TEXT NOT NULL,
            updated_at      TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            PRIMARY KEY (contact_id, labeler_user_id)
        );
        """
    )


async def m016_payjoin_descriptor_encryption(db):
    """
    Privacy hardening: encrypt PayJoin descriptors/xpubs AT REST.

    An account xpub lets anyone holding it derive all of a wallet's addresses and
    reconstruct its full balance/history (watch-only). The PayJoin flow needs the
    descriptor server-side to coordinate, so we now store descriptor + xpub
    encrypted (AESCipher keyed by the LNbits instance auth_secret) instead of in
    plaintext. This protects a leaked DB dump/backup; it does not protect against
    a full host compromise (which would also expose the key).

    Adds xpub_sha256: a non-reversible SHA256 tag used for duplicate-import
    detection, since the encrypted xpub can't be matched by equality. Backfills
    the tag for existing rows and encrypts any existing plaintext descriptor/xpub
    in place.
    """    
    # 1) Add the dedup-hash column (nullable; backfilled below).
    await db.execute("ALTER TABLE silnt.payjoin_descriptors ADD COLUMN xpub_sha256 TEXT;")    

    # 2) Index the dedup tag for fast existence checks.
    await db.execute(
        "CREATE INDEX idx_payjoin_desc_xpubhash ON silnt.payjoin_descriptors (user_id, xpub_sha256);"
    )


async def m017_sp_contacts(db):
    """
    Per-user private address book for SP sends. Users explicitly save recipients
    (a raw SP address OR a BitMail name) with a label, to reuse on the Send
    screen. Private to the saving user (scoped by user_id). The recipient value
    is encrypted at rest (same as PayJoin descriptors) since it's a recipient
    identity; the label is the user's own and kept plaintext.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.sp_contacts (
            id           TEXT PRIMARY KEY,
            user_id      TEXT NOT NULL,
            label        TEXT NOT NULL,
            kind         TEXT NOT NULL,          -- 'bitmail' | 'sp'
            value        TEXT NOT NULL,          -- encrypted recipient (name or sp address)
            value_sha256 TEXT,                   -- non-reversible dedup tag
            created_at   TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            last_used_at TIMESTAMP
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_sp_contacts_user ON silnt.sp_contacts (user_id, value_sha256);"
    )

async def m019_drop_stray_utxos_vout_unique(db):    
    await db.execute("DROP INDEX IF EXISTS silnt.idx_silnt_utxos_vout")
    await db.execute("ALTER TABLE silnt.utxos DROP CONSTRAINT IF EXISTS idx_silnt_utxos_vout")

async def m020_admin_alerts(db):
    """
    Admin-visible alerts surfaced in the Admin console (e.g. BitMail tampering
    detected on a send: the DNS TXT for a siLNt-issued BitMail resolved to an SP
    address that does NOT match the one siLNt recorded — a possible hijack).
    """
    await db.execute(
        f"""
        CREATE TABLE IF NOT EXISTS silnt.admin_alerts (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'warning',
            title       TEXT NOT NULL,
            detail      TEXT NOT NULL DEFAULT '',
            meta        TEXT,
            acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
            created_at  INTEGER NOT NULL
        );
        """
    )
    await db.execute(
        "CREATE INDEX IF NOT EXISTS idx_admin_alerts_open "
        "ON silnt.admin_alerts (acknowledged, created_at)"
    )

async def m021_login_alerts(db):
    """
    Dedup store for new-device sign-in alert emails. When an untrusted device
    accesses an account, we email the user once per (user, device signature)
    within a cooldown window — this table records the last time we alerted for a
    given signature so refreshes / VPN flaps / cookie drops don't spam the user.
    """
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.login_alerts (
            user_id       TEXT NOT NULL,
            sig           TEXT NOT NULL,       -- hash of UA + IP (coarse device id)
            last_alert_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, sig)
        );
        """
    )

async def m022_device_codes(db):
    """Short numeric codes for new-device confirmation (replaces email-link flow)."""
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.device_codes (
            user_id     TEXT NOT NULL,
            code_hash   TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            user_agent  TEXT,
            ip          TEXT,
            expires_at  INTEGER NOT NULL,
            attempts    INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id)
        );
        """
    )

async def m023_backend_config_per_network(db):
    # Rename blindbit_config -> backend_config, keyed per-network. The legacy
    # singleton row (id='blindbit') is copied to its network id. Old table is
    # left in place for now (dropped in a later cleanup migration after Stage 2).
    await db.execute(
        """
        CREATE TABLE IF NOT EXISTS silnt.backend_config (
            id TEXT PRIMARY KEY,
            json_data TEXT NOT NULL DEFAULT '{}'
        );
        """
    )


async def m024_sp_contacts_network(db):
    """Scope the SP address book per network. Without this, a user with wallets
    on more than one network (e.g. a mainnet build reusing a signet test account)
    sees every network's contacts. Contacts predate this column were created in
    the signet-only phase, so backfill them to signet; new rows carry their
    creating build's network. The dedup index gains `network` so the same
    recipient can be saved on more than one network.
    """
    await db.execute(
        "ALTER TABLE silnt.sp_contacts ADD COLUMN network TEXT NOT NULL DEFAULT 'signet';"
    )
    await db.execute("DROP INDEX IF EXISTS silnt.idx_sp_contacts_user")
    await db.execute(
        "CREATE INDEX idx_sp_contacts_user ON silnt.sp_contacts (user_id, network, value_sha256);"
    )


async def m025_background_scan(db):
    """Opt-in "Remote Scanner": a user may let the server scan a wallet in the
    background (so a returning user isn't faced with a huge catch-up). This
    requires storing the wallet's SCAN private key — a detection-only capability
    (it can find payments but never spend). The spend key is never stored; the
    background scanner derives the spend PUBLIC key from the wallet's sp_address.
    The scan key is encrypted at rest. Presence of a row = opted in; disabling
    deletes the row (removing the key from the server).
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.background_scan (
            wallet_id   TEXT PRIMARY KEY,
            scan_secret TEXT NOT NULL,          -- encrypted at rest (AESCipher)
            created_at  TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )


async def m026_fcm_tokens(db):
    """Firebase Cloud Messaging device tokens, per user, so the server can push a
    notification (e.g. "payment received" from a background scan) to a user's
    phone(s). A user can have several devices; a token is unique."""
    await db.execute(
        f"""
        CREATE TABLE silnt.fcm_tokens (
            token      TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT {db.timestamp_now}
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_fcm_tokens_user ON silnt.fcm_tokens (user_id);"
    )


async def m027_plain_incoming(db):
    """
    Plain-chain payments a wallet has made to ITS OWN Silent Payments address,
    recorded at broadcast so every one of the user's devices can show them while
    they are in flight.

    Without this the transaction is invisible to the server: it spends P2WPKH
    coins that were never in silnt.utxos, so there is no send to report, and the
    output is a Silent Payments output that does not exist as a receive until a
    scan finds it. The device that broadcast it can remember locally; no other
    device has anything to fetch.

    Deliberately ONLY self-payments. Those coins are entering the wallet, so the
    server is going to publish them as a receive within the hour regardless —
    recording the txid early tells it nothing it is not about to learn. Payments
    OUT of the plain chain are not recorded, which is where keeping the server
    ignorant actually matters.

    Rows are transient: dropped once the scanned receive supersedes them, and
    swept after a day so a transaction that never confirmed does not linger.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.plain_incoming (
            txid       TEXT PRIMARY KEY,
            wallet_id  TEXT NOT NULL,
            amount     {db.big_int} NOT NULL,
            -- Epoch seconds, written explicitly like wallet_addresses, so the
            -- TTL below is a plain integer comparison on every backend.
            created_at INTEGER NOT NULL
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_plain_incoming_wallet ON silnt.plain_incoming (wallet_id);"
    )


async def m028_pending_registrations(db):
    """Registrations awaiting a 6-digit email code.

    The emailed LINK carries everything needed to create the account, which is
    why registration needed no server-side state at all. A 6-digit code cannot:
    it is short enough to type, which means it cannot also carry a username, an
    email and a password hash. So those wait here until the code arrives.

    The code exists because a deployment can have its web app closed to the
    outside, leaving the link with nowhere to open — see BUILD_ANDROID.md. The
    app-facing path must not depend on a browser being able to reach anything
    except the API.

    What is stored: the same bcrypt hash the token carries, and an HMAC of the
    code rather than the code itself, so a database leak on its own does not
    hand over pending registrations. Six digits is only ~20 bits, so the real
    protection is the attempt cap and the TTL, not the HMAC.

    Keyed by email because that is the only thing the user can be asked to
    retype alongside the code. Registering twice for one address replaces the
    pending row rather than accumulating.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.pending_registrations (
            email         TEXT PRIMARY KEY,
            username      TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            code_hmac     TEXT NOT NULL,
            -- Wrong guesses so far. The row is dropped once this passes the cap,
            -- so a caller cannot grind 6 digits.
            attempts      INTEGER NOT NULL DEFAULT 0,
            -- Epoch seconds, written explicitly like plain_incoming, so the TTL
            -- is a plain integer comparison on every backend.
            created_at    INTEGER NOT NULL
        );
        """
    )
    # Username uniqueness is enforced at account creation, but a pending row
    # holding a username someone else is also mid-registering should be findable
    # cheaply enough to reject early.
    await db.execute(
        "CREATE INDEX idx_pending_reg_username "
        "ON silnt.pending_registrations (username);"
    )


async def m030_drop_spend_watch(db):
    """Remove the unexpected-spend watch tables.

    The feature they backed was withdrawn: a "coins left your wallet and it did
    not send them" warning reads as an emergency, and every plausible cause
    other than a stolen key — a broadcast whose txid was not recorded, a
    restored wallet, an indexer disagreeing with our own records — produced the
    same alarming wording. A warning that cannot reliably tell those apart from
    theft costs more trust than it buys.

    A new number rather than editing m029, which has already run on deployed
    instances and so would never be re-applied. DROP ... IF EXISTS so a fresh
    install, where m029 no longer exists to create them, is a no-op. The index
    on spend_alerts goes with its table.
    """
    await db.execute("DROP TABLE IF EXISTS silnt.spend_alerts")
    await db.execute("DROP TABLE IF EXISTS silnt.broadcast_txids")


async def m031_payjoin_sp_requests(db):
    """Silent Payments PayJoin coordination. Client-signed, key-free server.

    Separate from payjoin_requests rather than more nullable columns on it,
    because that table is PSBT- and descriptor-shaped end to end: every party
    is identified by a payjoin_descriptors row, and four of its columns hold
    base64 PSBTs. An SP PayJoin has neither. There is no descriptor — an SP
    UTXO's key is a one-off from a tweak and has no derivation path — and no
    PSBT, because PSBT exists to hand a transaction to an external signer and
    here both signers are the parties' own apps.

    WHAT THE SERVER HOLDS, AND WHAT IT NEVER SEES

    Held: outpoints, the inputs' x-only PUBLIC keys and amounts, the two
    derived output scriptPubKeys, witnesses, the assembled transaction. All of
    it is on-chain data or about to be.

    Never sent, never stored: b_scan, b_spend, or any input's private key
    tweak. Each party derives its own output on its own device (the derivation
    needs that party's scan key) and signs its own inputs there. helpers/
    payjoin_sp.py::payment_script, change_script and signing_key are the
    functions that would need those keys; nothing in views_api.py calls them,
    and they remain only for the fixture generators and the spike check.

    THE STATE MACHINE, AND WHY IT HAS AN EXTRA STEP

    A taproot key-path signature commits to every output, and every SP output
    is derived from the whole input set. So inputs must be frozen before any
    output exists, and every output must exist before anyone signs. Adding an
    input later invalidates the entire transaction, which is why there is no
    "contribute and sign in one call" here as there is in the PSBT flow:

      PROPOSED      payer named the payee, the amount and its own inputs
      CONTRIBUTED   payee added its inputs AND its derived payment script.
                    The input set is frozen from this point.
      PAYER_SIGNED  payer posted its derived change script and witnesses for
                    its own inputs; the unsigned transaction now exists
      BROADCAST     payee's witnesses arrived, the two sets were combined and
                    the transaction went to the network
      CANCELLED     declined, cancelled or expired (terminal)

    Inputs and witnesses are JSON rather than child tables. They are written
    once and read as a whole — there is no query that wants one input — and a
    frozen set is easier to reason about as one value than as rows that could
    drift apart.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_sp_requests (
            id                  TEXT PRIMARY KEY,
            status              TEXT NOT NULL DEFAULT 'PROPOSED',
            network             TEXT NOT NULL,

            -- Parties, addressed by username as the PSBT flow does. Both are
            -- wallets on this instance: the derivation only works when each
            -- side can compute its own outputs from the shared input set.
            payer_user_id       TEXT NOT NULL,
            payer_username      TEXT NOT NULL,
            payer_wallet_id     TEXT NOT NULL,
            payee_user_id       TEXT,
            payee_username      TEXT NOT NULL,
            payee_wallet_id     TEXT,

            -- Economics. The payer pays the fee, as in payjoin_merge, and the
            -- payee's contributed input comes straight back out in the payment
            -- so it is no worse off for taking part.
            amount_sats         {db.big_int} NOT NULL,
            fee_rate            REAL NOT NULL,
            payer_in_sats       {db.big_int},
            payee_in_sats       {db.big_int},
            payment_sats        {db.big_int},
            change_sats         {db.big_int},
            fee_sats            {db.big_int},
            vsize               {db.big_int},

            -- The frozen input set: JSON arrays of txid, vout, pub_key and
            -- amount -- public data only. Kept per party so each side can be
            -- told which inputs are its own without the server guessing.
            -- (No braces in these comments: the whole statement is an
            -- f-string, so a brace is an interpolation. A JSON shape written
            -- out literally here raised NameError at migration time.)
            payer_inputs        TEXT,
            payee_inputs        TEXT,

            -- The two derived scriptPubKeys, hex. Each is computed on its
            -- owner's device and is opaque to the other party: only the payee
            -- holds the scan key the payment script comes from, which is why
            -- the payer verifies that output by its VALUE and not its script.
            payment_spk         TEXT,
            change_spk          TEXT,

            -- Witnesses, JSON mapping input index to signature hex, posted by
            -- whoever owns those inputs. Two slots rather than one so the two
            -- parties cannot overwrite each other, and the order they sign in
            -- does not matter.
            payer_witnesses     TEXT,
            payee_witnesses     TEXT,

            unsigned_tx         TEXT,
            tx_hex              TEXT,
            txid                TEXT,

            reject_reason       TEXT,
            created_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            -- Unix seconds, matching payjoin_requests: this codebase only ever
            -- uses db.timestamp_now for defaults and never writes a computed
            -- TIMESTAMP, so an int avoids datetime-serialization differences
            -- between Postgres and SQLite.
            expires_at          {db.big_int}
        );
        """
    )
    # The payee's incoming queue, the payer's outgoing one, and the expiry
    # sweep — the same three lookups the PSBT flow needs.
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_payee "
        "ON silnt.payjoin_sp_requests (payee_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_payer "
        "ON silnt.payjoin_sp_requests (payer_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_status "
        "ON silnt.payjoin_sp_requests (status, expires_at);"
    )


async def m032_payjoin_sp_offers(db):
    """An advertised PayJoin: the payee posts an amount, a contact claims it.

    m031 assumed the payer starts, so payer_user_id, payer_username and
    payer_wallet_id are NOT NULL. In an advertised PayJoin nobody is the payer
    yet, so those three have to become nullable.

    SQLite cannot drop a NOT NULL in place, so the table is rebuilt: create,
    copy, drop, rename. Portable to Postgres, and safe here because the only
    rows this can touch are in-flight PayJoins on an instance that has run m031
    -- which nothing has yet used in anger. Copying rather than truncating
    anyway: losing someone's half-signed PayJoin because a migration found it
    inconvenient is not a trade to make quietly.

    WHY THE ADVERTISED FLOW NEEDS A STATE m031 DOES NOT HAVE. Every SP output
    is derived from the WHOLE input set, so nothing can be derived until both
    parties' inputs are in. When the payer starts, the payee learns the full
    set at the moment it contributes, and derives its payment script in the
    same call. When the PAYEE starts, it posts before the payer exists -- so it
    cannot derive anything yet and has to come back once someone claims. Hence:

      OPEN         posted by the payee, with its own inputs. No payer.
      CLAIMED      a contact took it and added theirs. The set is frozen, and
                   now the payee can derive.
      CONTRIBUTED  the payee posted its payment script. From here the flow is
                   identical to the payer-initiated one.
      PAYER_SIGNED the payer derived change and signed
      BROADCAST    the payee signed and it went out

    A directed PayJoin still starts at PROPOSED and never passes through OPEN
    or CLAIMED. One table for both because they converge at CONTRIBUTED and
    share every endpoint after it.
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.payjoin_sp_requests_new (
            id                  TEXT PRIMARY KEY,
            status              TEXT NOT NULL DEFAULT 'PROPOSED',
            network             TEXT NOT NULL,

            -- Nullable now: an OPEN offer has no payer until it is claimed.
            payer_user_id       TEXT,
            payer_username      TEXT,
            payer_wallet_id     TEXT,
            payee_user_id       TEXT,
            payee_username      TEXT NOT NULL,
            payee_wallet_id     TEXT,

            amount_sats         {db.big_int} NOT NULL,
            fee_rate            REAL NOT NULL,
            payer_in_sats       {db.big_int},
            payee_in_sats       {db.big_int},
            payment_sats        {db.big_int},
            change_sats         {db.big_int},
            fee_sats            {db.big_int},
            vsize               {db.big_int},

            payer_inputs        TEXT,
            payee_inputs        TEXT,

            payment_spk         TEXT,
            change_spk          TEXT,

            payer_witnesses     TEXT,
            payee_witnesses     TEXT,

            unsigned_tx         TEXT,
            tx_hex              TEXT,
            txid                TEXT,

            -- What the payee wrote on the advertisement. Shown to contacts
            -- deciding whether to take it; never sent to the network.
            memo                TEXT,

            reject_reason       TEXT,
            created_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            expires_at          {db.big_int}
        );
        """
    )
    # Columns named explicitly rather than SELECT *: the new table has memo,
    # which the old one does not, and a positional copy would silently shift
    # every column after it.
    await db.execute(
        """
        INSERT INTO silnt.payjoin_sp_requests_new
            (id, status, network,
             payer_user_id, payer_username, payer_wallet_id,
             payee_user_id, payee_username, payee_wallet_id,
             amount_sats, fee_rate, payer_in_sats, payee_in_sats,
             payment_sats, change_sats, fee_sats, vsize,
             payer_inputs, payee_inputs, payment_spk, change_spk,
             payer_witnesses, payee_witnesses,
             unsigned_tx, tx_hex, txid,
             reject_reason, created_at, updated_at, expires_at)
        SELECT
             id, status, network,
             payer_user_id, payer_username, payer_wallet_id,
             payee_user_id, payee_username, payee_wallet_id,
             amount_sats, fee_rate, payer_in_sats, payee_in_sats,
             payment_sats, change_sats, fee_sats, vsize,
             payer_inputs, payee_inputs, payment_spk, change_spk,
             payer_witnesses, payee_witnesses,
             unsigned_tx, tx_hex, txid,
             reject_reason, created_at, updated_at, expires_at
        FROM silnt.payjoin_sp_requests
        """
    )
    # The indexes go with the old table, so drop them by name first: SQLite
    # keeps index names in a schema-wide namespace, so recreating them against
    # the new table would collide.
    # Written out rather than looped through an f-string. A loop would read
    # better and would also be the only interpolation in this file that is not
    # a db.* attribute — which is the rule tests/test_migrations_fstrings.py
    # enforces, and the rule is worth more than three saved lines. A guard with
    # an exception in it stops being a guard.
    await db.execute("DROP INDEX IF EXISTS idx_payjoin_sp_payee")
    await db.execute("DROP INDEX IF EXISTS idx_payjoin_sp_payer")
    await db.execute("DROP INDEX IF EXISTS idx_payjoin_sp_status")
    await db.execute("DROP TABLE silnt.payjoin_sp_requests")
    await db.execute(
        "ALTER TABLE silnt.payjoin_sp_requests_new "
        "RENAME TO payjoin_sp_requests"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_payee "
        "ON silnt.payjoin_sp_requests (payee_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_payer "
        "ON silnt.payjoin_sp_requests (payer_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_status "
        "ON silnt.payjoin_sp_requests (status, expires_at);"
    )
    # The offer board: every OPEN row, which is what a contact browses.
    await db.execute(
        "CREATE INDEX idx_payjoin_sp_open "
        "ON silnt.payjoin_sp_requests (status, network, payee_user_id);"
    )


async def m033_tango_rounds(db):
    """Tango: a two-party equal-output mix.

    Its own table rather than more columns on payjoin_sp_requests, because
    almost nothing about the money is the same. A PayJoin has a payer, a payee,
    a payment and one change; a Tango has two symmetric sides, one denomination
    paid to BOTH of them, up to two changes and a fee split down the middle.
    Modelling that as a PayJoin with nullable extras would leave every column
    meaning one thing in one flow and another in the other.

    The parties are `a` and `b`, not payer and payee, and that is deliberate:
    neither pays the other. A is whoever proposed the round and B is whoever
    was invited, which decides turn order and who owes the odd satoshi of fee,
    and nothing else.

    Both sides' derived scripts are stored: each has a MIX output at the
    denomination, and a CHANGE output when their coins did not divide evenly.
    The change is the leak in a two-party mix -- change plus mixed output is
    that party's input total, and with two inputs an observer can often solve
    it -- so `clean` records whether this round had any, and the clients say so
    rather than implying every mix is a clean one.

      PROPOSED   A named a denomination and picked its coins
      ACCEPTED   B matched it, added coins and derived its two scripts. The
                 input set is frozen: every SP output depends on all of it.
      A_SIGNED   A derived its two scripts and signed its own inputs
      BROADCAST  B signed and it went to the network
      CANCELLED  either side walked away (terminal)
    """
    await db.execute(
        f"""
        CREATE TABLE silnt.tango_rounds (
            id                  TEXT PRIMARY KEY,
            status              TEXT NOT NULL DEFAULT 'PROPOSED',
            network             TEXT NOT NULL,

            a_user_id           TEXT NOT NULL,
            a_username          TEXT NOT NULL,
            a_wallet_id         TEXT NOT NULL,
            b_user_id           TEXT,
            b_username          TEXT NOT NULL,
            b_wallet_id         TEXT,

            -- What both sides get back. One number, not two, because two
            -- different numbers would be two outputs an observer can tell
            -- apart, which is the whole of what this feature sells.
            denom_sats          {db.big_int} NOT NULL,
            fee_rate            REAL NOT NULL,

            a_in_sats           {db.big_int},
            b_in_sats           {db.big_int},
            a_change_sats       {db.big_int},
            b_change_sats       {db.big_int},
            a_fee_sats          {db.big_int},
            b_fee_sats          {db.big_int},
            fee_sats            {db.big_int},
            vsize               {db.big_int},
            -- True when neither side needed change. The honest measure of how
            -- much this round actually hid.
            clean               BOOLEAN,

            a_inputs            TEXT,
            b_inputs            TEXT,

            a_mix_spk           TEXT,
            a_change_spk        TEXT,
            b_mix_spk           TEXT,
            b_change_spk        TEXT,

            a_witnesses         TEXT,
            b_witnesses         TEXT,

            unsigned_tx         TEXT,
            tx_hex              TEXT,
            txid                TEXT,

            -- Set once the scanner has found a change output and labelled it,
            -- so the labelling is attempted until it succeeds and not after.
            change_labelled     BOOLEAN DEFAULT FALSE,

            reject_reason       TEXT,
            created_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            updated_at          TIMESTAMP NOT NULL DEFAULT {db.timestamp_now},
            expires_at          {db.big_int}
        );
        """
    )
    await db.execute(
        "CREATE INDEX idx_tango_a ON silnt.tango_rounds (a_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_tango_b ON silnt.tango_rounds (b_user_id, status);"
    )
    await db.execute(
        "CREATE INDEX idx_tango_status ON silnt.tango_rounds (status, expires_at);"
    )


async def m034_relabel_tango_coins(db):
    """Let the sweeper name every Tango coin again, under the current wording.

    Two things changed after rounds had already been labelled. The share is now
    labelled as well as the change — labelling only the change told the owner
    which coin was dangerous but not what it was dangerous WITH — and both
    labels now carry a short round marker, because two rounds with the same
    person produced two coins reading exactly the same thing.

    Rounds already marked change_labelled will never be revisited, so clearing
    the flag is what makes the sweeper pick them up. It relabels within five
    minutes and sets the flag again; coins the scanner has not found yet keep
    it clear until it has, which is the behaviour anyway.

    Nothing is destroyed here. The utxo labels themselves are rewritten by
    _tango_label_change, and only where the existing label is one this code
    wrote: a label the user typed does not begin with "Tango mix" or "Tango
    change", so it is left alone.
    """
    await db.execute(
        """
        UPDATE silnt.tango_rounds
        SET change_labelled = FALSE
        WHERE status = 'BROADCAST'
        """
    )
