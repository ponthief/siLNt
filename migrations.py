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
        CREATE TABLE IF NOT EXISTS silnt.blindbit_config (
            id TEXT PRIMARY KEY,
            json_data TEXT NOT NULL DEFAULT '{}'
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