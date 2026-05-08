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
        CREATE UNIQUE INDEX IF NOT EXISTS idx_silnt_utxos_vout ON silnt.utxos (txid, vout);
        """
    )


async def m002_subaccounts(db):
    await db.execute("""
    CREATE TABLE IF NOT EXISTS silnt.wallet_addresses (
        sp_address TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,        
        label_index INTEGER NOT NULL,
        created_at INTEGER NOT NULL DEFAULT 0        
    )
    """)
