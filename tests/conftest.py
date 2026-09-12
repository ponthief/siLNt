"""Import helpers/scan.py without LNbits.

scan.py is an LNbits extension module: it does `from ..crud import db, ...`, and
crud reaches into LNbits itself, which is the host application and not a
dependency this package can install. Rather than leave the scanning code
untestable — the part of a wallet that decides whether your money is found —
this stands up the small amount of package scaffolding the imports need and
loads the real module against it.

Only the module's *dependencies* are stubbed. scan.py itself is the real file.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _stub_loguru() -> None:
    """loguru comes from LNbits at runtime and is not installable here."""
    if "loguru" in sys.modules:
        return
    module = types.ModuleType("loguru")

    class _NullLogger:
        def __getattr__(self, _name):
            def noop(*_args, **_kwargs):
                return None

            return noop

    module.logger = _NullLogger()
    sys.modules["loguru"] = module


class FakeDB:
    """Records queries and replays canned rows.

    Deliberately not a real database: these tests are about which requests the
    scanner makes and what it does with the answers, and a fake that counts
    calls is what makes "this query ran once per block" observable.
    """

    def __init__(self):
        self.fetchall_calls: list[tuple[str, dict]] = []
        self.execute_calls: list[tuple[str, dict]] = []
        self.rows: list[dict] = []

    async def fetchall(self, query, values=None):
        self.fetchall_calls.append((query, values or {}))
        return list(self.rows)

    async def execute(self, query, values=None):
        self.execute_calls.append((query, values or {}))
        return None


class FakeBackend:
    def __init__(
        self,
        mempool_url="https://mempool.example",
        blindbit_url="http://oracle.example",
    ):
        self.mempool_url = mempool_url
        self.blindbit_url = blindbit_url


# The real package name. Registering the stub under it means nothing ever
# executes the repo's own __init__.py, which imports lnbits at module scope and
# would fail before any test ran.
PKG = ROOT.name


def _install_package_stubs(db: FakeDB) -> None:
    pkg = types.ModuleType(PKG)
    pkg.__path__ = [str(ROOT)]
    sys.modules[PKG] = pkg

    crud = types.ModuleType(f"{PKG}.crud")
    crud.db = db
    crud.DEFAULT_CONFIG_NETWORK = "signet"

    async def get_backend_config(_network=None):
        return FakeBackend()

    async def get_silnt_wallet(_wallet_id):
        return None

    async def get_silnt_wallets(_user, _network=None):
        return []

    async def get_wallet_addresses(_wallet_id):
        return []

    async def insert_utxos_for_wallet(_wallet_id, utxos):
        return len(utxos), sum(u.amount for u in utxos)

    async def update_balance(_wallet_id, _balance):
        return None

    async def ensure_labeled_address_row(*_args, **_kwargs):
        return None

    crud.get_backend_config = get_backend_config
    crud.get_silnt_wallet = get_silnt_wallet
    crud.get_silnt_wallets = get_silnt_wallets
    crud.get_wallet_addresses = get_wallet_addresses
    crud.insert_utxos_for_wallet = insert_utxos_for_wallet
    crud.update_balance = update_balance
    crud.ensure_labeled_address_row = ensure_labeled_address_row
    sys.modules[f"{PKG}.crud"] = crud

    helpers = types.ModuleType(f"{PKG}.helpers")
    helpers.__path__ = [str(ROOT / "helpers")]
    sys.modules[f"{PKG}.helpers"] = helpers

    dust = types.ModuleType(f"{PKG}.helpers.dust_check")

    async def evaluate_dust_for_wallet(_wallet_id):
        return 0

    dust.evaluate_dust_for_wallet = evaluate_dust_for_wallet
    sys.modules[f"{PKG}.helpers.dust_check"] = dust

    wallet_mod = types.ModuleType(f"{PKG}.helpers.wallet")
    wallet_mod.generate_labeled_sp_address = lambda **_kwargs: "sp1qtest"
    wallet_mod.get_spend_pub_from_secret = lambda *_args, **_kwargs: b""
    sys.modules[f"{PKG}.helpers.wallet"] = wallet_mod


FAKE_DB = FakeDB()

_stub_loguru()
_install_package_stubs(FAKE_DB)

_spec = importlib.util.spec_from_file_location(
    f"{PKG}.helpers.scan", ROOT / "helpers" / "scan.py"
)
scan = importlib.util.module_from_spec(_spec)
sys.modules[f"{PKG}.helpers.scan"] = scan
_spec.loader.exec_module(scan)
