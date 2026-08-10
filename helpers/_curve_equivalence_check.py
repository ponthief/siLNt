"""Validate curve_native (coincurve) against curve (pure Python) before swapping.

Run on a machine with coincurve + libsecp256k1 installed:

    cd helpers && python _curve_equivalence_check.py

Fuzzes the three EC operations wallet.py depends on across random vectors and
asserts byte-for-byte identical output, then benchmarks the speedup. If it
prints "OK", curve_native is a safe drop-in and you can point wallet.py's EC
imports at it. A single MISMATCH means DO NOT SWAP (it would change derived
addresses/keys → unrecoverable wallets).
"""
import secrets
import time

try:
    import curve as ref
    import curve_native as nat
except ImportError:  # run as a module: python -m helpers._curve_equivalence_check
    from . import curve as ref
    from . import curve_native as nat

N = nat.N
ROUNDS = 500


def rand_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def rand_point():
    return ref.pubkey_point_gen_from_int(rand_scalar())


def neg(P):
    # -(x, y) = (x, p - y) over the field prime.
    return (P[0], (ref.p - P[1]) % ref.p)


def check(name, a, b):
    if a != b:
        raise AssertionError(f"MISMATCH in {name}:\n  ref   = {a}\n  native= {b}")


def main() -> None:
    for _ in range(ROUNDS):
        s = rand_scalar()
        check("pubkey_gen",
              ref.pubkey_point_gen_from_int(s),
              nat.pubkey_point_gen_from_int(s))

    for _ in range(ROUNDS):
        P, Q = rand_point(), rand_point()
        check("add", ref.point_add(P, Q), nat.point_add(P, Q))
        check("double", ref.point_add(P, P), nat.point_add(P, P))
        check("inverse", ref.point_add(P, neg(P)), nat.point_add(P, neg(P)))

    for _ in range(ROUNDS):
        P, d = rand_point(), rand_scalar()
        check("mul", ref.point_mul(P, d), nat.point_mul(P, d))

    for _ in range(ROUNDS):
        P = rand_point()
        check("serP", ref.serP(P), nat.serP(P))

    print(f"OK: {ROUNDS} rounds each — pubkey_gen, add/double/inverse, mul, serP all match")

    # Benchmark the scan hot-path op (scalar * point).
    pts = [rand_point() for _ in range(200)]
    scs = [rand_scalar() for _ in range(200)]
    t0 = time.perf_counter()
    for P, d in zip(pts, scs):
        ref.point_mul(P, d)
    t1 = time.perf_counter()
    for P, d in zip(pts, scs):
        nat.point_mul(P, d)
    t2 = time.perf_counter()
    pure, native = t1 - t0, t2 - t1
    speedup = pure / native if native else float("inf")
    print(f"point_mul x200: pure-Python {pure:.3f}s | coincurve {native:.3f}s "
          f"| {speedup:.0f}x faster")


if __name__ == "__main__":
    main()
