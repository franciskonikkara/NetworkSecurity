#!/usr/bin/env python3
"""
rsa_breaker.py
Author: @samrudhmr
Credits: @RsaCtfTool
--------------
Lightweight RSA attack tool for the Network Security homework assignment.
Covers exactly three attacks:
  - Key 1: Small prime factorization  (trial division / Pollard rho)
  - Key 2: Shared prime GCD attack    (two public keys)

Usage:
  python rsa_breaker.py --mode key1 --publickey key1_public.pem --cipherfile key1_cipher.bin
  python rsa_breaker.py --mode key2 --publickey key2a_public.pem key2b_public.pem --cipherfile key2a_cipher.bin key2b_cipher.bin

Requirements:
  pip install pycryptodome sympy
"""

import argparse
import math
import sys
import time
import random
import requests
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Use gmpy2 if available — dramatically faster modular arithmetic
try:
    import gmpy2
    HAVE_GMPY2 = True
except ImportError:
    HAVE_GMPY2 = False


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def banner():
    print("""
╔═════════════════════════════════════════════════╗
║      RSA Breaker — ENPM693 Network Security     ║
║         Keys: small-prime · shared-gcd          ║
║            Inspired by @RsaCtfTool              ║
╚═════════════════════════════════════════════════╝
""")

    if HAVE_GMPY2:
        print("  [✓] gmpy2 available — fast arithmetic enabled\n")
    else:
        print("  [!] gmpy2 not found — install with: sudo apt install python3-gmpy2")
        print("      Factorization will be slower without it.\n")

def section(title):
    print(f"\n{'─'*54}")
    print(f"  {title}")
    print(f"{'─'*54}")

def ok(msg):   print(f"  [+] {msg}")
def info(msg): print(f"  [i] {msg}")
def warn(msg): print(f"  [!] {msg}")
def fail(msg): print(f"  [✗] {msg}"); sys.exit(1)


# ─────────────────────────────────────────────
# KEY / CIPHER LOADING
# ─────────────────────────────────────────────

def load_pubkey(path):
    try:
        with open(path, "rb") as f:
            key = RSA.import_key(f.read())
        info(f"Loaded: {path}  (n={key.n.bit_length()} bits, e={key.e})")
        return key
    except Exception as ex:
        fail(f"Could not load public key '{path}': {ex}")

def load_cipher(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        c = bytes_to_long(raw)
        info(f"Loaded: {path}  ({len(raw)} bytes)")
        return c
    except Exception as ex:
        fail(f"Could not load cipher file '{path}': {ex}")

def decode_plaintext(m_int):
    try:
        raw = long_to_bytes(m_int)
        return raw.lstrip(b'\x00').decode('utf-8', errors='replace')
    except Exception:
        return repr(long_to_bytes(m_int))


# ─────────────────────────────────────────────
# FACTORIZATION — BRENT'S IMPROVED POLLARD RHO
# ─────────────────────────────────────────────

def mulmod(a, b, m):
    """Modular multiplication — uses gmpy2 if available."""
    if HAVE_GMPY2:
        return int(gmpy2.mpz(a) * gmpy2.mpz(b) % gmpy2.mpz(m))
    return (a * b) % m

def brent_rho(n, max_iter=2_000_000):
    """
    Brent's improvement of Pollard's rho.
    Reliably cracks 512-bit n with random 256-bit primes in seconds
    when gmpy2 is installed. Multiple restarts with random seeds
    are essential — each call uses a fresh random state.
    """
    if n % 2 == 0:
        return 2

    y = random.randint(1, n - 1)
    c = random.randint(1, n - 1)
    m = random.randint(1, n - 1)

    g = 1; q = 1; r = 1
    ys = None; x = None

    while g == 1:
        x = y
        for _ in range(r):
            y = mulmod(y, y, n)
            y = (y + c) % n

        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = mulmod(y, y, n)
                y = (y + c) % n
                q = mulmod(q, abs(x - y), n)
            g = math.gcd(q, n)
            k += m
        r *= 2

        if r > max_iter:
            break

    if g == n:
        while True:
            ys = mulmod(ys, ys, n)
            ys = (ys + c) % n
            g  = math.gcd(abs(x - ys), n)
            if g > 1:
                break

    return g if g != n else None


def fermat_factor(n, max_iter=1_000_000):
    """
    Fermat's method — instant when p and q are close.
    Always worth a quick attempt before heavier algorithms.
    """
    if HAVE_GMPY2:
        a = int(gmpy2.isqrt(gmpy2.mpz(n))) + 1
    else:
        a = math.isqrt(n) + 1

    b2 = a * a - n
    for _ in range(max_iter):
        if HAVE_GMPY2:
            root, exact = gmpy2.isqrt_rem(gmpy2.mpz(b2))
            is_square = (exact == 0)
        else:
            root = math.isqrt(b2)
            is_square = (root * root == b2)

        if is_square:
            b = int(root)
            p, q = a - b, a + b
            if p > 1 and q > 1 and p * q == n:
                return int(p), int(q)
        a  += 1
        b2  = a * a - n

    return None


def factordb_lookup(n):
    """
    Query factordb.com — free crowdsourced factorization database.
    Many 512-bit numbers are already there. No API key needed.
    """
    info("Querying factordb.com (requires internet)...")
    try:
        r    = requests.get(f"http://factordb.com/api?query={n}", timeout=15)
        data = r.json()
        status  = data.get("status", "")
        factors = data.get("factors", [])

        if status in ("FF", "P"):
            primes = []
            for f, exp in factors:
                primes.extend([int(f)] * int(exp))
            if len(primes) >= 2:
                p = primes[0]
                q = n // p
                ok("factordb.com returned factors!")
                return p, q
        else:
            info(f"factordb status '{status}' — not in database yet.")
    except Exception as ex:
        warn(f"factordb query failed: {ex}")
    return None


def factorize(n):
    """
    Factorization pipeline — ordered fastest to slowest:
      1. Fermat          (instant if p ≈ q)
      2. Brent-Pollard   (10 attempts with random seeds — seconds with gmpy2)
      3. factordb.com    (network lookup — hits if n was generated before)
    """
    info(f"Factoring n ({n.bit_length()} bits)...")
    t0 = time.time()

    # 1 — Fermat
    info("  [1/3] Fermat factorization...")
    result = fermat_factor(n)
    if result:
        ok(f"Factored via Fermat in {time.time()-t0:.2f}s")
        return result

    # 2 — Brent-Pollard rho (10 independent random attempts)
    info("  [2/3] Brent-Pollard rho (10 attempts)...")
    for attempt in range(1, 11):
        sys.stdout.write(f"\r  [2/3] attempt {attempt}/10...  ")
        sys.stdout.flush()
        p = brent_rho(n)
        if p and 1 < p < n:
            q = n // p
            if p * q == n:
                print()
                ok(f"Factored via Brent-Pollard rho in {time.time()-t0:.2f}s (attempt {attempt})")
                return int(p), int(q)
    print()

    # 3 — factordb.com
    info("  [3/3] factordb.com lookup...")
    result = factordb_lookup(n)
    if result:
        ok(f"Factored via factordb in {time.time()-t0:.2f}s")
        return result

    raise RuntimeError(
        f"\n  Could not factor n ({n.bit_length()} bits).\n\n"
        "  Most likely cause: the generation script used getPrime(256) which\n"
        "  produces primes that are too large for fast pure-Python factorization.\n\n"
        "  Fix options (pick one):\n"
        "  A) Regenerate the key with smaller primes — edit generate_key1.py:\n"
        "       getPrime(256)  →  getPrime(128)\n"
        "     This gives a 256-bit n which Brent-Pollard cracks in < 1 second.\n\n"
        "  B) Install gmpy2 for faster arithmetic (if not already installed):\n"
        "       sudo apt install python3-gmpy2\n"
        "     Then run this script again.\n\n"
        "  C) Submit n to factordb.com manually and wait:\n"
        f"       http://factordb.com/index.php?query={n}\n"
    )


# ─────────────────────────────────────────────
# ATTACK 1 — SMALL PRIME FACTORIZATION
# ─────────────────────────────────────────────

def attack_key1(pubkey_path, cipher_path):
    section("KEY 1 ATTACK — Small Prime Factorization")

    key   = load_pubkey(pubkey_path)
    c     = load_cipher(cipher_path)
    n, e  = key.n, key.e
    
    # Factorize
    try:
        p, q = factorize(n)
    except RuntimeError as ex:
        fail(str(ex))

    ok(f"p = {p}")
    ok(f"q = {q}")
    assert p * q == n, "Sanity check failed: p*q != n"
    
    # Recover private key
    phi = (p - 1) * (q - 1)
    d   = pow(e, -1, phi)
    ok(f"Private key d recovered ({d.bit_length()} bits)")
    
    # Decrypt
    plaintext = decode_plaintext(pow(c, d, n))

    section("RESULT")
    ok(f"Plaintext: {plaintext}")
    print()
    _show_key_info(n, e, d, p, q)


# ─────────────────────────────────────────────
# ATTACK 2 — SHARED PRIME GCD
# ─────────────────────────────────────────────

def attack_key2(pubkey_paths, cipher_paths):
    section("KEY 2 ATTACK — Shared Prime Factor (GCD)")

    if len(pubkey_paths) != 2 or len(cipher_paths) != 2:
        fail("Key 2 requires exactly 2 public keys and 2 cipher files.")

    key_a = load_pubkey(pubkey_paths[0])
    key_b = load_pubkey(pubkey_paths[1])
    c_a   = load_cipher(cipher_paths[0])
    c_b   = load_cipher(cipher_paths[1])

    n_a, e = key_a.n, key_a.e
    n_b    = key_b.n

    # The core attack — one line
    info("Computing gcd(n_a, n_b)...")
    t0 = time.time()
    p = math.gcd(n_a, n_b)
    ok(f"gcd computed in {time.time()-t0:.4f}s")

    if p == 1:
        fail("gcd(n_a, n_b) = 1 — keys do not share a prime factor. Wrong keys?")
    if p == n_a or p == n_b:
        fail("gcd returned one of the moduli — something is wrong with the keys.")

    ok(f"Shared prime p found! ({p.bit_length()} bits)")
    ok(f"p = {p}")

    q_a = n_a // p
    q_b = n_b // p
    ok(f"q_a = {q_a}")
    ok(f"q_b = {q_b}")

    # Recover both private keys
    d_a = pow(e, -1, (p - 1) * (q_a - 1))
    d_b = pow(e, -1, (p - 1) * (q_b - 1))
    ok("Both private keys recovered.")

    # Decrypt both ciphertexts
    m_a = decode_plaintext(pow(c_a, d_a, n_a))
    m_b = decode_plaintext(pow(c_b, d_b, n_b))

    section("RESULT")
    ok(f"Plaintext A: {m_a}")
    ok(f"Plaintext B: {m_b}")
    print()
    info(f"Server A — n_a: {n_a.bit_length()} bits  d_a: {d_a.bit_length()} bits")
    info(f"Server B — n_b: {n_b.bit_length()} bits  d_b: {d_b.bit_length()} bits")
    info(f"Shared p : {p.bit_length()} bits")

# ─────────────────────────────────────────────
# SHARED UTILITY
# ─────────────────────────────────────────────

def _show_key_info(n, e, d, p, q):
    info(f"n : {n.bit_length()} bits")
    info(f"e : {e}")
    info(f"d : {d.bit_length()} bits")
    info(f"p : {p.bit_length()} bits")
    info(f"q : {q.bit_length()} bits")
    

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Lightweight RSA breaker for the Network Security homework.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python rsa_breaker.py --mode key1 --publickey key1_public.pem --cipherfile key1_cipher.bin
  python rsa_breaker.py --mode key2 --publickey key2a_public.pem key2b_public.pem --cipherfile key2a_cipher.bin key2b_cipher.bin
        """
    )
    p.add_argument(
        "--mode", required=True, choices=["key1", "key2", "key3"],
        help="Which attack to run:\n  key1 = small primes\n  key2 = shared GCD\n  key3 = e=1"
    )
    p.add_argument(
        "--publickey", required=True, nargs="+", metavar="PEM",
        help="Path(s) to PEM public key file(s). Key2 requires two."
    )
    p.add_argument(
        "--cipherfile", required=True, nargs="+", metavar="BIN",
        help="Path(s) to raw ciphertext file(s). Key2 requires two."
    )
    return p.parse_args()


def main():
    banner()
    args = parse_args()

    if args.mode == "key1":
        if len(args.publickey) != 1 or len(args.cipherfile) != 1:
            fail("key1 mode requires exactly 1 public key and 1 cipher file.")
        attack_key1(args.publickey[0], args.cipherfile[0])

    elif args.mode == "key2":
        attack_key2(args.publickey, args.cipherfile)

    print("\n  Done.\n")


if __name__ == "__main__":
    main()
