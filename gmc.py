"""
Implementation of Goldwasser Micali Cryptosystem 
(Implemented for understanding, not security: DO NOT USE)

This cryptosystem is (ignoring potential implementation leaks) semantically secure.
It is not, however, secure under an adaptive CCA attack.
"""
import os
import random
from math import gcd
from base64 import b64encode, b64decode

import sys


def exit(m=None):
    if m:
        print(m)
    sys.exit(0)


def fermat_primality(n, rounds=4):
    """
    Probabilistic primality test:
    Note: Usually (but not in general) increasing rounds lowers probability of error.
    This does not hold for Carmichael numbers (by definition).
    """
    a = 2
    for _ in range(rounds):
        while gcd(a, n) != 1:
            a += 1
        if pow(a, n - 1, n) != 1:
            return False
    return True


def simple_primality(n):
    """
    Basic primality test via trial division
    """
    if n <= 3:
        return n > 1
    if n % 2 == 0 or n % 3 == 0:
        return False

    i = 5
    while i * i < n:
        if (n % i == 0) or (n % (i + 2) == 0):
            return False
        i += 6

    return True


def find_next_prime(x, primality):
    # Coerce to 3 (mod 4)
    x += 3 - (x % 4)

    while not primality(x):
        x += 4
    return x


def is_QR(x, p, q):
    xp = x % p
    xq = x % q
    return pow(xp, (p - 1) // 2, p) == 1 and pow(xq, (q - 1) // 2, q) == 1


def bool_bit(bol):
    return 0 if bol else 1


def str_to_bin(s):
    return "".join([x[2:].zfill(7) for x in map(bin, s.encode("utf-8"))])


def chunk(l, size):
    if len(l) % size != 0:
        exit(f"LENGTH ERROR: {len(l)} : {l}")
    chunks = []
    for i in range(0, len(l), size):
        chunks.append("".join(map(str, l[i : i + size])))
    return chunks


def bin_to_str(b):
    letters = chunk(b, 7)
    return "".join([chr(int(l, 2)) for l in letters])


def ENC(pk, prg, m):
    """
    :param pk - Public Key of form (N=pq, N-1)
    :param prg - A pseudo random number generator with a randint function 
                (random.SystemRandom, for example)
    :param m - A string and the message to be encrypted

    :returns (bytes) the ciphertext c as utf-8 encoded base64 string 
    """
    assert m != ""

    N, x = pk

    bits = str_to_bin(m)
    c = []
    for u in bits:
        y2 = pow(prg.randint(1, N), 2, N)
        x_N = pow(x, (int(u)), N)
        ci = y2 * x_N % N
        c.append(ci)
    return b64encode(":".join(map(str, c)).encode("utf-8"))


def DEC(sk, c):
    p, q = sk
    bits = list(map(int, b64decode(c).decode("utf-8").split(":")))
    m = []
    for b in bits:
        m.append(bool_bit(is_QR(b, p, q)))

    return bin_to_str(m)


def KEYGEN(bitsize, primality=fermat_primality):
    p = int(random.getrandbits(bitsize - 1)) + (1 << bitsize)
    q = int(random.getrandbits(bitsize - 1)) + (1 << bitsize)
    p = find_next_prime(p, primality)
    q = find_next_prime(q, primality)
    while p == q:
        q = int(random.getrandbits(bitsize - 1)) + (1 << bitsize)
        q = find_next_prime(q, primality)

    N = p * q
    # (PK), (SK)
    return (N, N - 1), (p, q)


def fuzzy_testing(rounds):
    import string

    print("Starting testing...")
    for _ in range(rounds):
        m = "".join(random.choices(string.ascii_uppercase + string.digits, k=25))
        c = ENC(pk, prg, m)
        m_prime = DEC(sk, c)
        if m != m_prime:
            exit(f"FAILURE!\nm: {m}\npk: {pk}\nsk: {sk}")
    print("Success!")


if __name__ == "__main__":
    print("Generating keys...")
    pk, sk = KEYGEN(500)
    prg = random.SystemRandom()
    c = ENC(pk, prg, "HELLO")
    print(DEC(sk, c))
