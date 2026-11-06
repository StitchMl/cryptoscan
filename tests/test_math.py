from cryptoscan.mathutil import crt, discrete_log_bsgs, fermat_factor, integer_nth_root, small_factor, wiener_private_exponent


def test_exact_integer_root():
    assert integer_nth_root(123456**3, 3) == (123456, True)
    assert integer_nth_root(123456**3 + 1, 3) == (123456, False)


def test_fermat_close_primes():
    assert fermat_factor(1009 * 1013)[:2] == (1009, 1013)


def test_crt_and_wiener():
    value, modulus = crt([(2, 3), (3, 5), (2, 7)])
    assert (value, modulus) == (23, 105)
    p, q, d = 1009, 1013, 5
    n = p * q
    e = pow(d, -1, (p - 1) * (q - 1))
    assert wiener_private_exponent(n, e) == (d, q, p)


def test_small_factor_finds_weak_moduli_and_skips_strong_ones():
    assert small_factor(997 * (2 ** 61 - 1)) == 997           # trial division
    assert small_factor(1000003 * 1000033) in (1000003, 1000033)  # Pollard rho (above trial bound)
    assert small_factor(2 ** 61 - 1) is None                  # prime
    assert small_factor((2 ** 607 - 1) * (2 ** 1279 - 1)) is None  # strong


def test_bounded_discrete_log():
    assert discrete_log_bsgs(2, pow(2, 123, 1019), 1019) == 123
    assert discrete_log_bsgs(2, 4, 10**13, max_steps=10) is None
