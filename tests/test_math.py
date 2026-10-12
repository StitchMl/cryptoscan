from cryptoscan.mathutil import fermat_factor, integer_nth_root


def test_exact_integer_root():
    assert integer_nth_root(123456**3, 3) == (123456, True)
    assert integer_nth_root(123456**3 + 1, 3) == (123456, False)


def test_fermat_close_primes():
    assert fermat_factor(1009 * 1013)[:2] == (1009, 1013)
