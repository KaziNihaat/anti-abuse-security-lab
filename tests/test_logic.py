"""Small dependency-free checks for the risk-scoring thresholds.

Run with:
    python tests/test_logic.py
"""


def score(accounts_on_device, ip_usage, ip_limit=6):
    value = 0
    if accounts_on_device >= 2:
        value += 25
    if accounts_on_device >= 3:
        value += 25
    if ip_usage >= 3:
        value += 15
    if ip_usage >= ip_limit:
        value += 15
    return value


def main():
    assert score(1, 0) == 0
    assert score(2, 0) == 25
    assert score(3, 0) == 50
    assert score(3, 3) == 65
    assert score(3, 6) == 80
    print("All risk-scoring checks passed.")


if __name__ == "__main__":
    main()
