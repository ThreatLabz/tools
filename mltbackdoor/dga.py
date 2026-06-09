#!/usr/bin/env python3
import argparse
import datetime


def dga_domain(date) -> str:
    LCG_MULT  = 0x0019660D
    LCG_INC   = 0x3C6EF35F
    MASK32    = (1 << 32) - 1
    ALPHABET_SIZE = 36
    LETTER_COUNT  = 26
    DOMAIN_LEN    = 11
    TLD           = ".com"

    seed = date.year * 10000 + date.month * 100 + date.day
    state = (LCG_MULT * seed + LCG_INC) & MASK32

    label = []
    for _ in range(DOMAIN_LEN):
        upper16 = state >> 16

        idx = upper16 % ALPHABET_SIZE
        if idx < LETTER_COUNT:
            label.append(chr(ord('a') + idx))
        else:
            label.append(chr(ord('0') + idx - LETTER_COUNT))

        state = (LCG_MULT * state + LCG_INC) & MASK32

    return "".join(label) + TLD


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate MLTBackdoor DGA domains for N consecutive days."
    )
    ap.add_argument(
        "date",
        nargs="?",
        default=None,
        help="start date as YYYY-MM-DD (default: today)",
    )
    ap.add_argument(
        "-n", "--days",
        type=int,
        default=30,
        help="number of days to emit (default: 30)",
    )
    args = ap.parse_args()

    start = (
        datetime.date.today()
        if args.date is None
        else datetime.date.fromisoformat(args.date)
    )

    for i in range(args.days):
        d = start + datetime.timedelta(days=i)
        print(f"{d.isoformat()}  {dga_domain(d)}")


if __name__ == "__main__":
    main()
