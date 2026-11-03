"""Shared retry delay and HTTP status classification."""

import random


def delay_seconds(attempt, rng=None):
    """attempt is 1 for the first retry. Base 1s, doubles, caps at 30s, plus up to 25% jitter."""
    if attempt < 1:
        raise ValueError("attempt starts at 1")
    base = min(30.0, float(2 ** (attempt - 1)))
    roll = random.random() if rng is None else rng()
    return base + (base * 0.25 * roll)


def http_disposition(status):
    if 200 <= status <= 299:
        return "ok"
    if status in (408, 429) or 500 <= status <= 599:
        return "retry"
    return "permanent"
