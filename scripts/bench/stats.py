"""Percentile and summary-statistics helpers shared by the bench tools.

Kept separate from dnsproto.py (wire format) and the tools themselves so
test_helpers.py can pin down the percentile method with plain numbers,
without any networking involved.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


def percentile(samples: list[float], p: float) -> float:
    """The p-th percentile (0..100) of `samples`, nearest-rank on sorted data.

    Nearest-rank (as opposed to linear interpolation) is the method because
    it always returns a value that was actually observed -- for a latency
    tail, "the 99th percentile was 1.7 ms" should mean some real query took
    1.7 ms, not an interpolated point between two samples that never
    happened. `math.ceil` on the rank, 1-indexed, is the standard definition.
    """
    if not samples:
        raise ValueError("percentile of an empty sample set")
    if not 0 <= p <= 100:
        raise ValueError(f"percentile {p} out of range 0..100")
    ordered = sorted(samples)
    if p == 0:
        return ordered[0]
    rank = math.ceil(p / 100 * len(ordered))
    rank = min(max(rank, 1), len(ordered))
    return ordered[rank - 1]


@dataclass
class Summary:
    count: int
    min: float
    max: float
    mean: float
    p50: float
    p95: float
    p99: float

    def to_dict(self) -> dict:
        return {
            "count": self.count,
            "min": self.min,
            "max": self.max,
            "mean": self.mean,
            "p50": self.p50,
            "p95": self.p95,
            "p99": self.p99,
        }


def summarize(samples: list[float]) -> Summary:
    """Summary stats over a raw sample list, in whatever unit it was given in.

    Callers are responsible for unit conversion (seconds -> ms/us) before or
    after calling this -- it stays unit-agnostic so it does not need to know
    which of the bench tools' many timers it is summarizing.
    """
    if not samples:
        raise ValueError("summarize() of an empty sample set")
    return Summary(
        count=len(samples),
        min=min(samples),
        max=max(samples),
        mean=sum(samples) / len(samples),
        p50=percentile(samples, 50),
        p95=percentile(samples, 95),
        p99=percentile(samples, 99),
    )


def scaled(samples: list[float], factor: float) -> list[float]:
    """Multiply every sample by `factor` -- e.g. seconds -> milliseconds (1e3)."""
    return [s * factor for s in samples]
