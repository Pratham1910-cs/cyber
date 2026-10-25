#!/usr/bin/env python3
"""
ssh_bruteforce_features.py
==========================
Parse a Linux auth.log, extract SSH events, and engineer per-IP, sliding-window
features for an ML-based SSH brute-force detector.

Usage
-----
    python ssh_bruteforce_features.py                       # runs on the embedded sample
    python ssh_bruteforce_features.py /var/log/auth.log     # runs on a real log
    python ssh_bruteforce_features.py auth.log --window 5 --step 1 --year 2026 --csv out.csv

Pipeline
--------
    raw text  ->  parse_auth_log()  ->  events DataFrame
              ->  build_features()  ->  feature DataFrame (one row per IP per window)
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# --------------------------------------------------------------------------- #
# 0. Sample data (25 lines) - classic syslog timestamps (no year)
# --------------------------------------------------------------------------- #
SAMPLE_AUTH_LOG = """\
Oct 25 02:14:01 srv01 sshd[2101]: Invalid user admin from 203.0.113.45 port 51022
Oct 25 02:14:01 srv01 sshd[2101]: Failed password for invalid user admin from 203.0.113.45 port 51022 ssh2
Oct 25 02:14:03 srv01 sshd[2103]: Failed password for root from 203.0.113.45 port 51030 ssh2
Oct 25 02:14:05 srv01 sshd[2105]: Invalid user test from 203.0.113.45 port 51034
Oct 25 02:14:05 srv01 sshd[2105]: Failed password for invalid user test from 203.0.113.45 port 51034 ssh2
Oct 25 02:14:07 srv01 sshd[2107]: Invalid user oracle from 203.0.113.45 port 51040
Oct 25 02:14:07 srv01 sshd[2107]: Failed password for invalid user oracle from 203.0.113.45 port 51040 ssh2
Oct 25 02:14:09 srv01 sshd[2109]: Failed password for root from 203.0.113.45 port 51046 ssh2
Oct 25 02:14:11 srv01 sshd[2111]: Invalid user ubuntu from 203.0.113.45 port 51052
Oct 25 02:14:11 srv01 sshd[2111]: Failed password for invalid user ubuntu from 203.0.113.45 port 51052 ssh2
Oct 25 02:14:13 srv01 sshd[2113]: Failed password for root from 203.0.113.45 port 51058 ssh2
Oct 25 02:14:15 srv01 sshd[2115]: Invalid user postgres from 203.0.113.45 port 51064
Oct 25 02:14:15 srv01 sshd[2115]: Failed password for invalid user postgres from 203.0.113.45 port 51064 ssh2
Oct 25 03:31:10 srv01 sshd[2201]: Failed password for root from 192.0.2.99 port 60001 ssh2
Oct 25 03:31:40 srv01 sshd[2203]: Failed password for root from 192.0.2.99 port 60013 ssh2
Oct 25 03:32:10 srv01 sshd[2205]: Failed password for root from 192.0.2.99 port 60027 ssh2
Oct 25 09:02:11 srv01 CRON[2290]: pam_unix(cron:session): session opened for user root by (uid=0)
Oct 25 09:15:42 srv01 sshd[2301]: Failed password for alice from 198.51.100.7 port 40112 ssh2
Oct 25 09:15:49 srv01 sshd[2303]: Accepted password for alice from 198.51.100.7 port 40118 ssh2
Oct 25 09:15:49 srv01 sshd[2303]: pam_unix(sshd:session): session opened for user alice by (uid=0)
Oct 25 13:40:05 srv01 sshd[2410]: Accepted publickey for bob from 198.51.100.23 port 52111 ssh2: RSA SHA256:abc123
Oct 25 17:22:48 srv01 sshd[2502]: Accepted password for bob from 198.51.100.23 port 52390 ssh2
Oct 25 23:58:20 srv01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
Oct 25 23:59:02 srv01 sshd[2601]: Invalid user guest from 198.18.0.5 port 33210
Oct 25 23:59:02 srv01 sshd[2601]: Failed password for invalid user guest from 198.18.0.5 port 33210 ssh2
"""

# --------------------------------------------------------------------------- #
# 1. Regex definitions
# --------------------------------------------------------------------------- #
# Header: supports classic syslog ("Oct 25 02:14:01") and ISO-8601
# ("2026-10-25T02:14:01.123456+00:00", default on newer Ubuntu/Debian).
LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)

_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
_PORT = r"(?P<port>\d+)"

# Order matters: first match wins. Each tuple is (status_label, compiled regex).
MESSAGE_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "Failed password",
        re.compile(
            rf"^Failed password for (?:invalid user )?(?P<user>\S+) from {_IP} port {_PORT}"
        ),
    ),
    (
        "Accepted password",
        re.compile(
            rf"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from {_IP} port {_PORT}"
        ),
    ),
    (
        "Invalid user",
        re.compile(rf"^Invalid user (?P<user>\S+) from {_IP} port {_PORT}"),
    ),
]

EVENT_COLUMNS = ["timestamp", "source_ip", "port", "username", "auth_status"]

FEATURE_COLUMNS = [
    "failed_attempts_count",
    "failure_to_success_ratio",
    "unique_usernames_attempted",
    "request_rate_per_min",
    "off_peak_hour_flag",
    "root_attempt_flag",
]


# --------------------------------------------------------------------------- #
# 2. Parsing
# --------------------------------------------------------------------------- #
def _parse_line(line: str) -> dict | None:
    """Return one event dict for an SSH auth line, or None if irrelevant."""
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    msg = m.group("msg")
    for status, pattern in MESSAGE_PATTERNS:
        pm = pattern.match(msg)
        if pm:
            return {
                "ts_raw": m.group("ts"),
                "source_ip": pm.group("ip"),
                "port": int(pm.group("port")),
                "username": pm.group("user"),
                "auth_status": status,
            }
    return None


def _resolve_timestamps(ts_raw: pd.Series, default_year: int) -> pd.Series:
    """
    Convert raw timestamps to datetime64.

    Classic syslog stamps carry no year, so `default_year` is applied to the
    first line and incremented whenever the month wraps backwards (Dec -> Jan)
    while reading the file in order.
    """
    iso_mask = ts_raw.str.match(r"^\d{4}-")
    out = pd.Series(pd.NaT, index=ts_raw.index, dtype="datetime64[ns]")

    if iso_mask.any():
        parsed = pd.to_datetime(ts_raw[iso_mask], utc=True, errors="coerce")
        out[iso_mask] = parsed.dt.tz_localize(None)

    if (~iso_mask).any():
        classic = ts_raw[~iso_mask].str.replace(r"\s+", " ", regex=True)
        month = pd.to_datetime(classic.str.split(" ").str[0], format="%b").dt.month
        year = default_year + (month.diff().fillna(0) < 0).cumsum()
        out[~iso_mask] = pd.to_datetime(
            year.astype(str) + " " + classic, format="%Y %b %d %H:%M:%S", errors="coerce"
        )
    return out


def parse_auth_log(text: str, default_year: int | None = None) -> pd.DataFrame:
    """Parse raw auth.log text into an events DataFrame (one row per SSH event)."""
    default_year = default_year or datetime.now().year
    records = [r for r in map(_parse_line, text.splitlines()) if r]
    if not records:
        return pd.DataFrame(columns=EVENT_COLUMNS)

    df = pd.DataFrame(records)
    df["timestamp"] = _resolve_timestamps(df["ts_raw"], default_year)
    df = (
        df.dropna(subset=["timestamp"])
        .sort_values("timestamp", kind="stable")
        .reset_index(drop=True)
    )
    return df[EVENT_COLUMNS]


def load_auth_log(path: str | Path, default_year: int | None = None) -> pd.DataFrame:
    """Convenience wrapper: read a log file from disk and parse it."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_auth_log(text, default_year)


# --------------------------------------------------------------------------- #
# 3. Feature engineering
# --------------------------------------------------------------------------- #
def _window_features(w: pd.DataFrame) -> dict:
    """Compute the ML features for the events of one IP inside one window."""
    failed = int((w["auth_status"] == "Failed password").sum())
    success = int((w["auth_status"] == "Accepted password").sum())
    attempts = failed + success  # one per real authentication outcome

    # Rate: attempts per minute over the observed span, floored at 1 minute so
    # a single instantaneous burst does not produce an infinite/huge rate.
    span_min = (w["timestamp"].max() - w["timestamp"].min()).total_seconds() / 60.0

    return {
        "failed_attempts_count": failed,
        # Laplace-smoothed (+1) so IPs with zero successes stay finite and
        # a pure-failure IP scores higher the more it fails.
        "failure_to_success_ratio": failed / (success + 1),
        "unique_usernames_attempted": int(w["username"].nunique()),
        "request_rate_per_min": attempts / max(span_min, 1.0),
        "off_peak_hour_flag": int((w["timestamp"].dt.hour < 5).any()),
        "root_attempt_flag": int((w["username"] == "root").any()),
        # Extras kept for context / explainability (not in FEATURE_COLUMNS).
        "successful_logins": success,
        "invalid_user_count": int((w["auth_status"] == "Invalid user").sum()),
        "total_events": int(len(w)),
    }


def build_features(
    events: pd.DataFrame,
    window_minutes: float = 5,
    step_minutes: float | None = None,
) -> pd.DataFrame:
    """
    Aggregate events per source IP over a sliding (hopping) time window.

    window_minutes : length of each window.
    step_minutes   : hop between window starts. None -> equals the window
                     (non-overlapping). Use a smaller step (e.g. 1) for
                     overlapping, truly "sliding" windows.

    Returns one row per (IP, window) that contains at least one event.
    """
    meta_cols = ["source_ip", "window_start", "window_end"]
    extra_cols = ["successful_logins", "invalid_user_count", "total_events"]
    if events.empty:
        return pd.DataFrame(columns=meta_cols + FEATURE_COLUMNS + extra_cols)

    window = pd.Timedelta(minutes=window_minutes)
    step = pd.Timedelta(minutes=step_minutes) if step_minutes else window

    rows: list[dict] = []
    for ip, g in events.groupby("source_ip", sort=False):
        g = g.sort_values("timestamp").reset_index(drop=True)
        ts = g["timestamp"].to_numpy()
        start = g["timestamp"].min().floor("min")
        last = g["timestamp"].max()
        prev_span = None

        while start <= last:
            lo = np.searchsorted(ts, np.datetime64(start), side="left")
            hi = np.searchsorted(ts, np.datetime64(start + window), side="left")
            # Skip empty windows and windows identical to the previous one
            # (avoids duplicate rows when overlapping windows hold the same events).
            if hi > lo and (lo, hi) != prev_span:
                rows.append(
                    {
                        "source_ip": ip,
                        "window_start": start,
                        "window_end": start + window,
                        **_window_features(g.iloc[lo:hi]),
                    }
                )
                prev_span = (lo, hi)
            start += step

    df = pd.DataFrame(rows, columns=meta_cols + FEATURE_COLUMNS + extra_cols)
    df["failure_to_success_ratio"] = df["failure_to_success_ratio"].round(4)
    df["request_rate_per_min"] = df["request_rate_per_min"].round(4)
    return df.sort_values(["window_start", "source_ip"]).reset_index(drop=True)


def get_ml_matrix(features: pd.DataFrame) -> pd.DataFrame:
    """Return only the numeric model inputs (X), index-aligned with `features`."""
    return features[FEATURE_COLUMNS].astype(float)


# --------------------------------------------------------------------------- #
# 4. CLI / demo
# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="SSH brute-force feature extractor")
    ap.add_argument("logfile", nargs="?", help="path to auth.log (default: embedded sample)")
    ap.add_argument("--window", type=float, default=5, help="window length in minutes")
    ap.add_argument("--step", type=float, default=None, help="hop in minutes (default = window)")
    ap.add_argument("--year", type=int, default=None, help="year for syslog stamps lacking one")
    ap.add_argument("--csv", help="optional path to save the feature table")
    args = ap.parse_args()

    if args.logfile:
        events = load_auth_log(args.logfile, args.year)
    else:
        events = parse_auth_log(SAMPLE_AUTH_LOG, args.year or 2026)

    features = build_features(events, args.window, args.step)

    pd.set_option("display.width", 220)
    pd.set_option("display.max_columns", None)
    print(f"Parsed {len(events)} SSH events from {events['source_ip'].nunique()} IPs\n")
    print("=== Events (head) ===")
    print(events.head(8).to_string(index=False))
    print("\n=== ML feature table ===")
    print(features.to_string(index=False))

    if args.csv:
        features.to_csv(args.csv, index=False)
        print(f"\nSaved to {args.csv}")


if __name__ == "__main__":
    main()
