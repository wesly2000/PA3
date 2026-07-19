"""
Infer proxy protocol per pcap via n-gram voting and write inferred_protocol to database.csv.
"""

import argparse
import json
import logging
import os
from collections import Counter
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd

from pa3.tools.extractor import (
    array_path,
    identify_pcap_protocol_with_fallback,
    pcap_protocol_votes,
    pcap_protocol_votes_heuristic,
    train_ngram_protocol_models,
)

logger = logging.getLogger(__name__)

PROTOCOLS = ["vmess", "shadowsocks", "trojan"]
STRIP_INDICES = {
    "vmess": [3, 4],
    "shadowsocks": [4, 5],
    "trojan": [3, 4],
}
VOCAB_SIZES = {"vmess": 90, "shadowsocks": 7, "trojan": 30}
TRAIN_SAMPLES = {"vmess": 400, "shadowsocks": 40, "trojan": 4}
UPPER_BOUND = 1500
LOWER_BOUND = -1500
WINDOW_SIZE = 2
MIN_LEN = 15

def _parse_protocol_map(raw: str, name: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"Invalid JSON for {name}: {exc}") from exc
    if not isinstance(data, dict):
        raise argparse.ArgumentTypeError(f"{name} must be a JSON object")
    return data


def _classify_pcap_vote(
    paths,
    ngram_dbs,
    binners,
    window_size,
    strip_indices,
    min_len,
) -> str:
    """Return 'unknown', 'tie', or 'unique' for logging."""
    vote = pcap_protocol_votes(
        paths,
        ngram_dbs,
        binners,
        PROTOCOLS,
        window_size,
        strip_indices=strip_indices,
        min_len=min_len,
    )
    if max(vote.values()) == 0:
        vote = pcap_protocol_votes_heuristic(
            paths,
            ngram_dbs,
            binners,
            PROTOCOLS,
            window_size,
            strip_indices=strip_indices,
            min_len=min_len,
        )
    if max(vote.values()) == 0:
        return "unknown"
    top = max(vote.values())
    if len([p for p, v in vote.items() if v == top]) > 1:
        return "tie"
    return "unique"


def label_database(
    root_dir: Path,
    ngram_train_dir: Path,
    *,
    seed: int,
    lower_bound: int,
    upper_bound: int,
    window_size: int,
    min_len: int,
    strip_indices: dict,
    vocab_sizes: dict,
    train_samples: dict,
) -> Tuple[pd.DataFrame, Path]:
    db_path = root_dir / "database_with_infer.csv"
    array_dir = root_dir / "arrays"
    if not db_path.exists():
        raise FileNotFoundError(f"Database not found: {db_path}")
    if not array_dir.is_dir():
        raise FileNotFoundError(f"Array directory not found: {array_dir}")

    db = pd.read_csv(db_path)
    rng = np.random.default_rng(seed)

    logger.info("Training n-gram models from %s", ngram_train_dir)
    ngram_dbs, binners = train_ngram_protocol_models(
        ngram_train_dir,
        PROTOCOLS,
        strip_indices,
        window_size,
        lower_bound,
        upper_bound,
        vocab_sizes,
        train_samples,
    )

    inferred_by_pcap = {}
    n_unknown = 0
    n_tie = 0
    n_groups = 0

    for (host, pcap_id, capture_protocol), group in db.groupby(
        ["host", "id", "protocol"], sort=False
    ):
        n_groups += 1
        if capture_protocol == "normal":
            inferred_by_pcap[(host, pcap_id, capture_protocol)] = "normal"
            continue
        paths = group.apply(
            lambda row: array_dir
            / array_path(
                row["host"],
                row["id"],
                row["transport"],
                row["stream"],
                row["protocol"],
            ),
            axis=1,
        )

        inferred_by_pcap[(host, pcap_id, capture_protocol)] = (
            identify_pcap_protocol_with_fallback(
                paths,
                ngram_dbs,
                binners,
                PROTOCOLS,
                window_size,
                strip_indices=strip_indices,
                min_len=min_len,
                rng=rng,
            )
        )

    db["inferred_protocol"] = db.apply(
        lambda row: inferred_by_pcap[(row["host"], row["id"], row["protocol"])],
        axis=1,
    )

    logger.info("Pcap groups processed: %d", n_groups)
    logger.info("Unknown fallbacks (random label): %d", n_unknown)
    logger.info("Tie resolutions (random among tied): %d", n_tie)
    logger.info("Inferred protocol counts:\n%s", Counter(db["inferred_protocol"]))
    return db, db_path


def write_database_in_place(db: pd.DataFrame, db_path: Path) -> None:
    tmp_path = db_path.with_suffix(db_path.suffix + ".tmp")
    db.to_csv(tmp_path, index=False)
    os.replace(tmp_path, db_path)
    logger.info("Wrote %s (%d rows)", db_path, len(db))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Infer per-flow inferred_protocol from n-gram pcap voting."
    )
    parser.add_argument(
        "--root_dir",
        required=True,
        type=Path,
        help="Directory containing database.csv and arrays/",
    )
    parser.add_argument(
        "--ngram_train_dir",
        required=True,
        type=Path,
        help="Directory with per-protocol training flow pickles ({protocol}.pkl)",
    )
    parser.add_argument("--seed", type=int, default=42, help="RNG seed")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


    db, db_path = label_database(
        args.root_dir,
        args.ngram_train_dir,
        seed=args.seed,
        lower_bound=LOWER_BOUND,
        upper_bound=UPPER_BOUND,
        window_size=WINDOW_SIZE,
        min_len=MIN_LEN,
        strip_indices=STRIP_INDICES,
        vocab_sizes=VOCAB_SIZES,
        train_samples=TRAIN_SAMPLES,
    )
    write_database_in_place(db, db_path)


if __name__ == "__main__":
    main()
