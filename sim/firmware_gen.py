#!/usr/bin/env python3
"""
Firmware Corpus Generator for AnamolyzeAI

This module generates a corpus of simulated firmware images for BMC security
research. It creates both clean and tampered firmware blobs, supporting
cryptographic hash validation and ML-based anomaly detection.

By providing a diverse set of firmware images, including adversarially modified
samples, this tool enables robust evaluation of firmware integrity verification
pipelines and aligns with Axiado's "AI-driven, hardware-anchored" security vision.

Author: AnamolyzeAI Team
License: MIT
"""

import argparse
import gzip
import hashlib
import json
import logging
import os
import random
import sys
from pathlib import Path
from typing import Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

FIRMWARE_SIZE = 16 * 1024 * 1024  # 16 MiB
CLEAN_PREFIX = "fw_clean_"
TAMPERED_PREFIX = "fw_tampered_"


def random_bytes(size: int, seed: int = None) -> bytes:
    """Generate random bytes with optional seed for reproducibility."""
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(size))


def write_blob(path: Path, data: bytes) -> None:
    """Write binary data to a file."""
    with open(path, "wb") as f:
        f.write(data)


def sha256sum(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def tamper_pad_injection(data: bytes) -> bytes:
    """Inject a pad of 0xFF bytes at a random offset."""
    pad_len = 1024 * 64  # 64 KiB
    offset = random.randint(0, len(data) - pad_len)
    return data[:offset] + b"\xFF" * pad_len + data[offset + pad_len:]


def tamper_gzip_bomb(data: bytes) -> bytes:
    """Compress a small block and pad to firmware size (gzip bomb)."""
    small_block = b"A" * 1024  # 1 KiB
    gzipped = gzip.compress(small_block)
    # Pad to firmware size
    return (gzipped * (FIRMWARE_SIZE // len(gzipped) + 1))[:FIRMWARE_SIZE]


def tamper_byte_flip(data: bytes) -> bytes:
    """Flip random bytes throughout the firmware image."""
    data = bytearray(data)
    n_flips = 1000
    for _ in range(n_flips):
        idx = random.randint(0, len(data) - 1)
        data[idx] ^= 0xFF
    return bytes(data)


def generate_firmware_corpus(
    out_dir: Path,
    n_clean: int = 20,
    n_tampered: int = 5,
    seed: int = 42
) -> Dict[str, str]:
    """
    Generate clean and tampered firmware blobs and return filename to SHA-256 map.
    """
    logger.info(f"Generating {n_clean} clean and {n_tampered} tampered firmware blobs in {out_dir}")
    rng = random.Random(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    hashes = {}
    # Clean blobs
    for i in range(n_clean):
        fname = f"{CLEAN_PREFIX}{i:02d}.bin"
        path = out_dir / fname
        data = random_bytes(FIRMWARE_SIZE, seed=rng.randint(0, 1 << 30))
        write_blob(path, data)
        hashes[fname] = sha256sum(path)
    # Tampered blobs
    tamper_funcs = [tamper_pad_injection, tamper_gzip_bomb, tamper_byte_flip]
    for i in range(n_tampered):
        fname = f"{TAMPERED_PREFIX}{i:02d}.bin"
        path = out_dir / fname
        # Start from a clean blob
        base_data = random_bytes(FIRMWARE_SIZE, seed=rng.randint(0, 1 << 30))
        tamper_func = rng.choice(tamper_funcs)
        data = tamper_func(base_data)
        write_blob(path, data)
        hashes[fname] = sha256sum(path)
        logger.info(f"Tampered blob {fname} generated using {tamper_func.__name__}")
    return hashes


def main():
    """Main entry point for firmware corpus generator CLI."""
    parser = argparse.ArgumentParser(
        description="Firmware Corpus Generator for AnamolyzeAI Security Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate default corpus in ./firmware/
  python firmware_gen.py --out ./firmware

  # Generate 10 clean and 2 tampered blobs with seed 123
  python firmware_gen.py --out ./firmware --clean 10 --tampered 2 --seed 123
        """
    )
    parser.add_argument('--out', type=str, default="./firmware", help='Output directory for blobs')
    parser.add_argument('--clean', type=int, default=20, help='Number of clean firmware blobs (default: 20)')
    parser.add_argument('--tampered', type=int, default=5, help='Number of tampered blobs (default: 5)')
    parser.add_argument('--seed', type=int, default=42, help='Random seed for reproducibility')
    args = parser.parse_args()
    out_dir = Path(args.out)
    hashes = generate_firmware_corpus(
        out_dir=out_dir,
        n_clean=args.clean,
        n_tampered=args.tampered,
        seed=args.seed
    )
    # Write hashes.json
    hashes_path = out_dir / "hashes.json"
    with open(hashes_path, "w") as f:
        json.dump(hashes, f, indent=2)
    logger.info(f"Firmware corpus and hashes.json written to {out_dir}")

if __name__ == "__main__":
    main() 