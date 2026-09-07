# I1 — IoT Firmware Extractor

Binwalk-style firmware analysis: header/signature detection, Shannon entropy
analysis, string carving, and extraction — plus a deterministic lab firmware
fixture. Standard-library only.

## What the engine genuinely does

- **Signature scanner** — 16 signatures (uImage, SquashFS LE/BE, UBI/UBIFS,
  JFFS2, LZMA, ZSTD, 7z, ZIP, gzip, bzip2, XZ, ARM sled, NULL padding) at every
  offset.
- **uImage header parsing** — real `>IIIIIIII` unpack: magic, CRC, timestamp,
  packed OS/arch/type/compression, data size, data CRC, 32-byte name.
- **SquashFS superblock parsing** — LE (`hsqs`) / BE (`sqsh`) `struct` decode:
  inodes, block size, fragments, compressor.
- **Entropy analysis** — per-block Shannon entropy, high-entropy region
  detection, compressed-data heuristic.
- **Extraction** — filesystem-header carving to disk and full-gzip
  decompression (`gzip.decompress`).
- **Basic info** — size (human-readable), MD5/SHA-256, whole-file entropy.
- **String carving** — printable-ASCII extraction with "interesting" keyword
  filtering (pass/admin/root/openwrt/linux).

## Quick start

```bash
# Offline demo (builds fixtures/lab-router.bin, analyzes, writes reports/, exit 0)
python3 firmware_extractor.py

# Analyze a real firmware binary (yours / you are authorized to handle)
python3 firmware_extractor.py firmware.bin --output-dir extracted --json

# Rebuild the lab fixture
python3 firmware_extractor.py --make-fixture

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware_extractor.py [-h] [firmware] [--output-dir OUTPUT_DIR] [--json]
                              [--report-dir REPORT_DIR] [--make-fixture]
```

- `firmware` — binary to analyze; omitted → offline demo.
- `--output-dir/-o` — extraction target (default `extracted`).
- `--json` — write `reports/` JSON report.
- `--report-dir` — report directory (default `reports`).
- `--make-fixture` — regenerate the lab fixture and exit.

Exit codes: `0` success (incl. demo), `2` input error.

## Live Lab Test Plan

Prerequisites: a firmware image you own or are authorized to examine; the
`lab-router.bin` fixture stands in offline.

1. **Baseline**: `python3 firmware_extractor.py` — confirm uImage at offset 0,
   gzip at 0x87, ≥ 2 extractions, strings contain `admin`/`openwrt`.
2. **Real target**: run on a permitted image; cross-check uImage/squashfs
   parsing against `binwalk` output and embedded markers with `strings -n 6`.
3. **Entropy map**: compare `high_entropy_blocks` regions against compressed
   segments found by `binwalk -E`.
4. **Extraction**: verify the carved gzip payload decompresses and matches the
   rootfs file list (`bash bin/busybox` etc.).
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                     | Value |
|----------------------------|-------|
| Standard-library only      | Yes   |
| Third-party deps           | none  |
| Deterministic offline tests| 13    |
| Fixture                    | `fixtures/lab-router.bin` (uImage + gzip + markers) |
| Offline demo exit          | 0     |
| Report output              | `reports/*.json` (gitignored) |
| Inputs                     | firmware binary |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. See `LICENSE` for the full shield —
Authorization, CFAA / computer-crime statutes, Acceptable Use, Prohibited Use,
No Warranty, and Responsible Disclosure. Only analyze firmware you own or are
explicitly authorized to examine.

## License

MIT — full legal shield in `LICENSE`.