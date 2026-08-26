#!/usr/bin/env python3
"""
I1 - IoT Firmware Extractor
Binwalk-style firmware parsing, filesystem extraction, header detection, entropy analysis.
"""

import os
import sys
import struct
import hashlib
import zlib
import lzma
import math
from collections import namedtuple
from typing import List, Tuple, Optional

# --- Signature definitions ---
FirmwareHeader = namedtuple("FirmwareHeader", ["offset", "magic", "description", "size"])
FilesystemEntry = namedtuple("FilesystemEntry", ["path", "size", "offset", "file_type"])
EntropyBlock = namedtuple("EntropyBlock", ["offset", "length", "entropy"])

KNOWN_SIGNATURES = {
    b"\x27\x05\x19\x56": ("uImage", "U-Boot image header"),
    b"hsqs": ("SquashFS", "SquashFS filesystem (little-endian)"),
    b"sqsh": ("SquashFS", "SquashFS filesystem (big-endian)"),
    b"UBI#": ("UBI", "UBI volume header"),
    b"UBIFS": ("UBIFS", "UBIFS filesystem superblock"),
    b"jffs2": ("JFFS2", "JFFS2 filesystem"),
    b"\x85\x19\x01\x01": ("LZMA", "LZMA compressed data"),
    b"\x28\xb5\x2f\xfd": ("ZSTD", "Zstandard compressed data"),
    b"7z\xbc\xaf\x27\x1c": ("7z", "7-Zip archive"),
    b"PK\x03\x04": ("ZIP", "ZIP archive"),
    b"\x1f\x8b": ("GZIP", "Gzip compressed data"),
    b"BZh": ("BZIP2", "Bzip2 compressed data"),
    b"\xfd7zXZ\x00": ("XZ", "XZ compressed data"),
    b"UBIFS_VER_MAGIC": ("UBIFS", "UBIFS version magic"),
    b"\x90\x90\x90\x90": ("ARM", "ARM nop sled"),
    b"\x00\x00\x00\x00\x00\x00\x00\x00": ("NULL", "Null bytes (padding)"),
}

FILESYSTEM_TYPES = {
    "squashfs": {"name": "SquashFS", "extractable": True},
    "jffs2": {"name": "JFFS2", "extractable": True},
    "cramfs": {"name": "CramFS", "extractable": True},
    "romfs": {"name": "RomFS", "extractable": False},
    "ubifs": {"name": "UBIFS", "extractable": False},
}


class EntropyAnalyzer:
    """Shannon entropy analysis for firmware data blocks."""

    @staticmethod
    def calculate(data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def block_entropy(data: bytes, block_size: int = 1024) -> List[EntropyBlock]:
        blocks = []
        for i in range(0, len(data), block_size):
            chunk = data[i : i + block_size]
            ent = EntropyAnalyzer.calculate(chunk)
            blocks.append(EntropyBlock(offset=i, length=len(chunk), entropy=round(ent, 4)))
        return blocks

    @staticmethod
    def find_high_entropy_regions(
        data: bytes, block_size: int = 1024, threshold: float = 7.5
    ) -> List[EntropyBlock]:
        regions = []
        for block in EntropyAnalyzer.block_entropy(data, block_size):
            if block.entropy >= threshold:
                regions.append(block)
        return regions

    @staticmethod
    def is_compressed(data: bytes) -> bool:
        ent = EntropyAnalyzer.calculate(data)
        return ent > 7.0


class HeaderDetector:
    """Firmware header and signature detection."""

    def __init__(self, data: bytes):
        self.data = data

    def scan_signatures(self) -> List[FirmwareHeader]:
        results = []
        for magic, (name, desc) in KNOWN_SIGNATURES.items():
            start = 0
            while True:
                idx = self.data.find(magic, start)
                if idx == -1:
                    break
                results.append(
                    FirmwareHeader(offset=idx, magic=magic, description=f"{name}: {desc}", size=len(magic))
                )
                start = idx + 1
        results.sort(key=lambda h: h.offset)
        return results

    def detect_uimage(self) -> Optional[dict]:
        idx = self.data.find(b"\x27\x05\x19\x56")
        if idx == -1:
            return None
        try:
            fields = struct.unpack(">IIIIIIII", self.data[idx : idx + 32])
            return {
                "offset": idx,
                "magic": hex(fields[0]),
                "header_crc": hex(fields[1]),
                "timestamp": fields[2],
                "data_size": fields[6],
                "data_crc": hex(fields[7]),
                "os": fields[3] & 0xFF,
                "arch": (fields[3] >> 8) & 0xFF,
                "type": (fields[3] >> 16) & 0xFF,
                "compression": (fields[3] >> 24) & 0xFF,
                "name": self.data[idx + 32 : idx + 64].decode("ascii", errors="replace").rstrip("\x00"),
            }
        except (struct.error, IndexError):
            return None

    def detect_squashfs(self) -> Optional[dict]:
        for magic, endianness in [(b"hsqs", "<"), (b"sqsh", ">")]:
            idx = self.data.find(magic)
            if idx == -1:
                continue
            try:
                fields = struct.unpack(
                    endianness + "IIHHHHHHIIIIIIIIHHIIII",
                    self.data[idx : idx + 64],
                )
                return {
                    "offset": idx,
                    "magic": magic.decode(),
                    "inodes": fields[1],
                    "block_size": fields[7],
                    "fragments": fields[8],
                    "compressor": fields[4],
                }
            except struct.error:
                return {"offset": idx, "magic": magic.decode()}
        return None

    def detect_all_headers(self) -> dict:
        results = {
            "uimage": self.detect_uimage(),
            "squashfs": self.detect_squashfs(),
        }
        sigs = self.scan_signatures()
        results["signatures"] = [(hex(s.offset), s.description) for s in sigs]
        return results


class FirmwareExtractor:
    """Main firmware extraction and analysis engine."""

    def __init__(self, filepath: str):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Firmware file not found: {filepath}")
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.size = len(self.data)
        self.detector = HeaderDetector(self.data)
        self.extracted_files: List[FilesystemEntry] = []

    def get_basic_info(self) -> dict:
        md5 = hashlib.md5(self.data).hexdigest()
        sha256 = hashlib.sha256(self.data).hexdigest()
        ent = EntropyAnalyzer.calculate(self.data)
        return {
            "filename": self.filename,
            "size_bytes": self.size,
            "size_human": self._human_size(self.size),
            "md5": md5,
            "sha256": sha256,
            "entropy": round(ent, 4),
            "is_compressed": EntropyAnalyzer.is_compressed(self.data),
        }

    def detect_headers(self) -> dict:
        return self.detector.detect_all_headers()

    def entropy_analysis(self, block_size: int = 4096) -> dict:
        blocks = EntropyAnalyzer.block_entropy(self.data, block_size)
        high_ent = EntropyAnalyzer.find_high_entropy_regions(self.data, block_size)
        avg_entropy = sum(b.entropy for b in blocks) / len(blocks) if blocks else 0
        return {
            "block_size": block_size,
            "total_blocks": len(blocks),
            "average_entropy": round(avg_entropy, 4),
            "high_entropy_blocks": len(high_ent),
            "max_entropy": round(max(b.entropy for b in blocks), 4) if blocks else 0,
            "min_entropy": round(min(b.entropy for b in blocks), 4) if blocks else 0,
        }

    def extract_filesystem(self, output_dir: str) -> List[FilesystemEntry]:
        os.makedirs(output_dir, exist_ok=True)
        entries = []
        headers = self.detector.scan_signatures()
        if not headers:
            print("[!] No recognized filesystem headers found.")
            return entries
        for i, header in enumerate(headers):
            ext = header.description.split(":")[0].lower().replace(" ", "_")
            out_path = os.path.join(output_dir, f"extract_{i}_{ext}.bin")
            raw = self.data[header.offset :]
            try:
                decompressed = lzma.decompress(raw[:65536])
            except lzma.LZMAError:
                decompressed = raw[:65536]
            with open(out_path, "wb") as f:
                f.write(decompressed)
            entry = FilesystemEntry(path=out_path, size=len(decompressed), offset=header.offset, file_type=ext)
            entries.append(entry)
            self.extracted_files.append(entry)
            print(f"[+] Extracted {header.description} at {hex(header.offset)} -> {out_path}")
        return entries

    def extract_compressed(self, output_dir: str) -> List[FilesystemEntry]:
        os.makedirs(output_dir, exist_ok=True)
        entries = []
        offset = 0
        while offset < len(self.data):
            if self.data[offset : offset + 2] == b"\x1f\x8b":
                try:
                    import gzip
                    decompressed = gzip.decompress(self.data[offset:])
                    out_path = os.path.join(output_dir, f"gzip_{hex(offset)}.bin")
                    with open(out_path, "wb") as f:
                        f.write(decompressed)
                    entry = FilesystemEntry(
                        path=out_path, size=len(decompressed), offset=offset, file_type="gzip"
                    )
                    entries.append(entry)
                    print(f"[+] Decompressed gzip at {hex(offset)} -> {out_path}")
                    offset += len(decompressed)
                except Exception as e:
                    print(f"[!] Gzip decompress failed at {hex(offset)}: {e}")
                    offset += 1
            else:
                offset += 1
        return entries

    def scan_strings(self, min_length: int = 6) -> List[str]:
        strings = []
        current = []
        for byte in self.data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []
        return strings

    def full_analysis(self, output_dir: str) -> dict:
        print(f"\n{'='*60}")
        print(f"  I1 - IoT Firmware Extractor")
        print(f"{'='*60}")
        info = self.get_basic_info()
        print(f"\nFile: {info['filename']}")
        print(f"Size: {info['size_human']}")
        print(f"MD5:  {info['md5']}")
        print(f"SHA256: {info['sha256']}")
        print(f"Entropy: {info['entropy']}")
        print(f"Compressed: {info['is_compressed']}")
        print(f"\n--- Header Detection ---")
        headers = self.detect_headers()
        for key, val in headers.items():
            if key == "signatures":
                continue
            if val:
                print(f"  {key}: {val}")
        sigs = headers.get("signatures", [])
        if sigs:
            print(f"\n  Found {len(sigs)} signature(s):")
            for off, desc in sigs[:20]:
                print(f"    {off}: {desc}")
        print(f"\n--- Entropy Analysis ---")
        ent = self.entropy_analysis()
        for k, v in ent.items():
            print(f"  {k}: {v}")
        print(f"\n--- String Extraction ---")
        strings = self.scan_strings()
        print(f"  Found {len(strings)} printable strings")
        interesting = [s for s in strings if any(kw in s.lower() for kw in ["pass", "admin", "root", "firmware", "openwrt", "linux"])][:10]
        if interesting:
            print(f"  Interesting strings:")
            for s in interesting:
                print(f"    {s}")
        print(f"\n--- Filesystem Extraction ---")
        fs_entries = self.extract_filesystem(output_dir)
        print(f"  Extracted {len(fs_entries)} entries")
        print(f"\n{'='*60}")
        return {
            "info": info,
            "headers": headers,
            "entropy": ent,
            "strings_count": len(strings),
            "extracted": len(fs_entries),
        }

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 firmware_extractor.py <firmware_file> [output_dir]")
        print("  Analyzes IoT firmware binaries for headers, entropy, and filesystems.")
        print("  Output directory defaults to ./extracted/")
        sys.exit(1)
    filepath = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "extracted"
    extractor = FirmwareExtractor(filepath)
    extractor.full_analysis(output_dir)
    print(f"\nExtraction complete. Output: {output_dir}/")


if __name__ == "__main__":
    main()
