# I1 — IoT Firmware Extractor

Binwalk-style firmware parsing, filesystem extraction, header detection, and entropy analysis.

## Overview

This project implements an IoT firmware analysis toolkit that:
- Detects firmware headers (uImage, SquashFS, JFFS2, UBI, LZMA, GZIP, etc.)
- Performs Shannon entropy analysis to find compressed/encrypted regions
- Extracts and decompresses filesystems from firmware images
- Scans for printable strings (credentials, config, URLs)
- Computes file hashes (MD5, SHA256)

## Features

- **Header Detection**: Identifies 15+ known firmware and archive signatures
- **Entropy Analysis**: Block-based Shannon entropy with high-entropy region detection
- **Filesystem Extraction**: Extracts recognized filesystems from firmware blobs
- **String Scanning**: Finds interesting strings (passwords, URLs, device info)
- **uImage Parsing**: Full U-Boot image header parsing with arch/OS/compression info
- **SquashFS Detection**: Parses SquashFS superblocks for inode count, block size, compressor

## Dependencies

Standard library only (no pip install needed):
- `struct`, `hashlib`, `zlib`, `lzma`, `math`, `os`

## Usage

```bash
# Analyze a firmware image
python3 firmware_extractor.py <firmware_file> [output_dir]

# Example
python3 firmware_extractor.py router_fw.bin ./extracted/
```

## Example Output

```
============================================================
  I1 - IoT Firmware Extractor
============================================================

File: router_fw.bin
Size: 16.00 MB
MD5:  a1b2c3d4e5f6...
SHA256: deadbeef...
Entropy: 7.8234
Compressed: True

--- Header Detection ---
  uimage: {'offset': 0, 'magic': '0x27051956', ...}
  squashfs: {'offset': 65536, 'inodes': 1024, ...}

  Found 5 signature(s):
    0x0: uImage: U-Boot image header
    0x10000: SquashFS: SquashFS filesystem (little-endian)

--- Entropy Analysis ---
  block_size: 4096
  total_blocks: 4096
  average_entropy: 7.1234
  high_entropy_blocks: 2048

--- String Extraction ---
  Found 3421 printable strings
  Interesting strings:
    root:admin
    /etc/config/wireless

--- Filesystem Extraction ---
  [+] Extracted uImage at 0x0 -> extracted/extract_0_uimage.bin
  [+] Extracted SquashFS at 0x10000 -> extracted/extract_1_squashfs.bin
  Extracted 2 entries

============================================================
```

## How It Works

1. **Signature scanning**: Brute-force search for known magic bytes throughout the binary
2. **Entropy calculation**: Shannon entropy on 4KB blocks to distinguish code vs data vs compressed
3. **Header parsing**: Struct unpacking of uImage (big-endian) and SquashFS superblocks
4. **Extraction**: LZMA decompression fallback for unrecognized compressed sections

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the device owner before analyzing firmware
- Reverse engineering consumer devices may violate DMCA or local laws
- This tool should ONLY be used on firmware you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **DMCA Anti-Circumvention (17 U.S.C. § 1201)**: Circumventing technological protection measures may be illegal
- **State Laws**: Many states have additional computer crime statutes
- **Export Controls**: Firmware analysis tools may be subject to export regulations

### Acceptable Use
- Analyzing firmware from devices you own
- Authorized security research with written scope
- Academic research in controlled lab environments
- Security education and training
- Contributing to open-source firmware projects

### Prohibited Use
- Analyzing firmware from devices you do not own
- Bypassing DRM or copy protection commercially
- Any activity that violates applicable laws or regulations
- Commercial exploitation without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
