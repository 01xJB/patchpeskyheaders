<div align="center">

# patchpeskyheaders

**A lightweight PE metadata sanitizer for Windows EXE and DLL files**

[![License](https://img.shields.io/github/license/01xJB/patchpeskyheaders?color=blue&style=for-the-badge)](LICENSE)
![Python](https://img.shields.io/badge/python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)

</div>

---

## Overview

**patchpeskyheaders** is a small Python command-line tool for sanitizing selected metadata in Windows Portable Executable (PE) files. It can clear the legacy DOS stub, remove Rich-header and debug-directory metadata, strip embedded PDB path information, and normalize the COFF timestamp.

For authorized red-team exercises, malware-analysis labs, and reverse-engineering work, these changes can help reduce incidental build-environment details exposed by a sample. For example, PDB paths may reveal usernames or project directories, while timestamps and compiler metadata can provide clues about a binary’s build environment. Sanitizing these fields can make test samples more suitable for controlled analysis and validation.

The tool writes to a separate output file, preserving the original for comparison or recovery. It does **not** guarantee anonymity, evade detection, or remove every identifying feature from a binary.

## Features

- Sanitizes selected PE metadata and build-environment artifacts
- Clears the legacy DOS stub while preserving the DOS header fields needed to locate the PE headers
- Removes the Microsoft Rich Header
- Removes the debug-directory reference and associated debug metadata
- Removes embedded PDB path information
- Sets the COFF timestamp to zero
- Supports Windows EXE and DLL files
- Uses Python’s standard library; no third-party packages required
- Preserves the input file and writes changes to a separate output path

## Requirements

- Python 3.x
- A Windows PE file (`.exe` or `.dll`)
- No external Python dependencies

## Installation

```bash
git clone https://github.com/01xJB/patchpeskyheaders.git
cd patchpeskyheaders
```

## Usage
```bash
python patch_headers.py -i <input.exe> -o <output.exe>
```

| Option       | Description                        |
| ------------ | ---------------------------------- |
| -i, --input  | Path to input EXE or DLL           |
| -o, --output | Path for the sanitized output file |

## Example
```bash
python patch_headers.py -i raw_compiled_binary.exe -o sanitized_binary.exe
```
## What It Changes

### DOS stub
Traditional PE files include a legacy DOS stub between the DOS header and the NT headers. This tool clears the stub’s content while retaining the structural fields used to locate the PE headers. This removes the familiar DOS-mode message and stub instructions, but does not alter the program’s main executable code.

### Rich Header
The Rich Header is an undocumented structure commonly found between the DOS header and NT headers. It can contain compiler and linker build information. Removing it can reduce the amount of build-environment metadata available during inspection.

### Debug information and PDB paths
PE debug data may include references to Program Database (PDB) files. Those references can contain local paths that disclose usernames, project names, or directory layouts. The tool removes the relevant debug metadata and directory reference.

### COFF timestamp
The COFF File Header contains a timestamp field. This tool sets that field to zero, removing the recorded build time from that location.

### Limitations and Compatability
This tool only modifies selected PE metadata. Other identifying or analyzable characteristics may remain, including imports, section layout, resources, strings, code patterns, hashes, and other compiler-generated data. Sanitization should not be treated as a way to bypass security products or guarantee that a binary cannot be identified.
Any modification can affect compatibility or trust properties. In particular, changing a digitally signed executable invalidates its existing Authenticode signature. Always test the output in an appropriate, isolated environment and retain the original file.

---

<div align="center">

Built by [**01xJB**](https://github.com/01xJB)

</div>
