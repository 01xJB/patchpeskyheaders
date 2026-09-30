<div align="center">

# patchpeskyheaders

**Portable Executable metadata sanitizer for Windows EXE and DLL files**

![License](https://img.shields.io/github/license/01xJB/patchpeskyheaders?color=blue&style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge)

</div>

---

## Overview

patchpeskyheaders is a Python-based PE metadata sanitizer designed to remove non-essential compiler fingerprints, Rich headers, compilation timestamps, debug information, and PDB paths from Windows Portable Executable files.

It operates directly on the underlying PE structure, identifying metadata that is not required by the Windows loader and modifying it while preserving the executable structure.

The result is a sanitized copy of the original binary with selected build-environment artifacts removed.

> ## Authorized Use Only
> patchpeskyheaders modifies Windows executable binaries. Only use it against binaries you own or are explicitly authorized to analyze or modify, such as software in a research environment, reverse-engineering project, security assessment, or personal lab. The author assumes no liability for misuse.

## Features

| | |
|---|---|
| **PE metadata sanitization** | Removes selected compiler and build-environment artifacts from Windows PE files |
| **Rich Header removal** | Removes the Microsoft Rich Header and associated compiler/build metadata |
| **Debug directory removal** | Removes the PE debug directory reference used to expose debugging information |
| **PDB path removal** | Removes embedded development-environment paths associated with Program Database information |
| **Timestamp normalization** | Sets the PE COFF compilation timestamp to zero |
| **DOS stub cleansing** | Clears legacy DOS stub instructions and message content |
| **EXE & DLL support** | Processes Windows executable and dynamic-link library PE files |
| **Standard library only** | Uses Python's native binary-processing functionality without third-party dependencies |
| **Separate output file** | Preserves the original input binary and writes modifications to a specified output path |
| **Command-line interface** | Simple input and output arguments for repeatable binary processing |

## Requirements

- Python 3.x
- Windows PE input (`.exe` or `.dll`)
- No external Python dependencies

## Installation

```bash
git clone https://github.com/01xJB/patchpeskyheaders.git
cd patchpeskyheaders
```

No additional Python packages are required.

## Usage

```bash
python patch_headers.py -i <input.exe> -o <output.exe>
```

| Flag | Description |
|---|---|
| `-i`, `--input` | Path to the input EXE or DLL |
| `-o`, `--output` | Path for the sanitized output binary |

### Example

```bash
$ python patch_headers.py -i raw_compiled_binary.exe -o targeted_output_binary.exe
```

The original binary remains unchanged and the sanitized PE is written to the output path.

## Metadata Processing

### Microsoft Rich Header Removal

The Microsoft Rich Header is an undocumented data structure commonly located between the legacy DOS header and the primary NT headers.

It contains compiler and linker build information that can expose details about the development environment used to produce a binary.

patchpeskyheaders removes this structure to eliminate the associated compiler metadata from the resulting PE.

### Debug Directory and PDB Isolation

PE binaries can contain an `IMAGE_DIRECTORY_ENTRY_DEBUG` structure containing information associated with debugging and the development environment.

Debug information may also contain absolute PDB paths exposing usernames, project directories, and other local filesystem information.

The sanitizer removes the relevant debug metadata and directory reference while leaving the executable instructions intact.

### Compilation Timestamp

The PE COFF File Header contains a 32-bit timestamp representing the time recorded by the compiler during the build process.

patchpeskyheaders overwrites this timestamp with a zero value, removing the original compilation timestamp from the PE header.

### Legacy DOS Stub Cleansing

Traditional PE files contain a legacy DOS stub located between the DOS header and the NT headers.

This area commonly contains the `This program cannot be run in DOS mode` message and associated legacy instructions.

patchpeskyheaders clears the legacy stub content while preserving the structural header information required to locate the PE's NT headers.

## Command-Line Help

To view the available command-line arguments:

```bash
python patch_headers.py --help
```

Example output:

```text
usage: patch_headers.py [-h] -i INPUT -o OUTPUT

Safe PE Header Sanitizer: Removes tracking telemetry and compiler environment
signatures while preserving full execution capability.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to input EXE/DLL payload
  -o OUTPUT, --output OUTPUT
                        Path for sanitized output binary
```

## Output

Given an input binary:

```text
raw_compiled_binary.exe
```

Running:

```bash
python patch_headers.py -i raw_compiled_binary.exe -o targeted_output_binary.exe
```

Produces:

```text
raw_compiled_binary.exe
targeted_output_binary.exe
```

The original input is retained while the modified PE is written to the specified output path.

## Limitations

patchpeskyheaders focuses specifically on selected PE metadata and compiler artifacts.

Removing these structures does not eliminate every characteristic that can be used to identify or analyze a binary. Other static properties can remain, including imported functions, section layout, embedded strings, resources, code patterns, hashes, signatures, and other compiler-generated structures.

Modifying a PE can also affect properties such as digital signatures. In particular, modifying a signed executable invalidates its existing Authenticode signature.

The resulting binary should therefore be tested after modification to verify that it behaves as expected.

## Security Disclaimer

This software utility is provided for objective research, reverse engineering verification, malware-analysis laboratories, security testing, and authorized environmental validation.

Only use this software against binaries that you own or are explicitly authorized to modify. Compliance with all applicable laws and regulations remains the responsibility of the user.

The developer accepts no legal liability for improper deployment, unauthorized use, data loss, system damage, or other consequences resulting from the use of this software.

## License

Released under the [GPL-3.0 License](LICENSE).

---

<div align="center">

Built by [**01xJB**](https://github.com/01xJB)

</div>
