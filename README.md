# patchpeskyheaders
A Python-based PE metadata sanitizer that strips compiler fingerprints, Rich headers, compilation timestamps, and debug (PDB) paths from Windows EXEs and DLLs to maximize OPSEC while preserving 100% execution capability.

# Portable Executable Sanitizer and Metadata Normalizer

A specialized Python utility designed to analyze and remove non-essential structural tracking artifacts, compiler artifacts, and environment footprints from Windows Portable Executable (PE) formats, including executable binaries (EXE) and dynamic link libraries (DLL). 

By identifying and safely zeroing out metadata categories ignored by the native Windows operating system loader, this utility ensures that the targeted binaries retain full runtime execution capability while fundamentally stripping static structural signatures.

## Architectural Concepts

During a standard software compilation pipeline, modern compilers insert significant tracking and telemetry markers into the resulting binary layout. Security analysis platforms, Endpoint Detection and Response (EDR) agents, and static signature scanners use these artifacts to build behavioral profiles, perform historical analysis, and cluster distinct tools to the same operational origin.

This script parses the underlying PE mapping architecture to isolate and neutralize these data structures:

### Microsoft Rich Header Removal
Compilers like Microsoft Visual Studio inject an undocumented data structure located between the legacy DOS header and the primary NT headers. This block contains data points regarding the developer's exact build environment, specifically the specific version numbers of the compiler used, the minor patch counts, and the precise number of times individual source objects were linked. The script wipes this block entirely, preventing static correlation to a specific build machine.

### Debug Directory and PDB Isolation
When a compiler optimizes code, it generates deep tracking paths mapping back to the local development environment inside the IMAGE_DIRECTORY_ENTRY_DEBUG structure. This often leaks absolute paths containing administrative usernames and directory hierarchies. The script disables the pointer to this table, leaving the operational instructions intact while blocking automated metadata extraction.

### Chronological Anonymization
Every PE binary contains a 32-bit integer timestamp inside the COFF File Header reflecting the exact second the compiler generated the file. This timestamp serves as a major correlation metric during security monitoring. The tool overwrites this parameter with zero value, normalizing the compilation state across different file variants.

### Legacy DOS Stub Cleansing
The message text indicating that a program cannot be run in DOS mode is a relic of older computing infrastructures. Automated signature frameworks rely on this specific text block and its surrounding padding bytes to cross-reference software patterns. The sanitizer zeros out the legacy instructions and content zones up to the critical offset pointers, deleting these static targets.

## Execution and Command-Line Interface

The utility utilizes Python's native binary processing modules to read, parse, modify, and rewrite the targeted files byte-by-byte. It operates with a fully native standard library, eliminating external dependency overhead or packaging requirements.

### Help Options and Menu Flags

To query structural parameters or view arguments from the terminal, execute the following syntax:

```text
python pe_sanitizer.py --help
```

The system will respond with a standardized positional map detailing necessary options:

```text
usage: pe_sanitizer.py [-h] -i INPUT -o OUTPUT

Safe PE Header Sanitizer: Removes tracking telemetry and compiler environment
signatures while preserving full execution capability.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to input EXE/DLL payload
  -o OUTPUT, --output OUTPUT
                        Path for sanitized output binary
```

### Technical Workflow

To execute the modifications on a specific file target, invoke the parameters via:

```text
python pe_sanitizer.py -i raw_compiled_binary.exe -o targeted_output_binary.exe
```

The execution runtime reads the source file directly into an internal memory array, extracts the exact placement of the NT headers via the preserved long pointer offset, strips the targeted blocks, and creates a functional, sanitized binary file structure on disk.

## Security Disclaimer

This software utility is provided exclusively for objective research, reverse engineering verification, security posture assessment, and authorized environmental validation. Compliance with all governing regional laws remains the sole accountability of the deploying individual. The developer accepts no legal liability for improper deployment or destructive operational practices.
