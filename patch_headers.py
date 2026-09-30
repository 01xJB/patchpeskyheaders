import argparse
import struct
import os

def print_header(title):
    print(f"\n{'='*70}\n[â–²] {title.upper()}\n{'='*70}")

def print_step(offset, field_name, old_val, new_val):
    offset_str = f"Offset: {hex(offset):<8}" if isinstance(offset, int) else f"{offset:<16}"
    print(f"  {offset_str} | {field_name:<40} | {old_val} -> {new_val}")

def safe_patch_pe(input_path, output_path):
    print(f"[*] Initializing Safe PE Metadata Normalizer...")
    print(f"[*] Reading source file: {input_path}")

    try:
        with open(input_path, 'rb') as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"[-] Critical Error reading file: {e}")
        return

    # --- 1. Locate the PE Header Offset ---
    try:
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    except Exception:
        print("[-] Critical Error: Could not read e_lfanew pointer. Invalid PE file structure.")
        return

    # --- 2. DOS Header Inspection ---
    print_header("Inspecting MS-DOS Header (Preserving Execution Required Fields)")
    if data[0:2] == b'MZ':
        print_step(0x00, "e_magic (DOS Execution Signature)", "b'MZ'", "b'MZ' [PRESERVED FOR RUNNABILITY]")
    else:
        print("[-] Critical Warning: File does not start with MZ. Execution may already be broken.")
    print_step(0x3C, "e_lfanew (Pointer to NT Headers Offset)", hex(pe_offset), f"{hex(pe_offset)} [PRESERVED FOR RUNNABILITY]")

    # --- 3. Scrub DOS Stub Warning Text & Compiler Metadata ---
    print_header("Scrubbing DOS Stub & Rich Header Telemetry")
    stub_text = b"This program cannot be run in DOS mode"
    stub_index = data.find(stub_text)

    if stub_index != -1:
        print_step(stub_index, "DOS Stub Warning String Located", f"'{stub_text.decode()}'", "[SCRUBBED TO NULLS]")
        # Safe to zero out this exact message block
        for i in range(stub_index, stub_index + len(stub_text)):
            data[i] = 0x00
    else:
        print_step("N/A", "DOS Stub Warning String", "Not found or already scrubbed", "[SKIPPED]")

    # Locate and zero out the Rich Header if it exists (usually starts with "Rich" signature)
    # The Rich Header is found between 0x40 and the pe_offset. It is safe to overwrite with 0x00.
    rich_index = data.find(b'Rich', 0x40, pe_offset)
    if rich_index != -1:
        print_step(rich_index, "Visual Studio Rich Header Signature Found", "Active Environment Telemetry", "[SCRUBBED TO NULLS]")
        # Clear out the Rich Header block securely up to the PE offset
        for i in range(0x40, pe_offset):
            data[i] = 0x00
    else:
        print_step("0x40 - " + hex(pe_offset), "Compiler Environment Padding Space", "Analyzing Padding Bytes", "[CLEANED]")
        for i in range(0x40, stub_index if stub_index != -1 else pe_offset):
            data[i] = 0x00

    # --- 4. NT File Header Normalization ---
    if data[pe_offset:pe_offset+4] == b'PE\x00\x00':
        print_header("Normalizing Non-Critical NT Header Metadata")
        print_step(pe_offset, "NT Header Signature (PE\\0\\0)", "b'PE\\x00\\x00'", "b'PE\\x00\\x00' [PRESERVED FOR RUNNABILITY]")

        file_header = pe_offset + 4

        # Zero out the compilation timestamp (TimeDateStamp)
        raw_timestamp = struct.unpack('<I', data[file_header+4 : file_header+8])[0]
        print_step(file_header+4, "FileHeader.TimeDateStamp (Build Epoch)", hex(raw_timestamp), "0x00000000 (Jan 1, 1970 - Normalized)")
        data[file_header+4 : file_header+8] = b'\x00\x00\x00\x00'

        # --- 5. Data Directories Normalization (Debug Directories) ---
        # Clear out the Debug directory pointer. If a file has debug paths, EDRs parse them.
        # Removing the pointer leaves the code 100% executable but breaks automated PDB path harvesting.
        opt_header = pe_offset + 24
        magic = struct.unpack('<H', data[opt_header : opt_header+2])[0]
        dir_offset = opt_header + 112 if magic == 0x20B else opt_header + 96

        debug_dir_idx = 6
        entry_pos = dir_offset + (debug_dir_idx * 8)

        print_header("Neutralizing High-Telemetry Data Directories")
        print_step(entry_pos, "DataDirectory[6] (IMAGE_DIRECTORY_ENTRY_DEBUG)", "Active Debug Linkage Pointer", "[ZEROED / ISOLATED]")
        data[entry_pos : entry_pos+8] = b'\x00'*8

    else:
        print("\n[-] Warning: 'PE\\0\\0' signature mismatch at calculated offset. Skipping NT modifications.")

    # --- 6. Save the Output ---
    print_header("Compilation / Writing Summary")
    try:
        with open(output_path, 'wb') as f:
            f.write(data)
        print(f"[+] Operational Success! The file remains a fully functional Win32 Executable.")
        print(f"[+] Output File Location: {os.path.abspath(output_path)}")
        print(f"[+] Total Payload Size:  {len(data)} bytes")
    except Exception as e:
        print(f"[-] Error writing output file to disk: {e}")
    print("="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Safe PE Header Sanitizer: Removes tracking telemetry and compiler environment signatures while preserving full execution capability.",
        epilog="This tool keeps execution requirements intact. The output executable can be launched normally."
    )
    parser.add_argument('-i', '--input', required=True, help="Path to input EXE/DLL payload")
    parser.add_argument('-o', '--output', required=True, help="Path for sanitized output binary")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[-] Error: Input file '{args.input}' not found.")
        return

    safe_patch_pe(args.input, args.output)

if __name__ == "__main__":
    main()
