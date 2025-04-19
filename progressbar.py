import sys
import struct
from capstone import *
import pefile

MAX_RECURSIVE_DEPTH = 3

def disassemble_address(pe_raw, function_va, size = None):
    pe_format = pefile.PE(data=pe_raw)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True

    function_rva = function_va - pe_format.OPTIONAL_HEADER.ImageBase

    section = None
    for s in pe_format.sections:
        if s.VirtualAddress <= function_rva < s.VirtualAddress + s.Misc_VirtualSize:
            section = s
            break

    if not section:
        print(f"[Error] Could not locate section for function VA: 0x{function_va:x}")
        return

    section_offset = section.PointerToRawData
    section_data = pe_raw[section_offset:section_offset + section.SizeOfRawData]

    func_offset_in_section = function_rva - section.VirtualAddress
    if size:
        func_bytes = section_data[func_offset_in_section:func_offset_in_section+size]
    else:
        func_bytes = section_data[func_offset_in_section:]

    assembly = []
    for i in md.disasm(func_bytes, function_va):
        assembly.append(i)
        if i.mnemonic == "ret":
            break

    return assembly

def assembly_i_to_string(i):
    return "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)

def print_assembly(assembly):
    for i in assembly:
        print(assembly_i_to_string(i))

def find_markers_in_function(pe_raw, function_va, marker_fn_va, depth, allowed_fn_vas):
    ret = {"calls": [], "count": 0}
    assembly = disassemble_address(pe_raw, function_va)
    for i in assembly:
        line = assembly_i_to_string(i)
        if "call" in line:
            if "0x%x" % marker_fn_va in line:
                print(f"{line} <- marker")
                ret["calls"].append(i.address)
                ret["count"] += 1
            elif depth < MAX_RECURSIVE_DEPTH:
                #print(line)
                try:
                    next_function_va = int(line.strip().split()[2], 16)
                    if next_function_va in allowed_fn_vas:
                        result = find_markers_in_function(pe_raw, next_function_va, marker_fn_va, depth + 1, allowed_fn_vas)
                    else:
                        result = {"calls": [], "count": 0}
                except ValueError:
                    result = {"calls": [], "count": 0}
                if result["count"] > 0 and len(result["calls"]):
                    for call in result["calls"]:
                        ret["calls"].append(call)
                    ret["count"] += result["count"]
    return ret

def va_to_offset(pe_raw, va):
    pe = pefile.PE(data=pe_raw)
    for section in pe.sections:
        start = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
        end = start + section.Misc_VirtualSize

        if start <= va < end:
            offset_in_section = va - start
            file_offset = section.PointerToRawData + offset_in_section
            return file_offset

    raise ValueError(f"VA 0x{va:X} not found in any section.")

def replace_closest_bytes(pe_raw, offset, search_bytes, replace_to_bytes):
    pattern_len = len(search_bytes)

    if pattern_len != len(replace_to_bytes):
        raise ValueError("search_bytes and replace_to_bytes must be the same length")

    new_pe_raw = bytearray(pe_raw)

    for i in range(offset, pattern_len - 1, -1):
        if new_pe_raw[i - pattern_len + 1:i + 1] == search_bytes:
            print(f"Replacing {search_bytes.hex(sep=" ")} -> {replace_to_bytes.hex(sep=" ")} @ 0x{(i - pattern_len + 1):X} offset")
            new_pe_raw[i - pattern_len + 1:i + 1] = replace_to_bytes
            return bytes(new_pe_raw)  # Return as immutable bytes again

    raise RuntimeError("Pattern not found")

def main():
    if len(sys.argv) < 6:
        print("Usage: progressbar.py <path_to_binary> <path_to_map> <mangled_symbol_start_fn> <mangled_symbol_marker_fn> <mangled_symbol_fragment_allowed_fn>")
        return

    pe_path = sys.argv[1]
    map_path = sys.argv[2]
    start_fn = sys.argv[3]
    marker_fn = sys.argv[4]
    allowed_fns = sys.argv[5]

    print(f"PE File: {pe_path}")
    print(f"MAP File: {map_path}")
    print(f"Start function: {start_fn}")
    print(f"Marker function: {marker_fn}")
    print(f"Allowed functions: {allowed_fns.split("|")}")

    start_fn_va = None
    marker_fn_va = None

    with open(map_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            if marker_fn in line:
                print(line)
                marker_fn_va = int(line.strip().split()[2], 16)
            elif start_fn in line:
                print(line)
                start_fn_va = int(line.strip().split()[2], 16)
            if start_fn_va and marker_fn_va:
                break

    print(f"Start function VA: 0x{start_fn_va:x}")
    print(f"Marker function VA: 0x{marker_fn_va:x}")

    allowed_fn_vas = set()
    with open(map_path, "r") as file:
        lines = file.readlines()
        for line in lines:
            for allowed_fn in allowed_fns:
                if allowed_fn in line and " f " in line:
                    print(line)
                    fn_va = int(line.strip().split()[2], 16)
                    allowed_fn_vas.add(fn_va)

    print(f"Allowed FN VA count: {len(allowed_fn_vas)}")

    # --- Grab all marker calls
    pe_raw = b""
    with open(pe_path, "rb") as f:
        pe_raw = f.read()

    markers = find_markers_in_function(pe_raw, start_fn_va, marker_fn_va, 0, allowed_fn_vas)
    print(f"Total markers count: {markers["count"]}")

    # --- Replace immediate values

    undefined_max_step = struct.pack("<I", 0xBABEFACE)
    undefined_current_step = struct.pack("<I", 0xDEADBEEF)

    i = 1
    for marker_call in markers["calls"]:
        marker_percentage = int(float(i) / float(markers["count"]) * float(100))
        print("-" * 0x64)
        print(f"0x{marker_call:x} -> {i} / {markers["count"]} -> {marker_percentage}%")
        marker_call_raw_offset = va_to_offset(pe_raw, marker_call)
        print(f"Raw offset: 0x{marker_call_raw_offset:x}")
        pe_raw = replace_closest_bytes(pe_raw, marker_call_raw_offset, undefined_max_step, struct.pack("<I", markers["count"]))
        pe_raw = replace_closest_bytes(pe_raw, marker_call_raw_offset, undefined_current_step, struct.pack("<I", i))

        i += 1

    with open(pe_path, "wb") as f:
        f.write(pe_raw)
        print("\n\n")
        print("Binary has been patched successfuly.")

if __name__ == "__main__":
    main()
