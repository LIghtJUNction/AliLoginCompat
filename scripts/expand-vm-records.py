#!/usr/bin/env python3
"""Expand a saved Taobao VM image using its original native converter offline.

Requires Unicorn 2.x. No APK contents or account material are bundled. Only the
identified SG build and VM format are accepted; this does not run risk handlers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct


LIBRARY_SHA256 = "0bfbfff2bd2a9abdf82e34706276c8ad3d4e7e78a1dee276fa3984fab448f126"
ENTRY = 0x175D70
TEXT_END = 0x1BB070


def expand(library, image, image_base, records_base):
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC

    if hashlib.sha256(library).hexdigest() != LIBRARY_SHA256:
        raise ValueError("unsupported native library fingerprint")
    if not 0x70 <= len(image) <= 4 * 1024 * 1024:
        raise ValueError("invalid image size")
    if struct.unpack_from("<I", image)[0] != 0xB225081A:
        raise ValueError("invalid VM image magic")
    if struct.unpack_from("<I", image, 0x14)[0] != 0x10003:
        raise ValueError("unsupported VM format; 0x10005 is not validated")
    if struct.unpack_from("<I", image, 8)[0] != len(image):
        raise ValueError("image declaration does not match its size")
    code_offset, code_size = struct.unpack_from("<II", image, 0x1C)
    if not 4 <= code_size <= 2 * 1024 * 1024 or code_size % 4:
        raise ValueError("invalid code size")
    if code_offset + code_size + 4 > len(image):
        raise ValueError("code plus loader's extra word is out of bounds")
    # The original loader sets module+0x194 to (declared_code_bytes >> 2) + 1.
    words = code_size // 4 + 1
    output_size = (words - 1) * 16
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    pages = set()

    def write(address, data):
        for page in range(address & ~4095, (address + len(data) + 4095) & ~4095, 4096):
            if page not in pages:
                uc.mem_map(page, 4096)
                pages.add(page)
        uc.mem_write(address, bytes(data))

    phoff = struct.unpack_from("<Q", library, 32)[0]
    phsize, phcount = struct.unpack_from("<HH", library, 54)
    segments = [struct.unpack_from("<IIQQQQQQ", library, phoff + i * phsize)
                for i in range(phcount)]

    def file_offset(address):
        for kind, _, offset, virtual, _, size, _, _ in segments:
            if kind == 1 and virtual <= address < virtual + size:
                return offset + address - virtual
        raise ValueError("dynamic address outside file-backed LOAD")

    dynamic = {}
    for kind, _, offset, virtual, _, size, memory_size, _ in segments:
        if kind == 1:
            write(virtual, bytes(memory_size))
            uc.mem_write(virtual, library[offset:offset + size])
        if kind == 2:
            for position in range(offset, offset + size, 16):
                tag, value = struct.unpack_from("<QQ", library, position)
                if not tag:
                    break
                dynamic[tag] = value
    for position in range(file_offset(dynamic[7]), file_offset(dynamic[7]) + dynamic[8], dynamic[9]):
        address, info, addend = struct.unpack_from("<QQq", library, position)
        if info & 0xFFFFFFFF == 1027:
            uc.mem_write(address, struct.pack("<Q", addend))

    module, stack = 0x50000000, 0x20000000
    intervals = [(start, start + size) for start, size in
                 [(image_base, len(image)), (records_base, output_size),
                  (module, 512), (stack, 0x20000)]]
    intervals += [(s[3], s[3] + s[6]) for s in segments if s[0] == 1]
    for i, (left, right) in enumerate(intervals):
        if left < 0 or right >= 1 << 64:
            raise ValueError("address outside ARM64 range")
        if any(left < end and start < right for start, end in intervals[i + 1:]):
            raise ValueError("emulator regions overlap")
    write(image_base, image)
    write(records_base, bytes(output_size))
    context = bytearray(512)
    struct.pack_into("<Q", context, 8, records_base)
    struct.pack_into("<I", context, 0x194, words)
    struct.pack_into("<Q", context, 0x1A0, image_base + code_offset)
    write(module, context)
    write(stack, bytes(0x20000))
    uc.reg_write(UC_ARM64_REG_SP, stack + 0x1F000)
    uc.reg_write(UC_ARM64_REG_X0, module)
    uc.reg_write(UC_ARM64_REG_LR, stack)
    state = {"kind": "budget"}
    dependencies, writes = set(), set()
    instruction_count = 0

    def stop(kind, **details):
        state.clear()
        state.update(kind=kind, **details)
        uc.emu_stop()

    def instruction(_, address, size, user):
        nonlocal instruction_count
        instruction_count += 1
        if address == stack:
            stop("returned", result=uc.reg_read(UC_ARM64_REG_X0))
            return
        if not 0 <= address < TEXT_END:
            stop("outside_text", address=hex(address))
            return
        opcode = struct.unpack_from("<I", library, address)[0]
        if (opcode & 0xFC000000 == 0x94000000 or
                opcode & 0xFFFFFC1F == 0xD63F0000):
            stop("unmodeled_call", pc=hex(address))

    def invalid(_, access, address, size, value, user):
        stop("unmapped", address=hex(address), size=size,
             pc=hex(uc.reg_read(UC_ARM64_REG_PC)))
        return False

    def observe_read(_, access, address, size, value, user):
        if module <= address < module + 512:
            dependencies.add((address - module, size))

    def observe_write(_, access, address, size, value, user):
        if module <= address < module + 512:
            writes.add((address - module, size))

    uc.hook_add(UC_HOOK_CODE, instruction)
    uc.hook_add(UC_HOOK_MEM_INVALID, invalid)
    uc.hook_add(UC_HOOK_MEM_READ, observe_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, observe_write)
    try:
        uc.emu_start(ENTRY, stack + 4, timeout=12_000_000, count=8_000_000)
    except UcError as error:
        state["emulator_error"] = str(error)
    data = bytes(uc.mem_read(records_base, output_size))
    report = {
        "scope": "Offline original conversion only; no risk handler or network execution",
        "library_sha256": LIBRARY_SHA256,
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "format": "0x10003", "converter_elf": hex(ENTRY),
        "image_base": hex(image_base), "records_base": hex(records_base),
        "declared_code_bytes": code_size, "loader_code_words": words,
        "status": state, "native_instructions": instruction_count,
        "module_reads": sorted(dependencies), "module_writes": sorted(writes),
        "output_bytes": len(data), "output_sha256": hashlib.sha256(data).hexdigest(),
    }
    return data, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--image-base", type=lambda x: int(x, 0), default=0x30000000)
    parser.add_argument("--records-base", type=lambda x: int(x, 0), default=0x40000000)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    report_path = args.output.with_name(args.output.name + ".json")
    inputs = [p.resolve() for p in [args.library, args.image, args.reference] if p]
    if args.output.resolve() in inputs or report_path.resolve() in inputs:
        parser.error("output would overwrite an input")
    if not args.force and (args.output.exists() or report_path.exists()):
        parser.error("output exists; use --force to replace")
    try:
        data, report = expand(args.library.read_bytes(), args.image.read_bytes(),
                              args.image_base, args.records_base)
    except (ValueError, OSError, ImportError, struct.error) as error:
        parser.error(str(error))
    complete = report["status"] == {"kind": "returned", "result": 0}
    if args.reference:
        reference = args.reference.read_bytes()
        report["reference_sha256"] = hashlib.sha256(reference).hexdigest()
        report["reference_matches"] = data == reference
        complete = complete and report["reference_matches"]
    os.umask(0o077)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    if complete:
        with args.output.open("wb" if args.force else "xb") as target:
            target.write(data)
    print(json.dumps(report, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
