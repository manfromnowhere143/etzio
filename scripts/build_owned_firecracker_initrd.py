"""Build four closed owned Linux/x86-64 initramfs fixtures; execute none.

Uses the local assembler only. No downloaded build script, package or source is
executed. Each guest init prints a fixed marker then waits, spins or repeats it.
External deadlines and output limits are required before any guest execution.
"""

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

MODES = ("ready", "wrong", "spin", "output")


def assembly(mode):
    if mode not in MODES:
        raise ValueError("unknown owned fixture")
    marker = b"ETZIO_OWNED_WRONG_V1\n" if mode == "wrong" else b"ETZIO_OWNED_READY_V1\n"
    tail = {
        "ready": "mov $34, %eax\n syscall\n jmp wait_loop",
        "wrong": "mov $34, %eax\n syscall\n jmp wait_loop",
        "spin": "pause\n jmp wait_loop",
        "output": "jmp write_marker",
    }[mode]
    source = f""".text
.global _start
_start:
write_marker:
 mov $1, %eax
 mov $1, %edi
 lea marker(%rip), %rsi
 mov ${len(marker)}, %edx
 syscall
 cmp ${len(marker)}, %rax
 jne failed
wait_loop:
 {tail}
failed:
 mov $60, %eax
 mov $1, %edi
 syscall
 ud2
marker:
 .byte {",".join(str(x) for x in marker)}
"""
    return source, marker


def text_section(obj):
    if obj[:6] != b"\x7fELF\x02\x01":
        raise ValueError("assembler output is not ELF64 little endian")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", obj)
    if header[1:4] != (1, 62, 1) or header[11] != 64:
        raise ValueError("unexpected object architecture/layout")
    sections = [struct.unpack_from("<IIQQQQIIQQ", obj, header[6] + 64 * i) for i in range(header[12])]
    strings = sections[header[13]]
    names = obj[strings[4] : strings[4] + strings[5]]
    text = []
    for section in sections:
        name = names[section[0] :].split(b"\0", 1)[0]
        if section[1] in (4, 9) and section[5]:
            raise ValueError("unresolved object relocations")
        if name == b".text":
            if section[1] != 1 or section[2] != 6:
                raise ValueError("unexpected text flags")
            text.append(obj[section[4] : section[4] + section[5]])
    if len(text) != 1 or not 1 <= len(text[0]) <= 512:
        raise ValueError("unexpected fixture text size/count")
    return text[0]


def executable(code):
    size = 4096 + len(code)
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    return (header + load + stack).ljust(4096, b"\0") + code


def cpio_member(name, mode, data=b"", inode=1, major=0, minor=0):
    name_wire = name.encode() + b"\0"
    fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(name_wire), 0)
    head = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name_wire
    return head + b"\0" * ((-len(head)) % 4) + data + b"\0" * ((-len(data)) % 4)


def build(output):
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    compiler = subprocess.run(
        ["/usr/bin/clang", "--version"], check=True, capture_output=True, timeout=10
    ).stdout.decode()
    records = []
    for mode in MODES:
        source, marker = assembly(mode)
        asm = output / (mode + ".S")
        asm.write_text(source)
        obj = output / (mode + ".o")
        args = ["/usr/bin/clang", "-target", "x86_64-unknown-linux-gnu", "-c", str(asm), "-o", str(obj)]
        subprocess.run(args, check=True, capture_output=True, timeout=15)
        init = executable(text_section(obj.read_bytes()))
        (output / (mode + ".elf")).write_bytes(init)
        archive = b"".join(
            (
                cpio_member(".", 0o40755, inode=1),
                cpio_member("dev", 0o40755, inode=2),
                cpio_member("dev/console", 0o20600, inode=3, major=5, minor=1),
                cpio_member("init", 0o100500, init, inode=4),
                cpio_member("TRAILER!!!", 0, inode=0),
            )
        )
        archive += b"\0" * ((-len(archive)) % 512)
        (output / (mode + ".cpio")).write_bytes(archive)
        records.append(
            {
                "mode": mode,
                "marker_hex": marker.hex(),
                "elf_sha256": hashlib.sha256(init).hexdigest(),
                "initrd_sha256": hashlib.sha256(archive).hexdigest(),
                "elf_bytes": len(init),
                "initrd_bytes": len(archive),
            }
        )
    (output / "manifest.json").write_text(
        json.dumps(
            {"status": "built_not_executed", "compiler": compiler, "guest_executions": 0, "fixtures": records}, indent=2
        )
        + "\n"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_owned_initrd.py NEW_OUTPUT_DIRECTORY")
    build(Path(sys.argv[1]))
