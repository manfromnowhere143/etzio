"""Build two fixed owned memory-pressure initrds; execute neither."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from build_owned_firecracker_initrd import cpio_member, executable, text_section

SIZES = {"memory-low": 64 * 1024 * 1024, "memory-high": 384 * 1024 * 1024}
READY = b"ETZIO_MEMORY_READY_V1\n"
DONE = b"ETZIO_MEMORY_DONE_V1\n"


def assembly(mode):
    if type(mode) is not str or mode not in SIZES:
        raise ValueError("closed owned memory fixture")
    return f""".text
.global _start
_start:
 mov $1, %eax
 mov $1, %edi
 lea ready(%rip), %rsi
 mov ${len(READY)}, %edx
 syscall
 cmp ${len(READY)}, %rax
 jne failed
 mov $35, %eax
 lea delay(%rip), %rdi
 xor %esi, %esi
 syscall
 test %rax, %rax
 jne failed
 mov $9, %eax
 xor %edi, %edi
 mov ${SIZES[mode]}, %esi
 mov $3, %edx
 mov $0x22, %r10d
 mov $-1, %r8
 xor %r9d, %r9d
 syscall
 cmp $-4095, %rax
 jae failed
 mov %rax, %r12
 mov ${SIZES[mode] // 4096}, %r13d
touch:
 movb $0xa5, (%r12)
 add $4096, %r12
 dec %r13
 jne touch
 mov $1, %eax
 mov $1, %edi
 lea done(%rip), %rsi
 mov ${len(DONE)}, %edx
 syscall
 cmp ${len(DONE)}, %rax
 jne failed
wait_loop:
 mov $34, %eax
 syscall
 jmp wait_loop
failed:
 mov $60, %eax
 mov $1, %edi
 syscall
 ud2
.balign 8
delay:
 .quad 5, 0
ready:
 .byte {",".join(str(x) for x in READY)}
done:
 .byte {",".join(str(x) for x in DONE)}
"""


def build(output):
    output.mkdir(mode=0o700, exist_ok=False)
    compiler = subprocess.run(["/usr/bin/clang", "--version"], check=True, capture_output=True, timeout=10).stdout
    records = []
    for mode, size in SIZES.items():
        source = output / (mode + ".S")
        source.write_text(assembly(mode))
        obj = output / (mode + ".o")
        subprocess.run(
            ["/usr/bin/clang", "-target", "x86_64-unknown-linux-gnu", "-c", str(source), "-o", str(obj)],
            check=True,
            capture_output=True,
            timeout=15,
        )
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
                "touched_bytes": size,
                "initrd_bytes": len(archive),
                "initrd_sha256": hashlib.sha256(archive).hexdigest(),
                "elf_sha256": hashlib.sha256(init).hexdigest(),
            }
        )
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "status": "built_not_executed",
                "compiler": compiler.decode(),
                "fixtures": records,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: build_owned_resource_fixtures.py NEW_DIRECTORY")
    build(Path(sys.argv[1]))
