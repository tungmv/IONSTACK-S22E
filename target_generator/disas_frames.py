#!/usr/bin/env python3
"""Disassemble the futex/setsockopt frames used by the exp64 stack stamp.

Usage: disas_frames.py <kallsyms.txt> <Image> <symbol> [n_insns]
       disas_frames.py <kallsyms.txt> <Image> --scan-gr
"""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

TEXT_BASE = 0xFFFFFFC008000000


def parse(path):
    syms = {}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    syms[parts[2]] = int(parts[0], 16)
                except ValueError:
                    pass
    return syms


def main():
    ks_path, img_path = sys.argv[1], sys.argv[2]
    syms = parse(ks_path)
    data = open(img_path, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    def disas(name, count):
        addr = syms[name]
        off = addr - TEXT_BASE
        code = data[off:off + count * 4]
        out = []
        for i in md.disasm(code, addr):
            out.append("  %016x: %-8s %s" % (i.address, i.mnemonic, i.op_str))
        return out

    if sys.argv[3] == "--scan-gr":
        # find the 264/260-byte group_source_req copies in do_ipv6_setsockopt
        name = "do_ipv6_setsockopt"
        lines = disas(name, 900)
        for n, ln in enumerate(lines):
            if "#0x108" in ln or "#0x104" in ln or "copy_from_user" in ln:
                for k in range(max(0, n - 3), min(len(lines), n + 3)):
                    print(lines[k])
                print("  ---")
        return

    name = sys.argv[3]
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 40
    print("# %s @ %016x" % (name, syms[name]))
    for ln in disas(name, count):
        print(ln)


if __name__ == "__main__":
    main()
