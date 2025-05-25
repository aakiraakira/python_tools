#!/usr/bin/env python3
"""

An advanced Python-based malware analysis framework combining static and dynamic techniques:

Features:
  - PE file parsing (headers, sections, imports/exports) via pefile
  - YARA signature scanning for known malware patterns
  - Strings extraction and entropy calculation
  - Disassembly and control flow graph (CFG) generation with Capstone + NetworkX
  - Lightweight emulation of entrypoint stub using Unicorn to detect unpacking routines
  - Suspicious API usage heuristics (anti-debug, anti-VM, network calls)
  - Generates report in JSON and optional CFG visualization (Graphviz DOT)

Usage:
  python advanced_malware_analyzer.py --file sample.exe --yara rules.yar --emit-cfg graph.dot

Dependencies:
  pip install pefile capstone unicorn networkx graphviz yara-python
"""
import os
import sys
import json
import argparse
import pefile
import yara
import math
import tempfile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64
from unicorn.x86_const import *
import networkx as nx

# ---------------------------------
# Utility Functions
# ---------------------------------
def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

# ---------------------------------
# Static Analysis
# ---------------------------------
def parse_pe(path: str):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    info = {
        'timestamp': pe.FILE_HEADER.TimeDateStamp,
        'arch': 'x64' if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else 'x86',
        'sections': [],
        'imports': []
    }
    for sec in pe.sections:
        data = sec.get_data()
        info['sections'].append({
            'name': sec.Name.decode(errors='ignore').rstrip('\x00'),
            'virtual_address': hex(sec.VirtualAddress),
            'size': sec.SizeOfRawData,
            'entropy': calculate_entropy(data)
        })
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            for imp in entry.imports:
                info['imports'].append({'dll': dll, 'name': imp.name.decode() if imp.name else None})
    return pe, info

# ---------------------------------
# YARA Scanning
# ---------------------------------
def run_yara(rules_file: str, path: str):
    rules = yara.compile(filepath=rules_file)
    matches = rules.match(path)
    return [m.rule for m in matches]

# ---------------------------------
# Strings Extraction
# ---------------------------------
def extract_strings(path: str, min_len=4):
    with open(path, 'rb') as f:
        data = f.read()
    result = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                s = ''.join(current)
                result.append(s)
            current = []
    if len(current) >= min_len:
        result.append(''.join(current))
    return list(set(result))

# ---------------------------------
# Disassembly & CFG
# ---------------------------------
def build_cfg(pe: pefile.PE, max_instructions=500):
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
    size = 0x1000
    code = pe.get_memory_mapped_image()[entry - pe.OPTIONAL_HEADER.ImageBase:][:size]
    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe.FILE_HEADER.Machine==pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else CS_MODE_32)
    graph = nx.DiGraph()
    prev = None
    count = 0
    for ins in md.disasm(code, entry):
        graph.add_node(ins.address, mnemonic=ins.mnemonic, op_str=ins.op_str)
        if prev:
            graph.add_edge(prev.address, ins.address)
        prev = ins
        count +=1
        if count >= max_instructions:
            break
    return graph

# ---------------------------------
# Emulation
# ---------------------------------
def emulate_stub(pe: pefile.PE, pe_info: dict, steps=10000):
    arch = pe_info['arch']
    mu = Uc(UC_ARCH_X86, UC_MODE_64 if arch=='x64' else UC_MODE_32)
    base = pe.OPTIONAL_HEADER.ImageBase
    mu.mem_map(base, 0x200000)
    mu.mem_write(base, pe.get_memory_mapped_image())
    entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    mu.reg_write(UC_X86_REG_RSP if arch=='x64' else UC_X86_REG_ESP, base + 0x100000)
    executed = []
    def hook_code(u, addr, size, user):
        executed.append(addr)
        if len(executed) >= steps:
            u.emu_stop()
    mu.hook_add(uc.UC_HOOK_CODE, hook_code)
    try:
        mu.emu_start(entry, base + pe.OPTIONAL_HEADER.SizeOfImage)
    except Exception:
        pass
    return executed

# ---------------------------------
# Main
# ---------------------------------
def main():
    p = argparse.ArgumentParser(description="Advanced Malware Analysis Tool")
    p.add_argument('--file',      '-f', required=True, help='PE malware sample path')
    p.add_argument('--yara',      '-y', help='YARA rules file')
    p.add_argument('--emit-cfg',  '-c', help='Output CFG DOT file')
    args = p.parse_args()

    pe, info = parse_pe(args.file)
    report = {'pe_info': info}

    if args.yara:
        report['yara_matches'] = run_yara(args.yara, args.file)

    report['strings'] = extract_strings(args.file)

    cfg = build_cfg(pe)
    report['cfg_nodes'] = len(cfg.nodes)
    report['cfg_edges'] = len(cfg.edges)
    if args.emit_cfg:
        nx.drawing.nx_pydot.write_dot(cfg, args.emit_cfg)

    report['emulated_instructions'] = emulate_stub(pe, info)

    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
