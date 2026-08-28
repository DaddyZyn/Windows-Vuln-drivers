import pefile, sys, re, struct, os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from capstone import *
from capstone.x86 import *

SUSPICIOUS = ["MmMapIoSpaceEx", "MmMapIoSpace", "MmUnmapIoSpace", "ZwMapViewOfSection",
              "MmCopyVirtualMemory", "MmGetSystemRoutineAddress", "ExAllocatePool2",
              "ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages", "MmMapLockedPages",
              "ZwOpenProcess", "PsLookupProcessByProcessId", "ObReferenceObjectByHandle"]

def ctl_codes(disasm_text):
    # find immediates in CTL_CODE shape: DeviceType<<16 | Access<<14 | Function<<2 | Method
    codes = set()
    for m in re.finditer(r'0x([0-9a-fA-F]{6,8})', disasm_text):
        v = int(m.group(1), 16)
        devtype = (v >> 16) & 0xFFFF
        func = (v >> 2) & 0xFFF
        method = v & 3
        if 0 < devtype <= 0x8000 and 0x800 <= func <= 0xFFF and (v & 0x3FFC) != 0:
            codes.append(v) if False else codes.add(v)
    return sorted(codes)

def main(path):
    pe = pefile.PE(path)
    image_base = pe.OPTIONAL_HEADER.ImageBase

    # build import thunk map: iat va -> name
    iat_map = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            for imp in entry.imports:
                if imp.name:
                    iat_map[imp.address] = (dll, imp.name.decode())

    text = None
    for s in pe.sections:
        name = s.Name.decode(errors='ignore').strip('\x00')
        if name == '.text':
            text = (s.VirtualAddress, s.get_data())
    va_base, code = text

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(code, image_base + va_base))
    print(f"disasm: {len(insns)} instructions")

    # find thunk addresses of suspicious imports
    sus_thunks = {}
    for iat, (dll, fn) in iat_map.items():
        for sfn in SUSPICIOUS:
            if sfn == fn:
                sus_thunks[iat] = fn

    # find call/jmp xrefs to those thunks (RIP-relative: call qword [rip+X])
    xrefs = {}
    for i, ins in enumerate(insns):
        if ins.mnemonic in ('call', 'jmp') and 'rip' in ins.op_str:
            # compute target
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target = ins.address + ins.size + op.mem.disp
                    if target in sus_thunks:
                        xrefs.setdefault(sus_thunks[target], []).append((ins.address, i))
    print("\n--- XREFS TO SUSPICIOUS IMPORTS ---")
    for fn, refs in xrefs.items():
        for (addr, idx) in refs:
            print(f"  {fn:28s} called from {hex(addr)} (insn idx {idx})")

    # dump disasm to file for grep
    with open(path + ".asm", "w") as f:
        for ins in insns:
            comment = ""
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    t = ins.address + ins.size + op.mem.disp
                    if t in iat_map:
                        comment = f"  ; {iat_map[t][1]}"
            f.write(f"{hex(ins.address)}: {ins.mnemonic} {ins.op_str}{comment}\n")
    print(f"\nfull disasm -> {path}.asm")

    # CTL codes
    with open(path + ".asm") as f:
        t = f.read()
    print("\n--- POSSIBLE IOCTL CONSTANTS ---")
    for c in ctl_codes(t):
        dt, acc, func, meth = (c >> 16) & 0xFFFF, (c >> 14) & 3, (c >> 2) & 0xFFF, c & 3
        print(f"  {hex(c)}  DevType={hex(dt)} Access={acc} Func={hex(func)} Method={meth}"
              f" {'(BUFFERED)' if meth==0 else '(IN_DIRECT)' if meth==1 else '(OUT_DIRECT)' if meth==2 else '(NEITHER!)'}")

    # wide + ascii strings full dump
    data = open(path, 'rb').read()
    print("\n--- ALL ASCII STRINGS >=6 ---")
    seen = set()
    for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
        s = m.group().decode()
        if s not in seen:
            seen.add(s)
            print(f"  {s}")

if __name__ == "__main__":
    main(sys.argv[1])

