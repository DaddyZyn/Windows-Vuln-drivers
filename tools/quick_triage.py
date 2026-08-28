import pefile, sys, json, re, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone_imports import SUSPICIOUS_IMPORTS

def analyze(path):
    pe = pefile.PE(path)
    print(f"=== {path} ===")
    print(f"Machine: {hex(pe.FILE_HEADER.Machine)}  Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem} (1=native/kernel)")
    print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("\n--- IMPORTS ---")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            funcs = [imp.name.decode() for imp in entry.imports if imp.name]
            hits = [f for f in funcs if any(s.lower() in f.lower() for s in SUSPICIOUS_IMPORTS)]
            print(f"\n{dll}: {len(funcs)} funcs")
            if hits:
                for h in hits:
                    print(f"  [!] {h}")

    # sections
    print("\n--- SECTIONS ---")
    for s in pe.sections:
        name = s.Name.decode(errors='ignore').strip('\x00')
        print(f"  {name:10s} VA={hex(s.VirtualAddress):>10s} rawsz={s.SizeOfRawData:>8} entropy={s.get_entropy():.2f}")

    # strings of interest
    data = open(path, 'rb').read()
    print("\n--- DEVICE/OBJ STRINGS ---")
    for m in re.finditer(rb'[\x20-\x7e]{5,}', data):
        s = m.group().decode()
        if any(k in s for k in ('\\Device', '\\Dos', 'PhysicalMemory', '.sys', 'IOCTL')):
            print(f"  {s}")

if __name__ == "__main__":
    analyze(sys.argv[1])
