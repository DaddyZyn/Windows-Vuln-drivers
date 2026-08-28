import os, sys, json, re, hashlib, time
import pefile
from collections import defaultdict

FEED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feeds_loldrivers.json")

PRIMITIVES = {
    "MmMapIoSpace": 30, "MmMapIoSpaceEx": 30, "MmUnmapIoSpace": 2,
    "ZwMapViewOfSection": 25, "ZwOpenSection": 15, "ZwOpenProcess": 15,
    "ZwOpenThread": 12, "MmCopyVirtualMemory": 35, "MmGetPhysicalAddress": 10,
    "PsLookupProcessByProcessId": 15, "PsReferencePrimaryToken": 20,
    "PsReferenceAccessToken": 25, "ObReferenceObjectByHandle": 8,
    "MmGetSystemRoutineAddress": 5, "MmProbeAndLockPages": 8,
    "MmMapLockedPagesSpecifyCache": 12, "MmMapLockedPages": 12,
    "ProbeForRead": 3, "ProbeForWrite": 3, "KeStackAttachProcess": 25,
    "HalSetBusDataByOffset": 20, "HalGetBusDataByOffset": 10,
    "HalTranslateBusAddress": 8, "IoCreateSymbolicLink": 10,
    "ExAllocatePool": 2, "RtlCopyMemory": 1, "IoBuildSynchronousFsdRequest": 3,
    "NtQuerySystemInformation": 5, "ZwSetValueKey": 6, "CmRegisterCallbackEx": 4,
    "PsSetCreateProcessNotifyRoutineEx": 4, "IoCreateDevice": 3,
    "KeInitializeApc": 30, "KeInsertQueueApc": 30, "MmCreateMdl": 15,
    "ZwQueryInformationProcess": 6, "ZwQueryInformationThread": 6,
}

STRINGS = {
    b"\\Device\\PhysicalMemory": 40,
    b"KeServiceDescriptorTable": 25,
    b"HalDispatchTable": 25,
    b"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager": 5,
    b"g_CiEnabled": 30, b"CI.dll": 8,  # DSE tamper hints
    b"TokenPrivileges": 8,
}

IOCTL_RE = re.compile(rb'0x([0-9a-fA-F]{6,8})')  # fallback on asm text

def ctl_shape(v):
    devtype = (v >> 16) & 0xFFFF
    access = (v >> 14) & 3
    func = (v >> 2) & 0xFFF
    method = v & 3
    if 0 < devtype <= 0x8000 and 0x800 <= func <= 0xFFF:
        return devtype, access, func, method
    return None

def ensure_feed():
    if not os.path.exists(FEED):
        import urllib.request
        url = "https://www.loldrivers.io/api/drivers.json"
        print(f"[*] LOLDrivers feed not found, downloading from {url} (~30MB)...")
        urllib.request.urlretrieve(url, FEED)
        print(f"[+] saved to {FEED}")

def load_feed_hashes():
    ensure_feed()
    with open(FEED, encoding="utf-8") as f:
        data = json.load(f)
    h = {}
    for d in data:
        for s in d.get("KnownVulnerableSamples", []):
            ah = s.get("Authentihash", {})
            for v in ah.values():
                if v: h[v.lower()] = d
            for k in ("MD5", "SHA1", "SHA256"):
                if s.get(k): h[s[k].lower()] = d
    return h, len(data)

def get_ioctl_candidates(pe, asm_text):
    out = set()
    for m in re.finditer(r'0x([0-9a-f]{6,8})\b', asm_text, re.I):
        v = int(m.group(1), 16)
        s = ctl_shape(v)
        if s: out.add(v)
    return out

def scan(path, known_hashes):
    r = {"path": path, "name": os.path.basename(path), "score": 0,
         "hits": [], "ioctls": [], "known_vuln": None}
    try:
        data = open(path, "rb").read()
    except Exception as e:
        r["error"] = str(e); return r
    r["size"] = len(data)
    r["sha256"] = hashlib.sha256(data).hexdigest()
    if r["sha256"] in known_hashes:
        r["known_vuln"] = known_hashes[r["sha256"]].get("Category") or "LOLDrivers"
        return r
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    except Exception as e:
        r["error"] = f"pe: {e}"; return r

    imports = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in e.imports:
                if imp.name: imports.add(imp.name.decode())
    for fn, w in PRIMITIVES.items():
        if fn in imports:
            r["score"] += w
            r["hits"].append(f"import:{fn}(+{w})")

    # strings scan (ascii + utf16)
    low = data.lower()
    for s, w in STRINGS.items():
        if s.lower() in low:
            r["score"] += w
            r["hits"].append(f"string:{s.decode()}(+{w})")
    for pat, w in [(rb'\\Device\\[A-Za-z0-9_.\-]{2,32}', 8),
                   (rb'\\DosDevices\\[A-Za-z0-9_.\-]{2,32}', 8),
                   (rb'\\BaseNamedObjects\\\{[0-9A-Fa-f\-]{36}\}', 5)]:
        found = set(re.findall(pat, data))
        for f_ in list(found)[:8]:
            r["score"] += w
            r["hits"].append(f"string:{f_.decode()}(+{w})")

    # exports (WDF interface providers sometimes export)
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        try:
            names = [x.name.decode() for x in pe.DIRECTORY_ENTRY_EXPORT.symbols if x.name]
            r["exports"] = names[:20]
        except Exception:
            pass

    # disasm-lite: only scan .text-ish sections for CTL_CODE immediates using raw regex on section bytes
    ioctl_hits = set()
    try:
        for s in pe.sections:
            name = s.Name.decode(errors="ignore").strip("\x00")
            if name in (".text", "PAGE"):
                b = s.get_data()
                # scan 4-byte immediates of common mov cmp patterns: approximate by scanning dwords
                for i in range(0, len(b) - 4):
                    v = int.from_bytes(b[i:i+4], "little")
                    s_ = ctl_shape(v)
                    if s_: ioctl_hits.add(v)
    except Exception:
        pass
    # keep only plausible vendor ranges & dedupe method info
    good = {}
    for v in ioctl_hits:
        dt, acc, fn, mth = ctl_shape(v)
        if fn >= 0x800:
            good[v] = (dt, acc, fn, mth)
    r["ioctls"] = [{"code": hex(v), "devtype": hex(d), "access": a, "func": hex(f),
                    "method": m} for v, (d, a, f, m) in sorted(good.items())[:40]]
    neither = [x for x in r["ioctls"] if x["method"] == 3]
    if neither:
        r["score"] += min(20, 7 * len(neither))
        r["hits"].append(f"ioctl:METHOD_NEITHER x{len(neither)}(+{min(20, 7*len(neither))})")
    if r["ioctls"]:
        r["score"] += min(15, len(r["ioctls"]))
        r["hits"].append(f"ioctl:custom_count={len(r['ioctls'])}")
    return r

def main():
    t0 = time.time()
    known, n_feed = load_feed_hashes()
    print(f"[*] feed loaded: {n_feed} drivers, {len(known)} hashes", flush=True)
    roots = [r"C:\Windows\System32\drivers", r"C:\Windows\System32\DriverStore\FileRepository"]
    results = []
    count = 0
    for root in roots:
        for dirpath, _, files in os.walk(root):
            for f in files:
                if f.lower().endswith(".sys"):
                    p = os.path.join(dirpath, f)
                    count += 1
                    res = scan(p, known)
                    results.append(res)
                    if count % 100 == 0:
                        print(f"[*] scanned {count}...", flush=True)
    print(f"[*] total {count} drivers in {time.time()-t0:.0f}s", flush=True)
    known_v = [r for r in results if r.get("known_vuln")]
    unknown = [r for r in results if not r.get("known_vuln") and not r.get("error")]
    unknown.sort(key=lambda x: -x["score"])
    outdir = os.path.join(os.path.dirname(__file__), "..", "out")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "scan_results.json"), "w") as f:
        json.dump(results, f, indent=1)
    with open(os.path.join(outdir, "report_top.txt"), "w") as f:
        f.write(f"=== TOP 60 UNKNOWN-VULN CANDIDATES (of {len(unknown)}) ===\n")
        for r in unknown[:60]:
            f.write(f"\n[{r['score']:4d}] {r['name']}  ({r.get('size',0)//1024}KB)\n")
            f.write(f"      {r['path']}\n")
            f.write(f"      sha256={r.get('sha256','?')}\n")
            for h in r["hits"][:14]:
                f.write(f"      - {h}\n")
            for io in r["ioctls"][:10]:
                meth = ["BUFFERED","IN_DIRECT","OUT_DIRECT","NEITHER"][io["method"]]
                f.write(f"      IOCTL {io['code']} dev={io['devtype']} func={io['func']} {meth}\n")
        f.write(f"\n=== KNOWN-VULN PRESENT ON SYSTEM ({len(known_v)}) ===\n")
        for r in known_v:
            f.write(f"  {r['name']}  cat={r['known_vuln']}\n      {r['path']}\n")
    print(f"[+] known-vuln drivers on system: {len(known_v)}")
    print(f"[+] top candidates written to out/report_top.txt")

if __name__ == "__main__":
    main()

