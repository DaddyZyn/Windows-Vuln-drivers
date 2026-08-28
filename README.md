# Windows-Vuln-drivers

Tooling and research for hunting **vulnerable Windows kernel drivers** — drivers that
are validly signed, loadable under default policy, and expose powerful primitives
(arbitrary physical memory R/W, raw I/O port access, kernel pointer disclosure) to
user mode, yet are **absent from Microsoft's Vulnerable Driver Blocklist**.

Includes a complete case study: **Teledyne Sapera LT `CorMem.sys`** — a signed driver
actively abused in the wild (BYOVD) that exposes arbitrary physical memory mapping
and raw ring-0 I/O ports to any administrator process, with no CVE assigned and no
blocklist coverage.

> **Responsible use:** This project exists to support vulnerability research,
> defensive detection engineering, and coordinated disclosure. Only test against
> systems you own or have written authorization to assess.

---

## What's Inside

```
.
├── tools/                  # static analysis & triage tooling
│   ├── bulk_scan.py        # bulk scanner: every driver on a box → ranked candidate list
│   ├── quick_triage.py     # single-driver vitals: imports, sections, device strings
│   ├── deep_triage.py      # disassembly pass: xrefs, IOCTL constants, full string dump
│   └── capstone_imports.py # kernel primitive import watchlist
├── report/                 # full case study (responsible disclosure package)
│   ├── CorMem_Analysis.md  # vulnerability analysis with assembly-level evidence
│   ├── cormem.h            # reconstructed user-mode interface (C++ header)
│   └── poc_cormem.cpp      # non-destructive PoC (KASLR leak + port I/O + phys map)
└── LICENSE
```

## Requirements

- Windows (any version with `System32\drivers` — tested on Win11)
- Python 3.10+
- [`pefile`](https://pypi.org/project/pefile/) and [`capstone`](https://pypi.org/project/capstone/)

```
pip install pefile capstone
```

The LOLDrivers feed (~30 MB JSON) is **auto-downloaded on first run** of the bulk
scanner and cached next to the script.

## Usage

### 1. Bulk scan every driver on the system

```powershell
python tools\bulk_scan.py
```

Walks `System32\drivers` + `DriverStore\FileRepository`, hashes every `.sys` against
the [LOLDrivers](https://www.loldrivers.io/) feed, scores the rest by primitive
imports / strings / IOCTL surface, and writes:

- `out/scan_results.json` — full raw results
- `out/report_top.txt` — top-60 ranked candidates + known-vulnerable drivers found on the system

Scoring highlights: `MmMapIoSpace(Ex)` (+30), `ZwMapViewOfSection` (+25),
`MmCopyVirtualMemory` (+35), `\Device\PhysicalMemory` string (+40), APC primitives
(+30 ea.), `METHOD_BUFFERED` custom IOCTL counts, and more — see
`capstone_imports.py` and the weight tables in `bulk_scan.py`.

### 2. Triage a single driver

```powershell
python tools\quick_triage.py C:\path\to\driver.sys     # imports / sections / strings
python tools\deep_triage.py  C:\path\to\driver.sys     # disasm + xrefs + IOCTL shape scan
```

`deep_triage.py` emits a full Capstone disassembly (`<driver>.sys.asm`) with import
annotations, plus candidate `CTL_CODE`-shaped immediates with transfer-method
breakdown (`BUFFERED` / `IN_DIRECT` / `OUT_DIRECT` / `NEITHER`).

### 3. Read the case study

Start with [`report/CorMem_Analysis.md`](report/CorMem_Analysis.md) — it documents
the full workflow: device discovery, IOCTL map reconstruction (including
`sub`-chain switch obfuscation that hides constants from naive scans), the
`\Device\PhysicalMemory` mapping chain, and the raw I/O port primitives.

---

## Case Study: Teledyne Sapera LT `CorMem.sys` (v9.00)

**Status:** not on the Microsoft Vulnerable Driver Blocklist · **no CVE assigned** ·
documented BYOVD abuse (Cobalt Strike / IcedID execution parents, 0/71 VT detection
at feed entry time)

| Primitive | IOCTL(s) | Detail |
|---|---|---|
| Arbitrary physical memory map | `0x22200C`, `0x222034` (WOW64) | `ZwMapViewOfSection(\Device\PhysicalMemory)` with fully user-controlled `SectionOffset` — no validation; kernel VA returned to caller |
| Arbitrary I/O port read | `0x222014` | raw `in al/ax/eax, dx`, user-supplied port |
| Arbitrary I/O port write | `0x222018` | raw `out dx, al/ax/eax` |
| Kernel pointer disclosure | `0x222008` | 88 bytes / 15 kernel code pointers (KASLR defeat) |
| MDL user-page lock/map | `0x22201c` | `MmProbeAndLockPages` → kernel alias of user buffer |

Device: `\\.\CORMEM` (default ACL → admin/SYSTEM). Signed copies (`CorMem.sys`,
redeployed as `Svc_XXXXXXXX.sys`) load under default driver-signature policy;
unsigned copies are also dropped by the SDK installer.

**Impact:** admin → kernel. Full physical memory R/W + ring-0 port I/O is
sufficient for EDR/AV tampering, credential theft, and kernel code execution.

**Recommended for defenders:** hash-block both samples via WDAC/App Control for
Business; alert on `Svc_????????.sys` creation in `System32\drivers`; alert on
`\\.\CORMEM` opens by non-system processes.

Full details, assembly evidence, IOCs, and remediation guidance in
[`report/CorMem_Analysis.md`](report/CorMem_Analysis.md).

---

## Methodology

1. **Collect** — enumerate all on-disk drivers (`System32\drivers`, DriverStore)
2. **Dedupe** — hash against public vulnerable-driver intelligence (LOLDrivers) so
   already-known drivers don't waste analysis time
3. **Score** — static heuristics: primitive imports, device-name strings,
   `\Device\PhysicalMemory`, IOCTL shape/count, APCs, token APIs
4. **Manual RE** — disassemble top candidates; trace `IRP_MJ_DEVICE_CONTROL`
   handlers; validate argument provenance (attacker-controlled vs. hardware-derived)
5. **Confirm & disclose** — non-destructive PoC, vendor report, blocklist nomination

Static scoring is deliberately noisy (dword-level IOCTL scanning produces false
positives on core Windows drivers); treat it as a **triage funnel**, not a verdict.
Always finish with manual analysis — e.g. an MMIO import list alone is not a
vulnerability (see the IntelPMT.sys negative result discussed in the analysis).

## Credits

- [LOLDrivers](https://www.loldrivers.io/) — vulnerable driver intelligence feed
- [pefile](https://github.com/erocarrera/pefile) / [capstone](https://github.com/capstone-engine/capstone)
- Microsoft's [recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

## License

[MIT](LICENSE)
