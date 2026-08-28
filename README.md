# Windows-Vuln-drivers

signed drivers that hand out kernel primitives to user mode, and aren't on
microsoft's vulnerable driver blocklist. each folder under `report/` is one
driver: full analysis, reversed interface header, non-destructive PoC.

## index

| driver | vendor | version | primitives | blocklist | cve |
|---|---|---|---|---|---|
| [CorMem.sys](report/cormem/ANALYSIS.md) | Teledyne Digital Imaging | 9.00 | arbitrary physical memory map, raw I/O port R/W, kernel pointer disclosure | not listed | none |
| [AsIO3.sys](report/asio3/ANALYSIS.md) | ASUSTeK | 1.02.40 | ungated PCI config read, firmware-region phys map (RW), wide port allowlist (SMI/CMOS/EC), contiguous alloc oracle | not listed | none |
| [KslD.sys / MpKslDrv](report/ksld/ANALYSIS.md) | Microsoft (Defender) | 1.1.26051 | Intel TDT command interface (phys read, routine addr leak, file read, SPI flash) — image-name gate is registry-fed, but live test shows deployed build enforces more; downgraded to hardening finding | n/a (in-box) | n/a |
| [MEmuDrv.sys](report/memudrv/ANALYSIS.md) | Shanghai Microvirt (MEmu) | 5.1.34 | VirtualBox SUPDrv fork, hardening stripped: ring-0 module loader with exec-alloc fallback (no file/signature checks), MSR prober, kernel page map/protect — mapper-grade | not listed | none |

---

## CorMem.sys — Teledyne Sapera LT memory manager

machine vision SDK driver. deploys itself as randomly named `Svc_XXXXXXXX.sys`
copies in `System32\drivers`, several of which ship unsigned. device is
`\\.\CORMEM`, default ACL, admin only — but admin is all BYOVD abuse needs.

what it lets you do from user mode:

- map **any physical address** into the kernel via `\Device\PhysicalMemory`
  (`0x22200C`, wow64 variant `0x222034`), zero validation on the address
- raw `in`/`out` on **any x86 I/O port** (`0x222014` / `0x222018`)
- read **15 kernel code pointers** out of the driver image (`0x222008`)

documented in-the-wild abuse (Cobalt Strike / IcedID loaders, cheat kernel
loaders, 0/71 VT detection), still not blocklisted, still no CVE.

**files**

- [`report/cormem/ANALYSIS.md`](report/cormem/ANALYSIS.md) — full writeup with assembly evidence, IOCTL map, IOCs, remediation
- [`report/cormem/cormem.h`](report/cormem/cormem.h) — reversed interface header (all ioctls + structs)
- [`report/cormem/poc_cormem.cpp`](report/cormem/poc_cormem.cpp) — non-destructive proof (func table leak, RTC port read, phys map)

**hashes**

```
40C855D20D497823716A08A443DC85846233226985EE653770BC3B245CF2ED0F   signed
9977054734C44B080FB26FE8F296CD3CCEBACF2BDB7949617AECB14064A42247   unsigned copy
```

**samples**

binaries aren't hosted here (they're Teledyne's). both `CorMem.sys` and the
user-mode wrapper `CorMem.dll` ship inside the official Sapera LT SDK installer:

> https://www.teledynedalsa.com/en/products/imaging/vision-software/sapera-lt/

free download, requires a Teledyne account login. install on a throwaway VM and
pull `CorMem.sys` from `C:\Windows\System32\drivers\` (or the SDK's `bin` dir)
and `CorMem.dll` from the SDK runtime folder. verify SHA256 against the hashes
above before analyzing — 9.00 is what this writeup covers.

---

## AsIO3.sys — ASUS hardware access driver

ASUS's kernel hardware layer on every modern board (Armoury Crate stack), and
the current-gen successor to the blocklisted AsIO/AsIO2 — notably *harder* than
its ancestors, but with leftovers:

- **ungated PCI config read** via ports `0xCF8`/`0xCFC` (`0xa0400f70`) — every
  sibling port handler checks the port allowlist, this one doesn't
- physical page mapping through `\Device\PhysicalMemory`, `PAGE_READWRITE`,
  restricted to firmware/option-ROM regions (`0xE0000-0xFFFFF`, `0xF8000000+`)
  plus an **admin-writable registry allowlist**
- port I/O allowlist is real but wide: **`0xB2` SMI command port**, CMOS+NMI,
  EC/SIO index pairs
- `MmAllocateContiguousMemory(user_size)` returning VA **and physical address**
- `MmAllocateContiguousMemory`/`ZwUnmapViewOfSection(-1, user_ptr)` (wow64
  path) for controlled-crash primitives
- MSR rd/wr properly scoped to a curated Intel+AMD tuning table — this part is
  done right

**files**

- [`report/asio3/ANALYSIS.md`](report/asio3/ANALYSIS.md) — deep dive: full IOCTL map, dumped allowlists, primitive evidence
- [`report/asio3/asio3.h`](report/asio3/asio3.h) — reversed interface header
- [`report/asio3/poc_asio3.cpp`](report/asio3/poc_asio3.cpp) — read-only proof (PCI id, MSR 0xCE, port 0x80, alloc oracle)

**sample**

ships with Armoury Crate / the motherboard utility packages:

> https://www.asus.com/support/ (pick a board model → Driver & Utility → Armoured Crate)
> or grab the standalone "AsIO3" driver package from any ASUS board's support page

`AsIO3.sys` lands in `C:\Windows\System32\drivers\` (or inside the Armoury
Crate installer's extracted driver store). version analyzed: **1.02.40** — the
gates changed between releases, so hash-check before comparing:

```
version resource: 1.02.40, (C) 2022 Asustek Computer Inc.
device: \Device\Asusgio3        pdb: AsIO3_64.sys.pdb
```

---

## KslD.sys — Microsoft Defender KSL (Intel TDT command interface)

the big one. Defender's Kernel Signature Library embeds Intel's TDT command
set and exposes it through a single multiplexed IOCTL (`0x222044`): arbitrary
physical-memory page read, `MmGetSystemRoutineAddress` KASLR leak,
kernel-mode arbitrary file read, SPI BIOS flash read, process-attach by
arbitrary PID, and a virtual-memory copy primitive with separate read/write
flag bits.

the catch: `OpCreate` gates the device on **string comparison of the caller's
image path** against `AllowedProcessName` — a value the driver reads at init
from the service's `Parameters` registry key. HKLM, admin-writable. No token
check, no signature check — authentication by a registry string. an admin who
sets that value to their own image path passes the gate and gets kernel
physical-memory read through a Microsoft-signed driver; the mmcopy write path
being dead code keeps it at read-only, and the transient-instance timing keeps
it "moderate".

- [`report/ksld/ANALYSIS.md`](report/ksld/ANALYSIS.md) — full command reference, the gate and its registry source, impact matrix, recommendations

---

## MEmuDrv.sys — MEmu emulator's VirtualBox fork, hardening stripped

the strongest find of the hunt. MEmu's hypervisor driver is a **VirtualBox
SUPDrv fork** with the entire kernel primitive surface intact and the
hardening gone: no wintrust, no caller validation, the historical
*unrestricted* device (`\Device\MEmuDrvU`) still present.

the core defect is the ring-0 module loader. `SUP_IOCTL_LDR_OPEN` with a
**nonexistent filename** falls back to `RTMemExecAllocTag` — an RWX kernel
allocation with no file and no verification — and clears the flag that gates
the deeper entry-point validation in `SUP_IOCTL_LDR_LOAD`. the caller's image
and entry point are then registered and reachable through the fork's HPVR0
call path. plus `SUP_IOCTL_MSR_PROBER` (arbitrary rdmsr/wrmsr), kernel page
map/protect, and the full VBox R0 export surface for whatever gets loaded.

admin → kernel code execution via `CreateFile` + three IOCTLs on a driver
installed by a mainstream Android emulator, invisible to the blocklist.

- [`report/memudrv/ANALYSIS.md`](report/memudrv/ANALYSIS.md) — loader chain, fallback bypass, primitive table, blocklist case
- [`report/memudrv/memudrv.h`](report/memudrv/memudrv.h) — reversed interface header (full IOCTL table + unioned request structs)
- [`report/memudrv/poc_memudrv.cpp`](report/memudrv/poc_memudrv.cpp) — non-destructive PoC (handshake + session-ptr leak + LDR_OPEN fallback probe)

---

## disclosure

findings go to the vendor first, blocklist nomination to MSRC alongside.
analysis is published once a report is in the vendor's hands.

## contact / pgp

open an issue or reach out on the usual channels.

## license

[MIT](LICENSE)
