# Windows-Vuln-drivers

signed drivers that hand out kernel primitives to user mode, and aren't on
microsoft's vulnerable driver blocklist. each folder under `report/` is one
driver: full analysis, reversed interface header, non-destructive PoC.

## index

| driver | vendor | version | primitives | blocklist | cve |
|---|---|---|---|---|---|
| [CorMem.sys](report/cormem/ANALYSIS.md) | Teledyne Digital Imaging | 9.00 | arbitrary physical memory map, raw I/O port R/W, kernel pointer disclosure | not listed | none |
| [AsIO3.sys](report/asio3/ANALYSIS.md) | ASUSTeK | 1.02.40 | ungated PCI config read, firmware-region phys map (RW), wide port allowlist (SMI/CMOS/EC), contiguous alloc oracle | not listed | none |
| [KslD.sys / MpKslDrv](report/ksld/ANALYSIS.md) | Microsoft (Defender) | - | single provider-multiplexed IOCTL; PID-steering question open | n/a (in-box) | n/a |

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

## KslD.sys — Microsoft Defender Kernel Signature Library (MpKslDrv)

recon note, not a vuln report. the driver runs bugcheck-triage scanning for
Defender (bugcheck reason callbacks + triage dump blocks) and exposes exactly
one device IOCTL: `0x222044`, a C++ provider multiplexer. the interesting bit:
a caller-supplied dword (PID-shaped) flows into provider match/dispatch that
can open processes by ClientId — if a provider accepts it verbatim, that's an
admin→PPL-read relay through a Defender-signed driver. vtable reconstruction +
a live-instance test pending.

- [`report/ksld/ANALYSIS.md`](report/ksld/ANALYSIS.md) — surface map, vtable layout, open questions

---

## disclosure

findings go to the vendor first, blocklist nomination to MSRC alongside.
analysis is published once a report is in the vendor's hands.

## contact / pgp

open an issue or reach out on the usual channels.

## license

[MIT](LICENSE)
