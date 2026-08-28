# Windows-Vuln-drivers

signed drivers that hand out kernel primitives to user mode, and aren't on
microsoft's vulnerable driver blocklist. each folder under `report/` is one
driver: full analysis, reversed interface header, non-destructive PoC.

## index

| driver | vendor | version | primitives | blocklist | cve |
|---|---|---|---|---|---|
| [CorMem.sys](report/CorMem_Analysis.md) | Teledyne Digital Imaging | 9.00 | arbitrary physical memory map, raw I/O port R/W, kernel pointer disclosure | not listed | none |

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

- [`report/CorMem_Analysis.md`](report/CorMem_Analysis.md) — full writeup with assembly evidence, IOCTL map, IOCs, remediation
- [`report/cormem.h`](report/cormem.h) — reversed interface header (all ioctls + structs)
- [`report/poc_cormem.cpp`](report/poc_cormem.cpp) — non-destructive proof (func table leak, RTC port read, phys map)

**hashes**

```
40C855D20D497823716A08A443DC85846233226985EE653770BC3B245CF2ED0F   signed
9977054734C44B080FB26FE8F296CD3CCEBACF2BDB7949617AECB14064A42247   unsigned copy
```

**getting the samples**

binaries aren't hosted here (they're Teledyne's). both `CorMem.sys` and the
user-mode wrapper `CorMem.dll` ship inside the official Sapera LT SDK installer:

> https://www.teledynedalsa.com/en/products/imaging/vision-software/sapera-lt/

free download, requires a Teledyne account login. install on a throwaway VM and
pull `CorMem.sys` from `C:\Windows\System32\drivers\` (or the SDK's `bin` dir)
and `CorMem.dll` from the SDK runtime folder. verify SHA256 against the hashes
above before analyzing — the SDK version line matters, 9.00 is what this writeup
covers. older 8.x builds are floating around with the same interface.

---

## disclosure

findings go to the vendor first, blocklist nomination to MSRC alongside.
analysis is published once a report is in the vendor's hands.

## contact / pgp

open an issue or reach out on the usual channels.

## license

[MIT](LICENSE)
