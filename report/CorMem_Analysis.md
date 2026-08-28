# Vulnerability Analysis: Teledyne Sapera LT `CorMem.sys` — Arbitrary Physical Memory Mapping

**Classification:** Kernel Arbitrary Physical Memory Read/Write (CWE-125 / CWE-787 via CWE-20)
**Affected driver:** `CorMem.sys` 9.00 (aka `Svc_*.sys` when deployed), "Sapera Memory Manager", Sapera LT SDK
**Vendor:** Teledyne Digital Imaging Inc.
**Status:** Not on Microsoft Vulnerable Driver Blocklist; no CVE assigned; documented in-the-wild BYOVD abuse
**Analysis date:** 2026-08-28

---

## 1. Executive Summary

`CorMem.sys` is the kernel-mode memory manager shipped with the Teledyne Sapera LT
machine-vision SDK. It creates a user-openable device `\\.\CORMEM` and exposes a set
of buffered IOCTLs intended for DMA/window management for frame grabber hardware.

One of these IOCTLs (`0x22200c`) maps an **arbitrary, fully user-controlled physical
address** into kernel space via `\Device\PhysicalMemory` and returns the resulting
kernel virtual address to the caller. There is no validation of the physical address,
no size restriction, and no access-model check. A companion 64-bit-friendly variant
(`0x222034`) offers the same primitive with a WOW64-compatible input encoding.

Any administrator process can therefore obtain read/write access to all of physical
memory, defeating kernel-mode protections (credential theft, EDR/AV tampering,
kernel callback removal, code injection into kernel-space). Because the driver is
validly WHQL-style signed, it loads on systems with default driver-signature policy.

This primitive is **not hypothetical**: the driver family is catalogued as an actively
abused BYOVD target (execution parents incl. Cobalt Strike / IcedID loaders and
game-cheat kernel loaders; 0/71 VirusTotal detection at time of feed entry).

Additional risk amplifier observed in the wild: the SDK installer drops **multiple
randomly-named copies** (`Svc_XXXXXXXX.sys`) into `System32\drivers`, **some of them
unsigned or with broken signature chains**, on machines where the SDK was installed.

---

## 2. Driver Identification

| Property | Value |
|---|---|
| Original name | `CorMem.sys` |
| Description | Sapera Memory Manager |
| Version | 9.00 (build date string 1997–2024) |
| Machine/Subsystem | x64 / Native (kernel) |
| Signed sample SHA256 | `40C855D20D497823716A08A443DC85846233226985EE653770BC3B245CF2ED0F` |
| Unsigned sample SHA256 | `9977054734C44B080FB26FE8F296CD3CCEBACF2BDB7949617AECB14064A42247` |
| Signer | CN=Teledyne Digital Imaging Inc. |
| Device | `\Device\CORMEM`, symlink `\DosDevices\CORMEM` |
| Registry params | `\REGISTRY\Machine\System\CurrentControlSet\Services\CorMem\Parameters` |
| Deployment pattern | `Svc_<8 random chars>.sys` copies in `System32\drivers` |

Sample presence observed: 10 copies on one host — 6 valid-signed (identical hash),
4 unsigned/stripped (identical hash). Both binaries expose the same interface.

---

## 3. Attack Surface

### 3.1 Device creation (`DriverEntry` → `0x140004a??`)

- `IoCreateDevice` + `IoCreateSymbolicLink` (`0x140004bab`, `0x140004c02`).
- **No `IoCreateDeviceSecure`, no explicit SDDL/security descriptor.**
- Result: default WDM device ACL → device openable by **Administrators and SYSTEM**.
- Standard BYOVD preconditions (admin → kernel) are met.

### 3.2 IOCTL map (reconstructed from dispatch `0x140002c5c`–`0x1400034xx`)

All IOCTLs: `FILE_DEVICE_UNKNOWN (0x22)`, `FILE_ANY_ACCESS`, `METHOD_BUFFERED`.
Constant-folded switch chains (`sub eax, 0x222000 …`) hide most codes from naive
immediate-scanning.

| IOCTL | Handler | Reconstructed semantics | Confidence |
|---|---|---|---|
| `0x222000` | → `0x1400067e8` | info/status query, returns ≤ `0x1c`-byte record | medium |
| `0x222004` | → `0x140002ef4` | object free/release by handle+id | medium |
| `0x222008` | inline | returns 88-byte table of 15 **kernel code pointers** | high |
| `0x22200c` | → `0x140006154` → `0x14000147c` | **arbitrary physical memory map (see §4)** | **high** |
| `0x222010` | → `0x140006e40` | unknown (arg-plumbing identical to siblings) | low |
| `0x222014` | → `0x140006aa4` | **arbitrary I/O port READ** (`in al/ax/eax, dx`), port from input | **high** |
| `0x222018` | → `0x140006f7c` | **arbitrary I/O port WRITE** (`out dx, al/ax/eax`), port+value from input | **high** |
| `0x22201c` | → `0x1400060a0` | MDL-based lock/map (see §5) | medium |
| `0x222020`–`0x222030` | `0x140002f88` switch | object/pool management | low |
| `0x222034` | inline at `0x140002fc6` | **arbitrary 64-bit physical map, WOW64 split fields** | **high** |
| `0x222038` | → `0x1400031cc` | query | low |
| `0x22203c`/`0x222054`/`0x222058` | `0x14000320e` region | query/config | low |

### 3.3 Kernel pointer disclosure (`0x222008`)

Copies a static table of 15 kernel function pointers (`0x140002d04`–`0x140002db4`,
pointer array built on stack, `min(InputLen, 0x88)` bytes out) to user mode. Useful
to an attacker for KASLR defeat of the driver image itself.

---

## 4. Primary Primitive: Arbitrary Physical Memory Map (`0x22200c`)

### 4.1 Call chain

```
DeviceIoControl(\\.\CORMEM, 0x22200c, inbuf, ...)
  └ dispatch (0x140002e1e switch, case 0x22200c → 0x140002eda)
      └ 0x140006154   arg checks + struct rebuild
          └ 0x14000147c   internal map routine
              ├ RtlInitUnicodeString(L"\Device\PhysicalMemory")   ; 0x1400014c1
              ├ ZwOpenSection(..., SECTION_ALL_ACCESS 0xF001F)     ; 0x140001509
              ├ ObReferenceObjectByHandle(..., 0xF001F)            ; 0x140001560
              ├ ZwMapViewOfSection(SectionOffset = user WindowBase,
              │                    Protect = 4 (PAGE_READWRITE))   ; 0x140001688
              └ out_va = mapped_base + (PhysicalAddress − WindowBase); ZwClose
```

### 4.2 Input encoding (64-bit process)

`SystemBuffer` (24 bytes consumed; 16 used):

```c
struct CORMEM_MAP_REQ_64 {
    uint64_t PhysicalAddress;   // +0x00 → [rbp-0x30] target physical address
    uint64_t WindowBase;        // +0x08 → [rbp-0x28] view window base (SectionOffset)
    uint64_t Reserved;          // +0x10 → read, then overwritten with 1 internally
};
```

Evidence (`0x1400061e3`–`0x140006221`):

```
movups xmm0, [r8]                    ; load {+0x00,+0x08}
movsd  xmm1, [r8+0x10]               ; load +0x10 (discarded)
mov    dword ptr [rbp-0x20], 1       ; hardcoded flag
mov    qword ptr [rbp-0x30], r14     ; PhysicalAddress
mov    qword ptr [rbp-0x28], r15     ; WindowBase
call   0x14000147c                   ; map routine
```

No bounds, alignment, MMIO-whitelist, or region-type validation is performed on
`PhysicalAddress` or `WindowBase` at any point in the chain.

### 4.3 Mapping semantics (`0x14000147c`)

- `ZwOpenSection` on `\Device\PhysicalMemory` with `SECTION_ALL_ACCESS` (0xF001F),
  `ObjectAttributes` `0x240` (case-insensitive) — always succeeds in kernel context.
- `ZwMapViewOfSection` with `BaseAddress` = 0 (kernel-chosen), `SectionOffset` =
  user `WindowBase`, `Protect` = 4 (`PAGE_READWRITE`) hardcoded at `0x14000164d`.
- Returned VA compensates for window offset: `out = view_base + (phys − window)`
  (`0x140001741`–`0x140001756`), written to caller out-pointers, handle closed.
- View covers `WindowBase → PhysicalAddress + size` (size derived from
  `esi`/`[rcx+0x10]`, `-1` sentinel path at `0x1400015a5`).

### 4.4 Result

The driver copies back exactly one qword — the kernel virtual address of the
requested physical page (`0x1400062b0`–`0x1400062bf`; dword-truncated for
32-bit processes). Attacker selects any physical address (e.g. the physical
backing of any kernel structure, other processes' pages, SMM-reserved regions
below 4 GB, UEFI runtime services data) and receives a kernel VA aliasing it.
Combined with §5.2 (pointer table) this is a complete admin→kernel compromise
primitive set: physical R/W + raw port I/O + image-base disclosure.

### 4.5 WOW64 variant (`0x222034`)

Inline handler at `0x140002fc6` accepts a 16-byte struct of two dwords +
two dwords (64-bit value split), reconstructs the 64-bit physical address,
and calls the shared map routine (`0x140002988`). Same primitive, 32-bit-friendly.

---

## 5. Secondary Primitives

### 5.1 Arbitrary I/O port access (`0x222014` read / `0x222018` write)

Confirmed handlers execute raw ring-0 port I/O with **user-supplied port numbers**:

```
0x140006b4a: movzx edx, word ptr [rsp+0x24]   ; port from SystemBuffer
0x140006b4f: in   eax, dx                     ; width 3: dword read
0x140006b52: in   ax,  dx                     ; width 2: word read
0x140006b5e: in   al,  dx                     ; width 1: byte read
0x140006b67: mov  dword ptr [r8], eax         ; result -> SystemBuffer

0x140007013: movzx edx, word ptr [rsp+0x24]   ; port from SystemBuffer
0x140007018: out  dx, eax                     ; width 3/2/1: dword/word/byte write
```

Input encoding: `{Width (1|2|3), Port [, Value]}` as packed dwords. No port
whitelist, no HAL translation, no device ownership check. This grants
user-mode code the ability to program arbitrary legacy hardware (DMA
controllers, PIC, RTC, vendor SMI ports) — sufficient for a variety of
hardware-level attacks and a classic precursor to SMM-oriented abuse.

### 5.2 Kernel pointer disclosure (`0x222008`)

A static table of **15 kernel code pointers** (88 bytes) is copied to the caller
(`0x140002d04`–`0x140002db4`), disclosing the driver image base and internal
function layout — a direct KASLR defeat for the driver and a foothold for
signing/verifying further manipulation of the driver in memory.

### 5.3 MDL user-page lock/map (`0x22201c`)

Handler family using `MmProbeAndLockPages` (`0x140002b87`, `LockOperation`,
`KernelMode` probe), an MDL linked-list walk, and `MmMapLockedPagesSpecifyCache`
(`0x140002988` region) locks **caller-supplied user pages** and returns kernel
mappings with lock refcount management (`MmUnlockPages`/`IoFreeMdl` cleanup at
`0x140002c16`–`0x140002c33`). While probing makes this less directly abusable,
it provides a stable kernel alias of user memory useful for relayed writes and
for staging payloads into kernel-visible memory.

---

## 6. Impact

An unprivileged-code-in-admin-context threat model (the standard BYOVD model:
malware already executing with administrator privileges, but not in kernel) obtains:

- Read/write access to **all physical memory**, including kernel pools, HAL, and
  other processes' physical pages.
- **Raw I/O port access** (both read and write), enabling direct legacy-hardware
  manipulation (DMA controllers, interrupt controllers, RTC, SMI command ports).
- Arbitrary kernel code execution potential (primitive is sufficient for patching
  kernel code/data, forging kernel structures, or defeating code-integrity policy).
- Concretely observed downstream behavior for this driver family in threat reports:
  EDR/AV kernel callback removal, credential material theft, loader staging for
  unsigned kernel images.

Because the binary is validly signed and **absent from the Microsoft Vulnerable
Driver Blocklist**, HVCI-enabled systems will accept it; the blocklist gap makes it
a dependable, low-detection primitive for abuse (0/71 VT detection recorded).

## 7. Known Exploitation

- Catalogued in public vulnerable-driver feeds (entry: `CorMem.sys`, MITRE T1068).
- Documented wrapper API set includes `CorMemGetPhysMemory`, `CorMemMapPhysMemory`,
  `CorMemAllocPhysMemory`, `CorMemReadIo`, `CorMemWriteIo` (`CorMem.dll`).
- Execution parents documented: Cobalt Strike, IcedID, game-cheat kernel loaders.

---

## 8. Indicators of Compromise

| Type | Value |
|---|---|
| Device symlink | `\DosDevices\CORMEM` / `\\.\CORMEM` |
| Driver original name | `CorMem.sys` |
| Deployed names | `Svc_*.sys` (8 random alnum chars) in `System32\drivers` |
| SHA256 (signed) | `40C855D20D497823716A08A443DC85846233226985EE653770BC3B245CF2ED0F` |
| SHA256 (unsigned) | `9977054734C44B080FB26FE8F296CD3CCEBACF2BDB7949617AECB14064A42247` |
| Pool/trace strings | `CORMEM.SYS: CORMEMDISPATCH => Unknown IOCTL`, `\Device\CORLOG` |
| Service names | per-install random, pointing at `Svc_*.sys` |

Hunting: `Get-ChildItem C:\Windows\System32\drivers\Svc_????????.sys` (8-char),
hash-match the above, and check `\Device\` for `CORMEM`/`CORLOG` object existence.

---

## 9. Remediation Recommendations

1. **Vendor (Teledyne):**
   - Replace physical-memory mapping with `MmMapIoSpaceEx` restricted to frame
     grabber BAR ranges discovered via the PCI interface; reject anything else.
   - Use `IoCreateDeviceSecure` with a restrictive SDDL (Sdl/Sec) or admin-only +
     interactive-lock; enforce `FILE_ANY_ACCESS` removal (add per-IOCTL access checks).
   - Stop shipping unsigned copies; repack installer to use a single fixed,
     signed driver name (the `Svc_XXXXXXXX` randomization defeats name-based policy).
2. **Microsoft (blocklist nomination):**
   - Add `CorMem.sys` (both hashes; filename rules `CorMem.sys`, `Svc_*.sys` weak
     match not feasible — hash rules primary) to the Microsoft Vulnerable Driver
     Blocklist. Justification: active BYOVD abuse, no legitimate in-box dependency.
3. **Defenders:** block via WDAC/Smart App Control hash or App Control for Business
   policy; alert on `Svc_*.sys` creations and `\Device\PhysicalMemory` section
   access by non-system processes.

---

## 10. Reproduction

See `poc_cormem.cpp` (compiles as x64 user-mode C++, links `advapi32`).
The PoC maps the fixed physical page backing `KUSER_SHARED_DATA` (`0xFFDF0000`)
through the driver and compares against the user-mode alias at `0x7FFE0000` —
a non-destructive, deterministic proof of the primitive.
