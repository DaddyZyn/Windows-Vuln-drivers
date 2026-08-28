# AsIO3.sys — ASUS hardware access driver (v1.02.40): deep analysis

**Affected driver:** `AsIO3.sys` 1.02.40 x64, device `\Device\Asusgio3`
**Vendor:** ASUSTeK Computer Inc. (valid Authenticode)
**Distribution:** ASUS Armoury Crate / motherboard support packages
**Blocklist status:** not listed; not in public vulnerable-driver feeds (predecessors AsIO.sys / AsIO2.sys **are** blocklisted)
**Analysis date:** 2026-08-28 · static, x64 build, PDB `AsIO3_64.sys.pdb`

---

## 1. Executive summary

AsIO3 is ASUS's current-gen hardware access driver and the successor to the
blocklisted AsIO/AsIO2. It is **substantially hardened compared to its
ancestors**: port I/O runs through a real allowlist, MSR read/write is scoped to
a curated dual-vendor (Intel + AMD) tuning set, and physical memory mapping is
funneled through a range validator. That said, several surfaces remain that an
administrator can abuse, and a few that are outright ungated:

| # | Surface | Gate | Severity |
|---|---|---|---|
| 1 | PCI config space read via `0xCF8/0xCFC`, arbitrary bus/dev/fn/reg (`0xa0400f70`) | **none** | medium (disclosure) |
| 2 | I/O port allowlist is wide: includes `0xB2` (SMI command), `0x70-0x7E` (CMOS/NMI), EC/SIO, ACPI ports | allowlist | low-med |
| 3 | Physical page map (`\Device\PhysicalMemory`), **PAGE_READWRITE**, restricted to firmware/MMIO ranges + registry-extendable table (`0xa040200C` etc.) | range validator | medium (registry extension is admin-writable) |
| 4 | `MmAllocateContiguousMemory(user_size)` returning VA + physical address (`0xa0400f90`) | none | low (oracle/spray) |
| 5 | `MmFreeContiguousMemory(user_ptr)` (`0xa0400f94`), 32-bit `ZwUnmapViewOfSection(-1, user_ptr)` (`0xa0402450`) | none | low (bugcheck/DoS) |
| 6 | Memory-space read via `HalTranslateBusAddress` result deref (`0xa0406400`+ family) | weak (low-16 port allowlist) | medium |
| 7 | RDMSR (`0xa0400f88`, `0xa0406458`) / WRMSR (`0xa0400f8c`) | curated MSR table | low (as shipped) |

Net: not a BYOVD goldmine like AsIO2 was — but the ungated PCI config read,
the SMI/CMOS-capable port list, firmware-region write mapping, and the
admin-extensible validation tables are worth vendor attention, and the driver
does not validate *which process* issues IOCTLs (the process-tracking subsystem
is bookkeeping, not access control).

---

## 2. Attack surface

- Device `\\.\Asusgio3`, default WDM ACL → openable by admin/SYSTEM.
- WDM dispatch at `sub_140001960`; ~30 IOCTLs on device type `0xa040`.
- `WaitForIoAccess` named event (`\BaseNamedObjects\WaitForIoAccess`) serializes
  operations — arbitration between ASUS components, **not** a security gate.
- `PsSetCreateProcessNotifyRoutineEx` tracks ASUS service image names in a
  fixed-slot table (callback at `sub_140003C10` clears slots on process exit).
  Used for bookkeeping/cleanup; **no IOCTL path denies access based on caller**.
- Dynamic imports: `MmGetPhysicalMemoryRangesEx2`, `ZwQueryInformationProcess`.
  Static imports of note: `MmMapIoSpace`, `MmAllocateContiguousMemory`,
  `HalGetBusDataByOffset`, `HalSetBusDataByOffset`, `HalTranslateBusAddress`,
  `ZwOpenSection`, `ZwMapViewOfSection`, embedded SHA-256 (cert service
  integration via `C:\Program Files (x86)\ASUS\AsusCertService`).

### IOCTL map (confirmed immediates in `sub_140001960`)

| IOCTL | Handler | Function |
|---|---|---|
| `0xa0400f58` | `0x140001e18` | port read, indexed, width-dword (see 4.2) |
| `0xa0400f5c` | `0x140001dbb` | port read, width-word |
| `0xa0400f60` | `0x140001d3e` | EC-style write sequence (len 0x14) |
| `0xa0400f64` | `0x140001cc2` | EC-style write sequence |
| `0xa0400f68` | `0x140001c66` | EC-style write sequence |
| `0xa0400f6c` | `0x140001c07` | EC-style write sequence |
| `0xa0400f70` | `0x140001b8f` | **PCI config read** (see 4.1) |
| `0xa0400f74` | `0x140001b07` | bulk port read loop (>= 0x20C in, 512B out) |
| `0xa0400f78` | `0x140001a74` | indexed out/in bulk loop (>= 0x20C in) |
| `0xa0400f80` | `0x1400021dd` | -> `sub_1400043D0` (map bookkeeping) |
| `0xa0400f84` | `0x1400021d0` | -> `sub_1400040D4` (map bookkeeping) |
| `0xa0400f88` | `0x140002185` | **RDMSR** `{u32 msr}` -> `{u64 val}`, table-gated |
| `0xa0400f8c` | `0x140002142` | **WRMSR** `{u32 msr, u64 val}`, table-gated |
| `0xa0400f90` | `0x1400020cd` | **contiguous alloc** (see 4.4) |
| `0xa0400f94` | `0x1400020ab` | **contiguous free by user ptr** |
| `0xa0400f7c` | `0x1400021ea` | map query/op, sub-cmd `0x1020`/`0x1028` |
| `0xa0402000` | `0x140001fd8` | tracked-map op |
| `0xa0402004` | `0x140001f17` | port write (len 0x14, allowlist-gated) |
| `0xa040200C` | -> `sub_1400041D0` | **physical page map** (see 4.3) |
| `0xa0402014` | `0x1400023bb` | tracked-map read (len >= 0x23) |
| `0xa0402018` | `0x140002342` | tracked-map op (len >= 0x23) |
| `0xa040244c` | `0x14000256e` | tracked-map op |
| `0xa0402450` | `0x1400022ce` | **unmap / arbitrary ZwUnmapViewOfSection** (see 4.5) |
| `0xa0406400/01/04/05/08` | -> `sub_14000275C` | **HalTranslateBusAddress port/mem read** (see 4.6) |
| `0xa040640C` | falls through | (unrouted immediate; likely reserved) |
| `0xa0406458` | -> `sub_140003C48` | RDMSR variant, `msr >= 8`, 8-byte out |
| `0xa040a440/44/48` | -> `sub_140002888` | port **write** byte/word/dword via HalTranslate + allowlist |

## 3. Validation machinery (what the hardening actually does)

### 3.1 Port allowlist — `sub_14000143C`

Static table at `0x140009080`, 43 `{u16 base, u16 len}` ranges. Dumped:

```
002E-002F   0040-005E   0060-006E   0070-007E   0080        0084-008E
00B2        00E0        00EB        00ED        0200-021F   025C-025D
0270        0278-027E   0295-0296   02A0-02AE   02C0        02C2-02C5
02CE        02E8-02EE   02F8-02FE   0378-037E   0381-0383   03E8-03EE
03F8-03FE   0406        0500        0502        0800-0805   0830
0A00-0A7F   0AA0-0AA6   0B00-0B3E   0CD6-0CD7   0CF8-0CF9   0CFC
1800        1802        1830        1C00-1C3E   EFA0-EFBE   F000-F00E
F040-F07E
```

Plus a runtime-extendable table (header ptr pair `0x1400093D0/0x1400093D8`,
count `+0x14`); no `.text` writer — populated externally (registry config via
`ZwOpenKey`/`ZwQueryValueKey` at `0x140002E64/0x140002EAC` is the likely feed).

Notable inclusions: **`0xB2` = APM/SMI command port** (SMI generation),
**`0x70-0x7E`** = CMOS+NMI (write can toggle NMI sources), **`0xCF8/0xCFC`** =
PCI config mechanism-1 ports themselves, EC/SIO index-data pairs (hardware
control: fans, LEDs, battery, board ID), ACPI PM ranges.

### 3.2 Physical range validator — `sub_140001514`

Applied before `\Device\PhysicalMemory` maps (`sub_140003F58` calls it first;
failure = `STATUS_ACCESS_DENIED`). Three layers:

1. A linked list of pre-registered allowed ranges (populated at DriverEntry —
   the node-builder at `0x140001740`-region wires the list head), matching the
   exact physical address `rcx`.
2. A static 2-entry `{u64 base, u64 len}` table at `0x140009130`:
   - `0x00000000000E0000` + `0x20000` → `0xE0000-0xFFFFF` (firmware/option-ROM area below 1MB)
   - `0x00000000F8000000` + `0x07FFFFFF` → `0xF8000000-0x17FFFFFE` (firmware/MMIO hole)
   Logic: overlap with an entry **permits** the map (the driver's own use case
   is firmware/EC/SIO MMIO), i.e. normal RAM is the thing being *excluded*.
3. A registry-fed dynamic table (ptr pair `0x1400093DC`-adjacent, count at
   `+0x34`, entries from `+0xC`) — same external-population pattern as 3.1.

**The catch:** ranges live in registry-readable/writable config (HKLM). An
administrator that can write the ASUS service's configuration key extends the
allowed set to arbitrary RAM. The static entries also permit **read-write**
mapping (`Protect = 4`, `0x140004024`) of `0xE0000-0xFFFFF` — SMBIOS/DMI and
option-ROM shadow tampering territory.

### 3.3 MSR allowlist — `sub_1400014BC`

Static table at `0x140009000`, 29 dwords:

```
0x00000035 0x000000CE 0x00000150 0x00000194 0x00000198 0x000001A2
0x000001B1 0x000001A0 0x000001AD 0x000001AE 0x00000606 0x00000610
0x00000611 0x00000614 0x00000620 0x00000650 0x00000651 0x00000770
0x00000774 0xC0010015 0xC0010061 0xC0010062 0xC0010063 0xC0010064
0xC0010065 0xC0010066 0xC0010071 0xC0010292 0xC0010293
```

Intel power/turbo set (`PM_ENABLE`, `PLATFORM_INFO`, `TURBO_RATIO_LIMIT`,
`MISC_ENABLE`, `TEMPERATURE_TARGET`, RAPL `PKG_POWER_LIMIT`/`ENERGY`/`DRAM_*`)
plus AMD P-state/`CofVid` MSRs (`0xC00100xx`) — dual-vendor support. RAPL
`WRMSR` allows hardware power-limit manipulation (throttling/thermal games,
board-dependent), but no kernel-memory-relevant MSR is exposed. Appropriately
scoped as shipped; runtime extension is the only open question.

## 4. Primitive details

### 4.1 PCI config read — `0xa0400f70` (ungated)

```asm
0x140001BD7: mov eax, dword ptr [rcx]      ; user CONFIG_ADDRESS
0x140001BD9: mov edx, 0xcf8
0x140001BDE: out dx, eax                   ; bus<<16 | dev<<11 | fn<<8 | reg&0xFC
0x140001BDF: mov edx, 0xcfc
0x140001BE4: in eax, dx                    ; CONFIG_DATA
0x140001BE5: mov dword ptr [r8 + rcx + 0xA], eax
0x140001BEA: add dword ptr [rcx], 4        ; auto-advance
```

Input `{u32 addr; u8 pad[4]; u16 count; ...}`, output dwords at `+0xA`
(requires `InputBufferLength >= 0x20C`, so up to 512 dwords per call). **No
allowlist call in this branch** — every sibling port handler calls
`sub_14000143C`, this one does not. Full config-space read of all PCI
functions: device inventory (including hidden/deviously-configured devices),
BARs (physical memory layout disclosure), MSI-X tables' BIRs, capabilities.
Read-only as shipped; no matching config-*write* path via CF8/CFC was found
(`HalSetBusDataByOffset` is imported but its call sites are gated elsewhere).

### 4.2 Bulk port I/O — `0xa0400f74` / `0xa0400f78` (allowlisted)

`{u16 port @+4, u16 count @+8, u8 value @+6, u8 data[512] @+0xA}`, count
checked against `0x200`. `0xa0400f74` loops `in al,dx` incrementing port;
`0xa0400f78` loops `out dx,value; port++; in al,port` (indexed read pattern —
SMBUS/EC style). Every iteration consults `sub_14000143C`. Within the
allowlist this still buys: CMOS read/write incl. NMI-disable tricks (0x70),
EC/SIO register manipulation (fans, LEDs, board sensors), SMI triggering via
0xB2, and PCI config bytes via the CF8/CFC entries.

### 4.3 Physical page map — `0xa040200C` -> `sub_1400041D0` -> `sub_140003F58`

Sub-command `0x1020` takes the physical address as `{u32 lo @+0x10, u32 hi @+0x14}`;
`0x1028` as qword `@+0x18`. Address is page-aligned, validated by
`sub_140001514` (3.2), then mapped: `ZwOpenSection(\Device\PhysicalMemory,
SECTION_MAP_READ|WRITE|QUERY)`, `ObReferenceObjectByHandle`,
`ZwMapViewOfSection(Protect=PAGE_READWRITE)`, `lfence`-hardened after the
section handle deref (Spectre v1). View is tracked in a linked-list node
`{phys, kernel VA, section object}` — the same records `0xa0402450` consumes.

Consequence: admin can map (and **write**) the firmware area `0xE0000-0xFFFFF`
(SMBIOS/DMI, option-ROM shadows), the MMIO hole, and whatever ASUS registers at
runtime — plus any range added to the registry-driven allowlist.

### 4.4 Contiguous allocator — `0xa0400f90` / `0xa0400f94`

- `0xa0400f90`: `MmAllocateContiguousMemory(Size=[in+0x10], HighestAcceptable=-1)`
  — **user-controlled size**; result VA stored to `[in+0x20]`, its physical
  address (`MmGetPhysicalAddress`) to `[in+0x18]`, both copied back to the
  caller. A physical-address oracle + DMA-suitable buffer placement primitive.
- `0xa0400f94`: `MmFreeContiguousMemory([in+0x20])` — frees whatever pointer
  the caller supplies. Non-allocated addresses bugcheck; this is a
  controlled-crash / state-confusion primitive, not corruption per se.

### 4.5 Unmap — `0xa0402450`

- 64-bit path (`InputBufferLength == 0x28`): `{pad16, u64 handle @0x10,
  u64 base @0x18, u64 object @0x20}` -> `sub_140003DC8`: mutex-held unlink of
  the tracking node matching `{handle, base}`, `ZwUnmapViewOfSection(-1, base)`,
  `ObfDereferenceObject`, `ZwClose`. The intended API — arguments must match a
  tracked view.
- 32-bit path (`InputBufferLength == 4`): **`ZwUnmapViewOfSection(-1,
  *(PVOID*)SystemBuffer)` directly** — arbitrary address unmapped in the
  (system) process context. Unmapped-in-use address = bugcheck inside the
  kernel; tracked-state bypass confuses later bookkeeping. DoS-grade, no
  write primitive observed.

### 4.6 HalTranslateBusAddress family — `0xa0406400/01/04/05/08` -> `sub_14000275C`

`HalTranslateBusAddress(Isa, bus 0, {u32 bus-relative addr @in}, &space=1,
&translated)`; then `sub_14000143C` checks the **low 16 bits** of the
translated address; if HAL reports I/O space → `in al/ax/eax,dx` read into the
user buffer (width by IOCTL: 6400=byte, 6404=word, 6408=dword; the 601/605
variants take width from the 5th dispatch argument). If HAL reports **memory
space**, the handler dereferences the translated kernel VA directly
(`mov eax, [rax]`). Memory-space translation of a user-chosen bus address with
only a 16-bit I/O-port check is a thin gate — vendor should reject memory-space
translations outright here.

### 4.7 MSR — `0xa0400f88` (rdmsr), `0xa0400f8c` (wrmsr), `0xa0406458` (rdmsr v2)

Input `{u32 msr @0, u64 value @8}` / output `{u64 @8}`, length 0x10 enforced,
table check `sub_1400014BC` before each access. The `0xa0406458` variant
requires `msr >= 8` and 8-byte output. All three consult the same static table
(3.3). A fourth wrmsr/rdmsr pair exists at `0x140003F1A/0x140003F22` inside the
`sub_140003E2F` helper (used by tracked-map paths) — same gate family.

## 5. What's NOT here (vs AsIO2)

- No unvalidated arbitrary physical map of system RAM (range validator, even if
  extendable, is a real barrier for RAM).
- No ungated arbitrary port I/O (43-range allowlist).
- No token/process/kernel-write IOCTLs (nothing calls `MmCopyVirtualMemory`-
  class APIs; no `ZwOpenProcess`).
- No caller-process *authentication* either — but no caller-gated privilege
  difference to exploit; everything above is reachable by any admin handle.

## 6. Recommendations (vendor)

1. Gate `0xa0400f70` (PCI config) to ASUS device IDs or drop it — reading the
   whole bus is not a legitimate consumer use case.
2. Remove `0xB2` (SMI command) and narrow CMOS entries in the port allowlist.
3. Reject memory-space results from `HalTranslateBusAddress` (4.6).
4. Make the dynamic port/phys allowlists non-admin-writable (signed blob or
   kernel-hardcoded), or drop them.
5. Map firmware regions `PAGE_READONLY` unless the consumer documents writes.
6. Remove the 32-bit `ZwUnmapViewOfSection` shortcut.

## 7. Reproduction

See `asio3.h` (interface) and `poc_asio3.cpp` (non-destructive: PCI vendor/
device ID read of the host bridge, allowlisted MSR read of `0xCE`
PLATFORM_INFO, contiguous alloc + physical address oracle). All read-only.

## 8. Disclosure status

Static analysis complete for the primary surfaces; open items: runtime
population of the dynamic tables, `HalSetBusDataByOffset` call sites, the
`AsusCertService` handshake (`sub_14000143C`'s certificate-adjacent siblings).
Report to ASUSTeK PSIRT + MSRC note (blocklist inclusion likely **not**
warranted given the hardening; vendor fix recommended).
