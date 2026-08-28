# KslD.sys / MpKslDrv — Microsoft Defender KSL: Intel TDT command interface gated by an admin-writable registry string

**Driver:** `KslD.sys` ("KSLD", internal `MpKslDrv`) — Microsoft Defender Kernel
Signature Library embedding **Intel TDT** (`tdt_driver_lib`, Threat Detection
Technology / IPT telemetry). Deployed as transient per-scan instances
(`MpKsl<hex>`) under `System32\drivers\` and `System32\drivers\wd\`.
**Signer:** Microsoft Windows (inbox, WHQL)
**Status:** full static analysis (IDA Pro 9.3 headless + Hex-Rays, 4 passes)
**Finding:** kernel command interface (physical memory read, routine-address
leak, kernel file read, SPI flash read) whose only access control is an image-
path string comparison against `AllowedProcessName` — **a value read from the
service's Parameters registry key, writable by administrators**
**Analysis date:** 2026-08-28

---

## 1. Summary

MpKslDrv exposes one IOCTL (`0x222044`, buffered) implementing an Intel TDT
command interface through three command objects. Sub-commands include
**arbitrary physical-memory page read** (attach + `\device\physicalmemory`),
**kernel routine-address disclosure** (`MmGetSystemRoutineAddress` with a
caller-supplied name), **kernel-mode arbitrary file read**, **SPI BIOS flash
read** (direct SPI-cycle driving, Intel + AMD paths), process connection by
arbitrary PID, and per-CPU register reads.

Access control:

1. Device SDDL: `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` (SYSTEM/Administrators only).
2. `CDeviceKsl::OpCreate` compares the **caller's image path** (`ProcessImageFileName`)
   against the `AllowedProcessName` registry value — a plain
   `RtlCompareUnicodeString`. No token, capability, or signature check.

`AllowedProcessName` is read at device initialization from the service's
Parameters key (`CDeviceBase::getParamFromRegistry`), i.e. **HKLM, writable by
administrators**. An administrator who sets `AllowedProcessName` to a path they
control passes the gate, connects, and obtains **kernel physical-memory read
via a Microsoft-signed driver** — crossing the admin→kernel boundary for
reads (credential/structure/key material disclosure, KASLR defeat).

Severity: **moderate elevation (admin → kernel read)**, gated on winning a
configuration window against MsMpEng (§5). The categorical defect is that a
kernel command interface is protected by a registry string + image-name
comparison instead of a token/capability check.

## 2. Architecture

```
MsMpEng ──creates transient service + config──▶ MpKsl<hex> instance
admin process ──CreateFile──▶ OpCreate:
      caller image path == registry AllowedProcessName ?  ──✕--> ACCESS_DENIED
                                       │ pass ("connected")
      └──DeviceIoControl 0x222044──▶ CDeviceKsl::OpDeviceControl
          for each command in device+240 list:
              IsSupported(subcmd)  → Handle(subcmd, in, out)
              CCommand (0,1,2,7,8,0xB,0xC) | CCommandFile (3,4,5,6,9)
              | CCommandROM (0xE..0x13)
```

Device setup (`CDeviceKsl::Initialize`, `0x140004E80`):
- `WdfDeviceInitAssignSDDLString(&SDDL_DEVOBJ_SYS_ALL_ADM_ALL)` — admin/SYSTEM only
- Device name from registry `DeviceName` value (per-instance randomization)
- Queue configured with `CDeviceKsl::Create`/`Cleanup` callbacks
- Three command objects allocated (pool tags `K400`/`K410`/`K420`) and
  inserted into the provider list at device+240

## 3. Command reference

### CCommand::Handle (base, `0x140006D80`)

| cmd | in len | behavior |
|---|---|---|
| 0 | ≥4 | version query |
| **1** | ≥0x18 | **physical memory read** — `kslIoctlGetPhysicalMemory` (§3.1) |
| 2 | ≥8 | per-CPU register read |
| **7** | ≥0xC | **routine address leak** (§3.2) |
| **8** | ≥8 | **connect**: `SetConnectionHelper(*(u32*)(in+4))` — attach to arbitrary PID |
| 0xB | ≥4 | connected flag |
| 0xC | ≥0x20 | `kslIoctlMmCopy` — **inert in this build** (§3.3) |

### 3.1 Physical memory read (cmd 1, `0x140006FC0`)

Validations: count ≠ 0, offset ≥ 0, count ≤ output capacity, access must not
cross a 4KB page boundary. Then `KeStackAttachProcess(connected)` →
`ZwOpenSection(\device\physicalmemory)` → `ZwMapViewOfSection(PAGE_READONLY,
retry PAGE_READWRITE on STATUS_SECTION_PROTECTION_MISMATCH)` → `memmove` to
the caller's buffer at DISPATCH_LEVEL. **No restriction on which physical
page.** One page per call; repeat freely.

### 3.2 Routine address leak (cmd 7, `0x1400076F0`)

Caller supplies a UTF-16 routine name; response is the kernel VA from
`MmGetSystemRoutineAddress`. KASLR disclosure on demand.

### 3.3 MmCopy (cmd 0xC, `0x140007808`) — inert

Input `ksl_mmcopy_s {pad8, u64 target_va, u64 size, u32 flags}` — flags bit0 =
read, bit1 = write. The implementation is a callback stored at command object
`+0x18`, which the construction path explicitly **zeroes** (`Initialize`
writes 0 before `CCommand::Initialize`); no writer was identified anywhere in
traced code. `kslIoctlMmCopy` therefore returns `STATUS_NOT_FOUND` on every
call. **The read/write primitive is dead code in this build.** If a future
revision installs the callback, cmd 0xC becomes arbitrary virtual R/W — worth
monitoring.

### 3.4 CCommandFile (cmds 3,4,5,6,9)

Kernel-mode file read (two modes), file size, and file retrieval pointers
(physical extent layout) — `ZwReadFile` executed under the driver/attached
context, bypassing the caller's own process token for path-access decisions.

### 3.5 CCommandROM (cmds 0xE–0x13)

SPI flash tooling: support probe, **SPI BAR physical address acquisition**,
flash info (Intel + AMD), and `kslIoctlFlashRomRead` — maps the SPI controller
BAR (`MmMapIoSpace`, MmNonCached), drives SPI cycles, and streams BIOS ROM
content to the caller. Firmware disclosure primitive.

## 4. The gate — and why it fails

### 4.1 The comparison (`CDeviceKsl::OpCreate`, `0x140005AF0`)

```c
ZwOpenProcess(current process, GENERIC_ALL);
ZwQueryInformationProcess(ProcessImageFileName);          // caller's NT image path
expected = device->config[AllowedProcessName];            // registry string
if (RtlCompareUnicodeString(expected, caller_path, CASE_INSENSITIVE))
    return STATUS_ACCESS_DENIED;
connected = TRUE;
```

### 4.2 The configuration source (`CDeviceKsl::initializePrivatedata`, `0x1400056F4`)

```c
CString::Assign(this+32,  init_arg);                      // instance name
getParamFromRegistry(this+120, L"AllowedProcessName");    // ← the gate value
getParamFromRegistry(this+112, L"ImagePath");
getParamFromRegistry(this+128, L"Version");
fetchDeviceName(this, L"DeviceName");
```

`getParamFromRegistry` opens the key path supplied by the device's config
object (the transient service's `...\Services\MpKsl<hex>\Parameters`) and
reads the named value. **That key is under HKLM\SYSTEM\CurrentControlSet\Services
— writable by administrators.**

### 4.3 Consequence

An administrator sets `AllowedProcessName` to an image path they control,
launches a process there, opens the device, and drives the command interface:
arbitrary physical page read, routine addresses, kernel file reads, SPI flash
dump — all through a Microsoft-signed driver. The check authenticates a
*string in admin-writable storage*, not the caller.

Practical constraints (why moderate, not critical):
- The instance is transient; MsMpEng creates it per scan and re-writes the
  config. The admin must have the value in place for an instance
  initialization (service restart / new scan instance), or deny MsMpEng's
  write via key ACL — a race/leverage problem, not a cryptographic one.
- The exposed primitives are **read-class**; the write-capable mmcopy is
  inert (§3.3). No user (non-admin) path: SDDL + device-name randomization.
- Boundary crossed: admin → kernel read. Credential/structure disclosure,
  KASLR defeat, firmware dump.

## 5. Recommendations (Microsoft / Defender team)

1. Authenticate the consumer by reference, not by name: pass the consumer's
   EPROCESS at instance creation (kernel handle from MsMpEng's PPL context)
   or use a kernel-side capability, never a registry-supplied image path.
2. Protect the Parameters key with an ACL that denies admin write (SYSTEM-only),
   or move the config into the signed binary's own resources.
3. Log/telemetry on `AllowedProcessName` modification.
4. Keep mmcopy's callback uninstalled (or remove the command) — the read/write
   encoding is a loaded gun awaiting a future regression.

## 6. Tooling / addresses

Headless IDA 9.3 pipeline (`idat.exe -A -S`), 4 passes. Key addresses:
multiplexer `0x140005DC0`, OpCreate `0x140005AF0`, SetConnectionHelper
`0x1400058F0`, initializePrivatedata `0x1400056F4`, Initialize `0x140004E80`,
CreateDevice `0x140002A10`, getParamFromRegistry `0x140004280`, phys read
`0x140006FC0`, mmcopy `0x140007808`, routine-addr `0x1400076F0`, flash read
`0x140009C2C`, CDeviceKsl vtable `0x140046840`, command vtables
`0x1400468C8/0x1400468F8/0x140046910`.
