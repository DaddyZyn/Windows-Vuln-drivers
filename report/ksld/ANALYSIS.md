# KslD.sys / MpKslDrv — Microsoft Defender KSL: Intel TDT command interface behind image-name authentication

**Driver:** `KslD.sys` ("KSLD", internal `MpKslDrv`) — Microsoft Defender Kernel
Signature Library embedding **Intel TDT** (`tdt_driver_lib`, Threat Detection
Technology / IPT telemetry). Deployed as transient per-scan instances
(`MpKsl<hex>`) under `System32\drivers\` and `System32\drivers\wd\`.
**Signer:** Microsoft Windows (inbox, WHQL)
**Status:** full static analysis — command interface mapped; exploitability
hinges on one gate (§4)
**Analysis date:** 2026-08-28 · IDA Pro 9.3 headless + Hex-Rays

---

## 1. Summary

MpKslDrv exposes **one** IOCTL (`0x222044`, buffered, in ≥ 4) on its device.
The handler is a command multiplexer (`CDeviceKsl::OpDeviceControl`) walking
registered command objects (`CCommand`, `CCommandFile`, `CCommandROM` — an
Intel TDT command set). Sub-commands available through it include **arbitrary
physical-memory page read, arbitrary kernel routine-address disclosure,
kernel-mode arbitrary file read, SPI BIOS flash read, process connection by
arbitrary PID, and a virtual-memory copy primitive with separate read and
write flag bits**.

Access control is a single check in `CDeviceKsl::OpCreate`: the opening
process's image path (`ProcessImageFileName`) must **string-match** a
configured name (the Defender consumer, i.e. MsMpEng). No token, capability,
or signature verification exists. The entire command surface sits behind that
string comparison.

## 2. Architecture

```
user process ──CreateFile──▶ OpCreate: image-name gate (§4)
     │                                │ pass → device marked connected
     └──DeviceIoControl 0x222044──▶ CDeviceKsl::OpDeviceControl
                                       │ for each command object:
                                       │   vtable[1] IsSupported(cmd)
                                       │   vtable[2] Handle(cmd, in, out)
                                       ▼
                        CCommand (0,1,2,7,8,0xB,0xC)
                        CCommandFile (3,4,5,6,9)
                        CCommandROM (0xE..0x13)
```

- `CCommand` objects hold the owning device at `+0x10` and a **copy callback
  function pointer at `+0x18`** (installed at registration, used by the
  mmcopy command — the implementation is provided by the device layer).
- The connected `_KPROCESS` is set by `CDeviceKsl::SetConnectionHelper(pid)`
  (`ZwOpenProcess` by ClientId, `ObReferenceObjectByHandle`, EPROCESS stored
  at object `+0x58`) and is the attach target for physical-memory reads.

## 3. Command reference (sub-command → behavior)

### CCommand::Handle (base)

| cmd | in len | behavior |
|---|---|---|
| 0 | ≥4 | version string (`0x0104`) |
| **1** | ≥0x18 | **physical memory read** — see §3.1 |
| 2 | ≥8 | per-CPU register read (`kslIoctlGetCpuRegisters`) |
| **7** | ≥0xC | **routine address leak** — `MmGetSystemRoutineAddress(UnicodeName from input)` → 8-byte kernel VA out (§3.2) |
| **8** | ≥8 | **connect**: device vtable+8 → `SetConnectionHelper(*(u32*)(in+4))` |
| 0xB | ≥4 | connected flag query |
| **0xC** | ≥0x20 | **virtual memory copy** — see §3.3 |

### 3.1 `kslIoctlGetPhysicalMemory` (cmd 1)

Input `ksl_physmem_s {pad, i64 phys_offset, u64 count, ...}`. Validation:
count ≠ 0, `phys_offset ≥ 0`, count ≤ output capacity, and offset/count must
not cross a 4KB page boundary. Then:

```
KeStackAttachProcess(connected_process)
ZwOpenSection(\device\physicalmemory, SECTION_MAP_READ)
ZwMapViewOfSection(..., Protect=PAGE_READONLY; retry PAGE_READWRITE on access-denied)
memmove(out_buffer, mapped + offset_in_page, count)   @ DISPATCH_LEVEL, TLB flush
```

**No restriction on which physical page.** Kernel RAM, other processes' pages,
firmware — any page, per call, into the caller's output buffer. The
`KeStackAttachProcess` to the (PPL) connected process influences token context
for the section open, not the set of mappable memory.

### 3.2 `kslIoctlGetRoutineAddr` (cmd 7)

Caller supplies a UTF-16 kernel routine name; driver returns
`MmGetSystemRoutineAddress(name)` — a **kernel virtual address** to the
caller. KASLR disclosure for any exported (and this API-resolvable) routine.

### 3.3 `kslIoctlMmCopy` (cmd 0xC)

Input `ksl_mmcopy_s {pad8, u64 target_va, u64 size, u32 flags, ...}`, size ≤
output capacity, `lfence`-guarded call to the command object's copy callback
(field `+0x18`):

```
flags bit0 = 1 → mode 1 (read)
flags bit1 = 1 → mode 2 (write)
```

**Both read and write modes are selected by the input.** The callback
implementation is supplied by the device layer at command registration; the
write path's presence in the protocol (a dedicated mode-2 encoding) is the
difference between kernel-read and full kernel read/write. Implementation
needs one more tracing pass (callback target, set during command registration
inside `CDriver::CreateDevice`).

### 3.4 `CCommandFile` (cmds 3,4,5,6,9)

Kernel-mode file operations: **read arbitrary files** (two modes — standard
and a second read path, `kslIoctlReadFile`), file size, and
`kslIoctlFileRetrievalPointers` (physical extent layout of a file — useful for
the physical-read primitive to target cached file pages).

### 3.5 `CCommandROM` (cmds 0xE–0x13)

SPI flash tooling: flash-read support probe, **SPI BAR physical address
acquisition**, BIOS flash info (Intel + AMD variants), and
`kslIoctlFlashRomRead` — maps the SPI controller BAR with `MmMapIoSpace(MmNonCached)`,
drives SPI read cycles (`SpiWaitCheckCycleDone`/`SpiSendSpiCycle`), and
streams the BIOS ROM content to the caller. Firmware dump primitive.

## 4. The gate — `CDeviceKsl::OpCreate`

```c
pid  = PsGetCurrentProcessId();
ZwOpenProcess(&h, GENERIC_ALL, ..., &ClientId{pid});
ZwQueryInformationProcess(h, ProcessImageFileName, ...);   // caller's NT image path
expected = device->config->vtable[32](device->config);     // configured name
if (RtlCompareUnicodeString(expected, caller_path, CASE_INSENSITIVE) != 0)
    return STATUS_ACCESS_DENIED;                            // create fails
device->connected = TRUE;  device->caller_pid = pid;
```

Properties of this gate:

- **Authentication by string.** The caller's image *path* is compared to a
  configured Unicode string (the Defender consumer image, e.g. MsMpEng's
  platform path). Nothing about the caller's token, signature, or provenance
  is verified.
- The expected name is device configuration. `CDeviceBase::getParamFromRegistry`
  exists in the same class hierarchy — if the expected name is registry-fed
  (HKLM), an **administrator rewrites it and walks through**.
- Even without registry access, path-equivalence tricks (hardlinks/symlinks
  where ACLs permit, TOCTOU on image path) are the standard failures of
  name-based auth.
- Non-admin attackers face the KMDF default device ACL (admin/SYSTEM) *and*
  the randomized device name (`MpKsl<hex>` instances) — enumeration is
  possible but the name gate remains the barrier.

## 5. Impact assessment (conditional on gate passage)

| Primitive | Boundary crossed |
|---|---|
| physical page read (cmd 1) | **admin → kernel memory read** (credential/structure/KASLR material) |
| routine address leak (cmd 7) | KASLR defeat |
| kernel file read (cmd 3/5) | reads under the attached process's context (SYSTEM/PPL consumer) |
| SPI flash read (0x11/0x13) | firmware disclosure |
| mmcopy (cmd 0xC) | read = kernel read; **write = full admin→kernel EoP** (implementation confirmation pending) |

Everything is admin-gated at minimum (device ACL), so this is an
**admin→kernel elevation** finding, not a user→admin one — contingent on
passing the image-name gate as an admin (registry config writability, or
path equivalence). The design flaw is categorical: a full-featured kernel
command interface protected by *string comparison of the caller's image name*.

## 6. Remaining work

1. Trace the expected-name configuration source (registry value vs. hardcoded
   parent-supplied) — determines admin bypassability.
2. Trace the mmcopy callback implementation (read-only vs. write-capable).
3. Dynamic confirmation: capture a live `MpKsl*` instance during a Defender
   scan, verify device name/ACL, attempt `OpCreate` from a renamed test
   process vs. the configured name.

## 7. Reproduction / tooling

Headless IDA pipeline used: `idat.exe -A -S<script>` with IDAPython +
Hex-Rays (see repo history). Key addresses: multiplexer `0x140005DC0`,
`OpCreate` `0x140005AF0`, `SetConnectionHelper` `0x1400058F0`, command vtable
`0x1400468C8` (CCommand), `0x1400468F8` (CCommandFile), `0x140046910`
(CCommandROM), phys read `0x140006FC0`, mmcopy `0x140007808`, routine-addr
`0x1400076F0`, flash read `0x140009C2C`.
