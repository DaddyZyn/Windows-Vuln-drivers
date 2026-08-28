# MEmuDrv.sys — VirtualBox SUPDrv fork in MEmu emulator: unprotected ring-0 module loader (mapper-grade primitive set)

**Driver:** `MEmuDrv.sys` 5.1.34.121010 ("MemuHyperv Support Driver") — a fork of
the **VirtualBox `SUPDrv` kernel driver** (`HostDrivers/Support/SUPDrv.cpp`,
source path strings preserved: `D:\workspace\MemuHyperv-5.1.34\src\MEmu\...`)
**Vendor:** Shanghai Microvirt Software Technology Co., Ltd. (valid Authenticode)
**Distribution:** MEmu Android Emulator (`memuhyperv.org`); service `MEmuDrv`,
Start=demand, left installed after emulator use
**Devices:** `\Device\MEmuDrv` (extension `0x109D8`) + `\Device\MEmuDrvU`
(VBox's historical *unrestricted* sibling device) — plain `IoCreateDevice`,
default WDM ACL (admin/SYSTEM), **no `IoCreateDeviceSecure`**
**Status:** not on Microsoft blocklist, not in LOLDrivers; full static analysis
(IDA 9.3 headless + Hex-Rays, .pdata-driven, 1067 functions)
**Analysis date:** 2026-08-28

---

## 1. Summary

`MEmuDrv.sys` is a VirtualBox SUPDrv fork retaining the complete VBox kernel
primitive surface — and shipping it with the hardening stripped:

- **No `wintrust` import** — VBox's Windows image-verification layer is absent
- **No caller-validation imports** — no process-image checks at session open
- **`SUP_IOCTL_LDR_LOAD`** — a ring-0 **module loader**: allocates executable
  kernel memory, copies a caller-supplied image, registers a caller-supplied
  entry point, with the file/signature verification path **skipped on a
  fallback branch**
- `SUP_IOCTL_MSR_PROBER` (arbitrary rdmsr/wrmsr), `PAGE_MAP_KERNEL`,
  `PAGE_PROTECT`, `PAGE_ALLOC_EX`, `LOW_ALLOC`, `SET_VM_FOR_FAST`,
  `CALL_HPVR0` — the full VBox SUP_IOCTL menu

This is a **complete kernel code-execution primitive set** behind `CreateFile`
+ sequential IOCTLs from an administrator process — the same primitive class
as the blocklisted VBoxDrv ancestors and classic BYOVD loader drivers.

## 2. The module loader chain (the core finding)

### 2.1 `SUP_IOCTL_LDR_OPEN` → `sub_1400048A0` (full flow, `cbIn = 328 / cbOut = 40`)

Input: `cbImageWithTabs` (1..0xFFFFFF), `cbImageBits` (1..cbImageWithTabs),
`szName[32]` (charset-validated against a 22-byte whitelist), `szFilename[260]`.
Output: `hLdrMod` (u64) + two state bytes.

Flow:

1. Under the global mutex, the module list is searched by name. A hit
   increments its reference count and returns the existing handle — a name
   collision with another session's module reuses that module's image.
2. No match → a 160-byte module record is allocated (tag `K400`-family),
   initialized with the requested sizes and the `LDR_OPEN` state marker
   (`2261516`), name copied at +0x79.
3. `sub_140012720(devext, module, szFilename)` attempts to **open the file**.
   On `VERR_FILE_NOT_FOUND (-37)` — **the fallback**:

```c
v14 = RTMemExecAllocTag(cbImageWithTabs + 31);   // executable kernel memory
module->image       = v14;
module->imageAligned = (v14 + 31) & ~31;
module->fromFile    = 0;                          // +0x78 flag = 0
```

   No file, no hash, no signature, no name policy — an executable kernel
   allocation registered as a loadable module. On the file-found path the
   flag is set (`fromFile = 1`), which is the only difference downstream.
4. The handle and flags return to the caller; `SUPR0ResumeVTxOnCpu` is a
   no-op stub in this build.

**A nonexistent filename yields an RWX kernel allocation with no file, no
verification, and the `fromFile` flag cleared** — which disables the deeper
entry-point validation in the load step (§2.2).

### 2.2 `SUP_IOCTL_LDR_LOAD` → `sub_140004B90`

Validations performed: handle matches an opened module, size consistency
(prep vs load), state == LDR_OPEN, symbol-table offsets in bounds
(≤16384 symbols), reserved fields zero, entry-point pointer (`pfnServiceReq`)
**inside the module image**.

The decisive branch:

```c
if (module->fromFile)                              // +0x78, set only on the file path
    KernelFeatures = SUPR0GetKernelFeatures(...);  // deep validation — SKIPPED on fallback
```

On the §2.1 fallback (`fromFile == 0`), the entry-point callback is accepted
**without** the kernel-features validation. The image content is the caller's
buffer; the entry point is the caller's choice inside it.

A loader-lockdown flag exists (`devext+0x48`, `"Loader is locked down"`) —
no writer was identified in the traced paths; even if set after a first load,
a fresh instance race applies.

### 2.3 Execution

The registered entry point is reached through the fork's hypervisor call
interface (`SUP_IOCTL_CALL_HPVR0` / fast-call path `supdrvIOCtlFast` with
`SET_VM_FOR_FAST` session binding) — the standard VBox R0-module execution
flow, with the caller-controlled module in place of the hypervisor payload.

### 2.4 Supporting primitives (same IOCTL surface)

| IOCTL family | primitive |
|---|---|
| `SUP_IOCTL_MSR_PROBER` (7 codes, `0x228270`+) | arbitrary `rdmsr`/`wrmsr` (serialized per-thread; delegates to the TDT impl object's vtable+0x20) |
| `SUP_IOCTL_PAGE_MAP_KERNEL` (`0x22822C`) | map a PAGE_ALLOC_EX object into kernel space — `offSub`/`cbSub` 4K-aligned, returns R0 VA |
| `SUP_IOCTL_PAGE_PROTECT` (`0x228230`) | alter protections on a mapped object (`fProt` bits 0-2) |
| `SUP_IOCTL_PAGE_ALLOC_EX` (`0x228228`) | page alloc with user mapping capable |
| `SUP_IOCTL_LOW_ALLOC`/`LOW_FREE` (`0x228220`/`0x228224`) | <4GB page allocation returning **physical addresses + R0 VA** |
| `SUP_IOCTL_PAGE_LOCK` (`0x228234`) | lock an R3 buffer (MDL path) |
| `SUP_IOCTL_CALL_HPVR0`/`_BIG` (`0x22821C`/`0x22826C`) | invoke the loaded module's registered entry (VM-handle bound to session) |
| `SUP_IOCTL_SET_VM_FOR_FAST` (5 forms) | bind a VM for the fast-call path |
| `SUP_IOCTL_CALL_SERVICE` (3 forms) | internal service dispatch |
| exports (`SUPR0ChangeCR4`, `RTR0MemObjEnterPhysTag`, `SUPR0PageAllocEx`, `RTMemExecAllocTag`, …) | the full VBox R0 API for loaded modules |

Additional leaks/oracles observed on the surface:

- `SUP_IOCTL_COOKIE` response embeds the raw kernel `SUPDRVSESSION*`
  (`*(_QWORD *)(req + 48) = session`) — kernel pointer disclosure on the
  handshake.
- `SUP_IOCTL_QUERY_FUNCS` returns the complete 274-entry SUPR0 export-name
  table — a full API oracle for whatever module gets loaded.
- `CALL_HPVR0` binds execution to the session's VM object: the request's VM
  handle must equal `session+0x40`; the call dispatches through session
  vtable+0x38 with the module-registered entry.

## 3. What the fork stripped vs. upstream VBox

Upstream VirtualBox on Windows ships layered hardening for exactly this
surface: R3 process/image verification (`wintrust`-based signature checks on
the caller and loaded images), session-type restrictions on the unrestricted
device, and loader lockdown semantics tied to verified images. The MEmu fork:

- drops all `wintrust`/verification imports,
- retains the `MEmuDrvU` unrestricted-device pattern,
- adds the exec-alloc fallback that bypasses its own remaining validation,
- keeps the entire SUP_IOCTL menu reachable from a session.

## 4. Impact

Administrator → arbitrary kernel code execution: open a session, `LDR_OPEN`
with a nonexistent filename (RWX alloc), `LDR_LOAD` an attacker-crafted image
and entry point, invoke it. All from a validly signed driver installed by a
mainstream emulator, invisible to the blocklist and public feeds. The same
surface also yields MSR read/write, kernel page mapping/protection changes,
and physical-address mapping for loaded modules — sufficient for DSE
manipulation, EDR tampering, and credential theft with no additional bugs.

## 5. Recommendations

1. **Microvirt:** restore image verification on the loader path (file-backed
   modules only, signature-checked against the vendor cert), remove the
   exec-alloc fallback, close the unrestricted device to non-consumer
   sessions, and restrict the device ACL to the emulator service account.
2. **Microsoft (blocklist nomination):** the driver is a BYOVD-ready kernel
   loader — hash + filename rules for `MEmuDrv.sys` are warranted on the same
   grounds as previously blocklisted VBoxDrv-derived loaders.
3. **Defenders:** alert on `\Device\MEmuDrv`/`MEmuDrvU` opens by processes
   outside the MEmu install tree; hash-block the driver where the emulator is
   not business-required.

## 6. Open items

- Writer of the loader-lockdown flag (`devext+0x48`) — not found in traced
  paths; even if set post-first-load, first-load wins.
- IRP_MJ_CREATE session handler: no caller checks found (no validation
  imports); confirm no SDDL was applied out-of-band (none imported).
- Dynamic confirmation: service is present-but-stopped on the analysis host;
  a VM run driving the documented chain would complete the evidence (same
  pipeline as the KslD live test).

## 7. Tooling

Headless IDA 9.3, `.pdata`-driven per-function disassembly (1067 functions /
41k insns), 2 Hex-Rays passes. Key addresses: device creation `0x140011760`,
GDI-load/unload wrappers `0x1400127F3`/`0x140012570`, ioctl dispatch
`0x140005E80`, LDR_OPEN `0x1400048A0`, LDR_LOAD `0x140004B90`, exec-alloc
fallback inside LDR_OPEN (VERR_FILE_NOT_FOUND branch).
