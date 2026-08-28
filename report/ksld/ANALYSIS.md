# KslD.sys / MpKslDrv — Microsoft Defender Kernel Signature Library: recon

**Driver:** `KslD.sys` ("KSLD"), internal name `MpKslDrv` — deployed by Microsoft
Defender as randomly-suffixed instances (`MpKsl<hex>`) under both
`System32\drivers\` and `System32\drivers\wd\`
**Signer:** Microsoft Windows (inbox, WHQL)
**Status:** recon complete — **closed as not-a-vulnerability** (see §6)
**Analysis date:** 2026-08-28

---

## 1. What the driver is

`MpKslDrv` is the **Kernel Signature Library** component of Microsoft Defender.
The import set gives away the role:

- `KeRegisterBugCheckReasonCallback` / `KeDeregisterBugCheckReasonCallback`
- `KeAddTriageDumpDataBlock` / `KeInitializeTriageDumpDataArray` (all resolved
  at runtime via `MmGetSystemRoutineAddress` — 16+ dynamic resolutions)
- `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine(Ex)`,
  `PsSetLoadImageNotifyRoutine`, `PsRemove*`

It registers bugcheck-reason callbacks and feeds triage dump blocks — the
driver scans crash context for malicious-driver evidence and supports the
Defender scan engine with PID-targeted inspection. Memory machinery
(`ZwOpenProcess`, `ZwMapViewOfSection`, `MmMapIoSpace`, MDL build/lock) serves
that job. A section named `awesome` holds runtime-built strings (device-name
assembly).

Instances are transient: no `MpKsl*` service persists between Defender
operations (verified live — only `WdFilter` present between scans). The user
host is `MsMpEng`; the driver maintains a shared-memory bridge to it.

## 2. Attack surface

Exactly **one** device IOCTL in 66k instructions of code:

```
0x222044  FILE_DEVICE_UNKNOWN, FILE_ANY_ACCESS, METHOD_BUFFERED, in >= 4
```

Handler `sub_140005DC0` is a **provider multiplexer**:

```
for each registered provider in ctx->[0xC8] / ctx->[0xD0]:
    match  = provider->vtable[1]     // al = match(provider, input_dword)
    if match(input_dword):
        dispatch = provider->vtable[2]
        status = dispatch(provider, input_dword, inbuf, inlen, ...)
```

Providers are C++ objects with `.rdata` vtables (`0x140046820`-region). Function
pointer cross-references found in those tables:

| vtable slot | function | role |
|---|---|---|
| `0x140046848` | `sub_1400058F0` | **open target by ClientId**, access `0x80000000` (read-class), OBJECT_ATTRIBUTES `0x200` |
| `0x140046880` | `sub_140005AF0` | **open current process, `GENERIC_ALL`** — the MsMpEng bridge |
| `0x140046898` | `sub_140005DC0` | the multiplexer itself |

The `0x222044` input's first dword is passed to both the matcher and the
dispatcher — i.e. **a caller-supplied PID flows through the provider chain**
into process-opening logic.

## 3. The open question

Can an external process drive `0x222044` such that a provider opens an
**arbitrary PID** with read access? If yes, the driver is an admin→PPL-read
relay: a Defender-signed kernel component opening protected processes for
memory reading, reachable from an admin context — a legitimate MSRC report
(PPL/anti-tamper bypass via in-box AV driver).

Static analysis needed to settle it (not yet done):

1. Reconstruct the provider vtables: which providers register at DeviceAdd, and
   what their match functions accept (PID? scan-request ID? signature tag?)
2. Identify the device name construction (`\Device\` + runtime suffix in the
   `awesome` section) and the effective device SD (no SDDL strings in the
   binary; KMDF default is admin-only — but the consumer is MsMpEng, which runs
   as `SYSTEM`, so the device may effectively be reachable only to SYSTEM)
3. Enumerate what the matched dispatchers do with `{inbuf, inlen}` — is the PID
   used as a *scan target* (internal policy decides) or as an *opaque argument*
   to `sub_1400058F0` (attacker-steerable)?

Dynamic route: the service is transient and its start is gated; capturing a
live instance (`sc` during a Defender scan, or DEFCON-style: trigger the
`MsMpEng` scan path) and driving `0x222044` from an admin test process is the
fast path to a yes/no.

## 4. Related machinery (context, not primitives)

- `ZwMapViewOfSection` ×2 (`0x140007160`, `0x1400071B5`) — section mapping in
  the scan bridge (file-backed image sections, not `\Device\PhysicalMemory` —
  no PhysicalMemory string exists in this binary, unlike CorMem/AsIO3).
- `MmMapIoSpace` ×2 (`0x140009D76`, `0x14000A134`) — consistent with
  `HalAllocateHardwareCounters`-style PT/IPT counter setup for tracing.
- Registry: `ZwDeleteKey`/`ZwSetValueKey` imports — cleanup of its own service
  keys during transient instance lifecycle.

## 5. Verdict: the PID reaches ZwOpenProcess, but crosses no boundary

Vtable reconstruction settled §3. The provider class vtable is at `0x140046840`:

```
+0x00  0x140004CE0   destructor (via ctor/dtor helper sub_140004D20)
+0x08  0x1400058F0   "match" slot — IS open_target_by_cid
+0x10  0x140005AD0   "dispatch" slot — operate on the opened handle
```

The multiplexer flow, resolved: `0x222044 {pid}` walks providers calling
vtable+8 = **open_target_by_cid(provider, pid)** directly — the "match" step
*is* the process open (`ZwOpenProcess(ClientId=pid, DesiredAccess=0x80000000)`,
skipped when the provider already holds a handle at object `+0x58`). First
provider to succeed runs vtable+0x10 against the handle.

So yes — the IOCTL's PID dword is attacker-steerable and reaches
`ZwOpenProcess` in kernel mode. It still isn't a vulnerability:

- `Zw*` access checks evaluate the **calling process's token**. An unprotected
  admin opening a PPL target gets `STATUS_ACCESS_DENIED` exactly as it would
  from user mode — protection is checked against the opener, not the driver.
- For every non-protected process, an admin already holds `SeDebugPrivilege`;
  routing the open through a Microsoft-signed driver grants nothing extra.
- The opened handle lands in the provider object (`+0x58`), not the caller's
  handle table — the caller only sees what the vtable+0x10 operation outputs.

Unusual design, privilege math unchanged. MpKslDrv is Defender plumbing doing
Defender things, for a PPL consumer (MsMpEng) anyway. Closed.

## 6. Assessment

Single-IOCTL design, internally-registered providers, SYSTEM consumer — narrow
by construction, and the one spicy path (IOCTL-steered kernel process opens)
preserves all privilege boundaries. MpKslDrv joins the "analyzed — no
user-facing privilege primitive" list. Lesson for the hunt: Microsoft's
diagnostic/AV drivers expose *machinery*, not *primitives* — the productive
lane remains vendor-signed utility drivers.
