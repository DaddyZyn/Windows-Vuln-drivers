# KslD.sys / MpKslDrv — Microsoft Defender Kernel Signature Library: recon

**Driver:** `KslD.sys` ("KSLD"), internal name `MpKslDrv` — deployed by Microsoft
Defender as randomly-suffixed instances (`MpKsl<hex>`) under both
`System32\drivers\` and `System32\drivers\wd\`
**Signer:** Microsoft Windows (inbox, WHQL)
**Status:** recon — **no exploitable user→kernel path confirmed**; this note maps
the surface and documents what dynamic work remains
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

## 5. Assessment

The single-IOCTL design with internally-registered providers and a
SYSTEM-consumer device is a narrow surface by construction. The interesting
question is narrow too: *provider-steered PID targeting*. Until the vtable
reconstruction lands, this is a recon note, not a vulnerability report — and it
stays honest that way. If the dynamic test shows provider dispatch accepts an
arbitrary PID from the buffered input, that graduates to a report; otherwise
MpKslDrv joins the "analyzed — no user-facing primitive" list.
