// ksld.h — Microsoft Defender KSL (KslD.sys / MpKslDrv) command interface
//
// reversed from 1.1.26051.3007 x64 (system32\drivers\wd\KslD.sys).
// embeds Intel TDT (tdt_driver_lib). see ANALYSIS.md for the full study.
//
// device:   \Device\KslD  (DeviceName registry value), SDDL_DEVOBJ_SYS_ALL_ADM_ALL
// gate:     CDeviceKsl::OpCreate compares the caller's image path against
//           AllowedProcessName (service Parameters registry value, admin-
//           writable) — live test: matching name + verified driver restart
//           still DENIED on platform 4.18.26070.9 (additional enforcement).
// ioctl:    exactly ONE: 0x222044 = CTL_CODE(0x22, 0x811, FILE_ANY_ACCESS,
//           METHOD_BUFFERED). dispatch = CDeviceKsl::OpDeviceControl, walking
//           three command objects (CCommand / CCommandFile / CCommandROM).
//
// DOCUMENTATION ONLY. the gate blocks external sessions on current builds
// (live-confirmed); no client code is provided because there is no confirmed
// path through it. structs below are for detection/filtering work.

#pragma once
#include <windows.h>
#include <cstdint>

#define KSLD_DEVICE_PATH   L"\\\\.\\KslD"
#define KSLD_NT_PATH       L"\\Device\\KslD"
#define KSLD_SERVICE_KEY   L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\KslD"
#define KSLD_REG_ALLOWED   L"AllowedProcessName"
#define KSLD_REG_IMAGEPATH L"ImagePath"
#define KSLD_REG_DEVNAME   L"DeviceName"
#define KSLD_REG_VERSION   L"Version"

// the single IOCTL
#define KSLD_IOCTL 0x222044   // CTL_CODE(0x22, 0x811, FILE_ANY_ACCESS, METHOD_BUFFERED)

#pragma pack(push, 1)

// request: first dword selects the sub-command; the matched command object
// handles the rest. sizes below are the pre-validation minimums observed
// in each Handle().

struct KSLD_REQ_VERSION {                 // cmd 0 — CCommand::Handle case 0
    uint32_t SubCommand;                  // 0
    // out: u16 version (observed 0x0104), OutLen must be >= 2
};

struct KSLD_REQ_PHYSMEM {                 // cmd 1 — kslIoctlGetPhysicalMemory
    uint32_t SubCommand;                  // 1
    uint32_t Reserved;
    uint64_t Field0;                      // +0x08 (observed: passed through)
    int64_t  PhysOffset;                  // +0x10 must be >= 0
    uint64_t Length;                      // +0x18 must be > 0, <= OutCap
    // single-4K-page rule: PhysOffset and PhysOffset+Length-1 must share a page
    // out: physical memory contents copied to the output buffer
    // execution: KeStackAttachProcess(connected) -> \device\physicalmemory
    //            map PAGE_READONLY, retry PAGE_READWRITE on 0xC0000048
};

struct KSLD_REQ_CONNECT {                 // cmd 8 — SetConnectionHelper(pid)
    uint32_t SubCommand;                  // 8
    uint32_t ProcessId;                   // target PID (ZwOpenProcess 0x80000000)
    // stores the referenced EPROCESS at device+0x58 as the attach target
};

struct KSLD_REQ_ROUTINEADDR {             // cmd 7 — kslIoctlGetRoutineAddr
    uint32_t SubCommand;                  // 7
    uint32_t NameBytes;                   // +0x04 byte length of the name
    uint32_t MustBe12;                    // +0x08 observed == 12
    // +0x0C wchar_t Name[] — NUL-terminated
    // out: u64 = MmGetSystemRoutineAddress(Name) — KASLR disclosure
};

struct KSLD_REQ_CONNECTED {               // cmd 0xB — connected flag
    uint32_t SubCommand;                  // 0xB
    // out: u8 = (device+0x58 != 0)
};

struct KSLD_REQ_MMCOPY {                  // cmd 0xC — kslIoctlMmCopy (INERT)
    uint32_t SubCommand;                  // 0xC
    uint32_t Reserved;
    uint64_t Field0;                      // +0x08
    uint64_t TargetVa;                    // +0x10
    uint64_t Length;                      // +0x18
    uint32_t Flags;                       // +0x20 bit0 = read, bit1 = write
    // returns STATUS_NOT_FOUND in 1.1.26051: the copy callback (command+0x18)
    // is never installed — the read/write primitive is dead code.
};

// CCommandFile (cmd 3/4/5/6/9): kernel-mode file read (two modes), file size,
// retrieval pointers. CCommandROM (cmd 0xE..0x13): SPI flash probe / BAR
// acquisition / flash info / flash read (Intel + AMD). layouts not fully
// traced; see ANALYSIS.md.

#pragma pack(pop)

// live-test result matrix (platform 4.18.26070.9-0, 2026-08-28):
//   open as non-matching admin            -> ACCESS_DENIED
//   rewrite AllowedProcessName + restart  -> still ACCESS_DENIED
//   (see ANALYSIS.md 5b for the full matrix)
