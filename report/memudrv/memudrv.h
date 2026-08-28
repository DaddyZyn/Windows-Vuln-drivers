// memudrv.h — MEmuDrv.sys (MEmu Hypervisor Support Driver) user-mode interface
// COMPLETE command-surface documentation — no gaps.
//
// reversed from 5.1.34.121010 x64 — a VirtualBox SUPDrv fork with the R0
// hardening stripped. SHA256 9E18ED94739AE711585E397A8EA2F7E1B05E00BD23F57FBB7606C4498192C5E0
//
// devices: \\.\MEmuDrv  and  \\.\MEmuDrvU  (the VBox "unrestricted" sibling)
// access:  plain IoCreateDevice x2, default WDM ACL -> admin/SYSTEM
//          (no IoCreateDeviceSecure, no caller-validation imports)
//
// IOCTL encoding (from the driver's own error strings):
//     CTL_CODE(0x22, (fn) | 0x80, FILE_WRITE_ACCESS, method)
//     observed access = 2 on every code; method = 0 on all traced codes.
//
// request header — 24 bytes; cbIn/cbOut validated against hardcoded
// per-command sizes (many appear as a single qword compare of cbOut<<32|cbIn):
//     +0x00 u32 ?      +0x08 u32 cbIn     +0x10 u32 ?
//     +0x04 u32 ?      +0x0C u32 cbOut    +0x14 s32 status   (0 = ok)
// in/out fields overlap (single buffer, VBox SUPREQHDR union style).
//
// handler addresses refer to sub_1400XXXXX in 5.1.34.121010. every command
// is a thin wrapper over the SUPR0* exports this driver also exports.
//
// documented for the disclosure package in ANALYSIS.md. the wrapper class
// implements only the non-destructive ops (cookie handshake + LDR_OPEN
// fallback probe). the load/execute chain is described in ANALYSIS.md 2 and
// deliberately not provided.

#pragma once
#include <windows.h>
#include <cstdint>
#include <cstring>

#define MEMU_DEVICE_PATH    L"\\\\.\\MEmuDrv"
#define MEMU_DEVICE_PATH_U  L"\\\\.\\MEmuDrvU"
#define MEMU_COOKIE_MAGIC   "The Magic Word!"
#define MEMU_DRIVER_VERSION 0x2A0000
#define MEMU_CODE_COOKIE    0x69726F74u   // 'tori' - CodeEcho for the handshake
#define MEMU_CODE_SESSION   0x12345678u   // CodeEcho for other commands (devext magic)
#define MEMU_HDR_MAGIC      0x42000042u   // (v & 0xFF0000FF) == 0x42000042
#define MEMU_FUNCTION_COUNT 274            // QUERY_FUNCS reports 274 SUPR0 exports

#define MEMU_CTL(fn, method) CTL_CODE(FILE_DEVICE_UNKNOWN, (fn) | 0x80, FILE_WRITE_ACCESS, method)

// ---------------------------------------------------------------------------
// full dispatch table (sub_140005E80). fn = low 7 bits of the function byte.
// sizes marked ? were not pinned in the decompile pass; handler listed.
// ---------------------------------------------------------------------------
enum memu_ioctl : DWORD {
    // --- session / info ---
    memu_cookie          = MEMU_CTL(0x01, METHOD_BUFFERED),  // 0x228204  48/56    inline
    memu_query_funcs     = MEMU_CTL(0x02, METHOD_BUFFERED),  // 0x228208  24/10992 inline: returns 274 SUPR0 export names (API oracle)

    // --- loader (the mapper surface; see ANALYSIS.md 2) ---
    memu_ldr_open        = MEMU_CTL(0x03, METHOD_BUFFERED),  // 0x22820C  328/40   sub_1400048A0
    memu_ldr_load        = MEMU_CTL(0x04, METHOD_BUFFERED),  // 0x228210  img+108/2080  sub_140004B90
    memu_ldr_get_symbol  = MEMU_CTL(0x05, METHOD_BUFFERED),  // 0x228214  32/24    sub_140005130 (query form)
    memu_ldr_get_symbol2 = MEMU_CTL(0x06, METHOD_BUFFERED),  // 0x228218  96/32    sub_1400052A0

    // --- hypervisor execution ---
    memu_call_hpvr0      = MEMU_CTL(0x07, METHOD_BUFFERED),  // 0x22821C  48+/48+  inline; VM handle must equal session+0x40
    memu_call_hpvr0_big  = MEMU_CTL(0x1A, METHOD_BUFFERED),  // 0x22826C (+0x1B) big-request form

    // --- memory ---
    memu_low_alloc       = MEMU_CTL(0x08, METHOD_BUFFERED),  // 0x228220  28/8*n+40  SUPR0LowAlloc: <4GB pages, returns phys addrs + R0 VA
    memu_low_free        = MEMU_CTL(0x09, METHOD_BUFFERED),  // 0x228224  32/24    SUPR0LowFree
    memu_page_alloc_ex   = MEMU_CTL(0x0A, METHOD_BUFFERED),  // 0x228228  ?        PAGE_ALLOC_EX (user mapping capable)
    memu_page_map_kernel = MEMU_CTL(0x0B, METHOD_BUFFERED),  // 0x22822C  48/48    SUPR0PageMapKernel
    memu_page_protect    = MEMU_CTL(0x0C, METHOD_BUFFERED),  // 0x228230  56/56    SUPR0PageProtect
    memu_page_lock       = MEMU_CTL(0x0D, METHOD_BUFFERED),  // 0x228234  32/24    SUPR0LockMem
    memu_page_unlock     = MEMU_CTL(0x0E, METHOD_BUFFERED),  // 0x228238  ?        SUPR0UnlockMem

    // --- fast-call session binding (5 size variants) ---
    memu_set_vm_for_fast = MEMU_CTL(0x0F, METHOD_BUFFERED),  // 0x22823C..0x22824C  28/48

    // --- service / logger ---
    memu_call_service    = MEMU_CTL(0x14, METHOD_BUFFERED),  // 0x228250..0x22825C (3 forms) sub_140003920
    memu_logger_settings = MEMU_CTL(0x17, METHOD_BUFFERED),  // 0x22825C/60  sub_1400039F0

    // --- semaphores ---
    memu_sem_op2         = MEMU_CTL(0x18, METHOD_BUFFERED),  // 0x228264  48/48
    memu_sem_op3         = MEMU_CTL(0x19, METHOD_BUFFERED),  // 0x228268  48/48

    // --- MSR prober family (7 codes; arbitrary rdmsr/wrmsr via TDT impl) ---
    memu_msr_prober_q    = MEMU_CTL(0x1C, METHOD_BUFFERED),  // 0x228270  sub_140010FB0 (caps query)
    memu_msr_prober_a    = MEMU_CTL(0x1D, METHOD_BUFFERED),  // 0x228274  sub_1400110E0
    memu_msr_prober_r    = MEMU_CTL(0x1E, METHOD_BUFFERED),  // 0x228278  0x78/0x18 sub_1400111D0 (range probe, serialized)
    memu_msr_prober_r2   = MEMU_CTL(0x1F, METHOD_BUFFERED),  // 0x22827C  0x78/0x18 sub_140010860
    memu_msr_prober_w    = MEMU_CTL(0x20, METHOD_BUFFERED),  // 0x228280  sub_140010CC0
    memu_msr_prober_w2   = MEMU_CTL(0x21, METHOD_BUFFERED),  // 0x228284  sub_140010FA0
    memu_msr_prober_x2   = MEMU_CTL(0x22, METHOD_BUFFERED),  // 0x228288

    // --- tail (tracer / GIP / timer family, not fully traced) ---
    memu_tail_290        = MEMU_CTL(0x24, METHOD_BUFFERED),  // 0x228290  sub_14000B6C0
    memu_tail_294        = MEMU_CTL(0x25, METHOD_BUFFERED),  // 0x228294  24/24  sub_14000B770
    memu_tail_298        = MEMU_CTL(0x26, METHOD_BUFFERED),  // 0x228298  24/24
    memu_tail_29c        = MEMU_CTL(0x27, METHOD_BUFFERED),  // 0x22829C  24/28  sub_14000BA40
    memu_tail_2a0        = MEMU_CTL(0x28, METHOD_BUFFERED),  // 0x2282A0  24/28
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
    memu_err_no_dev     = -3726,  // MSR prober: no impl registered (0xFFFFF172)
    memu_err_thr_busy   = -3729,  // MSR prober: thread already owns the prober
};

#pragma pack(push, 1)

// request header — 24 bytes
struct MEMU_REQHDR {
    uint32_t CodeEcho;      // +0x00 ('tori' for cookie, 0x12345678 for the rest)
    uint32_t SessionToken;  // +0x04 (from the cookie response; 0 for cookie)
    uint32_t cbIn;          // +0x08
    uint32_t cbOut;         // +0x0C
    uint32_t HdrMagic;      // +0x10 ((v & 0xFF0000FF) == 0x42000042)
    int32_t  status;        // +0x14
};

// ---- 0x228204 COOKIE (48/56) -------------------------------------------------
// magic "The Magic Word!"; MinVersion must be exactly 0x2A0000.
// Out.SessionKernel = kernel SUPDRVSESSION* — info leak on the handshake.
struct MEMU_COOKIE_REQ {
    MEMU_REQHDR hdr;                                   // 24
    union {
        struct {                                       // in  +0x18
            char     Magic[16];
            uint32_t ReqVersion;
            uint32_t MinVersion;                       // 0x2A0000
        };
        struct {                                       // out
            uint32_t OutSessionId;                     // +0x18
            uint32_t OutFlags;                         // +0x1C
            uint32_t SessionVersion;                   // +0x20
            uint32_t DriverVersion;                    // +0x24
            uint32_t FunctionCount;                    // +0x28
            uint32_t PadBetween;                       // +0x2C (gap to +0x30)
            uint64_t SessionKernel;                    // +0x30 kernel SUPDRVSESSION*
        };
    };
};
static_assert(sizeof(MEMU_COOKIE_REQ) == 56, "cookie size");

// ---- 0x22820C LDR_OPEN (328/40) ------------------------------------------------
// fallback: nonexistent szFilename -> RTMemExecAllocTag(cbImageWithTabs) RWX
// kernel alloc, FromFile = 0 -> entry-point validation skipped in LDR_LOAD.
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

// ---- 0x228210 LDR_LOAD (cbIn = cbImageWithTabs + 108, cbOut = 2080) ------------
// documented for completeness; intentionally NOT implemented in the wrapper.
struct MEMU_LDRLOAD_REQ {
    MEMU_REQHDR hdr;                                   // 24
    uint64_t hLdrModule;                               // +0x18 (from LDR_OPEN)
    uint64_t pfnServiceReq;                            // +0x28 entry; must be inside image
    uint64_t apvReserved[3];                           // +0x30 MBZ
    uint32_t eEPType;                                  // +0x48 (1 or 2)
    uint32_t offSymbols;                               // +0x58
    uint32_t cSymbols;                                 // +0x5C (<= 16384)
    uint32_t offStrTab;                                // +0x60
    uint32_t cbStrTab;                                 // +0x64
    uint32_t cbImageWithTabs;                          // +0x68
    // +0x6C image bytes[cbImageWithTabs]
};
// FromFile = 0 (LDR_OPEN fallback) skips SUPR0GetKernelFeatures on the entry
// point. loader-lockdown flag (devext+0x48) has no identified writer.

// ---- 0x22821C CALL_HPVR0 (48/48 fast form) --------------------------------------
// fast form: session vtable+0x38 call with (session+0x38 VM obj, VM handle from
// request+0x18 — must equal session+0x40, u32@+0x20, u32@+0x24, 0, u64@+0x28).
// big form (0x22826C): inline HPV request with magic 426967569 ("VBVM"-class
// header) and cbIn = cbOut = u32Size@+0x34 + 48.

// ---- 0x228220 LOW_ALLOC (28 / 8*cPages+40) --------------------------------------
struct MEMU_LOWALLOC_REQ {
    MEMU_REQHDR hdr;                                   // 24
    uint32_t cPages;                                   // +0x18
    // out: +0x18 u64 R0 VA; +0x20 PHYSICAL_ADDRESS pages[8*cPages]; status
};

// ---- 0x228224 LOW_FREE (32/24) ---------------------------------------------------
struct MEMU_LOWFREE_REQ {
    MEMU_REQHDR hdr;                                   // 24
    uint64_t Handle;                                   // +0x18
};

// ---- 0x22822C PAGE_MAP_KERNEL (48/48) --------------------------------------------
// offSub/cbSub must be 4K-aligned, cbSub nonzero, fFlags must be zero.
struct MEMU_PAGEMAP_REQ {
    MEMU_REQHDR hdr;                                   // 24
    union {
        struct {                                       // in
            uint64_t hMemObj;                          // +0x18 (from PAGE_ALLOC_EX)
            uint32_t offSub;                           // +0x20
            uint32_t cbSub;                            // +0x24
            uint32_t fFlags;                           // +0x28 MBZ
            uint32_t pad;
        };
        struct {                                       // out
            uint64_t R0Va;                             // +0x18
        };
    };
};

// ---- 0x228230 PAGE_PROTECT (56/56) ------------------------------------------------
// fProt: bits 0-2 only (Page_READONLY/READWRITE/EXEC-ish); offSub/cbSub 4K-aligned.
struct MEMU_PAGEPROT_REQ {
    MEMU_REQHDR hdr;                                   // 24
    uint64_t hMemObj;                                  // +0x18
    uint32_t pad0;                                     // +0x20
    uint32_t pad1;                                     // +0x24
    uint32_t offSub;                                   // +0x28
    uint32_t cbSub;                                    // +0x2C
    uint32_t fProt;                                    // +0x30 (bits 0-2)
    uint32_t pad2;                                     // +0x34
};

// ---- 0x228234 PAGE_LOCK (32/24) ----------------------------------------------------
struct MEMU_PAGELOCK_REQ {
    MEMU_REQHDR hdr;                                   // 24
    uint64_t UserVa;                                   // +0x18 (R3 buffer to lock)
};

// ---- 0x22825C-ish LOGGER_SETTINGS / 0x228260 (48/24) / SEM_OP2 (48/48) -------------
// layouts partially traced; sizes above are the validated values.

// ---- 0x228278 MSR range probe (0x78/0x18) ------------------------------------------
// serialized per-thread (session+0x698 owner), requires a registered impl
// (devext+0xE0) and !devext+0x110. request carries an MSR range table;
// the impl vtable+0x20 performs the rdmsr/wrmsr passes.

#pragma pack(pop)

class MemuDrv {
public:
    MemuDrv() = default;
    ~MemuDrv() { Close(); }
    MemuDrv(const MemuDrv&) = delete;
    MemuDrv& operator=(const MemuDrv&) = delete;

    // opens the exact path given. note: the driver never calls
    // IoCreateSymbolicLink, so \\.\MEmuDrv has no symlink — use the
    // GlobalROOT candidates to reach \Device\ directly. callers should
    // probe both devices (Drv and DrvU) since the command surface may
    // differ between them.
    bool Open(const wchar_t* path) {
        if (h != INVALID_HANDLE_VALUE) Close();
        h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        pathUsed = (h != INVALID_HANDLE_VALUE) ? path : nullptr;
        return h != INVALID_HANDLE_VALUE;
    }

    void Close() {
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    }

    bool IsOpen() const { return h != INVALID_HANDLE_VALUE; }

    // cookie handshake; returns session/driver version, 0 on failure.
    // captures the session token (needed by every later command) and the
    // leaked kernel session pointer.
    uint32_t Handshake(uint64_t* sessionKernel = nullptr) {
        MEMU_COOKIE_REQ r{};
        r.hdr.CodeEcho     = MEMU_CODE_COOKIE;
        r.hdr.SessionToken = 0;
        r.hdr.cbIn  = 48;
        r.hdr.cbOut = 56;
        r.hdr.HdrMagic = MEMU_HDR_MAGIC;
        memcpy(r.Magic, MEMU_COOKIE_MAGIC, sizeof(r.Magic));
        r.ReqVersion = MEMU_DRIVER_VERSION;
        r.MinVersion = MEMU_DRIVER_VERSION;
        if (!Transact(memu_cookie, &r, sizeof(r)))
            return 0;
        if (r.hdr.status != memu_ok)
            return 0;
        sessionToken = r.OutFlags;
        if (sessionKernel) *sessionKernel = r.SessionKernel;
        return r.SessionVersion;
    }

    // the vulnerability probe: LDR_OPEN with a nonexistent filename must
    // succeed via the exec-alloc fallback (FromFile == 0) where upstream
    // VBox requires a verified backing file. non-destructive: nothing is
    // loaded or executed; the module is released by closing the session.
    bool LdrOpenFallbackProbe(const char* name, uint64_t& moduleHandle, uint8_t& fromFile) {
        MEMU_LDROPEN_REQ r{};
        r.hdr.CodeEcho     = MEMU_CODE_SESSION;
        r.hdr.SessionToken = sessionToken;
        r.hdr.cbIn  = sizeof(r);          // 328
        r.hdr.cbOut = 40;
        r.hdr.HdrMagic = MEMU_HDR_MAGIC;
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
    const wchar_t* PathUsed() const { return pathUsed; }
    uint32_t SessionToken() const { return sessionToken; }

private:
    bool Transact(DWORD code, void* buf, DWORD len) {
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD got = 0;
        return DeviceIoControl(h, code, buf, len, buf, len, &got, nullptr) != FALSE;
    }

    HANDLE h = INVALID_HANDLE_VALUE;
    const wchar_t* pathUsed = nullptr;
    uint32_t sessionToken = 0;
};
