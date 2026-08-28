// cormem.h — Teledyne Sapera LT CorMem.sys user-mode interface
// Reconstructed from static analysis of CorMem.sys 9.00 (x64)
// Signed copy:   SHA256 40C855D20D497823716A08A443DC85846233226985EE653770BC3B245CF2ED0F
// Unsigned copy: SHA256 9977054734C44B080FB26FE8F296CD3CCEBACF2BDB7949617AECB14064A42247
//
// Device:        \\.\CORMEM   (\Device\CORMEM, symlink \DosDevices\CORMEM)
// Access model:  default WDM ACL -> Administrators / SYSTEM only
// All IOCTLs:    FILE_DEVICE_UNKNOWN (0x22), FILE_ANY_ACCESS, METHOD_BUFFERED
//
// NOTE: every code in this file was re-verified against the dispatch switch
// in sub_140002C5C (v9.00). Function values = (code >> 2) & 0xFFF.
#pragma once
#include <windows.h>
#include <cstdint>

#define CORMEM_DEVICE_PATH  L"\\\\.\\CORMEM"
#define CORMEM_NT_PATH      L"\\Device\\CORMEM"
#define CORMEM_LOG_PATH     L"\\Device\\CORLOG"
#define CORMEM_REG_PARAMS   L"\\REGISTRY\\Machine\\System\\CurrentControlSet\\Services\\CorMem\\Parameters"
#define CORMEM_PHYS_SECTION L"\\Device\\PhysicalMemory"

#define CORMEM_IOCTL(fn) CTL_CODE(FILE_DEVICE_UNKNOWN, fn, FILE_ANY_ACCESS, METHOD_BUFFERED)

enum cormem_ioctl : DWORD {
    cormem_query_info    = CORMEM_IOCTL(0x800),  // 0x222000 -> sub_1400067E8
    cormem_free          = CORMEM_IOCTL(0x801),  // 0x222004 -> free by pool id
    cormem_get_funcs     = CORMEM_IOCTL(0x802),  // 0x222008 -> 0x88 bytes of kernel code ptrs
    cormem_map_phys      = CORMEM_IOCTL(0x803),  // 0x22200C -> sub_140006154 (phys map)
    cormem_unk_804       = CORMEM_IOCTL(0x804),  // 0x222010 -> sub_140006E40
    cormem_in_port       = CORMEM_IOCTL(0x805),  // 0x222014 -> sub_140006AA4 (in al/ax/eax)
    cormem_out_port      = CORMEM_IOCTL(0x806),  // 0x222018 -> sub_140006F7C (out dx)
    cormem_lock_pages    = CORMEM_IOCTL(0x807),  // 0x22201C -> sub_1400060A0 (MDL lock)
    cormem_unk_808       = CORMEM_IOCTL(0x808),  // 0x222020
    cormem_unk_809       = CORMEM_IOCTL(0x809),  // 0x222024
    cormem_unk_80a       = CORMEM_IOCTL(0x80A),  // 0x222028
    cormem_unk_80b       = CORMEM_IOCTL(0x80B),  // 0x22202C
    cormem_unk_80c       = CORMEM_IOCTL(0x80C),  // 0x222030
    cormem_map_phys_w64  = CORMEM_IOCTL(0x80D),  // 0x222034 -> inline 0x140002FC6 (wow64 map)
    cormem_query_cfg     = CORMEM_IOCTL(0x80E),  // 0x222038
    cormem_query_80f     = CORMEM_IOCTL(0x80F),  // 0x22203C
    cormem_query_815     = CORMEM_IOCTL(0x815),  // 0x222054
    cormem_query_816     = CORMEM_IOCTL(0x816),  // 0x222058
};

enum cormem_status : NTSTATUS {
    cormem_ok              = 0x00000000,
    cormem_err_failed      = 0xC0000001,
    cormem_err_invalid     = 0xC000000D,
    cormem_err_nores       = 0xC000009A,   // length checks failed
    cormem_err_unsupported = 0xC00000BB,
};

#pragma pack(push, 1)

// ---- 0x22200C input (native x64) -------------------------------------------
// consumes 24 bytes, first 16 meaningful; third qword is read then discarded
// (replaced internally with 1). no validation on either address field.
struct CORMEM_MAP_REQUEST {
    uint64_t PhysicalAddress;
    uint64_t WindowBase;        // ZwMapViewOfSection SectionOffset; use == phys
    uint64_t Reserved;
};

// output is one qword: kernel VA = view_base + (PhysicalAddress - WindowBase)
struct CORMEM_MAP_RESULT {
    uint64_t KernelVirtualAddress;
};

// ---- 0x222034 input (wow64 split encoding, inline handler 0x140002FC6) -----
// requires InputLen >= 0x10 and OutputLen >= 0x10
struct CORMEM_MAP_REQUEST_W64 {
    uint32_t PhysicalAddressLo;
    uint32_t PhysicalAddressHi;
    uint32_t LengthLo;
    uint32_t LengthHi;
};

// ---- 0x222014 input: port read (sub_140006AA4) ------------------------------
// width 1 = in al / 2 = in ax / 3 = in eax. anything else -> INVALID_PARAM.
// driver requires OutputLen >= 0xC; result overwrites the input buffer @+0.
// wow64 path reads a qword then a dword, so an 8-byte struct works for both.
struct CORMEM_PORT_IN {
    uint32_t Width;             // 1 | 2 | 3
    uint32_t Port;
};

struct CORMEM_PORT_IN_RESULT {
    uint32_t Value;
};

// ---- 0x222018 input: port write (sub_140006F7C) -----------------------------
// requires InputLen >= 0x10
struct CORMEM_PORT_OUT {
    uint32_t Width;             // 1 | 2 | 3
    uint32_t Port;
    uint32_t Value;
    uint32_t Reserved;
};

// ---- 0x222008 output: raw kernel pointer table ------------------------------
// the handler copies min(OutputLen, 0x88) bytes from a stack-built table of
// code pointers. no count field, no header - just 17 raw qwords.
struct CORMEM_FUNC_TABLE {
    uint64_t KernelPointers[17];    // 0x88 bytes
};

#pragma pack(pop)

class CorMemDriver {
public:
    CorMemDriver() = default;
    ~CorMemDriver() { Close(); }
    CorMemDriver(const CorMemDriver&) = delete;
    CorMemDriver& operator=(const CorMemDriver&) = delete;

    bool Open() {
        if (h != INVALID_HANDLE_VALUE) return true;
        h = CreateFileW(CORMEM_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }

    void Close() {
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    }

    bool IsOpen() const { return h != INVALID_HANDLE_VALUE; }

    // arbitrary physical memory map; returns kernel VA or 0
    uint64_t MapPhysical(uint64_t physicalAddress) {
        CORMEM_MAP_REQUEST req{ physicalAddress, physicalAddress, 0 };
        CORMEM_MAP_RESULT out{};
        if (!Transact(cormem_map_phys, &req, sizeof(req), &out, sizeof(out)))
            return 0;
        return out.KernelVirtualAddress;
    }

    // wow64-friendly map of a 64-bit physical address
    uint64_t MapPhysicalW64(uint64_t physicalAddress, uint64_t length = 0x1000) {
        CORMEM_MAP_REQUEST_W64 req{
            (uint32_t)physicalAddress, (uint32_t)(physicalAddress >> 32),
            (uint32_t)length,          (uint32_t)(length >> 32) };
        CORMEM_MAP_RESULT out{};
        if (!Transact(cormem_map_phys_w64, &req, sizeof(req), &out, sizeof(out)))
            return 0;
        return out.KernelVirtualAddress;
    }

    // raw port read; width 1|2|3
    bool ReadIoPort(uint16_t port, uint32_t width, uint32_t& value) {
        CORMEM_PORT_IN in{ width, port };
        unsigned char out[16] = {};                 // driver wants OutLen >= 0xC
        if (!Transact(cormem_in_port, &in, sizeof(in), out, sizeof(out)))
            return false;
        value = *reinterpret_cast<uint32_t*>(out);
        return true;
    }

    // raw port write; width 1|2|3
    bool WriteIoPort(uint16_t port, uint32_t width, uint32_t value) {
        CORMEM_PORT_OUT out{ width, port, value, 0 };
        return Transact(cormem_out_port, &out, sizeof(out), &out, sizeof(out));
    }

    bool Inb(uint16_t port, uint8_t& v)  { uint32_t t; if (!ReadIoPort(port, 1, t)) return false; v = (uint8_t)t;  return true; }
    bool Inw(uint16_t port, uint16_t& v) { uint32_t t; if (!ReadIoPort(port, 2, t)) return false; v = (uint16_t)t; return true; }
    bool Ind(uint16_t port, uint32_t& v) { return ReadIoPort(port, 3, v); }

    // kernel code pointer table (0x88 raw bytes)
    bool GetFunctionTable(CORMEM_FUNC_TABLE& t) {
        return Transact(cormem_get_funcs, nullptr, 0, &t, sizeof(t));
    }

    // proof-of-life for port io: RTC clock register read (index write 0x70,
    // data read 0x71 - both in the driver's legal set, reads only)
    uint8_t RtcRead(uint8_t reg) {
        WriteIoPort(0x70, 1, reg);
        uint32_t v = 0;
        ReadIoPort(0x71, 1, v);
        return (uint8_t)v;
    }

    HANDLE Handle() const { return h; }

private:
    bool Transact(DWORD code, void* in, DWORD in_len, void* out, DWORD out_len) {
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD got = 0;
        return DeviceIoControl(h, code, in, in_len, out, out_len, &got, nullptr) != FALSE;
    }

    HANDLE h = INVALID_HANDLE_VALUE;
};
