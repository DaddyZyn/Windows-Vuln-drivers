// asio3.h - user-mode interface to ASUSTeK AsIO3.sys (Asusgio3 device)
//
// reversed from 1.02.40 x64. deep-dive writeup lives in ANALYSIS.md next to
// this file - read that for the gates (port allowlist, phys range validator,
// msr table) before assuming anything here is wide open. short version:
// most of it is gated, the PCI config read is not.
//
// device: \\.\Asusgio3 (\Device\Asusgio3), default WDM ACL = admin/SYSTEM.
// all port/msr/pci handlers take KeWaitForSingleObject(WaitForIoAccess)
// first - that's ASUS component arbitration, not access control.
//
// for research/detection use. the ASUS services are the intended callers.

#pragma once
#include <windows.h>
#include <cstdint>

#define ASIO3_DEVICE_PATH L"\\\\.\\Asusgio3"
#define ASIO3_NT_PATH     L"\\Device\\Asusgio3"

// device type 0xa040 is ASUS custom. transfer method varies per ioctl, so
// each code spells out its own CTL_CODE instead of one macro.
#define ASIO3_CTL(fn, method)          CTL_CODE(0xa040, fn, FILE_ANY_ACCESS, method)
#define ASIO3_CTL_A(fn, access, method) CTL_CODE(0xa040, fn, access, method)

enum asio3_ioctl : DWORD {
    // port io family - all allowlist-checked (43 static ranges in .data,
    // incl. CMOS 0x70-0x7E, SMI cmd 0xB2, CF8/CFC, EC/SIO pairs)
    asio3_port_read_d      = ASIO3_CTL(0x3D6, METHOD_BUFFERED), // 0xa0400f58
    asio3_port_read_w      = ASIO3_CTL(0x3D7, METHOD_BUFFERED), // 0xa0400f5c
    asio3_ec_write_60      = ASIO3_CTL(0x3D8, METHOD_BUFFERED), // 0xa0400f60
    asio3_ec_write_64      = ASIO3_CTL(0x3D9, METHOD_BUFFERED), // 0xa0400f64
    asio3_ec_write_68      = ASIO3_CTL(0x3DA, METHOD_BUFFERED), // 0xa0400f68
    asio3_ec_write_6c      = ASIO3_CTL(0x3DB, METHOD_BUFFERED), // 0xa0400f6c
    // pci config read via ports 0xCF8/0xCFC - THE ungated one
    asio3_pci_config_read  = ASIO3_CTL(0x3DC, METHOD_BUFFERED), // 0xa0400f70
    asio3_port_read_bulk   = ASIO3_CTL(0x3DD, METHOD_BUFFERED), // 0xa0400f74
    asio3_port_read_index  = ASIO3_CTL(0x3DE, METHOD_BUFFERED), // 0xa0400f78
    asio3_map_get_7c       = ASIO3_CTL(0x3DF, METHOD_BUFFERED), // 0xa0400f7c
    asio3_rdmsr            = ASIO3_CTL(0x3E2, METHOD_BUFFERED), // 0xa0400f88
    asio3_wrmsr            = ASIO3_CTL(0x3E3, METHOD_BUFFERED), // 0xa0400f8c
    asio3_contiguous_alloc = ASIO3_CTL(0x3E4, METHOD_BUFFERED), // 0xa0400f90
    asio3_contiguous_free  = ASIO3_CTL(0x3E5, METHOD_BUFFERED), // 0xa0400f94
    asio3_map_op_2000      = ASIO3_CTL(0x800, METHOD_BUFFERED), // 0xa0402000
    asio3_port_write_2004  = ASIO3_CTL(0x801, METHOD_BUFFERED), // 0xa0402004
    asio3_phys_map         = ASIO3_CTL(0x803, METHOD_BUFFERED),   // 0xa040200c
    asio3_map_get_2010     = ASIO3_CTL(0x804, METHOD_BUFFERED),   // 0xa0402010 -> sub_1400041EA query
    asio3_map_read_2014    = ASIO3_CTL(0x805, METHOD_BUFFERED), // 0xa0402014
    asio3_map_op_2018      = ASIO3_CTL(0x806, METHOD_BUFFERED), // 0xa0402018
    asio3_map_op_244c      = ASIO3_CTL(0x913, METHOD_BUFFERED), // 0xa040244c
    asio3_unmap            = ASIO3_CTL(0x914, METHOD_BUFFERED), // 0xa0402450
    // haltranslate family: 6400/6404/6408 = mem-or-io read b/w/d
    // haltranslate family (FILE_READ_ACCESS): 6400=b 6404=w 6408=d
    // (6401/6405 are the same funcs with the method bits set)
    asio3_halt_read_b      = ASIO3_CTL_A(0x900, FILE_READ_ACCESS, METHOD_BUFFERED),  // 0xa0406400
    asio3_halt_read_w      = ASIO3_CTL_A(0x901, FILE_READ_ACCESS, METHOD_BUFFERED),  // 0xa0406404
    asio3_halt_read_d      = ASIO3_CTL_A(0x902, FILE_READ_ACCESS, METHOD_BUFFERED),  // 0xa0406408
    asio3_rdmsr_v2         = ASIO3_CTL_A(0x916, FILE_READ_ACCESS, METHOD_BUFFERED),  // 0xa0406458, msr >= 8
    // port write family (FILE_WRITE_ACCESS)
    asio3_port_out_b       = ASIO3_CTL_A(0x910, FILE_WRITE_ACCESS, METHOD_BUFFERED), // 0xa040a440
    asio3_port_out_w       = ASIO3_CTL_A(0x911, FILE_WRITE_ACCESS, METHOD_BUFFERED), // 0xa040a444
    asio3_port_out_d       = ASIO3_CTL_A(0x912, FILE_WRITE_ACCESS, METHOD_BUFFERED), // 0xa040a448
};

enum asio3_status : NTSTATUS {
    asio3_ok              = 0,
    asio3_err_failed      = 0xC0000001,
    asio3_err_nores       = 0xC0000004,   // buffer too small
    asio3_err_deny        = 0xC0000022,   // allowlist rejection
    asio3_err_quota       = 0xC0000023,   // msr < 8 on the v2 path
    asio3_err_invalid     = 0xC000000D,
};

#pragma pack(push, 1)

// ---- 0xa0400f70 pci config read --------------------------------------------
// no allowlist anywhere in this handler. addr is the raw CF8 value:
// enable(31) | bus<<16 | dev<<11 | fn<<8 | reg. reg auto-advances by 4 per
// dword read. count at +8, results at +0xA. in must be >= 0x20C (512 dwords).
struct ASIO3_PCI_READ {
    uint32_t addr;                    // CF8-style address
    uint32_t pad;
    uint16_t count;                   // dwords to read, <= 0x200
    uint32_t out[512];                // results land here, copied back
};

// ---- 0xa0400f74 / 0xa0400f78 bulk port io ----------------------------------
// f74: reads 'count' bytes starting at 'port' (in al,dx; port++).
// f78: indexed loop - out dx,value(+6); port+idx; in al -> data[idx].
// both allowlist-check every port they touch.
struct ASIO3_PORT_BULK {
    uint16_t pad;
    uint16_t port;                    // start port
    uint8_t  value;                   // f78: index written before each read
    uint8_t  pad2[3];
    uint16_t count;                   // bytes, <= 0x200
    uint8_t  data[512];               // results (f74) or payload+results (f78)
};

// ---- 0xa0400f88 / 0xa0400f8c msr -------------------------------------------
// table-gated (29 entries: intel rapl/turbo + amd pstate). wrmsr is EDX:EAX.
struct ASIO3_MSR_RW {
    uint32_t msr;
    uint32_t pad;
    uint64_t value;                   // in for wrmsr, out for rdmsr
};

// ---- 0xa0400f90 / 0xa0400f94 contiguous memory ------------------------------
// alloc: user-controlled size, boundary -1. returns both VA and phys.
// free: frees whatever VA you put in - bugchecks if it's not a live alloc.
struct ASIO3_CONTIG_ALLOC {
    uint32_t size;
    uint32_t pad;
    uint64_t phys;                    // out: MmGetPhysicalAddress result
    uint64_t kva;                     // out: kernel VA
};

// ---- 0xa040200c physical page map -------------------------------------------
// sub-command 0x1020: phys = lo(hi) dwords at +0x10/+0x14
// sub-command 0x1028: phys = qword at +0x18
// page-aligned then validated against firmware/MMIO ranges + registry table.
// mapped PAGE_READWRITE via \Device\PhysicalMemory, tracked by the driver.
struct ASIO3_PHYS_MAP {
    uint64_t pad;
    uint64_t subcmd_or_handle;        // 0x1020 / 0x1028, or handle on reply
    uint32_t phys_lo;
    uint32_t phys_hi;
    uint64_t reserved;
};

// ---- 0xa0402450 unmap --------------------------------------------------------
// x64: {pad, handle, base, object} must match a tracked view.
// wow64 + InputLen==4: dword at +0 is used DIRECTLY as the unmap address in
// ZwUnmapViewOfSection(-1, addr) - arbitrary, see ANALYSIS 4.5.
struct ASIO3_UNMAP {
    uint64_t pad;
    uint64_t handle;
    uint64_t base;
    uint64_t object;
};

// ---- 0xa0406400/01/04/05/08 haltranslate read -------------------------------
// addr is bus-relative (Isa, bus 0). allowlist applies to the translated
// port's LOW 16 BITS only; if HAL translates to memory space the driver
// dereferences it directly. width by ioctl (b/w/d).
struct ASIO3_HALT_READ {
    uint32_t addr;
    uint32_t value;                   // out
};

#pragma pack(pop)

class AsIO3Driver {
public:
    AsIO3Driver() = default;
    ~AsIO3Driver() { close(); }
    AsIO3Driver(const AsIO3Driver&) = delete;
    AsIO3Driver& operator=(const AsIO3Driver&) = delete;

    bool open() {
        if (h != INVALID_HANDLE_VALUE) return true;
        h = CreateFileW(ASIO3_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        return h != INVALID_HANDLE_VALUE;
    }

    void close() {
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
    }

    // ungated pci config read - the cleanest proof of kernel access.
    // returns vendor:device of bus/dev/fn, 0xFFFF on refusal.
    uint32_t pci_read(uint8_t bus, uint8_t dev, uint8_t fn, uint8_t reg, uint16_t count = 1) {
        ASIO3_PCI_READ r{};
        r.addr  = 0x80000000u | (bus << 16) | (dev << 11) | (fn << 8) | (reg & 0xFC);
        r.count = count;
        if (!transact(asio3_pci_config_read, &r, sizeof(r), &r, sizeof(r)))
            return 0xFFFFFFFF;
        return r.out[0];
    }

    // allowlisted msr read (0xCE platform-info etc, see table in ANALYSIS 3.3)
    bool rdmsr(uint32_t msr, uint64_t& val) {
        ASIO3_MSR_RW r{ msr, 0, 0 };
        if (!transact(asio3_rdmsr, &r, sizeof(r), &r, sizeof(r))) return false;
        val = r.value;
        return true;
    }

    // allowlisted port byte read
    bool inb(uint16_t port, uint8_t& v) {
        ASIO3_PORT_BULK r{};
        r.port = port; r.count = 1;
        if (!transact(asio3_port_read_bulk, &r, sizeof(r), &r, sizeof(r))) return false;
        v = r.data[0];
        return true;
    }

    // contiguous alloc - phys address oracle
    bool alloc_contiguous(uint32_t size, uint64_t& phys, uint64_t& kva) {
        ASIO3_CONTIG_ALLOC r{ size, 0, 0, 0 };
        if (!transact(asio3_contiguous_alloc, &r, sizeof(r), &r, sizeof(r))) return false;
        phys = r.phys; kva = r.kva;
        return true;
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
